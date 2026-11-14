import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { OsirClientHandoffController, OSIR_HANDOFF_TOKEN_URL, OSIR_HANDOFF_EXCHANGE_URL,
  type OsirClientHandoffOptions, type OsirHandoffAccountContext } from "./osir-client-handoff";
import { HandoffTransportError, type HandoffTokenRequest, type HandoffContext } from "./osir-client-handoff-transport";
import { DesktopSessionManager, DesktopSessionStore, type DesktopSessionPayload } from "./desktop-session";

// Synthetic protocol messages only. No actual code/JWT verification, IPC peer,
// system keychain, production app, account or model request is exercised here.
const flowId = Buffer.alloc(32, 1).toString("base64url");
const otherFlow = Buffer.alloc(32, 2).toString("base64url");
const state = Buffer.alloc(32, 3).toString("base64url");
const code = Buffer.alloc(32, 4).toString("base64url");
const receiverInstanceId = Buffer.alloc(32, 5).toString("base64url");
const codeVerifier = Buffer.alloc(48, 6).toString("base64url");
const assertion = [Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "osir-anywhere-handoff+jwt", kid: "fixture" })).toString("base64url"),
  Buffer.from(JSON.stringify({ sub: "123", aud: "osir-anywhere-server", fixture: true })).toString("base64url"), Buffer.alloc(64).toString("base64url")].join(".");
const identity = { issuer: "https://osirclaw.com", subject: "123", userId: "fixture-user" };
const session = (): DesktopSessionPayload => ({ accessToken: "synthetic-access-only", tokenType: "Bearer", expiresIn: 300,
  refreshToken: Buffer.alloc(32, 8).toString("base64url"), refreshExpiresIn: 604800, identity: { ...identity } });
const token = () => ({ code: 0, message: "success", data: { assertion,
  token_type: "urn:osir:params:token-type:anywhere-handoff", expires_in: 60, audience: "osir-anywhere-server" } });
const request = (): HandoffTokenRequest => ({ grant_type: "urn:osir:params:grant-type:anywhere-handoff", client_id: "osir-anywhere-desktop",
  code, code_verifier: codeVerifier, state, receiver_instance_id: receiverInstanceId, target_origin: "https://anywhere.osirclaw.com" });
const context = (): HandoffContext => ({ flowId, state, receiverInstanceId, targetOrigin: "https://anywhere.osirclaw.com",
  codeDeadline: performance.now() + 60_000, configuredToolTypes: ["codex"] });
const account = (): OsirHandoffAccountContext => ({ generation: 0, desktopIdentity: null, localBinding: null });
type Consume<T> = (request: HandoffTokenRequest, context: HandoffContext, signal: AbortSignal) => Promise<T>;
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(r => { resolve = r; }); return { resolve, promise }; }
function fixture(overrides: Partial<OsirClientHandoffOptions> = {}) {
  const calls: { url: string; init: RequestInit; body: Record<string, unknown> }[] = [];
  const accepted: Parameters<OsirClientHandoffOptions["onAuthenticated"]>[0][] = [];
  const rejected: DesktopSessionPayload[] = [];
  let transportCalls = 0, prepared = 0, reads = 0;
  let authContext = account(); let handoff = context(); let tokenRequest = request();
  let tokenResponse = () => Response.json(token()); let sessionResponse = () => Response.json(session());
  const options: OsirClientHandoffOptions = {
    transport: { async run<T>(flow: string, consume: Consume<T>, signal?: AbortSignal) {
      transportCalls++; assert.equal(flow, flowId);
      return consume(tokenRequest, handoff, signal ?? new AbortController().signal) as Promise<T>;
    } },
    fetcher: async (input, init = {}) => {
      const url = String(input); assert.ok([OSIR_HANDOFF_TOKEN_URL, OSIR_HANDOFF_EXCHANGE_URL].includes(url));
      calls.push({ url, init, body: JSON.parse(init.body as string) });
      return url === OSIR_HANDOFF_TOKEN_URL ? tokenResponse() : sessionResponse();
    },
    prepareLogin: async () => { prepared++; },
    readAccountContext: async () => { reads++; return authContext; },
    onAuthenticated: async value => { accepted.push(value); return true; },
    reject: async (value, server) => { assert.equal(server.serverUrl, "https://anywhere.osirclaw.com"); rejected.push(value); },
    ...overrides,
  };
  const controller = new OsirClientHandoffController(options);
  return { controller, options, calls, accepted, rejected, run: (signal?: AbortSignal) => controller.run({ flowId }, signal),
    get counts() { return { prepared, reads, transportCalls }; },
    set account(value: OsirHandoffAccountContext) { authContext = value; },
    set handoff(value: HandoffContext) { handoff = value; }, set request(value: HandoffTokenRequest) { tokenRequest = value; },
    set tokenResponse(value: () => Response) { tokenResponse = value; }, set sessionResponse(value: () => Response) { sessionResponse = value; },
  };
}
const failure = (reason: string) => ({ status: "error", reason });

test("explicit flow exchanges at fixed endpoints, then delivers only verified tool selection to Main", async () => {
  const f = fixture();
  assert.deepEqual(f.counts, { prepared: 0, reads: 0, transportCalls: 0 }, "construction never logs in");
  assert.deepEqual(await f.run(), { status: "authenticated" });
  assert.deepEqual(f.calls.map(c => c.url), [OSIR_HANDOFF_TOKEN_URL, OSIR_HANDOFF_EXCHANGE_URL]);
  assert.deepEqual(f.calls[0].body, request());
  assert.deepEqual(f.calls[1].body, { assertion, handoff: { flowId, state, receiverInstanceId, codeVerifier,
    targetOrigin: "https://anywhere.osirclaw.com" } });
  assert.equal(Object.hasOwn(f.calls[1].body, "configuredToolTypes"), false, "selection never goes to the cloud");
  for (const call of f.calls) {
    assert.equal(call.init.credentials, "omit"); assert.equal(call.init.redirect, "error"); assert.equal(call.init.cache, "no-store");
    assert.equal(call.init.method, "POST"); assert.equal(new Headers(call.init.headers).has("authorization"), false);
    assert.equal(new Headers(call.init.headers).has("cookie"), false);
  }
  assert.deepEqual(f.accepted[0].session, session());
  assert.deepEqual(f.accepted[0].configuredToolTypes, ["codex"]);
  assert.equal(Object.isFrozen(f.accepted[0].configuredToolTypes), true);
  assert.equal(f.accepted[0].accountGeneration, 0);
  assert.deepEqual(f.counts, { prepared: 1, reads: 2, transportCalls: 1 });
  assert.equal(f.rejected.length, 0);
});

test("matching existing refreshed identity and local owner permit handoff without another auth decision", async () => {
  const f = fixture();
  f.account = { generation: 7, desktopIdentity: { ...identity }, localBinding: { serverUrl: "https://anywhere.osirclaw.com", ownerUserId: identity.userId } };
  assert.deepEqual(await f.run(), { status: "authenticated" });
  assert.equal(f.accepted[0].accountGeneration, 7);
});

for (const tools of [[], ["claude"], ["dsh"], ["claude", "codex", "dsh"]] as const) {
  test(`configured selection ${JSON.stringify(tools)} is passed without guessing extra installed tools`, async () => {
    const f = fixture(); f.handoff = { ...context(), configuredToolTypes: tools };
    assert.deepEqual(await f.run(), { status: "authenticated" });
    assert.deepEqual(f.accepted[0].configuredToolTypes, tools);
  });
}

for (const patch of [{ issuer: "https://foreign.test" }, { subject: "124" }, { userId: "other-user" }]) {
  test(`account_mismatch rejects before accept for an existing identity ${Object.keys(patch)[0]} conflict`, async () => {
    const f = fixture(); f.account = { ...account(), desktopIdentity: { ...identity, ...patch } };
    const result = await f.run(); assert.deepEqual(result, failure("account_mismatch")); assert.equal(f.accepted.length, 0);
    // Invalid issuer can be rejected before exchange; otherwise reject only the new session.
    assert.equal(f.rejected.length, patch.issuer ? 0 : 1);
    assert.ok(!JSON.stringify(result).includes("other-user"));
  });
}

for (const binding of [
  { serverUrl: "https://anywhere.osirclaw.com", ownerUserId: "other-user" },
  { serverUrl: "https://other.test", ownerUserId: identity.userId },
  { serverUrl: "https://anywhere.osirclaw.com", ownerUserId: "" },
]) {
  test(`local binding owner/origin conflict fails closed: ${JSON.stringify(binding)}`, async () => {
    const f = fixture(); f.account = { ...account(), localBinding: binding };
    assert.deepEqual(await f.run(), failure("account_mismatch")); assert.equal(f.accepted.length, 0);
    assert.equal(f.rejected.length, binding.ownerUserId === "other-user" ? 1 : 0);
  });
}

test("account switch/logout/binding changes during exchange cannot overwrite current account", async () => {
  for (const changed of [
    { ...account(), generation: 1 }, { ...account(), desktopIdentity: { ...identity } },
    { ...account(), localBinding: { serverUrl: "https://anywhere.osirclaw.com", ownerUserId: identity.userId } },
  ]) {
    const f = fixture(); f.sessionResponse = () => { f.account = changed; return Response.json(session()); };
    assert.deepEqual(await f.run(), failure("account_mismatch"));
    assert.equal(f.accepted.length, 0); assert.equal(f.rejected.length, 1);
  }
});

test("context snapshots are copied, so mutation of the original identity cannot erase a race", async () => {
  const original = { ...account(), desktopIdentity: { ...identity } }; const f = fixture(); f.account = original;
  f.sessionResponse = () => { original.desktopIdentity.subject = "124"; return Response.json(session()); };
  assert.deepEqual(await f.run(), failure("account_mismatch")); assert.equal(f.rejected.length, 1);
});

test("prepareLogin drains existing revocations first and failure stops transport/exchange", async () => {
  const f = fixture({ prepareLogin: async () => { throw new Error("synthetic-secret-refresh"); } });
  assert.deepEqual(await f.run(), failure("invalid_handoff"));
  assert.equal(f.counts.transportCalls, 0); assert.equal(f.calls.length, 0); assert.equal(f.accepted.length, 0);
});

test("a stored-session read/refresh failure is never treated as no existing account", async () => {
  const f = fixture({ readAccountContext: async () => { throw new Error("synthetic-secret-refresh"); } });
  assert.deepEqual(await f.run(), failure("invalid_handoff")); assert.equal(f.calls.length, 0);
});

test("an explicit callback rejection/exception revokes the new session exactly once", async () => {
  for (const onAuthenticated of [async () => false, async () => { throw new Error("synthetic-secret-callback"); }]) {
    const f = fixture({ onAuthenticated });
    const result = await f.run(); assert.equal(result.status, "error"); assert.equal(f.rejected.length, 1);
    assert.deepEqual(f.rejected[0], session()); assert.ok(!JSON.stringify(result).includes("synthetic"));
  }
});

test("cleanup failure is explicit and never claims success", async () => {
  const f = fixture({ onAuthenticated: async () => false, reject: async () => { throw new Error("synthetic-secret-cleanup"); } });
  assert.deepEqual(await f.run(), failure("cleanup_failed"));
});

test("same flow is single flight; another flow is blocked until cleanup completes", async () => {
  const gate = deferred<void>(); let prepared = 0;
  const f = fixture({ prepareLogin: async () => { prepared++; await gate.promise; } });
  const first = f.run(); assert.equal(f.run(), first);
  assert.deepEqual(await f.controller.run({ flowId: otherFlow }), failure("flow_pending"));
  gate.resolve(); assert.deepEqual(await first, { status: "authenticated" }); assert.equal(prepared, 1);
  assert.deepEqual(await f.run(), failure("flow_pending"), "a consumed flow is not retried");
});

test("invalid inputs and already cancelled/stopped controllers cannot start authorization", async () => {
  const f = fixture();
  for (const input of [null, {}, { flowId: "bad" }, { flowId, assertion }, { flowId, endpoint: "https://evil.test" }]) {
    assert.deepEqual(await f.controller.run(input as { flowId: string }), failure("invalid_request"));
  }
  assert.deepEqual(await f.run(AbortSignal.abort()), failure("cancelled"));
  await f.controller.dispose(); assert.deepEqual(await f.run(), failure("cancelled")); assert.equal(f.calls.length, 0);
});

test("cancel during prepare or token response cannot proceed to exchange", async () => {
  const prepared = deferred<void>(), release = deferred<void>();
  const f = fixture({ prepareLogin: async () => { prepared.resolve(); await release.promise; } });
  const pending = f.run(); await prepared.promise; const cancelled = f.controller.cancel(); release.resolve();
  assert.deepEqual(await pending, failure("cancelled")); await cancelled; assert.equal(f.calls.length, 0);
  const g = fixture(); const fetcher = g.options.fetcher;
  const abort = new AbortController();
  g.options.fetcher = async (url, init) => { const response = await fetcher(url, init); abort.abort(); return response; };
  assert.deepEqual(await g.run(abort.signal), failure("cancelled")); assert.equal(g.calls.length, 1); assert.equal(g.rejected.length, 0);
});

test("cancel on an issued exchange response still takes cleanup ownership", async () => {
  const f = fixture(); const abort = new AbortController();
  f.sessionResponse = () => { abort.abort(); return Response.json(session()); };
  assert.deepEqual(await f.run(abort.signal), failure("cancelled"));
  assert.equal(f.accepted.length, 0); assert.equal(f.rejected.length, 1);
});

test("cancel during/after accept revokes even a session already saved by callback", async () => {
  const started = deferred<void>(), release = deferred<boolean>();
  const f = fixture({ onAuthenticated: async () => { started.resolve(); return release.promise; } });
  const pending = f.run(); await started.promise; const cancelled = f.controller.cancel(); release.resolve(true);
  assert.deepEqual(await pending, failure("cancelled")); await cancelled; assert.equal(f.rejected.length, 1);
});

test("transport cancellation cannot let a late exchange response escape cleanup", async () => {
  const response = deferred<Response>(), started = deferred<void>(); const transportAbort = new AbortController();
  const f = fixture({ transport: { async run<T>(_flow: string, consume: Consume<T>, signal?: AbortSignal) {
    const work = consume(request(), context(), AbortSignal.any([signal!, transportAbort.signal]));
    void work.catch(() => {});
    await started.promise; transportAbort.abort(); throw new HandoffTransportError("cancelled");
  } } });
  const fetcher = f.options.fetcher;
  f.options.fetcher = async (url, init) => {
    if (String(url) === OSIR_HANDOFF_EXCHANGE_URL) { started.resolve(); return response.promise; }
    return fetcher(url, init);
  };
  const pending = f.run(); await started.promise;
  assert.deepEqual(await f.controller.run({ flowId: otherFlow }), failure("flow_pending"));
  response.resolve(Response.json(session()));
  assert.deepEqual(await pending, failure("cancelled")); assert.equal(f.accepted.length, 0); assert.equal(f.rejected.length, 1);
});

for (const transportReason of ["peer_untrusted", "unsafe_path", "timeout", "flow_pending", "unavailable"] as const) {
  test(`transport ${transportReason} is a fixed local error without network consumption`, async () => {
    const f = fixture({ transport: { async run() { throw new HandoffTransportError(transportReason); } } });
    const result = await f.run();
    assert.deepEqual(result, failure(transportReason === "peer_untrusted" ? "receiver_untrusted" : ["timeout", "flow_pending"].includes(transportReason) ? transportReason : "invalid_handoff"));
    assert.equal(f.calls.length, 0);
  });
}

test("bad transport request/context/selection is rejected before sending code or verifier", async () => {
  for (const patch of [
    { flowId: otherFlow }, { state: code }, { receiverInstanceId: code }, { targetOrigin: "https://evil.test" },
    { configuredToolTypes: undefined }, { configuredToolTypes: ["codex", "claude"] }, { configuredToolTypes: ["codex", "codex"] },
    { configuredToolTypes: ["unknown"] },
  ]) {
    const f = fixture(); f.handoff = { ...context(), ...patch } as HandoffContext;
    assert.deepEqual(await f.run(), failure("invalid_handoff")); assert.equal(f.calls.length, 0);
  }
  const expired = fixture(); expired.handoff = { ...context(), codeDeadline: performance.now() - 1 };
  assert.deepEqual(await expired.run(), failure("timeout")); assert.equal(expired.calls.length, 0);
  const f = fixture(); f.request = { ...request(), extraSecret: "fixture" } as HandoffTokenRequest;
  assert.deepEqual(await f.run(), failure("invalid_handoff")); assert.equal(f.calls.length, 0);
});

test("token response validates exact v1 envelope, purpose, audience, TTL and bounded assertion", async () => {
  for (const response of [
    { ...token(), code: 1 }, { ...token(), message: "other" }, { ...token(), unexpected: true },
    { ...token(), data: { ...token().data, token_type: "urn:osir:params:token-type:anywhere-login" } },
    { ...token(), data: { ...token().data, audience: "other" } }, { ...token(), data: { ...token().data, expires_in: 61 } },
    { ...token(), data: { ...token().data, assertion: "unsafe" } }, { ...token(), data: { ...token().data, assertion: "x".repeat(4097) } },
    { ...token(), data: { ...token().data, refreshToken: "must-never-forward" } },
  ]) {
    const f = fixture(); f.tokenResponse = () => Response.json(response);
    assert.deepEqual(await f.run(), failure("invalid_handoff")); assert.equal(f.calls.length, 1); assert.equal(f.accepted.length, 0);
  }
});

test("duplicate keys, bad JSON/UTF8 and oversized responses cannot reach exchange", async () => {
  for (const body of ['{"code":0,"code":0}', '{"code":0.0}', '{}{}', 'not json', ' '.repeat(16385), Buffer.from([0xff])]) {
    const f = fixture(); f.tokenResponse = () => new Response(body);
    assert.deepEqual(await f.run(), failure("invalid_handoff")); assert.equal(f.calls.length, 1);
  }
});

test("HTTP failures preserve only allowlisted fixed reasons, without automatic POST retries", async () => {
  for (const [status, reason] of [[400, "invalid_request"], [401, "invalid_handoff"], [403, "consent_required"],
    [403, "capability_unavailable"], [409, "account_mismatch"], [429, "rate_limited"], [503, "dependency_unavailable"]] as const) {
    const f = fixture(); f.tokenResponse = () => Response.json({ code: status, reason, message: "secret-upstream-body" }, { status });
    assert.deepEqual(await f.run(), failure(reason)); assert.equal(f.calls.length, 1);
  }
  const f = fixture(); f.tokenResponse = () => Response.json({ reason: "secret-invalid-reason" }, { status: 401 });
  assert.deepEqual(await f.run(), failure("invalid_handoff")); assert.equal(f.calls.length, 1);
});

test("redirected and alternate-origin responses cannot deliver credentials", async () => {
  for (const patch of [{ redirected: true }, { url: "https://evil.test" }]) {
    const f = fixture(); f.tokenResponse = () => { const r = Response.json(token()); Object.defineProperties(r,
      Object.fromEntries(Object.entries(patch).map(([k, value]) => [k, { value }]))); return r; };
    assert.deepEqual(await f.run(), failure("invalid_handoff")); assert.equal(f.calls.length, 1);
  }
});

test("unsafe session identities are rejected/revoked; int64 subjects retain exact string identity", async () => {
  for (const subject of ["0", "01", "9223372036854775808"]) {
    const f = fixture(); f.sessionResponse = () => Response.json({ ...session(), identity: { ...identity, subject } });
    assert.deepEqual(await f.run(), failure("account_mismatch")); assert.equal(f.rejected.length, 1); assert.equal(f.accepted.length, 0);
  }
  const f = fixture(); f.sessionResponse = () => Response.json({ ...session(), identity: { ...identity, subject: "9223372036854775807" } });
  assert.deepEqual(await f.run(), { status: "authenticated" }); assert.equal(f.accepted[0].session.identity.subject, "9223372036854775807");
});

test("real session reject queues failed revocation without overwriting another active account", async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "handoff-session-fixture-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const store = new DesktopSessionStore(path.join(root, "session.enc"), {
    isEncryptionAvailable: () => true,
    encryptString: text => Buffer.from(`fixture-encrypted:${Buffer.from(text).toString("base64")}`),
    decryptString: bytes => Buffer.from(bytes.toString().slice("fixture-encrypted:".length), "base64").toString(),
  });
  const manager = new DesktopSessionManager(store, async () => { throw new Error("offline fixture"); });
  const old = { ...session(), refreshToken: Buffer.alloc(32, 9).toString("base64url"), identity: { ...identity, subject: "124", userId: "old-user" } };
  const server = { serverUrl: "https://anywhere.osirclaw.com", apiNamespace: "/api/v2", oauthWebOrigin: "https://anywhere.osirclaw.com" };
  manager.accept(old, server);
  const f = fixture({ prepareLogin: () => manager.prepareLogin(), reject: (value, target) => manager.reject(value, target) });
  f.account = { ...account(), desktopIdentity: old.identity };
  assert.deepEqual(await f.run(), failure("account_mismatch"));
  assert.equal(f.accepted.length, 0); assert.equal(store.read()?.refreshToken, old.refreshToken);
  assert.equal(store.readRevocations()[0].refreshToken, session().refreshToken);
});
