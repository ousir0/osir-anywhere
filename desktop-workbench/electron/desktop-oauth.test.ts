import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { request } from "node:http";
import test from "node:test";
import {
  DESKTOP_OAUTH_CALLBACK_PATH, DESKTOP_OAUTH_CLIENT_ID, DesktopOAuthFlow,
  createDesktopOAuthRequest, exchangeDesktopOAuthCode, listenDesktopOAuth, resolveDesktopIdentity,
  type DesktopOAuthMainResult, type DesktopOAuthPending,
} from "./desktop-oauth";
import { resolveDesktopServer } from "./desktop-server";

const code = () => randomBytes(32).toString("base64url");
const identity = { apiOrigin: "https://identity-api.example", webOrigin: "https://identity-web.example", allowLoopbackHttp: false };
const server = resolveDesktopServer("https://anywhere.example");
const env = { OSIR_IDENTITY_API_ORIGIN: identity.apiOrigin, OSIR_IDENTITY_WEB_ORIGIN: identity.webOrigin };
const envelope = (data: object) => Response.json({ code: 0, message: "success", data });
const tokens = () => ({ access_token: "synthetic-osir-access", refresh_token: "synthetic-osir-refresh", expires_in: 900, token_type: "Bearer", scope: "identity:read" });
const assertion = () => ({ assertion: "synthetic.assertion.value", token_type: "urn:osir:params:token-type:anywhere-login", expires_in: 60, audience: "osir-anywhere-server" });
const session = () => ({ accessToken: "synthetic-anywhere-token", tokenType: "Bearer", expiresIn: 300, refreshToken: "r".repeat(43), refreshExpiresIn: 604800, identity: { issuer: "https://osirclaw.com", subject: "123", userId: "synthetic-user" } });
const pending = (): DesktopOAuthPending => ({ state: "synthetic-state", verifier: randomBytes(48).toString("base64url"), redirectUri: `http://127.0.0.1:12345${DESKTOP_OAUTH_CALLBACK_PATH}` });
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(r => { resolve = r; }); return { promise, resolve }; }
function http(url: string, options: { method?: string; path?: string; host?: string; headers?: string[] } = {}): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = request({ hostname: "127.0.0.1", port: u.port, path: options.path ?? `${u.pathname}${u.search}`, method: options.method ?? "GET", headers: options.headers ?? { host: options.host ?? u.host }, agent: false }, res => {
      let text = ""; res.setEncoding("utf8"); res.on("data", chunk => { text += chunk; });
      res.on("end", () => resolve({ status: res.statusCode!, text }));
    });
    req.setTimeout(2000, () => req.destroy(new Error("test request timed out")));
    req.on("error", reject); req.end();
  });
}
function callback(authorizeUrl: string, fields?: Record<string, string>) {
  const params = new URL(authorizeUrl).searchParams;
  const result = new URL(params.get("redirect_uri")!);
  result.search = new URLSearchParams(fields ?? { code: code(), state: params.get("state")! }).toString();
  return result.toString();
}
function mockServices(overrides: Partial<Record<"token" | "assertion" | "exchange" | "logout" | "desktopLogout", (init: RequestInit) => Response | Promise<Response>>> = {}) {
  const calls: Array<{ url: string; init: RequestInit; body: Record<string, unknown> }> = [];
  const fetcher: typeof fetch = async (input, init = {}) => {
    const url = String(input); calls.push({ url, init, body: JSON.parse(String(init.body)) });
    assert.equal(init.method, "POST"); assert.equal(init.redirect, "error"); assert.equal(init.credentials, "omit"); assert.equal(init.cache, "no-store");
    assert.equal(new Headers(init.headers).get("content-type"), "application/json");
    if (url === `${identity.apiOrigin}/api/v1/auth/desktop/token`) return overrides.token?.(init) ?? envelope(tokens());
    if (url === `${identity.apiOrigin}/api/v1/auth/desktop/anywhere/assertion`) return overrides.assertion?.(init) ?? envelope(assertion());
    if (url === `${server.serverUrl}/api/v2/auth/osir/desktop/exchange`) return overrides.exchange?.(init) ?? Response.json(session());
    if (url === `${identity.apiOrigin}/api/v1/auth/logout`) return overrides.logout?.(init) ?? envelope({});
    if (url === `${server.serverUrl}/api/v2/auth/osir/desktop/logout`) return overrides.desktopLogout?.(init) ?? new Response(null, { status: 204 });
    assert.fail("unexpected service endpoint");
  };
  return { calls, fetcher };
}

test("identity API and Web origins are independent; HTTP is explicit development loopback only", () => {
  assert.deepEqual(resolveDesktopIdentity({ env }), identity);
  assert.equal(resolveDesktopIdentity({ env: {} }).apiOrigin, "https://osirclaw.com");
  for (const bad of ["http://remote.example", "http://127.0.0.1:9000", "https://user:secret@api.example", "https://api.example/path", "https://api.example?x=1", "https://api.example#x", "file:///tmp/test"]) {
    assert.throws(() => resolveDesktopIdentity({ env: { ...env, OSIR_IDENTITY_API_ORIGIN: bad } }));
  }
  for (const bad of ["http://remote.example", "https://user:secret@web.example", "https://web.example/path"]) {
    assert.throws(() => resolveDesktopIdentity({ env: { ...env, OSIR_IDENTITY_WEB_ORIGIN: bad } }));
  }
  const devEnv = { OSIR_IDENTITY_ALLOW_LOOPBACK_HTTP: "1", OSIR_IDENTITY_API_ORIGIN: "http://127.0.0.1:9000", OSIR_IDENTITY_WEB_ORIGIN: "http://localhost:9001" };
  assert.throws(() => resolveDesktopIdentity({ env: devEnv, development: false }));
  assert.equal(resolveDesktopIdentity({ env: devEnv, development: true }).apiOrigin, "http://127.0.0.1:9000");
  assert.throws(() => resolveDesktopIdentity({ env: { ...devEnv, OSIR_IDENTITY_WEB_ORIGIN: "http://remote.example" }, development: true }));
});

test("authorization uses OSIR route, identity:read, random state/verifier and S256 with a dynamic loopback redirect", async t => {
  const listener = await listenDesktopOAuth(identity.webOrigin); t.after(() => listener.close());
  const url = new URL(listener.authorizeUrl), params = url.searchParams;
  assert.equal(url.origin, identity.webOrigin); assert.equal(url.pathname, "/auth/desktop/authorize"); assert.equal(url.hash, "");
  assert.equal(params.get("client_id"), DESKTOP_OAUTH_CLIENT_ID); assert.equal(params.get("scope"), "identity:read");
  assert.equal(params.get("code_challenge_method"), "S256");
  assert.equal(params.get("code_challenge"), createHash("sha256").update(listener.pending.verifier, "ascii").digest("base64url"));
  assert.equal(params.get("state"), listener.pending.state); assert.equal(listener.pending.state.length, 43);
  assert.match(listener.pending.redirectUri, /^http:\/\/127\.0\.0\.1:[1-9][0-9]*\/osir\/desktop\/callback$/);
  const other = createDesktopOAuthRequest(identity.webOrigin, listener.pending.redirectUri);
  assert.notEqual(other.pending.state, listener.pending.state); assert.notEqual(other.pending.verifier, listener.pending.verifier);
  const authCode = code(); const res = await http(callback(listener.authorizeUrl, { code: authCode, state: listener.pending.state }));
  assert.equal(res.status, 200); assert.equal(await listener.code, authCode); assert.ok(!res.text.includes(authCode));
  await listener.close(); await assert.rejects(http(listener.pending.redirectUri));
  assert.throws(() => createDesktopOAuthRequest(identity.webOrigin, "osir-anywhere://oauth/callback"));
});

test("real HTTP listener rejects Host/method/path/state/code/duplicate and unknown fields without consuming the valid attempt", async t => {
  const listener = await listenDesktopOAuth(identity.webOrigin); t.after(() => listener.close());
  const valid = callback(listener.authorizeUrl), parsed = new URL(valid);
  const options = [
    { host: "localhost:" + parsed.port }, { host: "evil.example" }, { method: "POST" }, { method: "HEAD" },
    { path: "/osir/desktop/callback/" + parsed.search }, { path: "/osir/desktop/%63allback" + parsed.search },
    { path: "http://evil.example" + parsed.pathname + parsed.search },
    { path: parsed.pathname + parsed.search + "&state=duplicate" }, { path: parsed.pathname + parsed.search + "&code=duplicate" },
    { path: parsed.pathname + parsed.search + "&unknown=value" }, { path: parsed.pathname + "?code=" + code() + "&state=wrong" },
    { path: parsed.pathname + "?code=invalid&state=" + listener.pending.state }, { path: parsed.pathname + parsed.search + "&error=access_denied" },
    { headers: ["Host", parsed.host, "Host", parsed.host] },
  ];
  for (const input of options) assert.equal((await http(valid, input)).status, 400);
  assert.equal((await http(valid)).status, 200); await listener.code;
});

test("state-validated denial closes listener and never exposes remote error_description", async t => {
  const listener = await listenDesktopOAuth(identity.webOrigin); t.after(() => listener.close());
  const rejected = assert.rejects(listener.code, error => error instanceof Error && /declined/.test(error.message) && !error.message.includes("sensitive"));
  assert.equal((await http(callback(listener.authorizeUrl, { state: listener.pending.state, error: "access_denied", error_description: "sensitive value" }))).status, 400);
  await rejected; await listener.close(); await assert.rejects(http(listener.pending.redirectUri));
});

test("timeout and cancellation release real listener ports, including pre-aborted startup", async () => {
  const timeout = await listenDesktopOAuth(identity.webOrigin, { timeoutMs: 40 });
  await assert.rejects(timeout.code, /timed out/); await timeout.close(); await assert.rejects(http(timeout.pending.redirectUri));
  const abort = new AbortController(); const listener = await listenDesktopOAuth(identity.webOrigin, { signal: abort.signal });
  const rejection = assert.rejects(listener.code, /cancelled/); abort.abort(); await rejection; await listener.close();
  await assert.rejects(http(listener.pending.redirectUri));
  await assert.rejects(listenDesktopOAuth(identity.webOrigin, { signal: AbortSignal.abort() }));
});

test("exchange follows the native-session contract and returns refresh only on the Main stack", async () => {
  const services = mockServices(); const p = pending(); const authCode = code();
  assert.deepEqual(await exchangeDesktopOAuthCode(authCode, p, server, identity, services.fetcher, () => {}), session());
  assert.equal(services.calls.length, 4);
  assert.deepEqual(services.calls[0].body, { grant_type: "authorization_code", client_id: DESKTOP_OAUTH_CLIENT_ID, code: authCode, code_verifier: p.verifier, redirect_uri: p.redirectUri });
  assert.equal(new Headers(services.calls[0].init.headers).get("authorization"), null);
  assert.deepEqual(services.calls[1].body, {});
  assert.equal(new Headers(services.calls[1].init.headers).get("authorization"), `Bearer ${tokens().access_token}`);
  assert.deepEqual(services.calls[2].body, { assertion: assertion().assertion });
  assert.equal(new Headers(services.calls[2].init.headers).get("authorization"), null);
  assert.ok(!JSON.stringify(services.calls[2]).includes("synthetic-osir"));
  assert.deepEqual(services.calls[3].body, { refresh_token: tokens().refresh_token });
  assert.equal(new Headers(services.calls[3].init.headers).get("authorization"), null);
});

test("failed, malformed, redirected and oversized responses fail closed; issued refresh grants are revoked", async () => {
  const cases: Array<Parameters<typeof mockServices>[0]> = [
    { token: () => envelope({ ...tokens(), scope: "account:read" }) }, { token: () => envelope({ ...tokens(), access_token: "" }) },
    { token: () => Response.json({ code: 401, data: tokens(), message: "synthetic-secret" }) },
    { assertion: () => envelope({ ...assertion(), audience: "other" }) }, { assertion: () => envelope({ ...assertion(), expires_in: 3600 }) },
    { assertion: () => envelope({ ...assertion(), token_type: "Bearer" }) }, { assertion: () => new Response("invalid json") },
    { assertion: () => new Response("x".repeat(65537)) }, { assertion: () => Response.json({ message: "synthetic-secret" }, { status: 500 }) },
    { assertion: () => Response.redirect("https://untrusted.example", 302) },
    { exchange: () => Response.json({ ...session(), expiresIn: 3600 }) }, { exchange: () => Response.json({ ...session(), tokenType: "MAC" }) },
    { exchange: () => Response.json({ ...session(), accessToken: "" }) },
  ];
  for (const override of cases) {
    const services = mockServices(override);
    await assert.rejects(exchangeDesktopOAuthCode(code(), pending(), server, identity, services.fetcher, () => {}), e => e instanceof Error && /exchange failed/.test(e.message) && !e.message.includes("synthetic"));
    assert.equal(services.calls.at(-1)?.url, `${identity.apiOrigin}/api/v1/auth/logout`);
  }
  const noTokens = mockServices({ token: () => Response.json({ message: "synthetic-secret" }, { status: 401 }) });
  await assert.rejects(exchangeDesktopOAuthCode(code(), pending(), server, identity, noTokens.fetcher, () => {})); assert.equal(noTokens.calls.length, 1);
});

test("logout failure is best effort; remote HTTP and invalid namespace never receive credentials", async () => {
  const services = mockServices({ logout: () => { throw new Error("synthetic-refresh-must-not-escape"); } });
  assert.deepEqual(await exchangeDesktopOAuthCode(code(), pending(), server, identity, services.fetcher, () => {}), session());
  const blocked = mockServices();
  for (const target of [resolveDesktopServer("http://remote.example"), resolveDesktopServer("http://127.0.0.1:8000"), { ...server, apiNamespace: "" }]) {
    await assert.rejects(exchangeDesktopOAuthCode(code(), pending(), target, identity, blocked.fetcher, () => {}));
  }
  assert.equal(blocked.calls.length, 0);
});

function flowFixture(overrides: Parameters<typeof mockServices>[0] = {}, timeoutMs = 2000) {
  const services = mockServices(overrides), results: DesktopOAuthMainResult[] = [], completed = deferred<DesktopOAuthMainResult>();
  const opened: string[] = [];
  const flow = new DesktopOAuthFlow({ env, timeoutMs, fetcher: services.fetcher,
    openExternal: async url => { opened.push(url); }, onDiscard: async (credentials, origin) => {
      await services.fetcher(`${origin.serverUrl}/api/v2/auth/osir/desktop/logout`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ refreshToken: credentials.refreshToken }), credentials: "omit", redirect: "error", cache: "no-store" });
    }, onResult: result => { results.push(result); completed.resolve(result); return true; },
  });
  return { services, results, completed, opened, flow };
}

test("system-browser loopback verifies PKCE and delivers credentials to the Main result callback", async t => {
  const fixture = flowFixture(); t.after(() => fixture.flow.shutdown());
  const { authorizeUrl } = await fixture.flow.start(server); assert.deepEqual(fixture.opened, [authorizeUrl]);
  const params = new URL(authorizeUrl).searchParams; assert.equal((await http(callback(authorizeUrl))).status, 200);
  const result = await fixture.completed.promise; assert.deepEqual(result, { status: "success", accessToken: session().accessToken, credentials: session(), server });
  const tokenRequest = fixture.services.calls[0].body;
  assert.equal(createHash("sha256").update(String(tokenRequest.code_verifier), "ascii").digest("base64url"), params.get("code_challenge"));
  assert.equal(tokenRequest.redirect_uri, params.get("redirect_uri")); assert.ok(!JSON.stringify(result).includes("synthetic-osir"));
});

test("retry invalidates old listener/state; cancel and shutdown close listeners and suppress stale results", async t => {
  const fixture = flowFixture(); t.after(() => fixture.flow.shutdown());
  const first = await fixture.flow.start(server), second = await fixture.flow.start(server);
  await assert.rejects(http(callback(first.authorizeUrl)));
  const oldState = new URL(first.authorizeUrl).searchParams.get("state")!;
  assert.equal((await http(callback(second.authorizeUrl, { code: code(), state: oldState }))).status, 400);
  await fixture.flow.cancel(); await assert.rejects(http(callback(second.authorizeUrl)));
  assert.deepEqual(fixture.results, []); assert.equal(fixture.services.calls.length, 0);
  const third = await fixture.flow.start(server); await fixture.flow.shutdown();
  await assert.rejects(http(callback(third.authorizeUrl))); await assert.rejects(fixture.flow.start(server)); assert.deepEqual(fixture.results, []);
});

test("flow timeout publishes a retryable error and browser-open failure cleans up", async t => {
  const fixture = flowFixture({}, 50); t.after(() => fixture.flow.shutdown()); const attempt = await fixture.flow.start(server);
  const result = await fixture.completed.promise; assert.equal(result.status, "error"); if (result.status === "error") assert.match(result.error, /timed out/);
  await fixture.flow.cancel(); await assert.rejects(http(callback(attempt.authorizeUrl)));
  let opened = "";
  const failed = new DesktopOAuthFlow({ env, fetcher: fixture.services.fetcher, openExternal: async url => { opened = url; throw new Error("synthetic-secret"); }, onDiscard: async () => assert.fail("no issued session"), onResult: () => assert.fail("no result for failed browser launch") });
  t.after(() => failed.shutdown()); await assert.rejects(failed.start(server), /Could not open/); await assert.rejects(http(callback(opened)));
});

test("shutdown during exchange aborts request, revokes refresh independently and suppresses results", async t => {
  const entered = deferred<void>(); let aborted = false;
  const fixture = flowFixture({ assertion: init => new Promise<Response>((_, reject) => {
    entered.resolve(); init.signal!.addEventListener("abort", () => { aborted = true; reject(new Error("synthetic-secret")); }, { once: true });
  }) });
  t.after(() => fixture.flow.shutdown()); const attempt = await fixture.flow.start(server);
  await http(callback(attempt.authorizeUrl)); await entered.promise; await fixture.flow.shutdown();
  assert.equal(aborted, true); assert.deepEqual(fixture.results, []);
  assert.equal(fixture.services.calls.at(-1)?.url, `${identity.apiOrigin}/api/v1/auth/logout`);
  assert.equal(fixture.services.calls.at(-1)?.init.signal?.aborted, false); await assert.rejects(http(callback(attempt.authorizeUrl)));
});

test("mocked identity PKCE rejection never calls assertion or Anywhere exchange", async t => {
  const fixture = flowFixture({ token: () => Response.json({ code: 400, message: "invalid verifier" }, { status: 400 }) }); t.after(() => fixture.flow.shutdown());
  const attempt = await fixture.flow.start(server); await http(callback(attempt.authorizeUrl));
  const result = await fixture.completed.promise; assert.equal(result.status, "error"); assert.equal(fixture.services.calls.length, 1);
});
