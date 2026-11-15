import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { DesktopSessionManager, DesktopSessionStore } from "./desktop-session";
import test from "node:test";
import vm from "node:vm";
import ts from "typescript";
import type { OsirClientHandoffOptions } from "./osir-client-handoff";
import type { DesktopSessionPayload } from "./desktop-session";
import { clientHandoffFlowFromArgv, clientHandoffFlowFromSecondInstance, clientHandoffLockData } from "./osir-client-handoff-launch";

// Exercise actual Main wiring, rather than a second implementation of its
// callbacks. Electron/network/storage remain synthetic and no app is launched.
const source = ts.createSourceFile("main.ts", fs.readFileSync(path.resolve(__dirname, "../../electron/main.ts"), "utf8"), ts.ScriptTarget.Latest, true);
const declaration = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === "initializeClientHandoff")!;
const javascript = ts.transpileModule(declaration.getText(source), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
const credentials: DesktopSessionPayload = { accessToken: "synthetic-access", tokenType: "Bearer", expiresIn: 300,
  refreshToken: "r".repeat(43), refreshExpiresIn: 600,
  identity: { issuer: "https://osirclaw.com", subject: "123", userId: "synthetic-user" } };
const server = { serverUrl: "https://anywhere.osirclaw.com", apiNamespace: "/api/v2", oauthWebOrigin: "https://anywhere.osirclaw.com" };

function fixture(manager?: DesktopSessionManager) {
  let options!: OsirClientHandoffOptions;
  let generation = 3;
  const calls: string[] = [];
  const controls = { stopFails: false, bootstrap: async () => {}, binding: null as null | { serverUrl: string; ownerUserId: string } };
  const globals = {
    process: { platform: "darwin", resourcesPath: "/Synthetic/Resources" }, path, __dirname: "/Synthetic/Resources/app.asar/dist/electron",
    app: { isPackaged: true, getAppPath: () => "/Synthetic/Resources/app.asar", getPath: () => "/Synthetic/home" },
    readReleasePublicKey: () => "synthetic-key", resolvePythonBundleDir: () => "/Synthetic/python",
    bundledPythonExecutable: () => "/Synthetic/python/python",
    OsirClientHandoffTransport: class { constructor(readonly options: unknown) {} },
    OsirClientHandoffController: class { constructor(value: OsirClientHandoffOptions) { options = value; } },
    clientHandoff: null,
    desktopSessions: manager ?? {
      prepareClientHandoffLogin: async () => null, refresh: async () => {},
      identityForHandoff: () => ({ generation, identity: null }),
      acceptClientHandoff: () => { generation++; calls.push("accept"); },
      logout: async () => { generation++; calls.push("logout"); },
      reject: async () => { calls.push("reject-issued"); },
    },
    requireBackend: () => ({ request: async (route: string) => {
      calls.push(route); if (route === "/stop" && controls.stopFails) throw new Error("backend stopped"); return route === "/device/binding" ? controls.binding : null;
    } }),
    activeDesktopServer: () => server,
    desktopOAuthFlow: { cancel: async () => {} },
    isQuitting: false, desktopOAuthResult: null,
    serverStore: { save: () => calls.push("save-server") },
    syncBackendServerConnection: async () => { calls.push("sync-server"); },
    showMainWindow: () => {},
    bootstrapClientHandoff: async () => { calls.push("bootstrap"); await controls.bootstrap(); return []; },
    publishDesktopOAuthResult: () => calls.push("publish"),
    net: { fetch: () => assert.fail("no network") },
  };
  vm.runInNewContext(`${javascript}\ninitializeClientHandoff();`, globals);
  return { options, calls, controls, globals, changeAccount: () => { generation++; } };
}

test("Main publishes handoff success only after automatic provisioning completes", async () => {
  const f = fixture();
  let finish!: () => void;
  f.controls.bootstrap = () => new Promise<void>(resolve => { finish = resolve; });
  const operation = Promise.resolve(f.options.onAuthenticated({ session: credentials, server,
    configuredToolTypes: ["codex"], accountGeneration: 3 }, new AbortController().signal));
  await new Promise<void>(resolve => setImmediate(resolve));
  assert.ok(f.calls.includes("bootstrap")); assert.ok(!f.calls.includes("publish"));
  finish(); assert.equal(await operation, true); assert.equal(f.calls.at(-1), "publish");
});

test("accepted failure clears a rotated login and revokes even if backend stop fails", async () => {
  const f = fixture(); await f.options.prepareLogin();
  await f.options.onAuthenticated({ session: credentials, server, configuredToolTypes: [], accountGeneration: 3 }, new AbortController().signal);
  f.controls.stopFails = true;
  await assert.rejects(f.options.reject(credentials, server), /backend stopped/);
  assert.deepEqual(f.calls.slice(-3), ["/stop", "logout", "reject-issued"]);
  assert.equal(f.globals.desktopOAuthResult, null);
});

test("late failed handoff revokes its grant without logging out a newer account", async () => {
  const f = fixture(); await f.options.prepareLogin();
  await f.options.onAuthenticated({ session: credentials, server, configuredToolTypes: [], accountGeneration: 3 }, new AbortController().signal);
  f.changeAccount();
  await f.options.reject(credentials, server);
  assert.ok(!f.calls.includes("logout")); assert.equal(f.calls.at(-1), "reject-issued");
});

test("account change while provisioning prevents publishing an accepted result", async () => {
  const f = fixture(); f.controls.bootstrap = async () => { f.changeAccount(); };
  assert.equal(await f.options.onAuthenticated({ session: credentials, server, configuredToolTypes: [], accountGeneration: 3 }, new AbortController().signal), false);
  assert.ok(!f.calls.includes("publish"));
});

test("Main captures the original launch flow and forwards additionalData to the live controller", async () => {
  const flow = "B".repeat(43);
  const launchStatements = source.statements.filter(node => ts.isVariableStatement(node)
    && node.declarationList.declarations.some(row => ["initialClientHandoffFlow", "hasSingleInstanceLock"].includes(row.name.getText(source))));
  const queue = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === "queueClientHandoff")!;
  let secondInstance!: ts.Node;
  const visit = (node: ts.Node): void => {
    if (ts.isExpressionStatement(node) && ts.isCallExpression(node.expression)
      && node.expression.expression.getText(source) === "app.on"
      && node.expression.arguments[0]?.getText(source) === '"second-instance"') secondInstance = node;
    ts.forEachChild(node, visit);
  };
  visit(source);
  assert.equal(launchStatements.length, 2);
  assert.ok(secondInstance);
  const script = ts.transpileModule([...launchStatements, queue, secondInstance].map(node => node.getText(source)).join("\n"),
    { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  let captured: unknown;
  let handler!: (event: object, argv: string[], directory: string, data: unknown) => void;
  const received: string[] = [];
  vm.runInNewContext(script, {
    process: { argv: ["/synthetic/Anywhere", "--osir-client-handoff-flow", flow] },
    clientHandoffFlowFromArgv, clientHandoffFlowFromSecondInstance, clientHandoffLockData,
    app: { requestSingleInstanceLock: (data: unknown) => { captured = data; return true; },
      on: (_event: string, callback: typeof handler) => { handler = callback; } },
    clientHandoff: { run: async ({ flowId }: { flowId: string }) => { received.push(flowId); return { status: "authenticated" }; } },
    pendingClientFlows: new Set(), showMainWindow: () => {}, isQuitting: false,
    desktopOnboardingFromArgv: () => null, queueDesktopOnboarding: () => {},
  });
  handler({}, ["/synthetic/Anywhere", "--osir-client-handoff-flow", "--allow-file-access-from-files", "--enable-avfoundation", flow], "/", captured);
  await new Promise<void>(resolve => setImmediate(resolve));
  assert.deepEqual(received, [flow]);
});

for (const owner of [credentials.identity.userId, "different-tenant"]) {
  test(`real Main and session manager recover unreadable old ciphertext with binding owner ${owner}`, async t => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "handoff-keychain-recovery-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const file = path.join(dir, "session.enc"), key = randomBytes(32);
    const safe = {
      isEncryptionAvailable: () => true,
      encryptString: (text: string) => {
        const iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", key, iv);
        const bytes = Buffer.concat([cipher.update(text), cipher.final()]);
        return Buffer.concat([iv, cipher.getAuthTag(), bytes]);
      },
      decryptString: (bytes: Buffer) => {
        const cipher = createDecipheriv("aes-256-gcm", key, bytes.subarray(0, 12));
        cipher.setAuthTag(bytes.subarray(12, 28));
        return Buffer.concat([cipher.update(bytes.subarray(28)), cipher.final()]).toString();
      },
    };
    const store = new DesktopSessionStore(file, safe);
    new DesktopSessionManager(store, fetch).accept(credentials, server);
    const old = fs.readFileSync(file), decrypt = safe.decryptString;
    let deniedReads = 0;
    safe.decryptString = bytes => {
      if (bytes.equals(old)) { deniedReads++; throw new Error("synthetic-keychain-denied"); }
      return decrypt(bytes);
    };
    const manager = new DesktopSessionManager(store, async () => assert.fail("no old-session refresh"));
    const f = fixture(manager);
    assert.equal(deniedReads, 0, "initializing Main never invokes keychain");
    f.controls.binding = { serverUrl: server.serverUrl, ownerUserId: owner };
    await f.options.prepareLogin();
    const account = await f.options.readAccountContext(new AbortController().signal);
    assert.equal(account.desktopIdentity, null);
    assert.equal(account.localBinding?.ownerUserId, owner);
    assert.equal(deniedReads, 1, "account lookup never retries old decryption/refresh");
    // Exercise actual controller account checks with synthetic transport/HTTP only.
    const { OsirClientHandoffController } = await import("./osir-client-handoff.js");
    const { performance } = await import("node:perf_hooks");
    const flowId = Buffer.alloc(32, 1).toString("base64url"), state = Buffer.alloc(32, 2).toString("base64url");
    const receiver = Buffer.alloc(32, 3).toString("base64url");
    const controller = new OsirClientHandoffController({ ...f.options,
      transport: { run: async (_flow, consume, signal) => consume({ grant_type: "urn:osir:params:grant-type:anywhere-handoff",
        client_id: "osir-anywhere-desktop", code: Buffer.alloc(32, 4).toString("base64url"),
        code_verifier: Buffer.alloc(48, 5).toString("base64url"), state, receiver_instance_id: receiver,
        target_origin: "https://anywhere.osirclaw.com" }, { flowId, state, receiverInstanceId: receiver, targetOrigin: "https://anywhere.osirclaw.com",
        codeDeadline: performance.now() + 60000, configuredToolTypes: [] }, signal ?? new AbortController().signal) },
      fetcher: async url => String(url).endsWith("/token") ? Response.json({ code: 0, message: "success", data: {
        assertion: `${"a".repeat(30)}.${"b".repeat(80)}.${"c".repeat(85)}A`, token_type: "urn:osir:params:token-type:anywhere-handoff",
        expires_in: 60, audience: "osir-anywhere-server" } }) : Response.json(credentials),
      reject: async () => { f.calls.push("reject-issued"); },
    });
    const result = await controller.run({ flowId });
    if (owner !== credentials.identity.userId) {
      assert.deepEqual(result, { status: "error", reason: "account_mismatch" });
      assert.deepEqual(fs.readFileSync(file), old);
      assert.deepEqual(fs.readdirSync(dir), ["session.enc"]);
      assert.ok(!f.calls.includes("bootstrap"));
    } else {
      assert.deepEqual(result, { status: "authenticated" });
      assert.ok(f.calls.includes("bootstrap"));
      assert.equal(f.calls.at(-1), "publish");
      assert.equal(store.read()?.refreshToken, credentials.refreshToken);
      const backup = fs.readdirSync(dir).find(name => name.includes(".unreadable-"))!;
      assert.deepEqual(fs.readFileSync(path.join(dir, backup)), old);
    }
  });
}
