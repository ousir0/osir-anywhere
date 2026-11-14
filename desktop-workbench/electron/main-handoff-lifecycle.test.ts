import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import vm from "node:vm";
import ts from "typescript";
import type { OsirClientHandoffOptions } from "./osir-client-handoff";
import type { DesktopSessionPayload } from "./desktop-session";

// Exercise actual Main wiring, rather than a second implementation of its
// callbacks. Electron/network/storage remain synthetic and no app is launched.
const source = ts.createSourceFile("main.ts", fs.readFileSync(path.resolve(__dirname, "../../electron/main.ts"), "utf8"), ts.ScriptTarget.Latest, true);
const declaration = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === "initializeClientHandoff")!;
const javascript = ts.transpileModule(declaration.getText(source), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
const credentials: DesktopSessionPayload = { accessToken: "synthetic-access", tokenType: "Bearer", expiresIn: 300,
  refreshToken: "r".repeat(43), refreshExpiresIn: 600,
  identity: { issuer: "https://osirclaw.com", subject: "123", userId: "synthetic-user" } };
const server = { serverUrl: "https://anywhere.osirclaw.com", apiNamespace: "/api/v2", oauthWebOrigin: "https://anywhere.osirclaw.com" };

function fixture() {
  let options!: OsirClientHandoffOptions;
  let generation = 3;
  const calls: string[] = [];
  const controls = { stopFails: false, bootstrap: async () => {} };
  const globals = {
    process: { platform: "darwin", resourcesPath: "/Synthetic/Resources" }, path, __dirname: "/Synthetic/Resources/app.asar/dist/electron",
    app: { isPackaged: true, getAppPath: () => "/Synthetic/Resources/app.asar", getPath: () => "/Synthetic/home" },
    readReleasePublicKey: () => "synthetic-key", resolvePythonBundleDir: () => "/Synthetic/python",
    bundledPythonExecutable: () => "/Synthetic/python/python",
    OsirClientHandoffTransport: class { constructor(readonly options: unknown) {} },
    OsirClientHandoffController: class { constructor(value: OsirClientHandoffOptions) { options = value; } },
    clientHandoff: null,
    desktopSessions: {
      prepareLogin: async () => {}, refresh: async () => {},
      identityForHandoff: () => ({ generation, identity: null }),
      accept: () => { generation++; calls.push("accept"); },
      logout: async () => { generation++; calls.push("logout"); },
      reject: async () => { calls.push("reject-issued"); },
    },
    requireBackend: () => ({ request: async (route: string) => {
      calls.push(route); if (route === "/stop" && controls.stopFails) throw new Error("backend stopped"); return null;
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
