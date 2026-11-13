import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import vm from "node:vm";
import ts from "typescript";
import { normalizeServerOrigin, resolveDesktopServer, type DesktopServerConnection } from "./desktop-server";
import type { DesktopSessionPayload } from "./desktop-session";

// Execute the actual Main entrypoint functions without loading Electron or
// starting a Connector. Any new shutdown side effects must be accounted for.
const source = ts.createSourceFile(
  "main.ts",
  fs.readFileSync(path.resolve(__dirname, "../../electron/main.ts"), "utf8"),
  ts.ScriptTarget.Latest,
  true,
);
function loadFunctions(names: string[], globals: Record<string, unknown>) {
  const code = source.statements
    .filter((statement) => ts.isFunctionDeclaration(statement) && names.includes(statement.name?.text ?? ""))
    .map((statement) => statement.getText(source))
    .join("\n");
  const javascript = ts.transpileModule(code, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  return vm.runInNewContext(`${javascript}\n({${names.join(",")}})`, globals);
}

function loadOAuthCallback<Callback>(globals: Record<string, unknown>, propertyName: string): Callback {
  let result: ts.Expression | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isNewExpression(node) && node.expression.getText(source) === "DesktopOAuthFlow") {
      const options = node.arguments?.[0];
      if (options && ts.isObjectLiteralExpression(options)) {
        const property = options.properties.find(p => ts.isPropertyAssignment(p) && p.name.getText(source) === propertyName);
        if (property && ts.isPropertyAssignment(property)) result = property.initializer;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  assert.ok(result);
  return vm.runInNewContext(ts.transpileModule(`(${result.getText(source)})`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022 },
  }).outputText, globals) as Callback;
}
function loadOAuthResultHandler(globals: Record<string, unknown>) {
  return loadOAuthCallback<(result: object, signal: AbortSignal) => Promise<boolean>>(globals, "onResult");
}
function loadOAuthDiscardHandler(globals: Record<string, unknown>) {
  return loadOAuthCallback<(session: DesktopSessionPayload, server: DesktopServerConnection) => Promise<void>>(globals, "onDiscard");
}

test("OAuth success stops the Connector, persists in Main and strips refresh before publishing IPC", async () => {
  const calls: string[] = [];
  const published: object[] = [];
  const credentials = { accessToken: "synthetic-access", refreshToken: "synthetic-refresh-must-stay-main" };
  const handler = loadOAuthResultHandler({
    isQuitting: false,
    backend: { request: async (route: string) => { calls.push(route); return { running: false }; } },
    serverStore: { save: () => calls.push("save-server") },
    desktopSessions: { accept: (value: object) => { assert.equal(value, credentials); calls.push("encrypt-session"); } },
    syncBackendServerConnection: async () => calls.push("sync-server"),
    publishDesktopOAuthResult: (value: object) => published.push(value),
    showMainWindow: () => {},
  });
  await handler({ status: "success", accessToken: credentials.accessToken, credentials, server: {} }, new AbortController().signal);
  assert.deepEqual(calls, ["/stop", "encrypt-session", "save-server", "sync-server"]);
  assert.equal(JSON.stringify(published).includes("refresh"), false);
  assert.equal(JSON.stringify(published).includes("credentials"), false);
  assert.equal(JSON.stringify(published).includes("synthetic-access"), true);
});

test("failed secure persistence never publishes sign-in success; Flow discard delegates revocation to the manager", async () => {
  let revoked = false;
  const handler = loadOAuthResultHandler({
    isQuitting: false,
    backend: { request: async () => ({ running: false }) },
    serverStore: { save: () => assert.fail("must not persist server on storage failure") },
    desktopSessions: {
      accept: () => { throw new Error("synthetic-storage-secret"); },
      reject: async () => { revoked = true; },
    },
    publishDesktopOAuthResult: () => assert.fail("must not publish success"),
  });
  await assert.rejects(handler({ status: "success", credentials: {}, server: {} }, new AbortController().signal), /Secure Desktop sign-in could not be saved/);
  assert.equal(revoked, false, "Flow retains cleanup ownership until the callback accepts");
  const discard = loadOAuthDiscardHandler({ desktopSessions: { reject: async () => { revoked = true; } } });
  await discard({} as DesktopSessionPayload, {} as DesktopServerConnection);
  assert.equal(revoked, true);
});

function quitFixture(options: { confirm?: boolean; shutdown?: () => Promise<void>; window?: boolean } = {}) {
  const calls: string[] = [];
  const globals = {
    isQuitting: false,
    shutdownComplete: false,
    shutdownPromise: null,
    projectConnector: null,
    scopedTestConnector: null,
    tray: null as { destroy: () => void } | null,
    confirmQuit: async () => { calls.push("confirm"); return options.confirm ?? true; },
    mainWindow: options.window === false ? null : {
      isDestroyed: () => false,
      destroy: () => calls.push("destroy-renderer"),
    },
    backend: { shutdown: async () => { calls.push("stop-local-connector"); await options.shutdown?.(); } },
    desktopOAuthFlow: { shutdown: async () => { calls.push("stop-oauth"); } },
    desktopOAuthResult: null,
    updates: { dispose: () => calls.push("stop-updates") },
    app: { quit: () => calls.push("quit") },
    net: { fetch: () => assert.fail("Desktop quit must not close or renew terminals through the API") },
  };
  const { requestQuit } = loadFunctions(["requestQuit", "quiesceRendererForShutdown"], globals) as {
    requestQuit: (options?: { confirm?: boolean }) => Promise<void>;
  };
  return { calls, globals, requestQuit };
}

test("quit stops the owned local Connector without closing or renewing remote terminals", async () => {
  const fixture = quitFixture();
  await fixture.requestQuit();
  assert.deepEqual(fixture.calls, ["stop-oauth", "stop-updates", "destroy-renderer", "stop-local-connector", "quit"]);
  assert.equal(fixture.globals.shutdownComplete, true);
});

test("repeated quit requests wait for the same local Connector shutdown", async () => {
  let finish!: () => void;
  const pending = new Promise<void>((resolve) => { finish = resolve; });
  const fixture = quitFixture({ shutdown: () => pending });
  const first = fixture.requestQuit();
  const second = fixture.requestQuit();
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.deepEqual(fixture.calls, ["stop-oauth", "stop-updates", "destroy-renderer", "stop-local-connector"]);
  finish();
  await Promise.all([first, second]);
  assert.deepEqual(fixture.calls, ["stop-oauth", "stop-updates", "destroy-renderer", "stop-local-connector", "quit"]);
});

test("cancelling native quit leaves the renderer and Connector running", async () => {
  const fixture = quitFixture({ confirm: false });
  await fixture.requestQuit({ confirm: true });
  assert.deepEqual(fixture.calls, ["confirm"]);
  assert.equal(fixture.globals.isQuitting, false);
});

test("quit still completes if the window is already gone or local shutdown fails", async () => {
  const fixture = quitFixture({ window: false, shutdown: async () => { throw new Error("already stopped"); } });
  await assert.rejects(fixture.requestQuit(), /already stopped/);
  assert.deepEqual(fixture.calls, ["stop-oauth", "stop-updates", "stop-local-connector", "quit"]);
  assert.equal(fixture.globals.shutdownComplete, true);
});

test("Windows close hides the window without confirming quit, and reopening restores it", () => {
  const calls: string[] = [];
  class Window extends EventEmitter {
    openHandler?: (details: { url: string }) => unknown;
    webContents = Object.assign(new EventEmitter(), {
      setWindowOpenHandler: (handler: (details: { url: string }) => unknown) => { this.openHandler = handler; },
    });
    loadURL = async () => {};
    hide = () => calls.push("hide");
    isDestroyed = () => false;
    isMinimized = () => true;
    restore = () => calls.push("restore");
    show = () => calls.push("show");
    moveTop = () => {};
    focus = () => calls.push("focus");
  }
  const globals = {
    process: { platform: "win32", env: {} },
    app: { isPackaged: true },
    BrowserWindow: Window,
    APP_NAME: "OSIR Anywhere",
    path,
    __dirname,
    mainWindow: null,
    devOrigin: null,
    isQuitting: false,
    windowMaterialOptions: () => ({}),
    appWindowIcon: () => "icon.png",
    staticWorkbenchUrl: () => "osir-anywhere-workbench://web/",
    isWorkbenchUrl: (url: string) => url.startsWith("osir-anywhere-workbench://web/"),
    shell: { openExternal: (url: string) => calls.push(`external:${url}`) },
    showDockForWindow: () => {},
    requestQuit: () => assert.fail("Closing the Windows window must not request quit"),
  };
  const { createMainWindow, showMainWindow } = loadFunctions(["createMainWindow", "showMainWindow"], globals);
  const window = createMainWindow(false) as Window;
  const previewOptions = window.openHandler!({ url: "osir-anywhere-workbench://web/#/preview?path=main.ts" }) as {
    action: string;
    overrideBrowserWindowOptions: { webPreferences: { preload: string; contextIsolation: boolean; nodeIntegration: boolean; sandbox: boolean } };
  };
  assert.equal(previewOptions.action, "allow");
  const previewPreferences = previewOptions.overrideBrowserWindowOptions.webPreferences;
  assert.equal(previewPreferences.preload, path.join(__dirname, "preload.js"));
  assert.equal(previewPreferences.contextIsolation, true);
  assert.equal(previewPreferences.nodeIntegration, false);
  assert.equal(previewPreferences.sandbox, false);
  assert.equal((window.openHandler!({ url: "https://example.com/" }) as { action: string }).action, "deny");
  assert.deepEqual(calls, ["external:https://example.com/"]);
  calls.length = 0;
  window.emit("ready-to-show");
  assert.equal(calls.length, 0, "silent launch leaves the window hidden");
  window.emit("close", { preventDefault: () => calls.push("prevent-close") });
  assert.deepEqual(calls, ["prevent-close", "hide"]);
  showMainWindow();
  assert.deepEqual(calls.slice(2), ["restore", "show", "focus"]);
  calls.length = 0;
  globals.isQuitting = true;
  window.emit("close", { preventDefault: () => assert.fail("Confirmed quit must allow closing") });
  showMainWindow();
  assert.deepEqual(calls, [], "shutdown must not reopen the window");
});

test("Windows tray opens the app, cancels exit, and shuts down only after confirmation", async () => {
  for (const packaged of [false, true]) {
    let confirm = false;
    const fixture = quitFixture();
    const appPath = path.resolve(__dirname, "../..");
    const resourcesPath = path.join(appPath, "test-resources");
    type TrayItem = { label?: string; click?: () => void };
    class TestTray extends EventEmitter {
      menu: TrayItem[] = [];
      constructor(readonly icon: string) { super(); }
      setToolTip = (name: string) => assert.equal(name, "OSIR Anywhere");
      setContextMenu = (menu: TrayItem[]) => { this.menu = menu; };
      destroy = () => fixture.calls.push("destroy-tray");
    }
    const globals = Object.assign(fixture.globals, {
      tray: null as TestTray | null,
      process: { platform: "win32", resourcesPath },
      app: { ...fixture.globals.app, isPackaged: packaged, getAppPath: () => appPath },
      path,
      APP_NAME: "OSIR Anywhere",
      Tray: TestTray,
      Menu: { buildFromTemplate: (items: TrayItem[]) => items },
      showMainWindow: () => fixture.calls.push("show"),
      confirmQuit: async () => { fixture.calls.push("confirm"); return confirm; },
      requestQuit: fixture.requestQuit,
    });
    const { createWindowsTray } = loadFunctions(["createWindowsTray"], globals);
    createWindowsTray();
    const tray = globals.tray!;
    assert.equal(tray.icon, path.join(packaged ? resourcesPath : appPath, "build", "icon.ico"));
    createWindowsTray();
    assert.equal(globals.tray, tray, "initialization must retain a single tray instance");
    tray.emit("click");
    tray.menu.find((item) => item.label === "打开 OSIR Anywhere")!.click!();
    assert.deepEqual(fixture.calls, ["show", "show"]);
    fixture.calls.length = 0;
    const exit = tray.menu.find((item) => item.label === "退出")!.click!;
    exit();
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.deepEqual(fixture.calls, ["confirm"]);
    assert.equal(globals.tray, tray);
    assert.equal(globals.isQuitting, false);
    confirm = true;
    exit();
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.deepEqual(fixture.calls, ["confirm", "confirm", "stop-oauth", "stop-updates", "destroy-tray", "destroy-renderer", "stop-local-connector", "quit"]);
    assert.equal(globals.tray, null);
  }
});

test("tray quit confirmation stays accessible when the main window is hidden or destroyed", async () => {
  for (const state of ["visible", "hidden", "destroyed", "absent"]) {
    const window = state === "absent" ? null : {
      isDestroyed: () => state === "destroyed",
      isVisible: () => state === "visible",
    };
    const { confirmQuit } = loadFunctions(["confirmQuit"], {
      quitConfirmationPromise: null,
      mainWindow: window,
      dialog: { showMessageBox: async (...args: unknown[]) => {
        assert.equal(args.length, state === "visible" ? 2 : 1);
        if (state === "visible") assert.equal(args[0], window);
        return { response: 0 };
      } },
    });
    assert.equal(await confirmQuit(), false);
  }
});

test("the Windows tray ICO is included in packaged resources", () => {
  const root = path.resolve(__dirname, "../..");
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const resource = manifest.build.extraResources.find((item: { to: string }) => item.to === "build/icon.ico");
  assert.ok(resource, "the tray icon must be available outside app.asar");
  const icon = fs.readFileSync(path.join(root, resource.from));
  assert.equal(icon.readUInt16LE(2), 1, "the bundled asset must be an ICO");
  assert.ok(icon.readUInt16LE(4) > 0, "the ICO must contain images");
});

test("project API requests reach the Desktop proxy even with an empty API namespace", () => {
  const declaration = source.statements.find((statement) =>
    ts.isVariableStatement(statement) && statement.declarationList.declarations.some((item) => item.name.getText(source) === "API_ROUTE_PREFIXES"),
  );
  assert.ok(declaration);
  const prefixes = vm.runInNewContext(`${declaration.getText(source)}\nAPI_ROUTE_PREFIXES`);
  for (const namespace of ["", "/api/v2"]) {
    const { shouldProxyApiPath } = loadFunctions(["shouldProxyApiPath"], { API_ROUTE_PREFIXES: prefixes, apiNamespace: () => namespace });
    assert.equal(shouldProxyApiPath(`${namespace}/projects`), true);
    assert.equal(shouldProxyApiPath(`${namespace}/projects/project-id/sessions`), true);
    assert.equal(shouldProxyApiPath("/projects-help.html"), false);
    assert.equal(shouldProxyApiPath("/_next/static/app.js"), false);
  }
});

test("updates require an authenticated server matching a saved server and never use defaults", () => {
  const server = resolveDesktopServer("https://saved.example");
  let saved: DesktopServerConnection | null = null;
  const calls: Array<DesktopServerConnection | null> = [];
  const { syncDesktopUpdateSession } = loadFunctions(["syncDesktopUpdateSession"], {
    serverStore: { getSaved: () => saved, get: () => assert.fail("Update checks must not use fallback settings") },
    normalizeServerOrigin,
    updates: { check: (connection: DesktopServerConnection | null) => { calls.push(connection); } },
  });
  syncDesktopUpdateSession(server.serverUrl);
  assert.equal(calls.pop(), null, "a missing server record cannot trigger a check");
  saved = server;
  for (const input of [null, undefined, "", "  ", {}, "file:///tmp/server", "https://other.example"]) {
    syncDesktopUpdateSession(input);
    assert.equal(calls.pop(), null, "signed-out and mismatched sessions clear updates");
  }
  syncDesktopUpdateSession(server.serverUrl);
  assert.deepEqual(calls.pop(), server);
});

test("a backend that stops after ready opens the gate, and its recheck starts a new backend", async () => {
  const published: Array<{ status: string; recovery?: { kind: string } }> = [];
  const clients: Array<{ options: { onExit: (message: string) => void; onEvent: (event: { event: string; data: unknown }) => void } }> = [];
  let failStart = false;
  class FakeBackendClient {
    constructor(readonly options: { onExit: (message: string) => void; onEvent: (event: { event: string; data: unknown }) => void }) {
      clients.push(this);
    }
    async start() { if (failStart) throw new Error("Desktop backend did not become ready in time."); }
    getOwnership() { return { status: "checking" }; }
  }
  const globals = {
    DesktopBackendClient: FakeBackendClient,
    backend: null as unknown,
    ownership: { status: "owned" } as { status: string },
    isQuitting: false,
    app: { isPackaged: false },
    net: { fetch: () => assert.fail("no network in this test") },
    backendInit: () => ({}),
    applyLoginItemSettings: () => {},
    appendMainLog: () => {},
    errorMessage: (error: unknown) => error instanceof Error ? error.message : String(error),
    sendToRenderer: (_channel: string, state: { status: string; recovery?: { kind: string } }) => published.push(state),
    drainDesktopOAuthCallbacks: async () => {},
  };
  const { startDesktopBackend, restartDesktopBackend } = loadFunctions(
    ["startDesktopBackend", "restartDesktopBackend", "publishOwnership"],
    globals,
  ) as { startDesktopBackend: () => Promise<void>; restartDesktopBackend: () => Promise<{ status: string }> };

  await startDesktopBackend();
  globals.ownership = { status: "owned" };
  clients[0].options.onExit("Desktop backend stopped unexpectedly (code 1).");
  // States built inside the vm context have its prototypes; compare their data.
  const plain = (value: unknown) => JSON.parse(JSON.stringify(value)) as unknown;
  assert.deepEqual(plain(published.at(-1)), {
    status: "error",
    message: "Desktop backend stopped unexpectedly (code 1).",
    recovery: { kind: "backendStopped" },
  }, "an owned window is told the backend is gone");

  assert.equal((await restartDesktopBackend()).status, "checking");
  assert.equal(clients.length, 2);
  assert.equal(globals.backend, clients[1]);
  assert.equal(published.at(-1)?.status, "checking");
  const count = published.length;
  clients[0].options.onExit("late exit of the old backend");
  clients[0].options.onEvent({ event: "ownership", data: { status: "conflict" } });
  assert.equal(published.length, count, "the replaced backend no longer speaks for the window");

  failStart = true;
  const failed = await restartDesktopBackend();
  assert.equal(failed.status, "error");
  assert.deepEqual(plain(published.at(-1)?.recovery), { kind: "backendStopped" }, "a failed restart can be retried");
});

function loadIpcHandler(channel: string, globals: Record<string, unknown>) {
  let handler: ts.Expression | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && node.expression.getText(source) === "ipcMain.handle" &&
        ts.isStringLiteral(node.arguments[0]) && node.arguments[0].text === channel) handler = node.arguments[1];
    ts.forEachChild(node, visit);
  };
  visit(source);
  assert.ok(handler);
  return vm.runInNewContext(ts.transpileModule(`(${handler.getText(source)})`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022 },
  }).outputText, globals) as (event: object, input?: object) => Promise<{ status: string; authorizeUrl?: string; error?: string }>;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(r => { resolve = r; });
  return { promise, resolve };
}

// Actual Main IPC + OAuth loopback + session manager. Only loopback HTTP is real;
// all identity/Anywhere traffic and encrypted-store dependencies are synthetic.
async function coordinatorFixture() {
  const { DesktopOAuthFlow } = await import("./desktop-oauth.js");
  const { DesktopSessionManager } = await import("./desktop-session.js");
  const { DesktopServerError } = await import("./desktop-server.js");
  type Stored = ReturnType<import("./desktop-session").DesktopSessionStore["read"]>;
  let saved: Stored = null;
  let revocations: NonNullable<Stored>[] = [];
  const store = {
    read: () => structuredClone(saved), write: (value: Stored) => { saved = structuredClone(value); }, clear: () => { saved = null; },
    readRevocations: () => structuredClone(revocations), writeRevocations: (values: NonNullable<Stored>[]) => { revocations = structuredClone(values); },
  } as unknown as import("./desktop-session").DesktopSessionStore;
  const originA = resolveDesktopServer("https://synthetic-a.example");
  const originB = resolveDesktopServer("https://synthetic-b.example");
  const credentials = (value = "r"): import("./desktop-session").DesktopSessionPayload => ({
    accessToken: "synthetic-access", tokenType: "Bearer", expiresIn: 300, refreshToken: value.repeat(43), refreshExpiresIn: 604800,
    identity: { issuer: "https://osirclaw.com", subject: "123", userId: "synthetic-user" },
  });
  const calls: { url: string; body: Record<string, unknown>; signal?: AbortSignal | null }[] = [];
  const controls = {
    online: true,
    sourceLogout: async () => {},
    exchange: async () => {},
    stop: async () => {},
    sync: async () => {},
  };
  const fetcher: typeof fetch = async (input, init) => {
    const url = String(input);
    calls.push({ url, body: JSON.parse(String(init?.body)), signal: init?.signal });
    const data = (value: object) => Response.json({ code: 0, data: value });
    if (url.endsWith("/api/v2/auth/osir/desktop/logout")) {
      if (!controls.online) throw new Error("synthetic-refresh-secret https://secret.example");
      assert.equal(init?.signal?.aborted, false, "revocation has its own live bounded signal");
      return new Response(null, { status: 204 });
    }
    if (url.endsWith("/api/v1/auth/desktop/token")) return data({ access_token: "synthetic-source-access", refresh_token: "synthetic-source-refresh", token_type: "Bearer", expires_in: 900, scope: "identity:read" });
    if (url.endsWith("/api/v1/auth/desktop/anywhere/assertion")) return data({ assertion: "synthetic-assertion", token_type: "urn:osir:params:token-type:anywhere-login", expires_in: 60, audience: "osir-anywhere-server" });
    if (url.endsWith("/api/v2/auth/osir/desktop/exchange")) { await controls.exchange(); return Response.json(credentials("s")); }
    if (url.endsWith("/api/v1/auth/logout")) { await controls.sourceLogout(); return data({}); }
    assert.fail("no other API/Connector traffic is allowed");
  };
  const manager = new DesktopSessionManager(store, fetcher);
  const published: object[] = [];
  const completed = deferred<void>();
  const globals: Record<string, unknown> = {
    isQuitting: false, desktopSessions: manager, startingDesktopOAuth: false, desktopOAuthAttempt: 0, desktopOAuthResult: null,
    assertTrustedRenderer: () => {}, requireLocalOwnership: async () => {},
    resolveDesktopServer, DesktopServerError, config: { cloud: { serverUrl: originB.serverUrl } }, process: { env: {} }, app: { isPackaged: true },
    checkDesktopServer: async () => { calls.push({ url: "check-server", body: {} }); }, net: { fetch: fetcher },
    backend: { request: async (route: string) => { assert.equal(route, "/stop"); await controls.stop(); return { running: false }; } },
    serverStore: { save: () => {} }, syncBackendServerConnection: async () => controls.sync(),
    publishDesktopOAuthResult: (value: object) => { published.push(value); completed.resolve(); }, showMainWindow: () => {},
  };
  const onResult = loadOAuthResultHandler(globals);
  const onDiscard = loadOAuthDiscardHandler(globals);
  const flow = new DesktopOAuthFlow({ env: { OSIR_IDENTITY_API_ORIGIN: "https://synthetic-identity.example", OSIR_IDENTITY_WEB_ORIGIN: "https://synthetic-identity.example" },
    fetcher, openExternal: async () => {}, onResult,
    onDiscard,
  });
  globals.desktopOAuthFlow = flow;
  const start = loadIpcHandler("workbench:auth:startOAuth", globals);
  const authorize = async () => {
    const attempt = await start({}, { serverUrl: originB.serverUrl });
    assert.equal(attempt.status, "opened");
    const url = new URL(attempt.authorizeUrl!);
    const callback = new URL(url.searchParams.get("redirect_uri")!);
    callback.searchParams.set("code", "c".repeat(43)); callback.searchParams.set("state", url.searchParams.get("state")!);
    assert.equal((await fetch(callback)).status, 200);
  };
  return { manager, store, credentials, originA, originB, calls, controls, flow, start, authorize, published, completed };
}

test("same-process login retries offline logout against original A before authorizing on B, without reviving Connector", async t => {
  const f = await coordinatorFixture(); t.after(() => f.flow.shutdown());
  f.manager.accept(f.credentials(), f.originA);
  f.controls.online = false;
  assert.deepEqual(await f.manager.logout(), { pending: true });
  const denied = await f.start({}, { serverUrl: f.originB.serverUrl });
  assert.equal(denied.status, "error"); assert.ok(!JSON.stringify(denied).includes("synthetic"));
  assert.equal(f.store.read()?.pendingLogout, true); assert.deepEqual(f.published, []);
  assert.ok(f.calls.every(c => c.url === f.originA.serverUrl + "/api/v2/auth/osir/desktop/logout"));
  f.controls.online = true;
  await f.authorize(); await f.completed.promise;
  assert.equal(f.store.read()?.server.serverUrl, f.originB.serverUrl);
  assert.equal(f.store.read()?.pendingLogout, false);
  const revocations = f.calls.filter(c => c.url.endsWith("/api/v2/auth/osir/desktop/logout"));
  assert.equal(revocations.length, 3);
  assert.ok(revocations.every(c => c.url.startsWith(f.originA.serverUrl) && c.body.refreshToken === "r".repeat(43)));
  assert.equal(f.calls.findIndex(c => c.url === "check-server"), 3, "revocation precedes all new-origin work");
  assert.equal(JSON.stringify(f.published).includes("refresh"), false);
});

for (const mode of ["cancel-source-cleanup", "shutdown-source-cleanup", "cancel-exchange-response", "cancel-before-accept", "cancel-after-accept"] as const) {
  test(`issued session is revoked and never published: ${mode}`, async t => {
    const f = await coordinatorFixture(); t.after(() => f.flow.shutdown());
    const entered = deferred<void>(), release = deferred<void>();
    const block = async () => { entered.resolve(); await release.promise; };
    if (mode.endsWith("source-cleanup")) f.controls.sourceLogout = block;
    else if (mode === "cancel-exchange-response") f.controls.exchange = block;
    else if (mode === "cancel-before-accept") f.controls.stop = block;
    else f.controls.sync = block;
    await f.authorize(); await entered.promise;
    const cancelled = mode === "shutdown-source-cleanup" ? f.flow.shutdown() : f.flow.cancel();
    release.resolve(); await cancelled;
    assert.deepEqual(f.published, []); assert.equal(f.store.read(), null);
    assert.deepEqual(f.store.readRevocations(), []);
    const revoked = f.calls.filter(c => c.url.endsWith("/api/v2/auth/osir/desktop/logout"));
    assert.equal(revoked.length, 1); assert.equal(revoked[0].body.refreshToken, "s".repeat(43));
    assert.equal(revoked[0].url, f.originB.serverUrl + "/api/v2/auth/osir/desktop/logout");
  });
}

test("cancelled issued session survives failed revocation and is drained by the next Main login", async t => {
  const f = await coordinatorFixture(); t.after(() => f.flow.shutdown());
  const entered = deferred<void>(), release = deferred<void>();
  f.controls.sourceLogout = async () => { entered.resolve(); await release.promise; };
  await f.authorize(); await entered.promise;
  f.controls.online = false;
  const cancelled = f.flow.cancel(); release.resolve(); await cancelled;
  assert.deepEqual(f.published, []); assert.equal(f.store.read(), null);
  assert.equal(f.store.readRevocations().length, 1);
  assert.equal(f.store.readRevocations()[0].refreshToken, "s".repeat(43));
  assert.equal((await f.start({}, { serverUrl: f.originA.serverUrl })).status, "error");
  assert.equal(f.store.readRevocations().length, 1);
  f.controls.online = true; f.controls.sourceLogout = async () => {};
  await f.authorize(); await f.completed.promise;
  assert.deepEqual(f.store.readRevocations(), []);
  assert.equal(f.store.read()?.refreshToken, "s".repeat(43));
  const logout = f.calls.filter(c => c.url.endsWith("/api/v2/auth/osir/desktop/logout"));
  assert.ok(logout.every(c => c.url.startsWith(f.originB.serverUrl)));
  assert.equal(logout.length, 3, "normal successful delivery must not revoke the new login");
});
