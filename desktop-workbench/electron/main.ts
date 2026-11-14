import type { OwnershipState } from "./local-runtime";
import { desktopConnectorDataRoot } from "./local-runtime";
import {
  app,
  BrowserWindow,
  dialog,
  ipcMain,
  Menu,
  net,
  Notification,
  nativeTheme,
  protocol,
  session,
  safeStorage,
  shell,
  Tray,
  type IpcMainInvokeEvent,
} from "electron";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  DESKTOP_OAUTH_PROTOCOL,
  DesktopOAuthFlow,
  type DesktopOAuthResult,
} from "./desktop-oauth";
import { DesktopSessionManager, DesktopSessionStore } from "./desktop-session";
import { OsirScopedConnector } from "./osir-scoped-connector";
import {
  desktopOnboardingFromArgv,
  desktopOnboardingFromUrl,
  desktopOnboardingRoute,
  type DesktopOnboardingEntry,
} from "./desktop-onboarding";
import { DesktopUpdateService } from "./desktop-updates";
import { RELEASE_MANIFEST_URL, readReleasePublicKey } from "./release-manifest";
import { validateTitleBarColors } from "./title-bar";
import type { BackendInit } from "./backend/protocol";
import { DesktopBackendClient } from "./backend-client";
import { readDesktopSettings } from "./desktop-settings";
import { ConnectorLogStore } from "./log-store";
import { windowMaterialOptions } from "./window-material";
import { droppedFolderPath } from "./dropped-folder";
import config from "../config.json";
import { proxyDesktopApi } from "./api-proxy";
import {
  checkDesktopServer,
  DesktopServerError,
  DesktopServerStore,
  normalizeServerOrigin,
  resolveDesktopServer,
  type DesktopOAuthStartResult,
  type DesktopServerConnection,
} from "./desktop-server";
import type {
  ConnectorLogEntry,
  ConnectorLogPage,
  ConnectorState,
  DesktopFactoryResetInput,
  DesktopNotificationInput,
  DesktopNotificationResult,
} from "./connector-types";

const APP_NAME = "OSIR Anywhere";
const APP_ID = "com.osir.anywhere.desktop";
const WEB_PROTOCOL = "osir-anywhere-workbench";
const WEB_HOST = "web";
const LOGIN_ITEM_HIDDEN_ARG = "--hidden";
const API_ROUTE_PREFIXES = [
  "/admin",
  "/agents",
  "/auth",
  "/connector",
  "/connectors",
  "/health",
  "/oauth",
  "/pairing",
  "/projects",
  "/sessions",
  "/.well-known",
];

/** `checking` until the backend's first probe answers; the renderer shows it as progress. */
let ownership: OwnershipState = { status: "checking" };
let recheckingOwnership: Promise<OwnershipState> | null = null;

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let devOrigin: string | null = null;
let backend: DesktopBackendClient | null = null;
let updates: DesktopUpdateService | null = null;
let isQuitting = false;
let shutdownComplete = false;
let shutdownPromise: Promise<void> | null = null;
let quitConfirmationPromise: Promise<boolean> | null = null;
const activeNotifications = new Set<Notification>();
let serverStore: DesktopServerStore | null = null;
let startingDesktopOAuth = false;
let desktopOAuthAttempt = 0;
let desktopOAuthResult: DesktopOAuthResult | null = null;
let desktopSessions: DesktopSessionManager | null = null;
let scopedTestConnector: OsirScopedConnector | null = null;
let projectConnector: OsirScopedConnector | null = null;
const desktopOAuthFlow = new DesktopOAuthFlow({
  development: !app.isPackaged,
  env: process.env,
  fetcher: async (url, init) => {
    if (process.env.OSIR_ANYWHERE_SCOPED_TEST !== "1") return net.fetch(String(url), init);
    const route = new URL(String(url)).pathname;
    try {
      const response = await net.fetch(String(url), init);
      appendMainLog(`授权请求 ${route} ${response.status}`);
      return response;
    } catch (error) {
      const code = error instanceof Error && /net::ERR_[A-Z_]+/.exec(error.message)?.[0];
      appendMainLog(`授权请求失败 ${route} ${code || "network_error"}`);
      throw new Error("Desktop authorization network request failed.");
    }
  },
  openExternal: (url) => shell.openExternal(url),
  onDiscard: async (credentials, server) => {
    if (!desktopSessions) throw new Error("Desktop secure session storage is not ready.");
    await desktopSessions.reject(credentials, server);
  },
  onResult: async (result, signal) => {
    if (isQuitting || signal.aborted && result.status === "success") return false;
    if (result.status === "success") {
      if (!serverStore) throw new Error("Desktop server settings are not ready.");
      if (!desktopSessions) throw new Error("Desktop secure session storage is not ready.");
      try {
        if (backend) {
          const stopped = await backend.request<ConnectorState>("/stop", { method: "POST" });
          if (stopped.running) throw new Error();
        }
        if (signal.aborted || isQuitting) throw new Error();
        desktopSessions.accept(result.credentials, result.server);
      }
      catch {
        throw new Error("Secure Desktop sign-in could not be saved.");
      }
      serverStore.save(result.server);
      await syncBackendServerConnection();
      if (signal.aborted || isQuitting) return false;
    }
    publishDesktopOAuthResult(result.status === "success"
      ? { status: "success", accessToken: result.accessToken, server: result.server }
      : result);
    showMainWindow();
    return true;
  },
});
/** Onboarding entries that still have to reach the renderer. */
const pendingOnboarding: DesktopOnboardingEntry[] = [];
const handledOnboardingKeys = new Set<string>();

app.setName(APP_NAME);
app.setPath("userData", path.join(app.getPath("appData"), "OSIR Anywhere"));
if (process.platform === "win32") {
  app.setAppUserModelId(app.isPackaged ? APP_ID : process.execPath);
}
registerDesktopOnboardingProtocol();

protocol.registerSchemesAsPrivileged([
  {
    scheme: WEB_PROTOCOL,
    privileges: {
      standard: true,
      secure: true,
      supportFetchAPI: true,
      corsEnabled: true,
    },
  },
]);

const hasSingleInstanceLock = app.requestSingleInstanceLock();
if (!hasSingleInstanceLock) app.quit();

function webOutDir(): string {
  if (process.env.WORKBENCH_WEB_OUT_DIR?.trim()) {
    return path.resolve(process.env.WORKBENCH_WEB_OUT_DIR.trim());
  }
  return path.resolve(app.getAppPath(), "renderer", "out");
}

function staticWorkbenchUrl(route = "/"): string {
  return `${WEB_PROTOCOL}://${WEB_HOST}${route}`;
}

function apiOrigin(): string {
  return activeDesktopServer().serverUrl;
}

function apiNamespace(): string {
  return activeDesktopServer().apiNamespace;
}

/**
 * The backend receives the server once at start. A sign-in can select another
 * one, so push the current connection before anything provisions against it.
 */
async function syncBackendServerConnection(): Promise<void> {
  if (!backend) return;
  try {
    await backend.request("/server", {
      method: "POST",
      body: JSON.stringify({ serverUrl: apiOrigin(), apiNamespace: apiNamespace() }),
    });
  } catch (error) {
    appendMainLog({ level: "ERROR", message: `Could not update the Desktop backend server: ${errorMessage(error)}` });
  }
}

function activeDesktopServer(): DesktopServerConnection {
  return serverStore?.get() ?? resolveDesktopServer(
    process.env.WORKBENCH_API_ORIGIN?.trim() || process.env.AGENTS_ANYWHERE_API?.trim() || config.cloud.serverUrl,
    { env: process.env, development: !app.isPackaged },
  );
}

function registerDesktopOnboardingProtocol(): void {
  if (!app.isPackaged) return;
  app.setAsDefaultProtocolClient(DESKTOP_OAUTH_PROTOCOL);
}

/**
 * Plugin entries are independent of Connector ownership: the user may open
 * onboarding before signing in or while another Connector still holds the
 * machine. A redelivered URL is ignored so one click runs one flow.
 */
function queueDesktopOnboarding(entry: DesktopOnboardingEntry): void {
  if (handledOnboardingKeys.has(entry.key)) return;
  handledOnboardingKeys.add(entry.key);
  pendingOnboarding.push(entry);
  if (app.isReady()) drainDesktopOnboarding();
}

function drainDesktopOnboarding(): void {
  if (isQuitting || pendingOnboarding.length === 0) return;
  const window = mainWindow;
  if (!window || window.isDestroyed() || window.webContents.isLoading()) return;
  for (const entry of pendingOnboarding.splice(0)) {
    sendToRenderer("workbench:onboarding:open", {
      route: entry.route,
      source: entry.source,
      flowId: entry.flowId,
    });
  }
  showMainWindow();
}

/**
 * A user launch opens onboarding once, until the complete page records it.
 * Plugin entries and silent login-item launches never consult the flag.
 */
async function resolveLaunchRoute(silentLoginLaunch: boolean): Promise<string> {
  const queued = pendingOnboarding.shift();
  if (queued) return queued.route;
  if (silentLoginLaunch) return "/";
  try {
    const state = await backend?.request<{ completedAt?: unknown }>("/onboarding");
    if (typeof state?.completedAt === "string" && state.completedAt) return "/";
  } catch (error) {
    // A damaged record must not silently skip the flow; show it and log why.
    appendMainLog({ level: "ERROR", message: `Could not read Desktop onboarding state: ${errorMessage(error)}` });
  }
  return desktopOnboardingRoute({ source: "desktop" });
}

function publishDesktopOAuthResult(result: DesktopOAuthResult): void {
  desktopOAuthResult = result;
  sendToRenderer("workbench:auth:oauthResultReady");
}

function shouldProxyApiPath(pathname: string): boolean {
  const namespace = apiNamespace();
  if (namespace) return pathname === namespace || pathname.startsWith(`${namespace}/`);
  return API_ROUTE_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`),
  );
}

function registerStaticWebProtocol(): void {
  protocol.handle(WEB_PROTOCOL, (request) => {
    const url = new URL(request.url);
    if (url.hostname !== WEB_HOST) return new Response("Not found", { status: 404 });

    const backendPath = DesktopBackendClient.proxyPath(url.pathname);
    if (backendPath) {
      if (!backend) return new Response("Desktop backend is not ready.", { status: 503 });
      return backend.proxy(request, backendPath, url.search);
    }

    if (shouldProxyApiPath(url.pathname)) {
      return proxyDesktopApi(
        request,
        apiOrigin(),
        [`${WEB_PROTOCOL}://${WEB_HOST}`, ...(devOrigin ? [devOrigin] : [])],
        async (input, init) => {
          if (process.env.OSIR_ANYWHERE_SCOPED_TEST !== "1") return net.fetch(String(input), init);
          const route = new URL(String(input)).pathname;
          const started = Date.now();
          appendMainLog(`API 开始 ${init?.method ?? "GET"} ${route}`);
          try {
            const response = await net.fetch(String(input), init);
            appendMainLog(`API 完成 ${route} ${response.status} ${Date.now() - started}ms`);
            return response;
          } catch {
            appendMainLog(`API 失败 ${route} ${Date.now() - started}ms`);
            throw new Error("Desktop API connection failed.");
          }
        },
      );
    }

    const outDir = webOutDir();
    const filePath = resolveStaticFile(outDir, url.pathname);
    if (filePath) return net.fetch(pathToFileURL(filePath).toString());
    if (!fs.existsSync(outDir)) {
      return new Response(missingWebBuildHtml(outDir), {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }
    return new Response("Not found", { status: 404 });
  });
}

function resolveStaticFile(outDir: string, pathname: string): string | null {
  const rawPath = decodeURIComponent(pathname);
  const relativePath = rawPath === "/" ? "index.html" : rawPath.replace(/^\/+/, "");
  const candidates = [
    path.resolve(outDir, relativePath),
    path.resolve(outDir, relativePath, "index.html"),
    path.resolve(outDir, `${relativePath}.html`),
  ];
  for (const candidate of candidates) {
    if (!isInside(candidate, outDir)) continue;
    try {
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      // Try the next static-export candidate.
    }
  }
  return null;
}

function isInside(candidate: string, root: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function missingWebBuildHtml(outDir: string): string {
  return `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${APP_NAME}</title>
    <style>
      html, body { margin: 0; height: 100%; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0a0a0b; color: #f4f4f5; }
      body { display: grid; place-items: center; }
      main { width: min(560px, calc(100vw - 48px)); line-height: 1.5; }
      code { border: 1px solid #333; border-radius: 6px; background: #171717; padding: 2px 6px; }
    </style>
  </head>
  <body>
    <main>
      <h1>Web workbench build not found</h1>
      <p>Build the web app first, then start this Electron shell.</p>
      <p><code>yarn build:web</code></p>
      <p>Expected output directory: <code>${escapeHtml(outDir)}</code></p>
    </main>
  </body>
</html>`;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function createMainWindow(showOnReady = true, route = "/"): BrowserWindow {
  const devUrl = process.env.WORKBENCH_WEB_URL?.trim();
  devOrigin = devUrl ? new URL(devUrl).origin : null;
  const window = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 1040,
    minHeight: 680,
    show: false,
    title: APP_NAME,
    ...windowMaterialOptions(),
    icon: appWindowIcon(),
    titleBarStyle: process.platform === "darwin" || process.platform === "win32" ? "hidden" : "default",
    titleBarOverlay: process.platform === "win32"
      ? { color: "#00000000", symbolColor: "#fafafa", height: 32 }
      : undefined,
    trafficLightPosition: process.platform === "darwin" ? { x: 17, y: 16 } : undefined,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });
  mainWindow = window;
  if (!app.isPackaged) {
    window.webContents.on("before-input-event", (event, input) => {
      if (input.type !== "keyDown" || input.isAutoRepeat) return;
      const key = input.key.toLowerCase();
      const isToggleDevToolsShortcut = process.platform === "darwin"
        ? input.meta && input.alt && key === "i"
        : (input.control && input.shift && key === "i") || key === "f12";
      if (!isToggleDevToolsShortcut) return;
      event.preventDefault();
      window.webContents.toggleDevTools();
    });
  }
  window.once("ready-to-show", () => {
    if (showOnReady) showMainWindow();
  });
  window.webContents.setWindowOpenHandler(({ url }) => {
    if (isWorkbenchUrl(url)) {
      return {
        action: "allow",
        overrideBrowserWindowOptions: {
          webPreferences: {
            preload: path.join(__dirname, "preload.js"),
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: false,
          },
        },
      };
    }
    void shell.openExternal(url);
    return { action: "deny" };
  });
  window.webContents.on("will-navigate", (event, url) => {
    if (isWorkbenchUrl(url)) return;
    event.preventDefault();
    void shell.openExternal(url);
  });
  window.webContents.on(
    "did-fail-load",
    (_event, errorCode, errorDescription, validatedUrl) => {
      appendMainLog({
        level: "ERROR",
        message: `Desktop UI failed to load ${validatedUrl}: ${errorCode} ${errorDescription}`,
      });
    },
  );
  window.on("close", (event) => {
    if (isQuitting) return;
    event.preventDefault();
    if (process.platform === "darwin" || process.platform === "win32") {
      window.hide();
      return;
    }
    void requestQuit({ confirm: true });
  });
  window.on("closed", () => {
    if (mainWindow === window) mainWindow = null;
  });
  // A deep link that arrived before the renderer mounted waits here.
  window.webContents.on("did-finish-load", () => drainDesktopOnboarding());
  void window.loadURL(devUrl ? `${devUrl.replace(/\/+$/, "")}${route}` : staticWorkbenchUrl(route));
  return window;
}

function showMainWindow(): void {
  if (isQuitting) return;
  const window = mainWindow && !mainWindow.isDestroyed() ? mainWindow : createMainWindow(false);
  showDockForWindow();
  if (window.isMinimized()) window.restore();
  window.show();
  window.moveTop();
  if (process.platform === "darwin") app.focus({ steal: true });
  window.focus();
}

function createWindowsTray(): void {
  if (process.platform !== "win32" || tray) return;
  const iconPath = path.join(app.isPackaged ? process.resourcesPath : app.getAppPath(), "build", "icon.ico");
  tray = new Tray(iconPath);
  tray.setToolTip(APP_NAME);
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: "打开 OSIR Anywhere", click: () => showMainWindow() },
    { type: "separator" },
    { label: "退出", click: () => { void requestQuit({ confirm: true }); } },
  ]));
  tray.on("click", () => showMainWindow());
}

function hideDockIfIdle(): void {
  if (process.platform === "darwin" && !process.env.WORKBENCH_WEB_URL) {
    app.setActivationPolicy("accessory");
  }
}

function showDockForWindow(): void {
  if (process.platform !== "darwin") return;
  app.setActivationPolicy("regular");
  if (app.dock && !app.dock.isVisible()) void app.dock.show();
}

function isWorkbenchUrl(rawUrl: string): boolean {
  try {
    const url = new URL(rawUrl);
    if (url.protocol === `${WEB_PROTOCOL}:` && url.hostname === WEB_HOST) return true;
    return Boolean(devOrigin && url.origin === devOrigin);
  } catch {
    return false;
  }
}

function assertTrustedRenderer(event: IpcMainInvokeEvent): void {
  const senderUrl = event.senderFrame?.url || event.sender.getURL();
  if (!isWorkbenchUrl(senderUrl)) {
    throw new Error("Desktop IPC is only available to the Workbench renderer.");
  }
}

function sendToRenderer(channel: string, value?: unknown): void {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  mainWindow.webContents.send(channel, value);
}

function connectorDataPath(): string {
  return path.join(app.getPath("userData"), "connector");
}

function connectorLogsPath(): string {
  return path.join(app.getPath("userData"), "logs");
}

function desktopSettingsPath(): string {
  return path.join(app.getPath("userData"), "desktop-settings.json");
}

function resolveConnectorDir(): string {
  if (process.env.WORKBENCH_CONNECTOR_DIR?.trim()) {
    return path.resolve(process.env.WORKBENCH_CONNECTOR_DIR.trim());
  }
  if (app.isPackaged) return path.join(process.resourcesPath, "connector");
  return path.resolve(app.getAppPath(), "..", "connector");
}

/**
 * The uv that packaging bundles. Development uses the same build output, so a
 * dev launch runs the exact uv the installer ships instead of whatever `uv`
 * happens to be on the developer's PATH. Run `yarn bundle:uv` to create it.
 */
function resolveUvBundleDir(): string {
  if (process.env.WORKBENCH_UV_BUNDLE_DIR?.trim()) {
    return path.resolve(process.env.WORKBENCH_UV_BUNDLE_DIR.trim());
  }
  if (app.isPackaged) return path.join(process.resourcesPath, "uv");
  return path.join(app.getAppPath(), "build", "uv");
}

/**
 * The CPython that packaging bundles, so the Connector never waits on uv
 * downloading an interpreter. Development uses the same build output once
 * `yarn bundle:python` has created it; until then uv picks an interpreter.
 */
function resolvePythonBundleDir(): string {
  if (process.env.WORKBENCH_PYTHON_BUNDLE_DIR?.trim()) {
    return path.resolve(process.env.WORKBENCH_PYTHON_BUNDLE_DIR.trim());
  }
  if (app.isPackaged) return path.join(process.resourcesPath, "python");
  return path.join(app.getAppPath(), "build", "python");
}

function appWindowIcon(): string {
  if (app.isPackaged) return path.join(process.resourcesPath, "build", "icon-mac-source.png");
  return path.join(app.getAppPath(), "build", "icon-mac-source.png");
}

function launchedAsLoginItem(): boolean {
  const login = app.getLoginItemSettings(loginItemOptions());
  return Boolean(
    login.wasOpenedAtLogin ||
      login.wasOpenedAsHidden ||
      process.argv.includes(LOGIN_ITEM_HIDDEN_ARG) ||
      process.argv.includes("--background") ||
      process.argv.includes("--squirrel-firstrun"),
  );
}

function loginItemOptions(): { path?: string; args?: string[] } {
  if (process.platform !== "win32") return {};
  return {
    path: process.execPath,
    args: backend?.getSettings()?.silentLaunch ? [LOGIN_ITEM_HIDDEN_ARG] : [],
  };
}

function applyLoginItemSettings(): void {
  const settings = backend?.getSettings();
  if (!settings) return;
  app.setLoginItemSettings({
    openAtLogin: settings.openAtLogin,
    openAsHidden: settings.silentLaunch,
    ...loginItemOptions(),
  });
}

/** Main-process messages join the same log stream the renderer already reads. */
function appendMainLog(entry: string | Partial<ConnectorLogEntry>): void {
  const payload = typeof entry === "string"
    ? { level: "INFO", message: entry }
    : { level: entry.level ?? "INFO", message: String(entry.message ?? "") };
  if (backend?.running) {
    void backend.request("/logs/append", { method: "POST", body: JSON.stringify(payload) }).catch(() => undefined);
    return;
  }
  // The running backend owns the log. Before it is ready or after it stopped,
  // Main appends to the same files, so a failed launch or a crash still leaves
  // its reason there. A fresh store continues the sequence the backend wrote.
  new ConnectorLogStore(connectorLogsPath(), () => backend?.getSettings() ?? readDesktopSettings(desktopSettingsPath()))
    .append(payload);
}

function syncDesktopUpdateSession(serverUrl: unknown) {
  const saved = serverStore?.getSaved();
  let connection: DesktopServerConnection | null = null;
  if (saved && typeof serverUrl === "string" && serverUrl.trim()) {
    try {
      if (normalizeServerOrigin(serverUrl) === saved.serverUrl) connection = saved;
    } catch {
      // An incomplete or invalid session must never select a fallback server.
    }
  }
  return updates?.check(connection) ?? null;
}

/** Throws on a Connector conflict, matching the previous acquire semantics. */
async function requireLocalOwnership(): Promise<void> {
  if (isQuitting || !backend) throw new Error("Desktop is shutting down or not ready.");
  ownership = await backend.request<OwnershipState>("/ownership/acquire", { method: "POST", body: "{}" });
}

function registerIpcHandlers(): void {
  ipcMain.handle("workbench:files:droppedFolderPath", (event, value: unknown) => {
    assertTrustedRenderer(event);
    return droppedFolderPath(value);
  });
  ipcMain.handle("workbench:ownership:getState", event => {
    assertTrustedRenderer(event);
    return ownership;
  });
  ipcMain.handle("workbench:ownership:recheck", event => {
    assertTrustedRenderer(event);
    recheckingOwnership ??= (async () => {
      if (isQuitting || !backend) return ownership;
      if (!backend.running) return restartDesktopBackend();
      try {
        ownership = await backend.request<OwnershipState>("/ownership/recheck", { method: "POST", body: "{}" });
      } catch { return ownership; }
      return ownership;
    })().finally(() => { recheckingOwnership = null; });
    return recheckingOwnership;
  });
  ipcMain.handle("workbench:ownership:quit", event => {
    assertTrustedRenderer(event);
    return requestQuit();
  });
  ipcMain.handle("workbench:window:setTheme", (event, theme: unknown) => {
    assertTrustedRenderer(event);
    if (event.sender !== mainWindow?.webContents) return;
    if (theme !== "light" && theme !== "dark") throw new Error("Invalid window theme.");
    nativeTheme.themeSource = theme;
  });
  ipcMain.handle("workbench:window:setTitleBarColors", (event, input: unknown) => {
    assertTrustedRenderer(event);
    if (process.platform !== "win32" || event.sender !== mainWindow?.webContents) return;
    const colors = validateTitleBarColors(input);
    mainWindow.setTitleBarOverlay({ ...colors, color: "#00000000" });
  });
  ipcMain.handle("workbench:updates:syncSession", (event, serverUrl: unknown) => {
    assertTrustedRenderer(event);
    return syncDesktopUpdateSession(serverUrl);
  });
  for (const [method, action] of Object.entries({
    getState: () => updates?.getState() ?? null,
    open: () => updates?.showPrompt() ?? null,
    ignore: () => updates?.ignoreVersion() ?? null,
    download: () => updates?.download() ?? null,
    cancel: () => updates?.cancelDownload() ?? null,
  })) {
    ipcMain.handle(`workbench:updates:${method}`, (event) => {
      assertTrustedRenderer(event);
      return action();
    });
  }
  ipcMain.handle("workbench:backend:endpoint", (event) => {
    assertTrustedRenderer(event);
    // Only the development renderer needs this: it is served from an HTTP
    // origin, where the same-origin /desktop-api proxy does not exist.
    if (app.isPackaged) throw new Error("The Desktop backend endpoint is only available in development.");
    if (!backend) throw new Error("Desktop backend is not ready.");
    return { baseUrl: backend.origin, token: backend.token };
  });
  ipcMain.handle("workbench:openExternal", async (event, url: string) => {
    assertTrustedRenderer(event);
    if (!/^https?:\/\//i.test(url)) throw new Error("Only http(s) URLs can be opened externally.");
    await shell.openExternal(url);
  });
  // Only the complete page calls this. Entering onboarding never records it.
  ipcMain.handle("workbench:onboarding:complete", (event, input?: { source?: unknown }) => {
    assertTrustedRenderer(event);
    if (!backend) throw new Error("Desktop backend is not ready.");
    const source = input?.source === "dsh-plugin" || input?.source === "desktop" ? input.source : null;
    if (!source) throw new Error("Unsupported Desktop onboarding source.");
    return backend.request("/onboarding/complete", { method: "POST", body: JSON.stringify({ source }) });
  });
  ipcMain.handle("workbench:auth:getServer", (event) => {
    assertTrustedRenderer(event);
    return activeDesktopServer();
  });
  ipcMain.handle("workbench:auth:startOAuth", async (event, input?: { serverUrl?: string }): Promise<DesktopOAuthStartResult> => {
    assertTrustedRenderer(event);
    await requireLocalOwnership();
    if (startingDesktopOAuth) throw new Error("A sign-in request is already starting.");
    startingDesktopOAuth = true;
    const attempt = ++desktopOAuthAttempt;
    desktopOAuthResult = null;
    await desktopOAuthFlow.cancel();
    try {
      const server = resolveDesktopServer(input?.serverUrl ?? config.cloud.serverUrl, {
        env: process.env,
        development: !app.isPackaged,
      });
      if (!desktopSessions) throw new Error("Desktop secure session storage is not ready.");
      await desktopSessions.prepareLogin();
      await checkDesktopServer(server, (url, init) => net.fetch(String(url), init));
      if (isQuitting || attempt !== desktopOAuthAttempt) throw new Error("Desktop sign-in was cancelled.");
      const request = await desktopOAuthFlow.start(server);
      return { status: "opened", authorizeUrl: request.authorizeUrl };
    } catch (error) {
      await desktopOAuthFlow.cancel();
      return {
        status: "error",
        code: error instanceof DesktopServerError ? error.code : "oauth",
        error: error instanceof DesktopServerError ? error.message : "Could not start OSIR sign-in. Check your connection and retry.",
      };
    } finally {
      startingDesktopOAuth = false;
    }
  });
  ipcMain.handle("workbench:auth:cancelOAuth", async (event): Promise<void> => {
    assertTrustedRenderer(event);
    desktopOAuthAttempt += 1;
    await desktopOAuthFlow.cancel();
    desktopOAuthResult = null;
  });
  ipcMain.handle("workbench:auth:consumeOAuthResult", (event): DesktopOAuthResult | null => {
    assertTrustedRenderer(event);
    const result = desktopOAuthResult;
    desktopOAuthResult = null;
    return result;
  });
  ipcMain.handle("workbench:auth:refreshSession", async (event) => {
    assertTrustedRenderer(event);
    try {
      if (!desktopSessions) throw new Error();
      const restored = await desktopSessions.refresh(activeDesktopServer());
      if (!restored) await backend?.request("/stop", { method: "POST" }).catch(() => {});
      return restored;
    } catch {
      await backend?.request("/stop", { method: "POST" }).catch(() => {});
      throw new Error("Desktop session unavailable. Sign in again or check your connection.");
    }
  });
  ipcMain.handle("workbench:auth:logout", async (event) => {
    assertTrustedRenderer(event);
    await projectConnector?.stop();
    await scopedTestConnector?.stop();
    desktopOAuthAttempt++;
    desktopOAuthResult = null;
    await desktopOAuthFlow.cancel();
    // Stop remote access even when secure storage or the server is unavailable.
    let connectorStopped = false;
    try {
      const stopped = backend ? await backend.request<ConnectorState>("/stop", { method: "POST" }) : null;
      connectorStopped = !stopped?.running;
    } catch { /* report explicitly; never claim the remote connector was stopped */ }
    try {
      if (!desktopSessions) throw new Error();
      const result = await desktopSessions.logout();
      return { ...result, connectorStopped };
    } catch { throw new Error("Desktop sign-out is incomplete. Server revocation may still be pending; close OSIR Anywhere and retry."); }
  });
  ipcMain.handle(
    "workbench:notifications:show",
    (event, input: DesktopNotificationInput): DesktopNotificationResult => {
      assertTrustedRenderer(event);
      if (!backend?.getSettings()?.notificationsEnabled) {
        return { shown: false, reason: "disabled" };
      }
      if (!Notification.isSupported()) {
        return { shown: false, reason: "unsupported" };
      }
      const title = normalizeNotificationText(input?.title, 120);
      const body = normalizeNotificationText(input?.body, 500);
      if (!title || !body) return { shown: false, reason: "invalid" };

      const notification = new Notification({ title, body });
      activeNotifications.add(notification);
      notification.once("close", () => activeNotifications.delete(notification));
      notification.once("click", () => {
        activeNotifications.delete(notification);
        showMainWindow();
        sendToRenderer("workbench:notifications:click", {
          sessionId: typeof input.sessionId === "string" ? input.sessionId : undefined,
        });
      });
      notification.show();
      return { shown: true };
    },
  );
  ipcMain.handle("workbench:connector:openDataFolder", async (event) => {
    assertTrustedRenderer(event);
    fs.mkdirSync(connectorDataPath(), { recursive: true, mode: 0o700 });
    return shell.openPath(connectorDataPath());
  });
  ipcMain.handle("workbench:connector:openLogsFolder", async (event) => {
    assertTrustedRenderer(event);
    const state = await backend?.request<ConnectorState>("/state").catch(() => null);
    const page = !state?.logsPath?.trim()
      ? await backend?.request<ConnectorLogPage>("/logs?pageSize=1").catch(() => null)
      : null;
    const logsDir = state?.logsPath?.trim() || page?.logsPath?.trim() || connectorLogsPath();
    fs.mkdirSync(logsDir, { recursive: true, mode: 0o700 });
    return shell.openPath(logsDir);
  });
  ipcMain.handle("workbench:connector:exportLogs", async (event) => {
    assertTrustedRenderer(event);
    const stamp = new Date().toISOString().slice(0, 10);
    const options = {
      title: "Export Connector logs",
      defaultPath: path.join(app.getPath("documents"), `osir-anywhere-connector-${stamp}.jsonl`),
      filters: [{ name: "JSON Lines", extensions: ["jsonl"] }],
    };
    const result = mainWindow
      ? await dialog.showSaveDialog(mainWindow, options)
      : await dialog.showSaveDialog(options);
    if (result.canceled || !result.filePath) return { canceled: true, filePath: null, count: 0 };
    const exported = await requireBackend().request<{ count: number }>("/logs/export", {
      method: "POST",
      body: JSON.stringify({ filePath: result.filePath }),
    });
    return { canceled: false, filePath: result.filePath, count: exported.count };
  });
  ipcMain.handle("workbench:connector:factoryReset", async (event, input: DesktopFactoryResetInput) => {
    assertTrustedRenderer(event);
    const forceLocal = input?.forceLocal === true;
    const client = requireBackend();
    const binding = await client.request<{ connectorId: string } | null>("/device/binding");
    if (binding && !forceLocal) {
      // Server revoke happens first. If it fails, local credentials and binding
      // remain untouched so the user can retry instead of creating an orphan.
      await client.request("/device/revoke", {
        method: "POST",
        body: JSON.stringify({
          userToken: input?.userToken ?? "",
          userId: input?.userId ?? "",
          serverUrl: input?.serverUrl,
        }),
      });
    }
    isQuitting = true;
    await desktopOAuthFlow.shutdown();
    await desktopSessions?.logout();
    quiesceRendererForShutdown();
    await client.shutdown();
    await session.defaultSession.clearStorageData();
    await session.defaultSession.clearCache();
    // Async removal keeps the UI process free; the app is about to relaunch.
    await fs.promises.rm(connectorDataPath(), { recursive: true, force: true });
    await fs.promises.rm(connectorLogsPath(), { recursive: true, force: true });
    await fs.promises.rm(desktopSettingsPath(), { force: true });
    await fs.promises.rm(path.join(app.getPath("userData"), "desktop-server.json"), { force: true });
    app.relaunch();
    shutdownComplete = true;
    app.exit(0);
  });
}

function normalizeNotificationText(value: unknown, maximumLength: number): string {
  if (typeof value !== "string") return "";
  return value.replace(/\s+/g, " ").trim().slice(0, maximumLength);
}

function requireBackend(): DesktopBackendClient {
  if (!backend) throw new Error("Desktop backend is not ready.");
  return backend;
}

function backendInit(): BackendInit {
  const dataPath = connectorDataPath();
  return {
    dataPath,
    connectorDataRoot: desktopConnectorDataRoot({
      packaged: app.isPackaged, productName: APP_NAME, userDataPath: app.getPath("userData"),
    }),
    logsPath: connectorLogsPath(),
    settingsPath: desktopSettingsPath(),
    bindingPath: path.join(dataPath, "desktop-binding.json"),
    configPath: path.join(dataPath, "connector.json"),
    connectorDir: resolveConnectorDir(),
    resourcesPath: process.resourcesPath,
    uvBundleDir: resolveUvBundleDir(),
    pythonBundleDir: resolvePythonBundleDir(),
    homePath: app.getPath("home"),
    clientModelBinding: "required-v1",
    documentsPath: app.getPath("documents"),
    packaged: app.isPackaged,
    requireExplicitConnection: true,
    scopedVerificationOnly: process.env.OSIR_ANYWHERE_SCOPED_TEST === "1",
    preferredLanguages: app.getPreferredSystemLanguages(),
    defaultServerUrl: apiOrigin(),
    apiNamespace: apiNamespace(),
    desktopExecutablePath: process.platform === "linux" && app.isPackaged && process.env.APPIMAGE
      ? process.env.APPIMAGE
      : process.execPath,
    desktopAppPath: app.getAppPath(),
  };
}

/**
 * Starts the backend process. The window no longer waits for Connector
 * ownership, the login-shell environment snapshot, or installation bookkeeping;
 * those run inside the backend and arrive over the event stream.
 */
async function initializeDesktopServices(): Promise<void> {
  serverStore = new DesktopServerStore(path.join(app.getPath("userData"), "desktop-server.json"), activeDesktopServer());
  desktopSessions = new DesktopSessionManager(
    new DesktopSessionStore(path.join(app.getPath("userData"), "desktop-session.enc"), {
      isEncryptionAvailable: () => safeStorage.isEncryptionAvailable(),
      encryptString: value => safeStorage.encryptString(value),
      decryptString: value => safeStorage.decryptString(value),
      ...(process.platform === "linux" ? { getSelectedStorageBackend: () => safeStorage.getSelectedStorageBackend() } : {}),
    }),
    (url, init) => net.fetch(String(url), init),
  );
  await startDesktopBackend();
}

/** Explicit local acceptance menu; normal launches never enter this path. */
function installScopedTestMenu(): void {
  if (process.env.OSIR_ANYWHERE_SCOPED_TEST !== "1") return;
  scopedTestConnector = new OsirScopedConnector({
    configPath: path.join(app.getPath("userData"), "connector", "connector.json"),
    refresh: async () => desktopSessions?.refresh(activeDesktopServer()) ?? null,
    fetcher: (input, init) => net.fetch(String(input), init),
    log: (message) => appendMainLog(message),
  });
  projectConnector = new OsirScopedConnector({
    configPath: path.join(app.getPath("userData"), "connector", "connector.json"),
    refresh: async () => desktopSessions?.refresh(activeDesktopServer()) ?? null,
    fetcher: (input, init) => net.fetch(String(input), init),
    log: (message) => appendMainLog(message),
    project: true,
    resolveProxy: () => session.defaultSession.resolveProxy("https://anywhere.osirclaw.com"),
  });
  const action = async (start: boolean) => {
    try {
      if (start) {
        await projectConnector?.stop();
        const ready = await scopedTestConnector!.start();
        await dialog.showMessageBox(mainWindow!, { type: "info", message: "授权测试目录已连接",
          detail: `仅同步本次新建文字会话。\n${ready.workspace}\n最多 4 个会话、共 8 次执行；不读取历史、文件或终端。`, buttons: ["确定"] });
      } else {
        await scopedTestConnector!.stop();
        await dialog.showMessageBox(mainWindow!, { type: "info", message: "测试目录已断开", buttons: ["确定"] });
      }
    } catch (error) { dialog.showErrorBox("OSIR 测试连接", errorMessage(error)); }
  };
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { role: "appMenu" }, { role: "editMenu" }, { role: "viewMenu" },
    { label: "测试连接", submenu: [
      { label: "连接已授权 OSIR 项目", click: () => { void (async () => {
        try {
          await scopedTestConnector?.stop();
          const ready = await projectConnector!.start();
          await dialog.showMessageBox(mainWindow!, { type: "info", message: "已连接 OSIR 项目",
            detail: `正在分批拉取并同步此目录的 Codex 会话：\n${ready.workspace}\n不会扫描其他项目。`, buttons: ["确定"] });
        } catch (error) { dialog.showErrorBox("OSIR 项目连接", errorMessage(error)); }
      })(); } },
      { label: "断开 OSIR 项目", click: () => { void projectConnector?.stop().catch(error => {
        dialog.showErrorBox("OSIR 项目连接", errorMessage(error));
      }); } },
      { label: "连接授权测试目录", click: () => { void action(true); } },
      { label: "断开授权测试目录", click: () => { void action(false); } },
    ] },
  ]));
}

/** Starts the backend process; a recheck after it stopped starts a new one. */
async function startDesktopBackend(): Promise<void> {
  const client = new DesktopBackendClient({
    fetcher: (input, init) => net.fetch(String(input), init),
    onEvent: (event) => {
      if (backend !== client) return;
      if (event.event === "ownership") {
        publishOwnership(event.data as OwnershipState);
        return;
      }
      if (event.event === "settings") applyLoginItemSettings();
    },
    onExit: (message) => {
      appendMainLog({ level: "ERROR", message });
      if (backend !== client || isQuitting) return;
      // Every Connector, device and settings call goes through the backend,
      // so an owned window would keep failing without saying why. The gate
      // says it, and its recheck starts a new backend.
      publishOwnership({ status: "error", message, recovery: { kind: "backendStopped" } });
    },
  });
  backend = client;
  await client.start(backendInit());
  ownership = client.getOwnership();
  applyLoginItemSettings();
}

/** The new backend probes ownership itself; its events replace this state. */
async function restartDesktopBackend(): Promise<OwnershipState> {
  appendMainLog({ level: "WARNING", message: "Restarting the Desktop backend." });
  try {
    await startDesktopBackend();
    publishOwnership(ownership);
  } catch (error) {
    appendMainLog({ level: "ERROR", message: `Could not restart the Desktop backend: ${errorMessage(error)}` });
    publishOwnership({ status: "error", message: errorMessage(error), recovery: { kind: "backendStopped" } });
  }
  return ownership;
}

function publishOwnership(state: OwnershipState): void {
  ownership = state;
  sendToRenderer("workbench:ownership:state", ownership);
}

/** Only a silent login-item launch has to wait for the first ownership result. */
async function waitForOwnership(timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (ownership.status !== "owned" && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
}

async function confirmQuit(): Promise<boolean> {
  if (quitConfirmationPromise) return quitConfirmationPromise;
  quitConfirmationPromise = (async () => {
    const options = {
      type: "warning" as const,
      title: "退出 OSIR Anywhere？",
      message: "退出 OSIR Anywhere？",
      detail: "退出后，本机将离线，其他设备将无法在本机发起 Agent 会话。",
      buttons: ["取消", "退出程序"],
      defaultId: 1,
      cancelId: 0,
      noLink: true,
    };
    // A hidden window must not own the tray's confirmation dialog.
    const result = mainWindow && !mainWindow.isDestroyed() && mainWindow.isVisible()
      ? await dialog.showMessageBox(mainWindow, options)
      : await dialog.showMessageBox(options);
    return result.response === 1;
  })().finally(() => {
    quitConfirmationPromise = null;
  });
  return quitConfirmationPromise;
}

async function requestQuit({ confirm = false }: { confirm?: boolean } = {}): Promise<void> {
  if (shutdownComplete) {
    app.quit();
    return;
  }
  if (shutdownPromise) return shutdownPromise;
  if (confirm && !(await confirmQuit())) return;
  if (shutdownPromise) return shutdownPromise;
  isQuitting = true;
  shutdownPromise = (async () => {
    try {
      await desktopOAuthFlow.shutdown();
      await projectConnector?.stop();
      await scopedTestConnector?.stop();
      desktopOAuthResult = null;
      updates?.dispose();
      tray?.destroy();
      tray = null;
      quiesceRendererForShutdown();
      await backend?.shutdown();
    } finally {
      shutdownComplete = true;
      app.quit();
    }
  })();
  return shutdownPromise;
}

function quiesceRendererForShutdown(): void {
  const window = mainWindow;
  if (!window || window.isDestroyed()) return;
  window.destroy();
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

if (hasSingleInstanceLock) {
  registerIpcHandlers();
  // Onboarding entries also work in development, where the OS protocol handler
  // is not installed and the URL only arrives through argv.
  const initialOnboarding = desktopOnboardingFromArgv(process.argv);
  if (initialOnboarding) queueDesktopOnboarding(initialOnboarding);
  app.on("open-url", (event, rawUrl) => {
    event.preventDefault();
    const onboarding = desktopOnboardingFromUrl(rawUrl);
    if (onboarding) {
      queueDesktopOnboarding(onboarding);
      return;
    }
    // Custom-scheme OAuth callbacks are intentionally ignored. Loopback owns OAuth.
  });
  app.whenReady().then(async () => {
    Menu.setApplicationMenu(null);
    registerStaticWebProtocol();
    await initializeDesktopServices();
    updates = new DesktopUpdateService({
      directory: path.join(app.getPath("userData"), "updates"),
      currentVersion: app.getVersion(),
      manifestUrl: RELEASE_MANIFEST_URL,
      publicKeyPem: readReleasePublicKey(app.isPackaged ? process.resourcesPath : app.getAppPath()),
      platform: process.platform,
      arch: process.arch,
      checkTimeoutMs: config.healthTimeoutMs,
      fetcher: (input, init) => net.fetch(String(input), init),
      openInstaller: async (filePath) => {
        const error = await shell.openPath(filePath);
        if (error) throw new Error(error);
      },
      onState: (state) => sendToRenderer("workbench:updates:state", state),
    });
    createWindowsTray();
    // A silent login-item launch must not flash a window when this machine
    // already owns the Connector, so it is the one case that waits.
    const silentLoginLaunch = backend?.getSettings()?.silentLaunch === true
      && launchedAsLoginItem()
      && !process.env.WORKBENCH_WEB_URL;
    let showOnLaunch = true;
    if (silentLoginLaunch) {
      await waitForOwnership(10_000);
      showOnLaunch = ownership.status !== "owned";
    }
    createMainWindow(showOnLaunch, await resolveLaunchRoute(silentLoginLaunch));
    installScopedTestMenu();
    if (process.platform === "darwin" && app.dock) app.dock.setIcon(appWindowIcon());
    if (!showOnLaunch) hideDockIfIdle();
  }).catch((error) => {
    console.error("Failed to initialize Desktop Workbench", error);
    appendMainLog({ level: "ERROR", message: `Desktop failed to start: ${errorMessage(error)}` });
    // No window may exist yet, so this box is the only place the reason shows.
    dialog.showErrorBox("OSIR Anywhere 无法启动", `${errorMessage(error)}\n\n日志目录：${connectorLogsPath()}`);
    void requestQuit();
  });

  app.on("activate", () => showMainWindow());
  app.on("second-instance", (_event, argv) => {
    const onboarding = desktopOnboardingFromArgv(argv);
    if (onboarding) queueDesktopOnboarding(onboarding);
    showMainWindow();
  });
  app.on("window-all-closed", () => {
    // Connector cleanup is handled by the explicit quit flow.
  });
  app.on("before-quit", (event) => {
    if (shutdownComplete) return;
    event.preventDefault();
    void requestQuit({ confirm: true });
  });
}
