import { EventEmitter } from "node:events";
import { ConnectorLogStore } from "../log-store";
import { ConnectorSupervisor } from "../connector-supervisor";
import { DesktopBindingStore } from "../desktop-binding";
import { awaitConnectionOperation, DesktopDeviceService } from "../desktop-device-service";
import { DesktopSettingsStore } from "../desktop-settings";
import { desktopInstallation, MachineStateStore } from "../machine-state";
import { localRuntimePath } from "../local-runtime";
import type { DesktopOnboardingSource, DesktopOnboardingState } from "../machine-state";
import { readShellEnvironment } from "../shell-environment";
import { LogBatcher } from "./log-batcher";
import type { OwnershipState } from "../local-runtime";
import type {
  ConnectorConfigPatch,
  ConnectorLogEntry,
  ConnectorLogPage,
  ConnectorLogQuery,
  ConnectorState,
  DesktopDeviceAuthInput,
  DesktopDeviceNameInput,
  DesktopDeviceProvisionInput,
  DesktopDeviceReconnectInput,
  DesktopSettings,
  DesktopSettingsPatch,
  PublicLocalDesktopBinding,
} from "../connector-types";
import type { BackendEventName, BackendInit } from "./protocol";

/**
 * Outbound HTTP for device registration. It is injected so the backend can
 * reuse the main process's Chromium network stack (system proxy, certificates)
 * instead of the plain Node agent.
 */
export type BackendFetcher = (input: string | URL, init?: RequestInit) => Promise<Response>;

type EventName = BackendEventName;

/**
 * Owns every stateful Desktop service. Construction is synchronous so the
 * process can report ready immediately; the two slow startup steps (reading the
 * login shell environment and the first Connector ownership probe) run in
 * `initialize()` and never delay the window.
 */
export class BackendState {
  private readonly events = new EventEmitter();
  private readonly settings: DesktopSettingsStore;
  private readonly logs: ConnectorLogStore;
  private readonly binding: DesktopBindingStore;
  private readonly machineState: MachineStateStore;
  private readonly connector: ConnectorSupervisor;
  private readonly devices: DesktopDeviceService;
  private ownership: OwnershipState = { status: "checking" };
  /** The server this backend talks to. Main pushes changes after a sign-in. */
  private server: { serverUrl: string; apiNamespace: string };
  private readonly logBatcher = new LogBatcher((batch) => this.emit("logs", batch));
  private closed = false;
  private initialized = false;
  /** Only device create/reconnect grants permission to start the remote runtime. */
  private explicitConnectionRequested = false;
  private connectionEpoch = new AbortController();
  /** Only local runtime mutations join this queue. Network provisioning never
   * holds up stop. Supervisor RPCs already have their own finite deadlines.
   */
  private mutationTail: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly init: BackendInit,
    fetcher: BackendFetcher,
    connectControl?: ConstructorParameters<typeof ConnectorSupervisor>[0]["connectControl"],
  ) {
    if (init.requireExplicitConnection) this.ownership = { status: "idle" };
    this.server = { serverUrl: init.defaultServerUrl, apiNamespace: init.apiNamespace };
    const dataRoot = init.connectorDataRoot ?? (process.env.AGENT_CONNECTOR_DATA_DIR?.trim() || undefined);
    this.machineState = new MachineStateStore(
      localRuntimePath(init.homePath, dataRoot),
      (message) => this.appendLog({ level: "WARNING", message }),
      !dataRoot,
    );
    this.settings = new DesktopSettingsStore(init.settingsPath, init.preferredLanguages);
    this.logs = new ConnectorLogStore(init.logsPath, () => this.settings.get());
    this.binding = new DesktopBindingStore(init.bindingPath);
    this.connector = new ConnectorSupervisor({
      connectControl,
      onOwnership: (state) => {
        this.ownership = state;
        this.emit("ownership", state);
      },
      configPath: init.configPath,
      dataPath: init.dataPath,
      connectorDataRoot: dataRoot,
      connectorDir: init.connectorDir,
      resourcesPath: init.resourcesPath,
      uvBundleDir: init.uvBundleDir,
      pythonBundleDir: init.pythonBundleDir,
      packaged: init.packaged,
      homePath: init.homePath,
      clientModelBinding: init.clientModelBinding,
      shellEnvironment: {},
      settings: this.settings,
      binding: this.binding,
      logs: this.logs,
      onState: (state) => this.emit("state", state),
      onLog: (entry) => { if (!this.connector.hasRuntimeLogs()) this.bufferLog(entry); },
      onRuntimeLog: (entry) => this.bufferLog(entry),
      onLogSourceChanged: () => { this.logBatcher.flush(); this.emit("logsCleared", undefined); },
    });
    this.devices = new DesktopDeviceService({
      requireOwnership: () => this.requireOwnership(),
      activate: (method, signal) => this.activateConnector(method, signal),
      binding: this.binding,
      connector: this.connector,
      fetcher,
      defaultServerUrl: () => this.server.serverUrl,
      apiNamespace: () => this.server.apiNamespace,
      readLocalConnectorIds: () => this.machineState.readConnectorIds(),
    });
  }

  on(event: EventName, listener: (data: unknown) => void): void {
    this.events.on(event, listener);
  }

  off(event: EventName, listener: (data: unknown) => void): void {
    this.events.off(event, listener);
  }

  /**
   * Startup work that must not block the window. Ownership failures stay
   * observable through the `ownership` event; the renderer shows the retry
   * action exactly as before.
   *
   * It runs after `ready`, where a rejection would only reach Main's log, so
   * every failure lands where the renderer looks: the ownership gate while it
   * still blocks the app, the Connector's `lastError` once it does not.
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;
    this.initialized = true;
    try {
      const shellEnvironment = await readShellEnvironment().catch(() => ({} as NodeJS.ProcessEnv));
      if (Object.keys(shellEnvironment).length === 0) {
        // Without it, a GUI launch on macOS may not find codex or claude on PATH.
        this.appendLog({ level: "WARNING", message: "Could not read the login shell environment; the Connector starts with Desktop's own PATH." });
      }
      if (this.closed) return;
      this.connector.setShellEnvironment(shellEnvironment);
      // The supervisor logs a failed probe and reports it as the `error` state.
      if (!this.init.requireExplicitConnection) await this.acquireOwnership().catch(() => undefined);
      await this.recordInstallation().catch((error) => this.appendLog({
        level: "ERROR",
        message: `Could not record Desktop installation: ${errorMessage(error)}`,
      }));
      if (this.closed) return;
      const config = this.connector.loadPrivateConfig();
      if (config && !this.binding.get()) this.binding.adoptConfig(config);
      this.connector.bindingChanged();
      if (this.ownership.status === "owned") {
        await this.startOwnedConnectorOnLaunch().catch((error) => this.reportStartupError(
          `Could not start the local Connector on launch: ${errorMessage(error)}`,
        ));
      }
    } catch (error) {
      this.reportStartupError(`Desktop backend initialization failed: ${errorMessage(error)}`);
    }
  }

  ownershipState(): OwnershipState {
    return this.ownership;
  }

  /**
   * Signing in can select a different server than the one this backend started
   * with, and the backend only sees the launch-time snapshot. Main pushes the
   * current connection so provisioning never falls back to the old server.
   */
  setServerConnection(input: { serverUrl?: unknown; apiNamespace?: unknown }): { serverUrl: string; apiNamespace: string } {
    const serverUrl = typeof input?.serverUrl === "string" ? input.serverUrl.trim() : "";
    if (!/^https?:\/\/[^\s]+$/i.test(serverUrl)) throw new Error("The Desktop backend server URL is invalid.");
    const apiNamespace = typeof input?.apiNamespace === "string" ? input.apiNamespace.trim() : "";
    this.server = { serverUrl, apiNamespace };
    return { ...this.server };
  }

  /** Login's ownership request must not claim a Connector before device consent. */
  async acquireOwnershipOrThrow(): Promise<OwnershipState> {
    if (this.closed) throw new Error("Desktop backend is shutting down.");
    if (this.awaitingExplicitConnection()) return this.ownership;
    await this.requireOwnership();
    return this.ownership;
  }

  /** Clearing an environment does not grant permission to reconnect it. */
  async resetConnectorEnvironment(): Promise<ConnectorState> {
    if (this.closed) throw new Error("Desktop backend is shutting down.");
    this.cancelConnections();
    const state = await this.mutateConnector(() => this.connector.resetEnvironment());
    if (this.init.requireExplicitConnection) {
      this.explicitConnectionRequested = false;
      this.ownership = { status: "idle" };
      this.emit("ownership", this.ownership);
    }
    return state;
  }

  async recheckOwnership(): Promise<OwnershipState> {
    if (this.closed) return this.ownership;
    if (this.awaitingExplicitConnection()) return this.ownership;
    await this.acquireOwnership().catch(() => undefined);
    return this.ownership;
  }

  getSettings(): DesktopSettings {
    return this.settings.get();
  }

  /** Read-only view used by the main process before it creates the window. */
  getOnboarding(): DesktopOnboardingState {
    return this.machineState.readOnboarding();
  }

  /** Called from the complete page only; the entry itself never records completion. */
  completeOnboarding(input: { source?: unknown }): Promise<DesktopOnboardingState> {
    const source = input?.source;
    if (source !== "desktop" && source !== "dsh-plugin") throw new Error("Unsupported Desktop onboarding source.");
    return this.machineState.completeOnboarding(source as DesktopOnboardingSource);
  }

  saveSettings(patch: DesktopSettingsPatch): Promise<ConnectorState> {
    const previous = this.settings.get();
    const saved = this.settings.save(patch ?? {});
    return this.applyConnectorSettings(previous).then(
      (state) => {
        this.logs.updateSettings(() => this.settings.get());
        this.emit("settings", this.settings.get());
        return state;
      },
      async (error: unknown) => {
        this.settings.save(previous);
        try {
          await this.applyConnectorSettings(saved);
        } catch (rollbackError) {
          this.appendLog({ level: "ERROR", message: `Failed to restore Connector settings: ${errorMessage(rollbackError)}` });
        }
        this.logs.updateSettings(() => this.settings.get());
        this.emit("settings", this.settings.get());
        throw error;
      },
    );
  }

  getConnectorState(): Promise<ConnectorState> {
    // RPC getState starts a sidecar. Metadata reads must remain passive.
    return Promise.resolve(this.connector.publicState());
  }

  getPublicConfig() {
    return this.connector.getPublicConfig();
  }

  async saveConfig(patch: ConnectorConfigPatch): Promise<ConnectorState> {
    this.assertConnectionRequested();
    const signal = this.connectionEpoch.signal;
    return awaitConnectionOperation(this.mutateConnector(() => {
      this.assertLiveConnection(signal);
      return this.connector.saveConfig(patch ?? {});
    }), signal);
  }

  async startConnector(requestSignal?: AbortSignal): Promise<ConnectorState> {
    this.assertConnectionRequested();
    return this.connectionOperation(async signal => {
      await awaitConnectionOperation(this.requireOwnership(), signal);
      return this.activateConnector("start", signal);
    }, requestSignal);
  }

  stopConnector(): Promise<ConnectorState> {
    // Invalidate synchronously, before awaiting anything. Older provisioning
    // cannot start even when its cloud result arrives after this stop returns.
    this.cancelConnections();
    return this.mutateConnector(() => this.connector.stop());
  }

  async restartConnector(requestSignal?: AbortSignal): Promise<ConnectorState> {
    this.assertConnectionRequested();
    return this.connectionOperation(async signal => {
      await awaitConnectionOperation(this.requireOwnership(), signal);
      return this.activateConnector("restart", signal);
    }, requestSignal);
  }

  readLogs(query: ConnectorLogQuery): Promise<ConnectorLogPage> {
    return this.connector.readLogs(query ?? {});
  }

  async clearLogs(): Promise<ConnectorLogPage> {
    const page = await this.connector.clearLogs();
    this.emit("logsCleared", undefined);
    return page;
  }

  exportLogs(filePath: string): Promise<number> {
    return this.connector.exportLogs(filePath);
  }

  appendLog(entry: string | Partial<ConnectorLogEntry>): void {
    const stored = this.logs.append(entry);
    if (!this.connector?.hasRuntimeLogs()) this.bufferLog(stored);
  }

  getLocalBinding(): PublicLocalDesktopBinding | null {
    return this.devices.getLocalBinding();
  }

  createAndConnect(input: DesktopDeviceProvisionInput, requestSignal?: AbortSignal): Promise<PublicLocalDesktopBinding> {
    this.assertOrdinaryConnectionAllowed();
    return this.connectionOperation(signal => {
      this.explicitConnectionRequested = true;
      return this.devices.createAndConnect(input, signal);
    }, requestSignal);
  }

  reconnectAndConnect(input: DesktopDeviceReconnectInput, requestSignal?: AbortSignal): Promise<PublicLocalDesktopBinding> {
    this.assertOrdinaryConnectionAllowed();
    return this.connectionOperation(signal => {
      this.explicitConnectionRequested = true;
      return this.devices.reconnectAndConnect(input, signal);
    }, requestSignal);
  }

  disconnectLocal(input: DesktopDeviceAuthInput): Promise<PublicLocalDesktopBinding> {
    return this.devices.disconnectLocal(input);
  }

  revokeLocal(input: DesktopDeviceAuthInput): Promise<PublicLocalDesktopBinding> {
    return this.devices.revokeLocal(input);
  }

  updateLocalBindingName(name: DesktopDeviceNameInput["name"]): PublicLocalDesktopBinding {
    return this.devices.updateLocalBindingName(name ?? "");
  }

  /** Starts the Connector on launch when a credential is already present. */
  async startOwnedConnectorOnLaunch(): Promise<void> {
    if (this.init.scopedVerificationOnly) return;
    if (this.init.requireExplicitConnection) return;
    if (!this.settings.get().startConnectorOnLaunch) return;
    const signal = this.connectionEpoch.signal;
    const state = await awaitConnectionOperation(this.connector.getState(), signal);
    if (state.hasCredential && !state.manualDisconnected) await this.activateConnector("start", signal);
  }

  async shutdown(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.cancelConnections();
    this.logBatcher.dispose();
    await this.mutateConnector(() => this.connector.shutdown()).catch(() => undefined);
  }

  private cancelConnections(): void {
    const previous = this.connectionEpoch;
    this.connectionEpoch = new AbortController();
    this.explicitConnectionRequested = false;
    previous.abort();
  }

  private connectionOperation<T>(operation: (signal: AbortSignal) => Promise<T>, requestSignal?: AbortSignal): Promise<T> {
    if (this.closed || requestSignal?.aborted) return Promise.reject(new Error("Desktop connection cancelled."));
    const epoch = this.connectionEpoch;
    const signal = requestSignal ? AbortSignal.any([epoch.signal, requestSignal]) : epoch.signal;
    const abort = () => {
      if (this.connectionEpoch !== epoch) return;
      // The HTTP socket disappearing is a local cancellation event, even though
      // the outbound Main netFetch may still deliver a committed credential.
      void this.stopConnector().catch(() => this.reportStartupError("Could not stop the cancelled Desktop connection."));
    };
    signal.addEventListener("abort", abort, { once: true });
    return awaitConnectionOperation(operation(signal), signal).finally(() => signal.removeEventListener("abort", abort));
  }

  private mutateConnector<T>(operation: () => Promise<T>): Promise<T> {
    const pending = this.mutationTail.then(operation);
    this.mutationTail = pending.catch(() => undefined);
    return pending;
  }

  private assertLiveConnection(signal?: AbortSignal): void {
    if (this.closed || signal?.aborted) throw new Error("Desktop connection cancelled.");
    this.assertConnectionRequested();
  }

  private activateConnector(method: "start" | "restart", signal?: AbortSignal): Promise<ConnectorState> {
    return this.mutateConnector(() => {
      this.assertLiveConnection(signal);
      return this.connector[method]();
    });
  }

  private reportStartupError(message: string): void {
    this.appendLog({ level: "ERROR", message });
    if (this.closed) return;
    if (this.ownership.status === "owned") {
      this.connector.reportError(message);
      return;
    }
    // A conflict already explains itself; anything else would leave the gate on `checking`.
    if (this.ownership.status === "conflict") return;
    this.ownership = { status: "error", message };
    this.emit("ownership", this.ownership);
  }

  private async requireOwnership(): Promise<void> {
    if (this.closed) throw new Error("Desktop backend is shutting down.");
    this.assertConnectionRequested();
    await this.connector.acquireOwnership();
  }

  private awaitingExplicitConnection(): boolean {
    return Boolean(this.init.requireExplicitConnection && !this.explicitConnectionRequested);
  }

  private assertConnectionRequested(): void {
    this.assertOrdinaryConnectionAllowed();
    if (this.awaitingExplicitConnection()) {
      throw new Error("Create or reconnect this device explicitly before starting or configuring its Connector.");
    }
  }

  private assertOrdinaryConnectionAllowed(): void {
    if (this.init.scopedVerificationOnly) {
      throw new Error("Project verification mode only permits the locally scoped connection menu.");
    }
  }

  private applyConnectorSettings(previous: DesktopSettings): Promise<ConnectorState> {
    // Save launcher/mirror choices even if the environment does not exist yet.
    if (this.awaitingExplicitConnection()) return Promise.resolve(this.connector.bindingChanged());
    const signal = this.connectionEpoch.signal;
    return this.mutateConnector(() => {
      this.assertLiveConnection(signal);
      return this.connector.applySettings(previous);
    });
  }

  private acquireOwnership(): Promise<void> {
    return this.connector.acquireOwnership();
  }

  private recordInstallation(): Promise<void> {
    return this.machineState.recordInstallation(desktopInstallation({
      executablePath: this.init.desktopExecutablePath,
      appPath: this.init.desktopAppPath,
      packaged: this.init.packaged,
      platform: process.platform,
    }));
  }

  private emit(event: EventName, data: unknown): void {
    this.events.emit(event, data);
  }

  /**
   * The Connector can log many lines per second. Coalescing them keeps the SSE
   * frame rate bounded, so the renderer performs one state update per batch
   * instead of one per line.
   */
  private bufferLog(entry: ConnectorLogEntry): void {
    this.logBatcher.push(entry);
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
