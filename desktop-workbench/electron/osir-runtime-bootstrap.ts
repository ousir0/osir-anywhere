/**
 * Runtime setup ONLY after the caller has validated a Client handoff and its
 * explicit connection action. This module neither verifies nor grants consent.
 * Keep one coordinator per authenticated API context; discard it on sign-out.
 */
export type OsirBootstrapTool = "claude" | "codex" | "dsh";

/** Structural projections of dashboard DeviceRuntimeView / RuntimeTypeView.
 * Full dashboard DTOs are assignable without importing renderer-only modules.
 */
export type BootstrapRuntime = {
  connectorId: string;
  runtimeId: string;
  runtimeType: string;
  present: boolean;
  available?: boolean;
  configured: boolean;
  active: boolean;
  status: "stopped" | "discovering" | "available" | "unavailable" | "validating"
    | "starting" | "running" | "stopping" | "error" | "unknown";
};
export type BootstrapRuntimeType = {
  connectorId: string;
  runtimeType: string;
  present: boolean;
  available: boolean;
  schema: Record<string, unknown> | null;
};

export type OsirRuntimeBootstrapApi = {
  getRuntimes(connId: string): Promise<{ connectorId: string; runtimes: readonly BootstrapRuntime[] }>;
  getRuntimeTypes(connId: string): Promise<{ connectorId: string; runtimeTypes: readonly BootstrapRuntimeType[] }>;
  /** Matches createConnectorRuntime's payload; never forward discovery defaults. */
  createRuntime(connId: string, payload: {
    runtimeType: OsirBootstrapTool;
    name: string;
    config: Record<string, never>;
    active: false;
  }): Promise<BootstrapRuntime>;
  setActive(connId: string, runtimeId: string, active: true): Promise<BootstrapRuntime>;
  /** Local adapter, NOT a dashboard endpoint. Verify/use the Client-configured
   * bridge without changing an existing runtime's configuration. No paths,
   * credentials, model settings or arbitrary config cross this boundary.
   */
  configureDSH(connId: string): Promise<
    { status: "ready" } | { status: "blocked"; code: "dsh_bridge_unconfigured" }
  >;
};

type BlockedCode = "runtime_type_unavailable" | "runtime_unavailable"
  | "runtime_configuration_required" | "dsh_bridge_unconfigured"
  | "runtime_starting" | "runtime_not_ready";
type ErrorCode = "inventory_read_failed" | "invalid_runtime_response"
  | "dsh_configuration_failed" | "runtime_create_failed" | "runtime_start_failed";
export type OsirRuntimeBootstrapResult = { tool: OsirBootstrapTool; runtimeId?: string } & (
  { status: "ready"; code: "runtime_ready" }
  | { status: "blocked"; code: BlockedCode }
  | { status: "error"; code: ErrorCode }
);
export type OsirRuntimeBootstrapInput = {
  connId: string;
  /** Only tools confirmed configured and available by the Client. Selection is
   * not inferred from installed SDKs, server defaults, or an existing instance.
   */
  selectedAvailableToolTypes: readonly OsirBootstrapTool[];
};

const TOOLS: readonly OsirBootstrapTool[] = ["claude", "codex", "dsh"];
const NAMES: Record<OsirBootstrapTool, string> = { claude: "Claude", codex: "Codex", dsh: "DSH" };

export class OsirRuntimeBootstrap {
  private readonly flights = new Map<string, Promise<OsirRuntimeBootstrapResult[]>>();
  private readonly queues = new Map<string, Promise<void>>();

  constructor(private readonly api: OsirRuntimeBootstrapApi) {}

  /** Identical concurrent selections share a promise; overlapping selections
   * on one Connector serialize. A later call is an explicit retry, rereading
   * persisted inventory even if creation/start previously threw after saving.
   * No automatic retry of an uncertain mutation, no permanent success cache.
   * This is process-local coordination, not cross-process server idempotency.
   */
  run(input: OsirRuntimeBootstrapInput): Promise<OsirRuntimeBootstrapResult[]> {
    const connId = input.connId;
    if (!connId || connId.trim() !== connId) throw new Error("Invalid Connector identity.");
    if (input.selectedAvailableToolTypes.some(tool => !TOOLS.includes(tool))) {
      throw new Error("Unsupported bootstrap tool.");
    }
    const selected = TOOLS.filter(tool => input.selectedAvailableToolTypes.includes(tool));
    const key = JSON.stringify([connId, selected]);
    const current = this.flights.get(key);
    if (current) return current;
    const previous = this.queues.get(connId) ?? Promise.resolve();
    const work = previous.then(() => this.bootstrap(connId, selected)).finally(() => {
      if (this.flights.get(key) === work) this.flights.delete(key);
      if (this.queues.get(connId) === tail) this.queues.delete(connId);
    });
    const tail = work.then(() => {}, () => {});
    this.flights.set(key, work);
    this.queues.set(connId, tail);
    return work;
  }

  private async bootstrap(connId: string, tools: OsirBootstrapTool[]): Promise<OsirRuntimeBootstrapResult[]> {
    if (!tools.length) return [];
    let inventory;
    let types;
    try {
      [inventory, types] = await Promise.all([this.api.getRuntimes(connId), this.api.getRuntimeTypes(connId)]);
    } catch {
      return tools.map(tool => ({ tool, status: "error", code: "inventory_read_failed" }));
    }
    if (inventory.connectorId !== connId || types.connectorId !== connId) {
      return tools.map(tool => ({ tool, status: "error", code: "invalid_runtime_response" }));
    }
    const results: OsirRuntimeBootstrapResult[] = [];
    for (const tool of tools) {
      const type = types.runtimeTypes.find(item => item.connectorId === connId && item.runtimeType === tool);
      const instances = inventory.runtimes.filter(item => item.connectorId === connId && item.runtimeType === tool);
      results.push(await this.setupTool(connId, tool, type, instances));
    }
    return results;
  }

  private async setupTool(
    connId: string, tool: OsirBootstrapTool, type: BootstrapRuntimeType | undefined,
    instances: readonly BootstrapRuntime[],
  ): Promise<OsirRuntimeBootstrapResult> {
    if (!type) return { tool, status: "blocked", code: "runtime_type_unavailable" };
    if (tool === "dsh") {
      try {
        const bridge = await this.api.configureDSH(connId);
        if (bridge.status === "blocked" && bridge.code === "dsh_bridge_unconfigured") {
          return { tool, status: "blocked", code: "dsh_bridge_unconfigured" };
        }
        if (bridge.status !== "ready") throw new Error();
      } catch {
        return { tool, status: "error", code: "dsh_configuration_failed" };
      }
    }
    if (!type.present || !type.available) return { tool, status: "blocked", code: "runtime_type_unavailable" };

    // Prefer a usable configured instance, never rename it or rewrite config.
    const configured = instances.filter(item => item.configured);
    const usable = configured.filter(item => item.present && item.available !== false);
    let runtime = usable.find(item => item.active && item.status === "running")
      ?? usable.find(item => item.active && item.status === "starting")
      ?? usable[0] ?? configured[0] ?? instances[0];
    if (!runtime) {
      // Empty config lets the local provider resolve its own defaults. Do not
      // copy even "default" fields: they may contain homes, model keys or env.
      if (type.schema === null || (Array.isArray(type.schema.required) && type.schema.required.length > 0)) {
        return { tool, status: "blocked", code: "runtime_configuration_required" };
      }
      try {
        runtime = await this.api.createRuntime(connId, {
          runtimeType: tool, name: NAMES[tool], config: {}, active: false,
        });
      } catch {
        return { tool, status: "error", code: "runtime_create_failed" };
      }
    }
    if (!matches(runtime, connId, tool)) return { tool, status: "error", code: "invalid_runtime_response" };
    const runtimeId = runtime.runtimeId;
    if (!runtime.configured) return { tool, runtimeId, status: "blocked", code: "runtime_configuration_required" };
    if (!runtime.present || runtime.available === false || runtime.status === "unavailable") {
      return { tool, runtimeId, status: "blocked", code: "runtime_unavailable" };
    }
    if (!runtime.active || (runtime.status !== "running" && runtime.status !== "starting")) {
      try {
        runtime = await this.api.setActive(connId, runtimeId, true);
      } catch {
        return { tool, runtimeId, status: "error", code: "runtime_start_failed" };
      }
      if (!matches(runtime, connId, tool) || runtime.runtimeId !== runtimeId) {
        return { tool, status: "error", code: "invalid_runtime_response" };
      }
    }
    // Runtime Control 2.0: active is desired state, not a readiness guarantee.
    if (runtime.status === "error") return { tool, runtimeId, status: "error", code: "runtime_start_failed" };
    if (!runtime.configured) return { tool, runtimeId, status: "blocked", code: "runtime_configuration_required" };
    if (!runtime.present || runtime.available === false || runtime.status === "unavailable") {
      return { tool, runtimeId, status: "blocked", code: "runtime_unavailable" };
    }
    if (runtime.active && runtime.status === "running") return { tool, runtimeId, status: "ready", code: "runtime_ready" };
    return { tool, runtimeId, status: "blocked", code: runtime.active && runtime.status === "starting" ? "runtime_starting" : "runtime_not_ready" };
  }
}

function matches(runtime: BootstrapRuntime, connId: string, tool: OsirBootstrapTool): boolean {
  return runtime?.connectorId === connId && runtime.runtimeType === tool
    && (runtime.runtimeId === tool || /^rti_[A-Za-z0-9_-]+$/.test(runtime.runtimeId));
}
