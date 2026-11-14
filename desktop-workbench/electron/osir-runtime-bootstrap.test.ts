import assert from "node:assert/strict";
import { test } from "node:test";
import {
  OsirRuntimeBootstrap,
  type BootstrapRuntime,
  type BootstrapRuntimeType,
  type OsirBootstrapTool,
  type OsirRuntimeBootstrapApi,
} from "./osir-runtime-bootstrap";

const CONN = "conn_fixture";
const TOOLS: OsirBootstrapTool[] = ["claude", "codex", "dsh"];
const SECRET = "synthetic-model-key-never-forward";
type FixtureRuntime = BootstrapRuntime & { config: Record<string, unknown>; name: string };
const runtime = (tool: OsirBootstrapTool, patch: Partial<FixtureRuntime> = {}): FixtureRuntime => ({
  connectorId: CONN, runtimeId: `rti_${tool}`, runtimeType: tool, present: true,
  available: true, configured: true, active: false, status: "stopped",
  name: "User instance", config: { environment: { MODEL_KEY: SECRET }, home: "/fixture/private/home" },
  ...patch,
});
const descriptor = (tool: OsirBootstrapTool): BootstrapRuntimeType & { defaults: Record<string, unknown> } => ({
  connectorId: CONN, runtimeType: tool, present: true, available: true, schema: { type: "object" },
  defaults: { modelKey: SECRET, codexHome: "/fixture/private/home", model: "user-choice" },
});
function fixture() {
  const calls: { method: string; connId: string; runtimeId?: string; payload?: unknown }[] = [];
  const data = {
    instances: [] as FixtureRuntime[],
    types: TOOLS.map(descriptor),
    bridgeConfigured: true,
  };
  const api: OsirRuntimeBootstrapApi = {
    getRuntimes: async connId => {
      calls.push({ method: "getRuntimes", connId });
      return { connectorId: connId, runtimes: data.instances.map(item => ({ ...item })) };
    },
    getRuntimeTypes: async connId => {
      calls.push({ method: "getRuntimeTypes", connId });
      return { connectorId: connId, runtimeTypes: data.types };
    },
    createRuntime: async (connId, payload) => {
      calls.push({ method: "createRuntime", connId, payload });
      const item = runtime(payload.runtimeType, { connectorId: connId, name: payload.name, config: payload.config });
      data.instances.push(item);
      return { ...item };
    },
    setActive: async (connId, runtimeId, active) => {
      calls.push({ method: "setActive", connId, runtimeId, payload: { active } });
      const item = data.instances.find(item => item.connectorId === connId && item.runtimeId === runtimeId)!;
      item.active = active;
      item.status = "running";
      return { ...item };
    },
    configureDSH: async connId => {
      calls.push({ method: "configureDSH", connId });
      return data.bridgeConfigured ? { status: "ready" } : { status: "blocked", code: "dsh_bridge_unconfigured" };
    },
  };
  const bootstrap = new OsirRuntimeBootstrap(api);
  const run = (tools: readonly OsirBootstrapTool[] = TOOLS, connId = CONN) => bootstrap.run({ connId, selectedAvailableToolTypes: tools });
  const mutations = () => calls.filter(call => call.method === "createRuntime" || call.method === "setActive");
  return { data, api, bootstrap, calls, run, mutations };
}
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

test("creates each selected tool inactive, then enables it; sends only fixed public defaults", async () => {
  const f = fixture();
  const results = await f.run();
  assert.deepEqual(results, TOOLS.map(tool => ({ tool, runtimeId: `rti_${tool}`, status: "ready", code: "runtime_ready" })));
  assert.deepEqual(f.mutations(), TOOLS.flatMap(tool => [
    { method: "createRuntime", connId: CONN, payload: { runtimeType: tool, name: { claude: "Claude", codex: "Codex", dsh: "DSH" }[tool], config: {}, active: false } },
    { method: "setActive", connId: CONN, runtimeId: `rti_${tool}`, payload: { active: true } },
  ]));
  assert.equal(f.calls.findIndex(call => call.method === "configureDSH") < f.calls.findIndex(call => call.method === "createRuntime" && (call.payload as { runtimeType: string }).runtimeType === "dsh"), true);
  assert.equal(JSON.stringify(f.calls).includes(SECRET), false);
  assert.equal(JSON.stringify(f.calls).includes("/fixture"), false);
  assert.equal(JSON.stringify(results).includes(SECRET), false);
});

test("repeat calls reread inventory without recreating or restarting running instances", async () => {
  const f = fixture();
  await f.run();
  const mutations = f.mutations().length;
  assert.equal((await f.run()).every(result => result.status === "ready"), true);
  assert.equal(f.mutations().length, mutations);
  assert.equal(f.calls.filter(call => call.method === "getRuntimes").length, 2);
});

test("prefers existing configured running instances and preserves user config/name", async () => {
  const f = fixture();
  f.data.instances = [
    runtime("codex", { runtimeId: "rti_empty", configured: false }),
    runtime("codex", { runtimeId: "rti_stopped" }),
    runtime("codex", { runtimeId: "rti_ready", active: true, status: "running" }),
  ];
  const before = structuredClone(f.data.instances);
  assert.deepEqual(await f.run(["codex"]), [{ tool: "codex", runtimeId: "rti_ready", status: "ready", code: "runtime_ready" }]);
  assert.deepEqual(f.mutations(), []);
  assert.deepEqual(f.data.instances, before);
});

test("enables the configured instance rather than duplicating or overwriting it", async () => {
  const f = fixture();
  f.data.instances = [runtime("claude", { configured: false, runtimeId: "rti_empty" }), runtime("claude")];
  const config = structuredClone(f.data.instances[1].config);
  assert.equal((await f.run(["claude"]))[0].status, "ready");
  assert.deepEqual(f.mutations().map(call => call.method), ["setActive"]);
  assert.deepEqual(f.data.instances[1].config, config);
  assert.equal(f.data.instances[1].name, "User instance");
});

test("unconfigured existing instance blocks without a duplicate or enable request", async () => {
  const f = fixture();
  f.data.instances = [runtime("claude", { configured: false })];
  assert.deepEqual(await f.run(["claude"]), [{ tool: "claude", runtimeId: "rti_claude", status: "blocked", code: "runtime_configuration_required" }]);
  assert.deepEqual(f.mutations(), []);
});

test("only selected Client-configured tools are touched; empty selection is passive", async () => {
  const f = fixture();
  assert.deepEqual(await f.run([]), []);
  assert.equal(f.calls.length, 0);
  await f.run(["codex", "codex"]);
  assert.deepEqual(f.mutations().map(call => call.method), ["createRuntime", "setActive"]);
  assert.equal(f.calls.some(call => call.method === "configureDSH"), false);
});

for (const unavailable of ["missing", "absent", "unavailable", "schema", "required"] as const) {
  test(`${unavailable} type cannot create a runtime from unsafe/incomplete defaults`, async () => {
    const f = fixture();
    const type = f.data.types[0];
    if (unavailable === "missing") f.data.types = [];
    if (unavailable === "absent") type.present = false;
    if (unavailable === "unavailable") type.available = false;
    if (unavailable === "schema") type.schema = null;
    if (unavailable === "required") type.schema = { required: ["home"] };
    const result = (await f.run(["claude"]))[0];
    assert.equal(result.status, "blocked");
    assert.equal(result.code, ["schema", "required"].includes(unavailable) ? "runtime_configuration_required" : "runtime_type_unavailable");
    assert.deepEqual(f.mutations(), []);
  });
}

test("an unavailable configured instance is not enabled or replaced", async () => {
  const f = fixture();
  f.data.instances = [runtime("codex", { available: false })];
  assert.equal((await f.run(["codex"]))[0].code, "runtime_unavailable");
  assert.deepEqual(f.mutations(), []);
});

for (const saved of [false, true]) {
  test(`DSH without Client bridge is blocked even with ${saved ? "an active saved instance" : "no instance"}`, async () => {
    const f = fixture();
    f.data.bridgeConfigured = false;
    f.data.types[2].available = false;
    if (saved) f.data.instances = [runtime("dsh", { active: true, status: "running" })];
    assert.deepEqual(await f.run(["dsh"]), [{ tool: "dsh", status: "blocked", code: "dsh_bridge_unconfigured" }]);
    assert.deepEqual(f.mutations(), []);
    f.data.bridgeConfigured = true;
    f.data.types[2].available = true;
    assert.equal((await f.run(["dsh"]))[0].status, "ready");
  });
}

test("DSH local adapter failure is fixed-code, isolated from other tools, and retryable", async t => {
  const f = fixture();
  const original = f.api.configureDSH;
  const mock = t.mock.method(f.api, "configureDSH", async () => { throw new Error(SECRET); });
  assert.deepEqual((await f.run()).map(result => [result.status, result.code]), [
    ["ready", "runtime_ready"], ["ready", "runtime_ready"], ["error", "dsh_configuration_failed"],
  ]);
  mock.mock.restore();
  f.api.configureDSH = original;
  assert.equal((await f.run(["dsh"]))[0].status, "ready");
});

for (const method of ["getRuntimes", "getRuntimeTypes"] as const) {
  test(`${method} failure does not mutate and a later explicit call retries`, async t => {
    const f = fixture();
    const mock = t.mock.method(f.api, method, async () => { throw new Error(SECRET); });
    const results = await f.run();
    assert.equal(results.every(result => result.status === "error" && result.code === "inventory_read_failed"), true);
    assert.equal(JSON.stringify(results).includes(SECRET), false);
    assert.deepEqual(f.mutations(), []);
    mock.mock.restore();
    assert.equal((await f.run()).every(result => result.status === "ready"), true);
  });
}

test("creation persisted before error: explicit retry reuses it instead of creating twice", async t => {
  const f = fixture();
  const create = f.api.createRuntime;
  const mock = t.mock.method(f.api, "createRuntime", async (...args: Parameters<typeof create>) => {
    await create(...args);
    throw new Error(SECRET);
  });
  assert.deepEqual(await f.run(["codex"]), [{ tool: "codex", status: "error", code: "runtime_create_failed" }]);
  mock.mock.restore();
  assert.equal((await f.run(["codex"]))[0].status, "ready");
  assert.deepEqual(f.mutations().map(call => call.method), ["createRuntime", "setActive"]);
});

test("activation error can retry without duplicate creation or config updates", async t => {
  const f = fixture();
  const mock = t.mock.method(f.api, "setActive", async () => { throw new Error(SECRET); });
  assert.deepEqual(await f.run(["claude"]), [{ tool: "claude", runtimeId: "rti_claude", status: "error", code: "runtime_start_failed" }]);
  mock.mock.restore();
  assert.equal((await f.run(["claude"]))[0].status, "ready");
  assert.equal(f.mutations().filter(call => call.method === "createRuntime").length, 1);
});

test("activation persisted before error: retry observes running state without another start", async t => {
  const f = fixture();
  const start = f.api.setActive;
  const mock = t.mock.method(f.api, "setActive", async (...args: Parameters<typeof start>) => {
    await start(...args);
    throw new Error(SECRET);
  });
  assert.equal((await f.run(["codex"]))[0].code, "runtime_start_failed");
  mock.mock.restore();
  assert.equal((await f.run(["codex"]))[0].status, "ready");
  assert.deepEqual(f.mutations().map(call => call.method), ["createRuntime", "setActive"]);
});

test("active starting state is blocked until observed running; never restarted while starting", async () => {
  const f = fixture();
  f.data.instances = [runtime("codex", { active: true, status: "starting" })];
  assert.equal((await f.run(["codex"]))[0].code, "runtime_starting");
  assert.deepEqual(f.mutations(), []);
  f.data.instances[0].status = "running";
  assert.equal((await f.run(["codex"]))[0].status, "ready");
});

for (const status of ["starting", "error", "stopped", "unavailable"] as const) {
  test(`active=true with ${status} response never reports ready`, async t => {
    const f = fixture();
    f.data.instances = [runtime("claude")];
    t.mock.method(f.api, "setActive", async () => runtime("claude", { active: true, status }));
    const result = (await f.run(["claude"]))[0];
    assert.equal(result.code, { starting: "runtime_starting", error: "runtime_start_failed", stopped: "runtime_not_ready", unavailable: "runtime_unavailable" }[status]);
    assert.notEqual(result.status, "ready");
  });
}

test("identical concurrent selections, including reorder/duplicates, share one promise", async t => {
  const f = fixture();
  const gate = deferred();
  const entered = deferred();
  const create = f.api.createRuntime;
  t.mock.method(f.api, "createRuntime", async (...args: Parameters<typeof create>) => {
    entered.resolve(); await gate.promise; return create(...args);
  });
  const first = f.run(["codex", "claude"]);
  const second = f.run(["claude", "codex", "codex"]);
  assert.equal(first, second);
  await entered.promise;
  gate.resolve();
  assert.equal((await first).every(result => result.status === "ready"), true);
  assert.equal(f.mutations().filter(call => call.method === "createRuntime").length, 2);
});

test("overlapping selections serialize per Connector and reread before adding tools", async t => {
  const f = fixture();
  const gate = deferred();
  const entered = deferred();
  const create = f.api.createRuntime;
  t.mock.method(f.api, "createRuntime", async (...args: Parameters<typeof create>) => {
    entered.resolve(); await gate.promise; return create(...args);
  });
  const first = f.run(["codex"]);
  await entered.promise;
  const second = f.run(["codex", "dsh"]);
  await Promise.resolve();
  assert.equal(f.calls.filter(call => call.method === "getRuntimes").length, 1);
  gate.resolve();
  await Promise.all([first, second]);
  assert.deepEqual(f.mutations().filter(call => call.method === "createRuntime").map(call => (call.payload as { runtimeType: string }).runtimeType), ["codex", "dsh"]);
});

test("a failed concurrent flight clears so a later explicit call can retry", async t => {
  const f = fixture();
  const gate = deferred();
  const mock = t.mock.method(f.api, "createRuntime", async () => { await gate.promise; throw new Error(SECRET); });
  const first = f.run(["codex"]);
  assert.equal(first, f.run(["codex"]));
  gate.resolve();
  assert.equal((await first)[0].code, "runtime_create_failed");
  mock.mock.restore();
  assert.equal((await f.run(["codex"]))[0].status, "ready");
});

test("foreign inventory cannot authorize mutations on another Connector", async t => {
  const f = fixture();
  t.mock.method(f.api, "getRuntimes", async () => ({ connectorId: "conn_other", runtimes: [] }));
  assert.equal((await f.run(["codex"]))[0].code, "invalid_runtime_response");
  assert.deepEqual(f.mutations(), []);
});

test("foreign type and instance rows are ignored", async () => {
  const f = fixture();
  f.data.types[1].connectorId = "conn_other";
  f.data.instances = [runtime("codex", { connectorId: "conn_other" })];
  assert.equal((await f.run(["codex"]))[0].code, "runtime_type_unavailable");
  assert.deepEqual(f.mutations(), []);
});

for (const method of ["createRuntime", "setActive"] as const) {
  test(`${method} response with a different identity is rejected`, async t => {
    const f = fixture();
    if (method === "setActive") f.data.instances = [runtime("codex")];
    t.mock.method(f.api, method, async () => runtime("codex", { runtimeId: "rti_other", connectorId: "conn_other", active: true, status: "running" }));
    assert.deepEqual(await f.run(["codex"]), [{ tool: "codex", status: "error", code: "invalid_runtime_response" }]);
    if (method === "createRuntime") assert.equal(f.mutations().some(call => call.method === "setActive"), false);
  });
}

test("activation must acknowledge the exact requested instance, not a sibling", async t => {
  const f = fixture();
  f.data.instances = [runtime("codex")];
  t.mock.method(f.api, "setActive", async () => runtime("codex", { runtimeId: "rti_sibling", active: true, status: "running" }));
  assert.deepEqual(await f.run(["codex"]), [{ tool: "codex", status: "error", code: "invalid_runtime_response" }]);
});

test("creation returning an unconfigured instance never proceeds to activation", async t => {
  const f = fixture();
  t.mock.method(f.api, "createRuntime", async () => runtime("codex", { configured: false }));
  assert.equal((await f.run(["codex"]))[0].code, "runtime_configuration_required");
  assert.equal(f.calls.some(call => call.method === "setActive"), false);
});

test("activation returning running but unconfigured or inactive cannot be ready", async t => {
  const f = fixture();
  f.data.instances = [runtime("codex")];
  const mock = t.mock.method(f.api, "setActive", async () => runtime("codex", { configured: false, active: true, status: "running" }));
  assert.equal((await f.run(["codex"]))[0].code, "runtime_configuration_required");
  mock.mock.restore();
  t.mock.method(f.api, "setActive", async () => runtime("codex", { active: false, status: "running" }));
  assert.equal((await f.run(["codex"]))[0].code, "runtime_not_ready");
});

test("an errored active instance is explicitly enabled again, not considered ready", async () => {
  const f = fixture();
  f.data.instances = [runtime("codex", { active: true, status: "error" })];
  assert.equal((await f.run(["codex"]))[0].status, "ready");
  assert.deepEqual(f.mutations().map(call => call.method), ["setActive"]);
});

test("independent Connectors do not wait for each other's flights", async t => {
  const f = fixture();
  const gate = deferred();
  const entered = deferred();
  const getRuntimes = f.api.getRuntimes;
  t.mock.method(f.api, "getRuntimes", async (connId: string) => {
    if (connId === CONN) { entered.resolve(); await gate.promise; }
    return getRuntimes(connId);
  });
  const first = f.run(["codex"]);
  await entered.promise;
  // Missing types for the second Connector should return immediately, while
  // the first is still waiting for its inventory.
  assert.equal((await f.run(["claude"], "conn_independent"))[0].code, "runtime_type_unavailable");
  gate.resolve();
  assert.equal((await first)[0].status, "ready");
});

test("invalid identities/tools fail before any dependency is called", () => {
  const f = fixture();
  assert.throws(() => f.run(["codex"], " "), /Invalid Connector identity/);
  assert.throws(() => f.run(["other" as OsirBootstrapTool]), /Unsupported bootstrap tool/);
  assert.deepEqual(f.calls, []);
});
