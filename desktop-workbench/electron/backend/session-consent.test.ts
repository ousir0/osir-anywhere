import assert from "node:assert/strict";
import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";
import type { ConnectorChannel } from "../connector-supervisor";
import { ConnectorRpcError } from "../connector-rpc-error";
import type { OwnershipState } from "../local-runtime";
import * as shellEnvironment from "../shell-environment";
import { BACKEND_TOKEN_HEADER, type BackendInit } from "./protocol";
import { BackendServer } from "./server";
import { BackendState, type BackendFetcher } from "./state";

const credential = { serverUrl: "https://server.example.test", connectorId: "saved-device", connectorToken: "test-credential" };
const account = { userId: "test-user", userToken: "test-session" };

/** Real Backend + stores + Supervisor + device service; only transport is synthetic. */
function fixture(t: TestContext, options: {
  explicit?: boolean;
  saved?: boolean;
  missingLauncher?: boolean;
  scopedVerificationOnly?: boolean;
  fetcher?: BackendFetcher;
} = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "desktop-idle-consent-"));
  const init: BackendInit = {
    dataPath: root, connectorDataRoot: root, logsPath: path.join(root, "logs"),
    settingsPath: path.join(root, "settings.json"), bindingPath: path.join(root, "binding.json"),
    configPath: path.join(root, "connector.json"), connectorDir: path.join(root, "source"),
    resourcesPath: root, uvBundleDir: path.join(root, "uv"), pythonBundleDir: path.join(root, "python"),
    homePath: root, documentsPath: root, packaged: false,
    ...(options.explicit === false ? {} : { requireExplicitConnection: true }),
    ...(options.scopedVerificationOnly === undefined ? {} : { scopedVerificationOnly: options.scopedVerificationOnly }),
    preferredLanguages: ["en-US"], defaultServerUrl: credential.serverUrl, apiNamespace: "/api/v2",
    desktopExecutablePath: process.execPath, desktopAppPath: root,
  };
  fs.mkdirSync(init.connectorDir);
  if (!options.missingLauncher) fs.writeFileSync(path.join(init.connectorDir, "pyproject.toml"), "");
  fs.writeFileSync(init.settingsPath, JSON.stringify({ uvPath: process.execPath, startConnectorOnLaunch: true }));
  if (options.saved) {
    fs.writeFileSync(init.configPath, JSON.stringify(credential));
    fs.writeFileSync(init.bindingPath, JSON.stringify({
      connectorId: credential.connectorId, serverUrl: credential.serverUrl,
      ownerUserId: account.userId, name: "Test Desktop", manualDisconnected: false,
    }));
  }
  t.mock.method(shellEnvironment, "readShellEnvironment", async () => ({ UV_PROJECT_ENVIRONMENT: path.join(root, ".venv") }));
  // Never inherit a developer's direct CLI, including in environment-reset tests.
  const directCli = process.env.WORKBENCH_CONNECTOR_CLI;
  delete process.env.WORKBENCH_CONNECTOR_CLI;
  const calls: string[] = [];
  let allowSpawn = false;
  let conflict = false;
  let running = false;
  const runtimeState = () => ({ running, authFailed: false, status: running ? "online" : "stopped" });
  const stayOpen = async function* (_since: number | null, input?: { signal?: AbortSignal }) {
    await new Promise<void>(resolve => {
      if (input?.signal?.aborted) resolve();
      else input?.signal?.addEventListener("abort", () => resolve(), { once: true });
    });
  };
  const channel: ConnectorChannel = {
    control: {
      getState: async () => { calls.push("rpc:getState"); return runtimeState(); },
      acquireOwnership: async () => {
        calls.push("rpc:acquire");
        if (conflict) throw { code: "connector_already_running", details: { owner: { kind: "cli", pid: 1234 } } };
        return runtimeState();
      },
      saveConfig: async config => { calls.push("rpc:saveConfig"); return config; },
      start: async () => { calls.push("rpc:start"); running = true; return runtimeState(); },
      restart: async () => { calls.push("rpc:restart"); running = true; return runtimeState(); },
      stop: async () => { calls.push("rpc:stop"); running = false; return runtimeState(); },
      events: stayOpen,
    },
    logs: {
      tail: (_since, _source, input) => stayOpen(null, input),
      read: async () => ({ items: [], firstSeq: null, lastSeq: null, total: 0, hasMoreBefore: false, hasMoreAfter: false }),
      clear: async () => ({ items: [], firstSeq: null, lastSeq: null, total: 0, hasMoreBefore: false, hasMoreAfter: false }),
    },
  };
  // A harmless Node stdio fixture stands in for the sidecar; no Python or server.
  const script = path.join(root, "sidecar.cjs");
  fs.writeFileSync(script, `
process.stdout.write(JSON.stringify({ kind: 'connector.ready', version: 1, instanceId: 'test', pid: process.pid, endpoint: { unixPath: '/nonexistent/test.sock' }, key: 'mk_host_test' }) + '\\n');
process.stdin.resume();
process.stdin.on('end', () => process.exit(0));
`);
  const spawn = childProcess.spawn;
  t.mock.method(childProcess, "spawn", (command: string, args: readonly string[], spawnOptions: childProcess.SpawnOptions) => {
    if (command === "taskkill.exe") return spawn(command, args, spawnOptions);
    calls.push("sidecar:spawn");
    assert.equal(allowSpawn, true, "passive Backend calls must not spawn a Connector sidecar");
    assert.equal(command, process.execPath);
    assert.equal(args.includes("rpc"), true);
    return spawn(process.execPath, [script], spawnOptions);
  });
  const state = new BackendState(init, async (url, request) => {
    calls.push(`http:${request?.method}`);
    if (options.fetcher) return options.fetcher(url, request);
    return Response.json(request?.method === "GET"
      ? { connectors: [] }
      : { connector: { id: "new-device", name: "Test Desktop" }, connectorToken: "new-test-credential" });
  }, async () => channel);
  const ownership: OwnershipState[] = [];
  state.on("ownership", value => ownership.push(value as OwnershipState));
  t.after(async () => {
    await state.shutdown();
    if (directCli === undefined) delete process.env.WORKBENCH_CONNECTOR_CLI;
    else process.env.WORKBENCH_CONNECTOR_CLI = directCli;
    fs.rmSync(root, { recursive: true, force: true });
  });
  return { state, init, root, calls, ownership, control: channel.control,
    permitSidecar: () => { allowSpawn = true; },
    setConflict: (value: boolean) => { conflict = value; },
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(r => { resolve = r; });
  return { promise, resolve };
}
const nextTurn = () => new Promise<void>(resolve => setImmediate(resolve));

for (const action of ["createAndConnect", "reconnectAndConnect"] as const) {
  test(`${action}: stop returns before cloud provisioning settles and its late success never starts`, { timeout: 15_000 }, async t => {
    const posted = deferred<void>(), response = deferred<Response>();
    const f = fixture(t, { saved: action === "reconnectAndConnect", fetcher: async (_url, request) => {
      // Like Main netFetch IPC: deliberately ignore any AbortSignal.
      if (request?.method === "GET") return Response.json({ connectors: [] });
      posted.resolve(); return response.promise;
    } });
    if (action === "reconnectAndConnect") fs.unlinkSync(f.init.configPath);
    f.permitSidecar();
    const pending = f.state[action]({ ...account, name: "Test Desktop" });
    const rejected = assert.rejects(pending, /cancelled/);
    await posted.promise;
    // Main's logout calls this exact loopback route; no second stop is needed.
    const server = new BackendServer(f.state), { port, token } = await server.start();
    t.after(() => server.close());
    const stopResponse = await fetch(`http://127.0.0.1:${port}/stop`, {
      method: "POST", headers: { [BACKEND_TOKEN_HEADER]: token },
    });
    assert.equal(stopResponse.status, 200);
    const stopped = await stopResponse.json() as { running: boolean };
    await rejected;
    assert.equal(stopped.running, false);
    await assert.rejects(f.state.startConnector(), /Create or reconnect/);
    await assert.rejects(f.state[action](account), /still settling/, "uncertain cloud write prevents duplicate create/rotation");
    response.resolve(Response.json({ connector: { id: action === "reconnectAndConnect" ? credential.connectorId : "new-device", name: "Test Desktop" }, connectorToken: "late-credential" }));
    await nextTurn();
    assert.equal(f.calls.some(call => /rpc:(start|restart)/.test(call)), false);
    assert.equal((await f.state.getConnectorState()).running, false);
    assert.equal(f.state.getLocalBinding()?.manualDisconnected, true);
    assert.equal(f.state.getLocalBinding()?.hasCredential, true, "keep the one-time credential for explicit recovery");
    const requests = f.calls.filter(call => call.startsWith("http:"));
    await f.state.reconnectAndConnect(account);
    assert.deepEqual(f.calls.filter(call => call.startsWith("http:")), requests, "explicit recovery reuses the saved device without another cloud POST");
    assert.equal((await f.state.getConnectorState()).running, true);
  });
}

test("stop during ownership acquisition cancels promptly and a late owner cannot provision", { timeout: 15_000 }, async t => {
  const f = fixture(t);
  const acquired = deferred<void>(), release = deferred<void>();
  const original = f.control.acquireOwnership.bind(f.control);
  t.mock.method(f.control, "acquireOwnership", async () => { acquired.resolve(); await release.promise; return original(); });
  f.permitSidecar();
  const rejected = assert.rejects(f.state.createAndConnect(account), /cancelled/);
  await acquired.promise;
  await f.state.stopConnector();
  await rejected;
  release.resolve(); await nextTurn();
  assert.equal(f.calls.some(call => /http:|rpc:(start|restart)/.test(call)), false);
  assert.equal((await f.state.getConnectorState()).running, false);
  await assert.rejects(f.state.restartConnector(), /Create or reconnect/);
});

test("cancellation during the device list releases the caller and never sends a later create POST", { timeout: 15_000 }, async t => {
  const requested = deferred<void>(), response = deferred<Response>();
  const f = fixture(t, { fetcher: async () => { requested.resolve(); return response.promise; } });
  f.permitSidecar();
  const signal = new AbortController();
  const rejected = assert.rejects(f.state.createAndConnect({ ...account, name: "Test Desktop" }, signal.signal), /cancelled/);
  await requested.promise; signal.abort(); await rejected;
  await f.state.stopConnector();
  response.resolve(Response.json({ connectors: [] })); await nextTurn();
  assert.deepEqual(f.calls.filter(call => call.startsWith("http:")), ["http:GET"]);
  assert.equal(f.calls.some(call => /rpc:(start|restart)/.test(call)), false);
});

for (const method of ["start", "restart"] as const) test(`stop fences an already-issued local ${method}, then remains stopped after its late completion`, { timeout: 15_000 }, async t => {
  const f = fixture(t, { saved: true });
  const started = deferred<void>(), release = deferred<void>();
  const original = f.control[method].bind(f.control);
  t.mock.method(f.control, method, async (config: unknown, options?: { timeoutMs?: number }) => {
    started.resolve(); await release.promise; return original(config, options);
  });
  f.permitSidecar();
  const rejected = assert.rejects(method === "start" ? f.state.createAndConnect(account) : f.state.reconnectAndConnect(account), /cancelled/);
  await started.promise;
  let stopReturned = false;
  const stop = f.state.stopConnector().then(value => { stopReturned = true; return value; });
  await rejected; await nextTurn();
  assert.equal(stopReturned, false, "stop must fence the already-issued activation, but the cancelled caller is released");
  release.resolve();
  assert.equal((await stop).running, false);
  await nextTurn();
  assert.equal((await f.state.getConnectorState()).running, false);
  assert.deepEqual(f.calls.filter(call => /rpc:(start|stop|restart)/.test(call)), [`rpc:${method}`, "rpc:stop"]);
});

test("cancelled reconnect 404 cannot fall through to replacement provisioning", { timeout: 15_000 }, async t => {
  const posted = deferred<void>(), response = deferred<Response>();
  const f = fixture(t, { saved: true, fetcher: async () => { posted.resolve(); return response.promise; } });
  fs.unlinkSync(f.init.configPath); f.permitSidecar();
  const rejected = assert.rejects(f.state.reconnectAndConnect(account), /cancelled/);
  await posted.promise; await f.state.stopConnector(); await rejected;
  response.resolve(Response.json({ detail: "deleted" }, { status: 404 })); await nextTurn();
  assert.deepEqual(f.calls.filter(call => call.startsWith("http:")), ["http:POST"]);
  assert.equal(f.calls.some(call => /rpc:(start|restart)/.test(call)), false);
});

test("aborting a real loopback POST cancels Backend consent despite an uncancellable Main netFetch", { timeout: 15_000 }, async t => {
  const posted = deferred<void>(), response = deferred<Response>(), stopped = deferred<void>();
  const f = fixture(t, { fetcher: async (_url, request) => {
    if (request?.method === "GET") return Response.json({ connectors: [] });
    posted.resolve(); return response.promise;
  } });
  const originalStop = f.control.stop.bind(f.control);
  t.mock.method(f.control, "stop", async (...args: Parameters<typeof originalStop>) => {
    const result = await originalStop(...args); stopped.resolve(); return result;
  });
  f.permitSidecar();
  const server = new BackendServer(f.state), { port, token } = await server.start();
  t.after(() => server.close());
  const base = `http://127.0.0.1:${port}`, headers = { [BACKEND_TOKEN_HEADER]: token, "content-type": "application/json" };
  const controller = new AbortController();
  const rejected = assert.rejects(fetch(`${base}/device/create`, { method: "POST", headers,
    body: JSON.stringify({ ...account, name: "Test Desktop" }), signal: controller.signal }), { name: "AbortError" });
  await posted.promise; controller.abort(); await rejected; await stopped.promise;
  assert.equal((await f.state.getConnectorState()).running, false);
  await assert.rejects(f.state.startConnector(), /Create or reconnect/);
  response.resolve(Response.json({ connector: { id: "new-device" }, connectorToken: "late-credential" })); await nextTurn();
  assert.equal(f.calls.some(call => /rpc:(start|restart)/.test(call)), false);
  assert.equal(f.state.getLocalBinding()?.hasCredential, true);
  assert.equal(f.state.getLocalBinding()?.manualDisconnected, true);
  const recovered = await fetch(`${base}/device/reconnect`, { method: "POST", headers, body: JSON.stringify(account) });
  assert.equal(recovered.status, 200); await recovered.json(); await nextTurn();
  assert.equal((await f.state.getConnectorState()).running, true, "a normal response close must not cancel a successful connection");
  assert.deepEqual(f.calls.filter(call => call.startsWith("http:")), ["http:GET", "http:POST"]);
});

for (const saved of [false, true]) {
  test(`real explicit Backend initialization and metadata stay idle (${saved ? "saved credentials" : "fresh install"})`, async t => {
    const { state, init, calls, ownership } = fixture(t, { saved });
    assert.deepEqual(state.ownershipState(), { status: "idle" });
    assert.equal((await state.getConnectorState()).running, false);
    await state.initialize();
    await state.initialize();
    state.setServerConnection({ serverUrl: "https://login.example.test", apiNamespace: "/api/v2" });
    const metadata = await state.getConnectorState();
    assert.equal(metadata.running, false);
    assert.equal(metadata.hasCredential, saved);
    assert.equal(state.getPublicConfig().hasCredential, saved);
    assert.equal(Boolean(state.getLocalBinding()), saved);
    assert.deepEqual(await state.acquireOwnershipOrThrow(), { status: "idle" }, "OAuth's ownership request stays idle");
    assert.deepEqual(await state.recheckOwnership(), { status: "idle" });
    await state.startOwnedConnectorOnLaunch();
    assert.deepEqual(calls, []);
    assert.deepEqual(ownership, [], "idle must never be reported as owned");
    const record = JSON.parse(fs.readFileSync(path.join(init.connectorDataRoot!, "connector-runtime.json"), "utf8"));
    assert.equal(record.runtime, undefined, "installation metadata does not claim runtime ownership");
    assert.equal(record.desktop.executablePath, fs.realpathSync(process.execPath));
  });
}

test("real idle Backend settings, environment reset and config reads cannot grant a remote start", async t => {
  const { state, init, calls } = fixture(t, { saved: true, missingLauncher: true });
  await state.initialize();
  const original = fs.readFileSync(init.configPath, "utf8");
  const updated = await state.saveSettings({
    uvPath: path.join(init.dataPath, "future-uv"), pythonPath: path.join(init.dataPath, "future-python"),
    uvPypiIndexUrl: "https://mirror.example.test/simple", uvPythonInstallMirror: "https://mirror.example.test/python",
    startConnectorOnLaunch: true, logRetentionDays: 30,
  });
  assert.equal(updated.uvPypiIndexUrl, "https://mirror.example.test/simple");
  assert.equal(updated.setupIssue, "connectorSourceMissing", "missing setup must remain visible");
  assert.equal(state.getSettings().logRetentionDays, 30);
  await state.resetConnectorEnvironment();
  assert.equal((await state.getConnectorState()).running, false);
  assert.equal(state.getPublicConfig().hasCredential, true);
  assert.deepEqual(await state.recheckOwnership(), { status: "idle" });
  await assert.rejects(state.startConnector(), /Create or reconnect/);
  await assert.rejects(state.restartConnector(), /Create or reconnect/);
  await assert.rejects(state.saveConfig({ heartbeatSeconds: 42 }), /Create or reconnect/);
  await state.stopConnector();
  assert.equal(fs.readFileSync(init.configPath, "utf8"), original);
  assert.deepEqual(calls, []);
});

test("explicit create acquires ownership before device HTTP or runtime start", { timeout: 15_000 }, async t => {
  const f = fixture(t);
  await f.state.initialize();
  assert.deepEqual(f.calls, []);
  f.permitSidecar();
  const binding = await f.state.createAndConnect({ ...account, name: "Test Desktop" });
  assert.equal(binding.connectorId, "new-device");
  assert.deepEqual(f.calls, ["sidecar:spawn", "rpc:acquire", "rpc:acquire", "http:GET", "http:POST", "rpc:acquire", "rpc:saveConfig", "rpc:start"]);
  assert.equal(f.state.ownershipState().status, "owned");
  const before = [...f.calls];
  assert.equal((await f.state.getConnectorState()).running, true);
  assert.deepEqual(f.calls, before, "metadata reads do not issue RPC even after connecting");
});

test("explicit reconnect with saved credentials acquires ownership and then restarts without device HTTP", { timeout: 15_000 }, async t => {
  const f = fixture(t, { saved: true });
  await f.state.initialize();
  f.permitSidecar();
  await f.state.reconnectAndConnect(account);
  assert.deepEqual(f.calls, ["sidecar:spawn", "rpc:acquire", "rpc:restart"]);
  assert.equal((await f.state.getConnectorState()).running, true);
  await f.state.resetConnectorEnvironment();
  assert.deepEqual(await f.state.recheckOwnership(), { status: "idle" });
  const afterReset = [...f.calls];
  await f.state.saveSettings({ uvPypiIndexUrl: "https://other.example.test/simple" });
  await assert.rejects(f.state.startConnector(), /Create or reconnect/);
  assert.deepEqual(f.calls, afterReset, "reset and settings changes cannot reconnect a saved device");
});

for (const action of ["createAndConnect", "reconnectAndConnect"] as const) {
  test(`${action} conflicts block HTTP, credentials and runtime start; recheck only claims ownership`, { timeout: 15_000 }, async t => {
    const f = fixture(t, { saved: true });
    await f.state.initialize();
    const savedConfig = fs.readFileSync(f.init.configPath, "utf8");
    const savedBinding = fs.readFileSync(f.init.bindingPath, "utf8");
    f.setConflict(true);
    f.permitSidecar();
    await assert.rejects(f.state[action](account), (error: unknown) => error instanceof ConnectorRpcError && error.ownershipConflict);
    assert.equal(f.state.ownershipState().status, "conflict");
    assert.deepEqual(f.calls, ["sidecar:spawn", "rpc:acquire"]);
    assert.equal((await f.state.recheckOwnership()).status, "conflict");
    f.setConflict(false);
    assert.equal((await f.state.recheckOwnership()).status, "owned");
    assert.equal((await f.state.getConnectorState()).running, false);
    assert.equal(f.calls.some(call => /http:|rpc:(start|restart)/.test(call)), false);
    assert.equal(fs.readFileSync(f.init.configPath, "utf8"), savedConfig);
    assert.equal(fs.readFileSync(f.init.bindingPath, "utf8"), savedBinding);
    f.setConflict(true);
    await assert.rejects(f.state.startConnector(), (error: unknown) => error instanceof ConnectorRpcError && error.ownershipConflict);
    await assert.rejects(f.state.restartConnector(), (error: unknown) => error instanceof ConnectorRpcError && error.ownershipConflict);
    f.setConflict(false);
    await f.state[action](account);
    assert.equal((await f.state.getConnectorState()).running, true);
  });
}

test("unset explicit-connection mode preserves ownership acquisition and saved-device auto-start", { timeout: 15_000 }, async t => {
  const f = fixture(t, { explicit: false, saved: true });
  assert.equal(f.state.ownershipState().status, "checking");
  f.permitSidecar();
  await f.state.initialize();
  assert.deepEqual(f.calls, ["sidecar:spawn", "rpc:acquire", "rpc:getState", "rpc:start"]);
  assert.equal(f.state.ownershipState().status, "owned");
});

test("real Backend HTTP state/config/ownership routes preserve idle through login and recheck", async t => {
  const f = fixture(t, { saved: true });
  const server = new BackendServer(f.state);
  const { port, token } = await server.start();
  t.after(() => server.close());
  const headers = { [BACKEND_TOKEN_HEADER]: token, "content-type": "application/json" };
  for (const phase of ["before initialize", "after initialize"]) {
    if (phase === "after initialize") await f.state.initialize();
    for (const route of ["state", "config", "ownership", "device/binding"]) {
      const response = await fetch(`http://127.0.0.1:${port}/${route}`, { headers });
      assert.equal(response.status, 200, `${phase}: ${route}`);
      const body = await response.json() as { status?: string };
      if (route === "ownership") assert.equal(body.status, "idle");
    }
    for (const route of ["ownership/acquire", "ownership/recheck"]) {
      const response = await fetch(`http://127.0.0.1:${port}/${route}`, { headers, method: "POST", body: "{}" });
      assert.deepEqual(await response.json(), { status: "idle" });
    }
  }
  assert.deepEqual(f.calls, []);
});

for (const explicit of [true, false]) {
  for (const saved of [true, false]) {
    test(`scoped-only Backend rejects ordinary connection actions without side effects (${explicit ? "explicit" : "legacy"}, ${saved ? "saved" : "fresh"})`, async t => {
      const f = fixture(t, { explicit, saved, scopedVerificationOnly: true });
      if (explicit) await f.state.initialize();
      const files = [f.init.configPath, f.init.bindingPath, f.init.settingsPath];
      const readFiles = () => files.map(file => fs.existsSync(file) ? fs.readFileSync(file) : null);
      const before = readFiles();
      const ownership = f.state.ownershipState();
      const binding = f.state.getLocalBinding();
      const config = f.state.getPublicConfig();
      const states: unknown[] = [];
      f.state.on("state", value => states.push(value));
      const denied = /Project verification mode only permits the locally scoped connection menu/;
      const actions = [
        () => f.state.createAndConnect({ ...account, name: "Must not register" }),
        () => f.state.reconnectAndConnect(account),
        () => f.state.startConnector(),
        () => f.state.restartConnector(),
        () => f.state.saveConfig({ heartbeatSeconds: 42 }),
      ];
      // Repeat to catch a rejected create/reconnect accidentally granting the
      // explicit-start latch. Legacy mode proves the scoped flag owns the ban.
      for (let attempt = 0; attempt < 2; attempt += 1) {
        for (const action of actions) {
          await assert.rejects(async () => action(), denied);
          assert.deepEqual(f.calls, [], "no sidecar, ownership RPC, HTTP, config save or runtime write");
          assert.deepEqual(readFiles(), before, "rejection must preserve persisted config, binding and settings");
        }
        await f.state.startOwnedConnectorOnLaunch();
        assert.equal((await f.state.getConnectorState()).running, false);
      }
      assert.deepEqual(f.calls, [], "saved-device launch cannot bypass scoped-only mode");
      assert.deepEqual(f.state.ownershipState(), ownership);
      assert.deepEqual(f.state.getLocalBinding(), binding);
      assert.deepEqual(f.state.getPublicConfig(), config);
      assert.deepEqual(f.ownership, []);
      assert.deepEqual(states, []);
    });
  }
}

test("scoped-only Backend HTTP rejects UI create/reconnect/start/restart without provisioning or spawning", async t => {
  const f = fixture(t, { saved: true, scopedVerificationOnly: true });
  await f.state.initialize();
  const config = fs.readFileSync(f.init.configPath);
  const binding = fs.readFileSync(f.init.bindingPath);
  const server = new BackendServer(f.state);
  const { port, token } = await server.start();
  t.after(() => server.close());
  const headers = { [BACKEND_TOKEN_HEADER]: token, "content-type": "application/json" };
  for (const route of ["device/create", "device/reconnect", "start", "restart"]) {
    const response = await fetch(`http://127.0.0.1:${port}/${route}`, {
      headers, method: "POST", body: JSON.stringify({ ...account, name: "Must not register" }),
    });
    assert.equal(response.status, 400, route);
    const body = await response.json() as { error: string };
    assert.match(body.error, /Project verification mode only permits the locally scoped connection menu/, route);
    assert.deepEqual(f.calls, [], `${route}: no ownership, device HTTP or runtime side effects`);
    assert.deepEqual(fs.readFileSync(f.init.configPath), config);
    assert.deepEqual(fs.readFileSync(f.init.bindingPath), binding);
  }
  await f.state.startOwnedConnectorOnLaunch();
  assert.deepEqual(f.state.ownershipState(), { status: "idle" });
  assert.equal((await f.state.getConnectorState()).running, false);
  assert.deepEqual(f.calls, []);
  assert.deepEqual(f.ownership, []);
});
