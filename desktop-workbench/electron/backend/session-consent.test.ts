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
import { BackendState } from "./state";

const credential = { serverUrl: "https://server.example.test", connectorId: "saved-device", connectorToken: "test-credential" };
const account = { userId: "test-user", userToken: "test-session" };

/** Real Backend + stores + Supervisor + device service; only transport is synthetic. */
function fixture(t: TestContext, options: {
  explicit?: boolean;
  saved?: boolean;
  missingLauncher?: boolean;
  scopedVerificationOnly?: boolean;
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
  const state = new BackendState(init, async (_url, request) => {
    calls.push(`http:${request?.method}`);
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
  return { state, init, root, calls, ownership,
    permitSidecar: () => { allowSpawn = true; },
    setConflict: (value: boolean) => { conflict = value; },
  };
}

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
