import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { MachineStateStore } from "./machine-state";
import { connectorDataRoot, desktopConnectorDataRoot, localRuntimePath, readLocalState, readMachineStateFile } from "./local-runtime";

test("OSIR can keep machine state under its private Connector data root", async t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "osir-anywhere-home-"));
  const root = path.join(home, "Library", "Application Support", "OSIR Anywhere", "connector");
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  assert.equal(connectorDataRoot(home, root), root);
  assert.equal(localRuntimePath(home, root), path.join(root, "connector-runtime.json"));
  assert.equal(localRuntimePath(home), path.join(home, ".agents-anywhere", "connector-runtime.json"));
  assert.equal(fs.existsSync(path.join(home, ".agents-anywhere")), false);
  assert.equal(connectorDataRoot(home, `  ${root}  `), root);
  assert.throws(() => connectorDataRoot(home, "~/connector"), /absolute/);
  assert.throws(() => connectorDataRoot(home, "relative/connector"), /absolute/);
  assert.equal(desktopConnectorDataRoot({ packaged: true, productName: "OSIR Anywhere", userDataPath: home, env: {} }), path.join(home, "connector"));
  assert.equal(desktopConnectorDataRoot({ packaged: true, productName: "Agents Anywhere", userDataPath: home, env: {} }), undefined);
  assert.equal(desktopConnectorDataRoot({ packaged: false, productName: "OSIR Anywhere", userDataPath: home, env: {} }), undefined);
  const legacy = path.join(home, ".agentsanywhere", "machine.json");
  fs.mkdirSync(path.dirname(legacy), { recursive: true });
  fs.writeFileSync(legacy, '{"version":1,"connectorIds":["upstream"]}');
  assert.deepEqual(readMachineStateFile(path.join(home, "connector", "connector-runtime.json"), false).connectorIds, []);
  const store = new MachineStateStore(path.join(home, "connector", "connector-runtime.json"), undefined, false);
  assert.deepEqual(store.readConnectorIds(), []);
  await store.completeOnboarding("desktop");
  assert.deepEqual(JSON.parse(fs.readFileSync(store.filePath, "utf8")).connectorIds, []);
  assert.equal(fs.readFileSync(legacy, "utf8"), '{"version":1,"connectorIds":["upstream"]}');
});

test("host reads preserve Python ownership and do not migrate legacy records", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "aa-read-state-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const file = localRuntimePath(home);
  assert.deepEqual(readMachineStateFile(file).connectorIds, []);
  assert.equal(fs.existsSync(file), false);
  const legacy = path.join(home, ".agentsanywhere", "machine.json");
  fs.mkdirSync(path.dirname(legacy), { recursive: true });
  const contents = JSON.stringify({ version: 1, connectorIds: ["old", "old"], desktop: { appPath: "/Desktop" }, future: true });
  fs.writeFileSync(legacy, contents);
  assert.deepEqual(readMachineStateFile(file).connectorIds, ["old"]);
  assert.deepEqual(readMachineStateFile(file).desktop, { appPath: "/Desktop" });
  assert.equal(fs.readFileSync(legacy, "utf8"), contents);
  assert.equal(fs.existsSync(file), false);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const owner = { instanceId: "python", pid: 99999999, kind: "cli", startedAt: "2026-09-08" };
  fs.writeFileSync(file, JSON.stringify({ version: 2, legacyMachineMigrated: true, connectorIds: ["new"], runtime: owner }));
  assert.deepEqual(readMachineStateFile(file).connectorIds, ["new"]);
  // Only Connector decides whether a PID is stale and may be replaced.
  assert.deepEqual(readLocalState(file).runtime, owner);
});

test("host rejects corrupt and future records without repairing or overwriting them", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "aa-invalid-state-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const file = localRuntimePath(home);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  for (const invalid of ["{broken", '{"version":3}', '{"version":2,"runtime":{}}', '{"version":2,"connectorIds":[""]}']) {
    fs.writeFileSync(file, invalid);
    assert.throws(() => readMachineStateFile(file));
    assert.equal(fs.readFileSync(file, "utf8"), invalid);
  }
});
