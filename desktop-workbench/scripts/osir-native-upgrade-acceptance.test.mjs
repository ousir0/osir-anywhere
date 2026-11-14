import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { lstat, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { verify } from 'node:crypto';
import { bytes, digest, fingerprint } from './osir-anywhere-release-common.mjs';
import { fileIdentity, fingerprintTree } from './osir-native-smoke.mjs';
import { validateNativeReport } from './osir-native-acceptance-aggregate.mjs';
import { BASELINE_VERSION, FINAL_VERSION, PATCH_VERSION, SERVER_VERSION, bindBaseline, copyIndependent, derivativeInventory, evidenceWriter, observeUpgradeHardware, PACKAGE_PATH, parseArguments, prepareBaseline, runAcceptance, validateDiscovery, validateSpec, versionOnlyDerivative } from './osir-native-upgrade-acceptance.mjs';
import { Inspector, observeUpgradeGui, ownedExit, packagedDiscoveryProbe, packagedWindowState, recordInspectorProtocolFailure, requestUpgradeQuit, sanitizeInspectorProtocolError, SEED_SETTINGS, syntheticUpgradeLaunch, UpgradeAdapter, waitForUpgradeWelcome, waitForUpgradeWindow } from './osir-native-upgrade-acceptance.runtime.mjs';
import { electronFromLock, reuseExtractedRuntime, validateElectronFramework } from './osir-native-upgrade-acceptance.extract.mjs';
import { collectRaw, discoveryTestSources, runSpec as transferredRunSpec, sealBaseline } from './osir-native-upgrade-acceptance.ci.mjs';
import { reviewedBindings } from './osir-artifact-acceptance-ci.mjs';

const originalPackage = Buffer.from('{\n  "name": "osir-anywhere-desktop-workbench",\n  "productName": "OSIR Anywhere",\n  "description": "测试不重写字节",\n  "version": "2.2.1"\n}\n');
const identity = data => ({ size: data.length, sha256: digest(data) });

class SyntheticInspectorSocket extends EventTarget {
  readyState = 1;
  requests = [];
  send(value) { this.requests.push(JSON.parse(value)); }
  reply(value) { this.dispatchEvent(new MessageEvent('message', { data: JSON.stringify(value) })); }
  close() { this.readyState = 3; }
}

test('inspector diagnostics retain only fixed protocol text, local method/operation and numeric protocol code', () => {
  assert.deepEqual(sanitizeInspectorProtocolError('Runtime.evaluate', 'window-state', {
    code: -32000, message: 'Cannot find context with specified id', data: 'Invalid parameters', extra: 'NEVER_RECORD_EXTRA',
  }), { schemaVersion: 1, kind: 'inspector-protocol-error', method: 'Runtime.evaluate', operation: 'window-state',
    error: { code: -32000, message: 'Cannot find context with specified id', data: 'Invalid parameters' } });
  const invalid = sanitizeInspectorProtocolError('NEVER_RECORD_METHOD', 'NEVER_RECORD_OPERATION', { code: 'NEVER_RECORD_CODE' });
  assert.equal(invalid.method, '[invalid-method]'); assert.equal(invalid.operation, '[invalid-operation]');
  assert.deepEqual(invalid.error.code, { omitted: true });
});

test('inspector diagnostic text fails closed for credentials, URLs, paths, JSON and unknown short strings', () => {
  for (const text of ['Bearer abc', 'password=q', 'https://user:pass@example.test/?token=q', '/Users/synthetic/private',
    '{"token":"q"}', 'q', 'Internal error token=q', 'Promise was collected\npassword=q', 'A'.repeat(100000)]) {
    const diagnostic = sanitizeInspectorProtocolError('Runtime.evaluate', 'packaged-action', { code: -32000, message: text, data: text });
    assert.deepEqual(diagnostic.error.message, { type: 'string', omitted: true, length: text.length });
    assert.deepEqual(diagnostic.error.data, { type: 'string', omitted: true, length: text.length });
    assert.ok(Buffer.byteLength(JSON.stringify(diagnostic)) < 1024);
  }
});

test('inspector diagnostics never traverse arbitrary data or call getters, coercion or toJSON', () => {
  let calls = 0;
  const arbitrary = { token: 'NEVER_RECORD_SECRET', get nested() { calls++; throw Error('getter invoked'); }, toJSON() { calls++; throw Error('toJSON invoked'); } };
  for (const data of [arbitrary, [arbitrary], null, true, 123, undefined, () => { calls++; }, Symbol('NEVER_RECORD_SYMBOL')]) {
    const diagnostic = sanitizeInspectorProtocolError('Runtime.evaluate', 'packaged-action', { code: arbitrary, message: arbitrary, data });
    assert.equal(diagnostic.error.data.omitted, true);
    assert.ok(!JSON.stringify(diagnostic).includes('NEVER_RECORD')); assert.deepEqual(diagnostic.error.code, { omitted: true });
  }
  const accessors = Object.defineProperties({}, Object.fromEntries(['code', 'message', 'data'].map(key => [key, { get() { calls++; throw Error('field getter invoked'); } }])));
  assert.ok(JSON.stringify(sanitizeInspectorProtocolError('Runtime.evaluate', 'packaged-action', accessors)).length < 1024);
  assert.equal(calls, 0);
});

test('inspector binds protocol errors to the pending request and writes final/discovery raw evidence before rethrow', async t => {
  const root = await mkdtemp(join(tmpdir(), 'osir-inspector-diagnostic-')); t.after(() => rm(root, { recursive: true, force: true }));
  const report = { evidence: [] }, evidence = await evidenceWriter(root, report);
  for (const stage of ['final', 'discovery']) {
    const socket = new SyntheticInspectorSocket(), inspector = new Inspector(socket); t.after(() => inspector.close());
    const expression = stage === 'final' ? '(packagedWindowState)() /* NEVER_RECORD_EXPRESSION */' : 'NEVER_RECORD_EXPRESSION';
    const evaluation = inspector.evaluate(expression);
    const request = socket.requests[0]; assert.equal(request.method, 'Runtime.evaluate');
    const rejected = assert.rejects(async () => {
      try { await evaluation; }
      catch (error) { await recordInspectorProtocolFailure(evidence, stage, error); throw error; }
    }, { message: 'Electron inspector command failed' });
    socket.reply({ id: request.id + 1, error: { code: -32000, message: 'Internal error' } });
    assert.equal(inspector.pending.size, 1);
    socket.reply({ id: request.id, method: 'NEVER_RECORD_RESPONSE_METHOD', error: { code: -32000, message: 'Promise was collected', data: { token: 'NEVER_RECORD_DATA' } } });
    await rejected; assert.equal(inspector.pending.size, 0);
    const path = `${stage}-inspector-protocol-error.json`, raw = await readFile(join(root, path)), observation = JSON.parse(raw);
    assert.equal(observation.stage, stage); assert.equal(observation.method, 'Runtime.evaluate');
    assert.equal(observation.operation, stage === 'final' ? 'window-state' : 'packaged-action');
    assert.deepEqual(observation.error, { code: -32000, message: 'Promise was collected', data: { type: 'object', omitted: true } });
    assert.ok(!raw.includes('NEVER_RECORD')); assert.ok(raw.length < 1024);
    const item = report.evidence.find(item => item.path === path); assert.deepEqual(identity(raw), { size: item.size, sha256: item.sha256 });
  }
});

test('inspector success, JavaScript exceptions and foreign errors retain existing failure semantics', async () => {
  const socket = new SyntheticInspectorSocket(), inspector = new Inspector(socket);
  try {
    const evaluation = inspector.evaluate('synthetic-success');
    socket.reply({ id: 1, result: { result: { value: { ready: true } } } });
    assert.deepEqual(await evaluation, { ready: true });
    const exception = inspector.evaluate('synthetic-exception');
    socket.reply({ id: 2, result: { exceptionDetails: { exception: { description: 'Synthetic packaged failure' } } } });
    await assert.rejects(exception, /Packaged Electron evaluation failed: Synthetic packaged failure/);
    let writes = 0; const evidence = async () => { writes++; };
    for (const error of [new Error('Synthetic packaged failure'), { inspectorProtocol: { token: 'NEVER_RECORD_FOREIGN' } }])
      assert.equal(await recordInspectorProtocolFailure(evidence, 'final', error), false);
    assert.equal(writes, 0);
  } finally { inspector.close(); }
});

test('window-state inspector reads synchronously while asynchronous probes remain awaited', async () => {
  const socket = new SyntheticInspectorSocket(), inspector = new Inspector(socket);
  try {
    const sync = inspector.evaluate('(packagedWindowState)()', { awaitPromise: false });
    assert.equal(socket.requests[0].params.awaitPromise, false);
    assert.equal(socket.requests[0].params.returnByValue, true);
    socket.reply({ id: 1, result: { result: { value: { ready: false, reason: 'node-process-not-ready' } } } });
    assert.equal((await sync).ready, false);
    const asyncProbe = inspector.evaluate('Promise.resolve({updated:true})');
    assert.equal(socket.requests[1].params.awaitPromise, true);
    socket.reply({ id: 2, result: { result: { value: { updated: true } } } });
    assert.equal((await asyncProbe).updated, true);
    await assert.rejects(inspector.evaluate('ignored', { awaitPromise: 'false' }), /must be boolean/);
    assert.equal(socket.requests.length, 2);
  } finally { inspector.close(); }
});

test('startup and welcome keep their last observations when an inspector protocol error aborts the phase', async () => {
  const socket = new SyntheticInspectorSocket(), inspector = new Inspector(socket);
  try {
    const evaluation = inspector.evaluate('(packagedWindowState)()');
    const caught = evaluation.catch(error => error);
    socket.reply({ id: 1, error: { code: -32000, message: 'Cannot find context with specified id' } });
    const failure = await caught, rejecting = { evaluate: async () => { throw failure; } };
    let startup, welcome;
    await assert.rejects(waitForUpgradeWindow(rejecting, {}, Date.now() + 1000, value => { startup = value; }), error => error === failure);
    await assert.rejects(waitForUpgradeWelcome(rejecting, 1, Date.now() + 1000, value => { welcome = value; }), error => error === failure);
    assert.deepEqual(startup, []); assert.deepEqual(welcome, { ready: false, branded: false, action: null });
    let writes = 0;
    assert.equal(await recordInspectorProtocolFailure(async () => { writes++; }, '../escape', failure), false);
    assert.equal(writes, 0);
  } finally { inspector.close(); }
});

test('real early inspector context without process remains a recorded bootstrap phase', () => {
  const observation = JSON.parse(JSON.stringify(vm.runInNewContext('(' + packagedWindowState.toString() + ')()', {})));
  assert.deepEqual(observation, { ready: false, reason: 'node-process-not-ready', phase: { processType: null, electron: null } });
});

test('packaged startup records browser bootstrap and exact missing-electron phases without hiding other exceptions', () => {
  let calls = 0, ready = false, moduleError = Object.assign(new Error("Cannot find module 'electron'\nRequire stack:\n- synthetic/app.asar/package.json"), { code: 'MODULE_NOT_FOUND' });
  const electron = { app: { isReady: () => ready, getName: () => 'OSIR Anywhere', getVersion: () => '2.2.0', isPackaged: true, getPath: () => '/synthetic' }, BrowserWindow: { getAllWindows: () => [] } };
  const runtimeProcess = { type: undefined, versions: { electron: '39.8.10' }, resourcesPath: '/synthetic', getBuiltinModule: () => ({ createRequire: () => () => { calls++; if (moduleError) throw moduleError; return electron; } }) };
  const evaluate = () => JSON.parse(JSON.stringify(vm.runInNewContext(`(${packagedWindowState.toString()})()`, { process: runtimeProcess })));
  assert.equal(evaluate().reason, 'electron-browser-not-ready'); assert.equal(calls, 0);
  runtimeProcess.type = 'browser';
  const early = evaluate(); assert.equal(early.reason, 'electron-module-not-ready'); assert.equal(early.phase.processType, 'browser'); assert.equal(early.error.code, 'MODULE_NOT_FOUND');
  moduleError = Object.assign(new Error("Cannot find module 'other-dependency'"), { code: 'MODULE_NOT_FOUND' });
  assert.throws(evaluate, /other-dependency/);
  moduleError = new Error('Invalid Electron API'); assert.throws(evaluate, /Invalid Electron API/);
  moduleError = null; assert.equal(evaluate().reason, 'electron-app-not-ready');
  ready = true; assert.equal(evaluate().state.version, '2.2.0');
});

test('startup waits for Electron and loaded window, preserving failed phase observations', async () => {
  const root = join(tmpdir(), 'synthetic-upgrade-startup');
  const context = { version: '2.2.0', nativeMachine: `${process.platform}-${process.arch}`, resources: join(root, 'resources'), accountHome: root, allowedDataRoots: [root], pid: 42 };
  const window = { id: 7, visible: true, destroyed: false, loading: false, width: 900, height: 600, url: 'osir-anywhere-workbench://web/', rendererPid: 43 };
  const state = { pid: 42, packaged: true, electron: '39.8.10', name: 'OSIR Anywhere', version: '2.2.0', platform: process.platform, arch: process.arch, resources: context.resources, home: root, userData: join(root, 'data'), windows: [window] };
  const observations = [{ ready: false, reason: 'electron-module-not-ready' }, { ready: true, state: { ...state, windows: [{ ...window, loading: true }] } }, { ready: true, state }];
  let count = 0, recorded;
  const result = await waitForUpgradeWindow({ evaluate: async (_source, options) => { assert.deepEqual(options, { awaitPromise: false }); return observations[count++]; } }, context, Date.now() + 2500, async value => { recorded = value; });
  assert.deepEqual(result, { state, window }); assert.equal(count, 3); assert.deepEqual(recorded, observations);
  let failed;
  await assert.rejects(waitForUpgradeWindow({ evaluate: async () => ({ ready: false, reason: 'electron-module-not-ready' }) }, context, Date.now() + 30, async value => { failed = value; }), /readiness timed out/);
  assert.equal(failed[0].reason, 'electron-module-not-ready');
  const unexpected = new Error('Packaged exception unrelated to bootstrap');
  await assert.rejects(waitForUpgradeWindow({ evaluate: async () => { throw unexpected; } }, context, Date.now() + 1000), error => error === unexpected);
  await assert.rejects(waitForUpgradeWindow({ evaluate: async () => ({ ready: true, state: { ...state, version: 'wrong' } }) }, context, Date.now() + 30), /identity\/version/);
});

test('graceful quit invokes only the existing packaged renderer API after acknowledgement', async () => {
  const scheduled = []; let quitCalls = 0;
  const rendererWindow = { desktopWorkbench: { ownership: { quit: async () => { quitCalls++; } } } };
  const webContents = { executeJavaScript: source => vm.runInNewContext(source, { window: rendererWindow, setTimeout: (fn, delay) => { assert.equal(delay, 100); scheduled.push(fn); } }) };
  const inspector = { evaluate: async source => JSON.parse(JSON.stringify(await vm.runInNewContext(source, { process: { resourcesPath: '/synthetic', getBuiltinModule: () => ({ createRequire: () => name => { assert.equal(name, 'electron'); return { BrowserWindow: { fromId: id => { assert.equal(id, 7); return { webContents }; } } }; } }) } }))) };
  assert.equal((await requestUpgradeQuit(inspector, 7)).requested, true); assert.equal(quitCalls, 0);
  scheduled[0](); assert.equal(quitCalls, 1);
  delete rendererWindow.desktopWorkbench;
  await assert.rejects(requestUpgradeQuit(inspector, 7), /ownership.quit API missing/);
  await assert.rejects(requestUpgradeQuit(inspector, undefined), /Owned window ID/);
});

test('durability requires acknowledged graceful quit and a real clean exit; errors and signals survive', async () => {
  const child = { exitCode: null, signalCode: null }; let closed = false, observation;
  const inspector = { evaluate: async source => { assert.ok(source.includes('desktopWorkbench')); setTimeout(() => { child.exitCode = 0; }, 5); return { requested: true, route: 'desktopWorkbench.ownership.quit' }; }, close: () => { closed = true; } };
  await ownedExit(child, inspector, true, {}, { windowId: 7, graceMs: 50, observe: async value => { observation = value; } });
  assert.equal(closed, true); assert.equal(observation.exitCode, 0); assert.equal(observation.forced, false); assert.equal(observation.clean, true);
  const failure = { evaluate: async () => { throw new Error('quit-request failed'); }, close() {} };
  await assert.rejects(ownedExit({ exitCode: 0, signalCode: null }, failure, true, {}, { windowId: 7, graceMs: 1, observe: async value => { observation = value; } }), /durability unproven/);
  assert.equal(observation.requestError, 'quit-request failed');
  await assert.rejects(ownedExit({ exitCode: null, signalCode: 'SIGTERM' }, inspector, true, {}, { windowId: 7, graceMs: 1, observe: async value => { observation = value; } }), /durability unproven/);
  assert.equal(observation.signal, 'SIGTERM'); assert.equal(observation.clean, false);
  await assert.rejects(ownedExit({ exitCode: null, signalCode: null }, { evaluate: async () => ({ requested: true, route: 'desktopWorkbench.ownership.quit' }), close() {} }, true, {}, { windowId: 7, graceMs: 1, observe: async value => { observation = value; } }), /durability unproven/);
  assert.equal(observation.clean, false);
  await ownedExit({ exitCode: 0, signalCode: null }, { evaluate: async source => { assert.ok(source.includes('.app.quit()')); throw new Error('app.quit failed'); }, close() {} }, false, {}, { observe: async value => { observation = value; } });
  assert.equal(observation.route, 'app.quit'); assert.equal(observation.requestError, 'app.quit failed'); assert.equal(observation.exitCode, 0);
});

test('Windows shared hardware probe retries once, preserving timeout even with exit 0 and valid JSON', async () => {
  const records = [], timeouts = [], machine = { arch: 'x64', translated: false };
  let attempts = 0;
  class Probe {
    constructor(context) { Object.assign(this, context); }
    async run(executable, args, label, options) {
      timeouts.push(options.timeout); attempts++;
      const result = { executable, args, code: 0, signal: null, stdout: '{"nativeMachine":34404,"processMachine":0}', stderr: '' };
      await this.evidence(`${label}.json`, bytes({ ...result, ...(attempts === 1 ? { failure: 'Native command timed out' } : {}) }));
      if (attempts === 1) throw Object.assign(new Error('Native command timed out'), { commandResult: result });
      return machine;
    }
    hardware() { return this.run('powershell.exe', ['shared-probe-synthetic'], 'hardware-machine'); }
  }
  const context = { evidence: async (name, raw) => records.push({ name, ...JSON.parse(raw) }) };
  assert.deepEqual(await observeUpgradeHardware(context, { Adapter: Probe, platform: 'win32' }), machine);
  assert.deepEqual(timeouts, [60000, 120000]); assert.equal(records.length, 2);
  assert.equal(records[0].name, 'hardware-attempt-1-hardware-machine.json'); assert.equal(records[0].code, 0); assert.equal(records[0].failure, 'Native command timed out');
  assert.equal(records[1].name, 'hardware-attempt-2-hardware-machine.json'); assert.equal(records[1].failure, undefined);
  for (const [platform, message, expectedCalls] of [['win32', 'Native command timed out', 2], ['win32', 'Native hardware-machine failed (exit 1)', 1], ['darwin', 'Native command timed out', 1]]) {
    let count = 0;
    class RejectedProbe { run() {} async hardware() { count++; throw new Error(message); } }
    await assert.rejects(observeUpgradeHardware(context, { Adapter: RejectedProbe, platform }), error => error.message === message);
    assert.equal(count, expectedCalls);
  }
});

test('forced cleanup of a real synthetic child cannot certify data durability', async t => {
  const child = spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { env: {}, stdio: 'ignore', detached: process.platform !== 'win32' });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  await new Promise((resolve, reject) => { child.once('spawn', resolve); child.once('error', reject); });
  let observed;
  await assert.rejects(ownedExit(child, { evaluate: async () => ({ requested: true, route: 'desktopWorkbench.ownership.quit' }), close() {} }, true, {},
    { windowId: 7, graceMs: 20, observe: async value => { observed = value; } }), /durability unproven/);
  assert.equal(observed.forced, true); assert.equal(observed.clean, false);
  assert.ok(observed.exitCode !== null || observed.signal !== null);
});

test('Windows GUI preflight retries one timeout and preserves its raw failure before a live success', async () => {
  const env = { synthetic: true }, records = [], gui = { interactiveDesktop: true, sessionId: 1 };
  const failure = Object.assign(new Error('Native command timed out'), { commandResult: { executable: 'powershell.exe', args: ['synthetic'], code: null, signal: 'SIGTERM', stdout: '', stderr: 'cold probe' } });
  let calls = 0;
  const probe = async actual => { assert.equal(actual, env); if (++calls === 1) throw failure; return gui; };
  assert.equal(await observeUpgradeGui(env, async (name, raw) => records.push({ name, ...JSON.parse(raw) }), probe, 'win32'), gui);
  assert.equal(calls, 2); assert.equal(records.length, 2);
  assert.equal(records[0].result, 'failed'); assert.deepEqual(records[0].command, failure.commandResult);
  assert.equal(records[1].result, 'passed'); assert.deepEqual(records[1].gui, gui);
});

test('GUI preflight never retries a rejection or accepts repeated timeout, and leaves Mac behavior unchanged', async () => {
  for (const [platform, message, expectedCalls] of [['win32', 'No native Windows GUI', 1], ['win32', 'Native command timed out', 2], ['darwin', 'Native command timed out', 1]]) {
    let calls = 0; const records = [], failure = new Error(message);
    await assert.rejects(observeUpgradeGui({}, async (_name, raw) => records.push(JSON.parse(raw)), async () => { calls++; throw failure; }, platform), error => error === failure);
    assert.equal(calls, expectedCalls); assert.equal(records.length, expectedCalls);
    assert.ok(records.every(record => record.result === 'failed'));
  }
});

test('a repeated GUI timeout preserves raw evidence and never attempts either installer', async t => {
  const f = await fixture(t), output = join(f.root, 'failed-gui');
  let createdAdapter = false;
  const report = await runAcceptance(f.spec, output, {
    adapterFactory: () => { createdAdapter = true; throw new Error('Adapter must not be reached'); },
    isolationVerifier: async (_spec, { evidence }) => observeUpgradeGui({}, evidence, async () => {
      throw Object.assign(new Error('Native command timed out'), { commandResult: { executable: 'powershell.exe', args: ['synthetic'], code: null, signal: 'SIGTERM', stdout: '', stderr: 'synthetic timeout' } });
    }, 'win32'),
  });
  assert.equal(report.result, 'failed'); assert.equal(createdAdapter, false);
  assert.deepEqual(report.execution, { baselineInstallAttempted: false, finalInstallAttempted: false });
  assert.deepEqual(report.checks, { upgradeDataPreserved: false, updateDiscovery: false });
  assert.equal(report.failure, 'Native command timed out');
  const attempts = report.evidence.filter(item => item.path.startsWith('runner-gui-attempt-'));
  assert.equal(attempts.length, 2);
  for (const item of attempts) {
    assert.deepEqual(await fileIdentity(join(output, item.path)), { size: item.size, sha256: item.sha256 });
    const record = JSON.parse(await readFile(join(output, item.path), 'utf8'));
    assert.equal(record.result, 'failed'); assert.equal(record.command.executable, 'powershell.exe');
  }
});

test('shipped Electron framework uses its exact build version without requiring an absent marketing version', () => {
  const framework = { CFBundleIdentifier: 'com.github.Electron.framework', CFBundlePackageType: 'FMWK', CFBundleVersion: '39.8.10' };
  const version = electronFromLock('  resolution: "electron@npm:39.8.10"\n');
  assert.doesNotThrow(() => validateElectronFramework(framework, version));
  assert.doesNotThrow(() => validateElectronFramework({ ...framework, CFBundleShortVersionString: version }, version));
  for (const metadata of [
    { ...framework, CFBundleVersion: undefined },
    { ...framework, CFBundleVersion: '39.8.11', CFBundleShortVersionString: version },
    { ...framework, CFBundleShortVersionString: '39.8.11' },
    { ...framework, CFBundleShortVersionString: null },
  ]) assert.throws(() => validateElectronFramework(metadata, version), /differs from reviewed dependency lock/);
  assert.throws(() => validateElectronFramework({ ...framework, CFBundleIdentifier: 'other.framework' }, version), /identity mismatch/);
  assert.throws(() => validateElectronFramework({ ...framework, CFBundlePackageType: 'APPL' }, version), /identity mismatch/);
});

test('upgrade waits past Loading for the shared welcome gate before allowing a screenshot', async () => {
  const ready = { ready: true, branded: true, action: { text: 'Sign in to OSIR Anywhere', enabled: true, visible: true } };
  let calls = 0, observed, screenshotAllowed = false;
  const inspector = { evaluate: async () => { assert.equal(screenshotAllowed, false); return ++calls === 1 ? { ready: true, branded: false, action: null } : ready; } };
  assert.deepEqual(await waitForUpgradeWelcome(inspector, 7, Date.now() + 2000, async value => { observed = value; }), ready);
  screenshotAllowed = true; assert.equal(calls, 2); assert.deepEqual(observed, ready);
});

test('serialized welcome probe bounds navigation suspension and still requires a real enabled welcome', async () => {
  const ready = { ready: true, branded: true, action: { text: 'Sign in', enabled: true, visible: true } };
  let calls = 0, executions = 0; const phases = [];
  const inspector = { evaluate: async source => {
    calls++;
    const webContents = {
      isLoading: () => calls === 1,
      executeJavaScript: () => { executions++; return calls === 2 ? new Promise(() => {}) : Promise.resolve(ready); },
    };
    const observation = JSON.parse(JSON.stringify(await vm.runInNewContext(source, {
      process: { resourcesPath: '/synthetic', getBuiltinModule: () => ({ createRequire: () => () => ({ BrowserWindow: { fromId: () => ({ webContents }) } }) }) },
      setTimeout: fn => setTimeout(fn, 1),
    })));
    phases.push(observation); return observation;
  } };
  assert.deepEqual(await waitForUpgradeWelcome(inspector, 7, Date.now() + 2500), ready);
  assert.equal(executions, 2); assert.equal(calls, 3);
  assert.equal(phases[0].phase, 'navigation-loading');
  assert.equal(phases[1].phase, 'renderer-probe-timeout');
});

test('a disabled welcome action times out and preserves the failed renderer observation', async () => {
  const disabled = { ready: true, branded: true, action: { text: 'Sign in', enabled: false, visible: true } };
  let observed;
  await assert.rejects(waitForUpgradeWelcome({ evaluate: async () => disabled }, 7, Date.now() + 30, async value => { observed = value; }), /welcome action/);
  assert.deepEqual(observed, disabled);
});

test('upgrade NSIS path accepts exact zero PE revision, rejects other revisions and keeps ASAR version exact', async t => {
  const f = await fixture(t), require = createRequire(import.meta.url), asar = require('@electron/asar');
  const source = join(f.root, 'tiny-windows-app'), destination = join(f.root, 'installed'), resources = join(destination, 'resources');
  await mkdir(join(source, 'dist'), { recursive: true }); await mkdir(resources, { recursive: true });
  const config = { synthetic: true }; await writeFile(join(source, 'dist/config.json'), bytes(config));
  const packageMetadata = { name: 'osir-anywhere-desktop-workbench', productName: 'OSIR Anywhere', version: '2.2.1', main: 'dist/electron/main.js' };
  const archive = join(resources, 'app.asar');
  await writeFile(join(source, 'package.json'), bytes(packageMetadata)); await asar.createPackage(source, archive);
  const pe = Buffer.alloc(128); pe.writeUInt16LE(0x5a4d); pe.writeUInt32LE(64, 60); pe.writeUInt32LE(0x4550, 64); pe.writeUInt16LE(process.arch === 'arm64' ? 0xaa64 : 0x8664, 68);
  await writeFile(join(destination, 'OSIR Anywhere.exe'), pe);
  let metadata = { ProductName: 'OSIR Anywhere', ProductVersion: '2.2.1.0', FileVersion: '2.2.1' };
  const spec = { ...f.spec, expected: { ...f.spec.expected, configSha256: fingerprint(config) } };
  const adapter = new UpgradeAdapter({ work: f.root, spec, env: {}, evidence: async () => {} });
  adapter.run = async (_exe, _args, label) => label.endsWith('-pe-metadata') ? JSON.stringify(metadata) : '';
  const artifact = { ...await fileIdentity(spec.finalInstallerPath) };
  assert.equal((await adapter.installWindows(spec.finalInstallerPath, artifact, '2.2.1', 'final')).pkg.version, '2.2.1');
  metadata = { ...metadata, ProductVersion: '2.2.1.1' };
  await assert.rejects(adapter.installWindows(spec.finalInstallerPath, artifact, '2.2.1', 'final'), /product\/version mismatch/);
  metadata.ProductVersion = '2.2.1.0'; metadata.FileVersion = '2.2.1.1';
  await assert.rejects(adapter.installWindows(spec.finalInstallerPath, artifact, '2.2.1', 'final'), /product\/version mismatch/);
  metadata.FileVersion = '2.2.1'; await rm(archive);
  await writeFile(join(source, 'package.json'), bytes({ ...packageMetadata, version: '2.2.1.0' })); await asar.createPackage(source, archive);
  await assert.rejects(adapter.installWindows(spec.finalInstallerPath, artifact, '2.2.1', 'final'), /ASAR product\/version mismatch/);
});

async function fixture(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'osir-upgrade-unit-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const save = async (name, value) => { const path = join(root, name); await writeFile(path, bytes(value)); return path; };
  const files = [{ path: PACKAGE_PATH, ...identity(originalPackage), executable: false }, { path: 'connector/synthetic.txt', ...identity(Buffer.from('same')), executable: false }];
  const source = { schemaVersion: 1, upstreamGitHead: 'a'.repeat(40), sourceSha256: fingerprint(files), files };
  const plan = { sourceSha256: source.sourceSha256, configSha256: 'c'.repeat(64), checkoutHead: 'b'.repeat(40), upstreamGitHead: source.upstreamGitHead,
    target: 'darwin-universal', version: '2.2.1', dependencies: { lockSha256: 'd'.repeat(64) } };
  const finalBytes = Buffer.from('NOT AN EXECUTABLE: synthetic final fixture');
  const artifact = { filename: 'osir-anywhere-2.2.1-darwin-universal.dmg', ...identity(finalBytes), systemSignature: 'unsigned' };
  const finalInstallerPath = join(root, artifact.filename); await writeFile(finalInstallerPath, finalBytes);
  const signature = { schemaVersion: 1, platform: 'darwin', artifactSha256: artifact.sha256, systemSignature: 'unsigned' };
  const systemSignatureReportPath = await save('signature.json', signature);
  const signatureIdentity = await fileIdentity(systemSignatureReportPath);
  const receipt = { schemaVersion: 1, plan, artifact, systemSignatureReportSha256: signatureIdentity.sha256 };
  const buildReceiptPath = await save('receipt.json', receipt);
  const expected = { ...plan, artifactSha256: artifact.sha256, artifactSize: artifact.size, systemSignatureReportSha256: signatureIdentity.sha256 }; delete expected.dependencies;
  const directory = join(root, 'baseline'); await mkdir(directory);
  const derivative = versionOnlyDerivative(originalPackage), baselineBytes = Buffer.from('NOT AN EXECUTABLE: synthetic controlled baseline');
  const baselineArtifact = { filename: 'TEST-ONLY-osir-anywhere-2.2.0-darwin-universal.dmg', ...identity(baselineBytes), systemSignature: 'unsigned' };
  await writeFile(join(directory, baselineArtifact.filename), baselineBytes);
  const baseline = { schemaVersion: 1, kind: 'controlled-version-only-derivative', result: 'prepared', releaseEligible: false, historicalBaseline: false,
    sourceSha256: source.sourceSha256, version: BASELINE_VERSION, target: plan.target, configSha256: plan.configSha256,
    parentArtifactSha256: artifact.sha256, metadataDiff: derivative.metadataDiff, artifact: baselineArtifact, artifactSha256: baselineArtifact.sha256,
    reusedOutputs: { mode: 'compiled-checkout', compiledReceiptSha256: '', parentCompiledOutputsSha256: 'e'.repeat(64), wholeCompiledTreeVerified: true, outputsSha256: 'e'.repeat(64), rendererSha256: 'f'.repeat(64), rebuilt: false }, evidence: [] };
  const inventory = { files: files.map(file => file.path === PACKAGE_PATH ? { ...file, ...identity(derivative.changed) } : file) }; inventory.sourceSha256 = fingerprint(inventory.files);
  baseline.derivedSourceSha256 = inventory.sourceSha256;
  const evidence = await evidenceWriter(directory, baseline);
  await evidence('original-package.json', originalPackage); await evidence('derivative-package.json', derivative.changed);
  await evidence('parent-build-receipt.json', bytes(receipt)); await evidence('parent-source-provenance.json', bytes(source));
  await evidence('derivative-source-inventory.json', bytes(inventory)); await evidence('metadata-diff.json', bytes(derivative.metadataDiff));
  await evidence('compiled-receipt.json', bytes({ planSha256: fingerprint(plan), outputsSha256: baseline.reusedOutputs.outputsSha256 }));
  baseline.reusedOutputs.compiledReceiptSha256 = (await fileIdentity(join(directory, 'compiled-receipt.json'))).sha256;
  await evidence('baseline-system-signature.json', bytes({ ...signature, artifactSha256: baselineArtifact.sha256 }));
  baseline.systemSignatureReportSha256 = (await fileIdentity(join(directory, 'baseline-system-signature.json'))).sha256;
  const baselineReceiptPath = join(directory, 'baseline-receipt.json'); await writeFile(baselineReceiptPath, bytes(baseline));
  const spec = { schemaVersion: 1, buildReceiptPath, finalInstallerPath, systemSignatureReportPath, expected, runner: { nativeMachine: 'darwin-arm64' },
    baselineReceiptPath, baselineReceiptSha256: (await fileIdentity(baselineReceiptPath)).sha256 };
  const updateBaseline = async patch => { Object.assign(baseline, patch); await writeFile(baselineReceiptPath, bytes(baseline)); spec.baselineReceiptSha256 = (await fileIdentity(baselineReceiptPath)).sha256; };
  return { root, directory, spec, baseline, source, derivative, updateBaseline };
}

function discoveryFixture() {
  return { kind: 'packaged-native-service-integration', syntheticManifest: true, temporaryTestKey: true, serverVersionUnchanged: true,
    actualVersions: { desktop: '2.2.1', manifestBaseline: '2.2.1', manifestPatch: '2.2.2', serverBefore: '2.2.0', serverAfter: '2.2.0' },
    baseline: { available: false }, patch: { available: true, latestVersion: '2.2.2', error: null }, invalidSignature: { error: 'checkFailed' },
    packageVersion: '2.2.1', packaged: true, electron: '39.2.7', serviceSha256: 'a'.repeat(64), servicePath: '/synthetic/app.asar/dist/electron/desktop-updates.js',
    requests: ['control-health', 'manifest', 'manifest', 'health', 'manifest', 'control-health'].map(kind => ({ kind, version: kind.endsWith('health') ? '2.2.0' : '2.2.1', method: 'GET', transport: 'synthetic-fetcher' })), installerCalls: 0 };
}

test('CLI requires known modes, absolute fresh paths and no hidden isolation bypass flags', () => {
  assert.deepEqual(parseArguments(['run', '--spec', '/a.json', '--output', '/out']), { action: 'run', spec: '/a.json', output: '/out' });
  for (const args of [['run', '--spec', 'relative', '--output', '/out'], ['run', '--spec', '/a', '--spec', '/b'], ['run', '--spec', '/a', '--output', '/b', '--skip-validation', '1'], ['_isolated']]) assert.throws(() => parseArguments(args));
});

test('baseline changes one version token, preserving Unicode, formatting and every other byte', () => {
  const { changed, metadataDiff } = versionOnlyDerivative(originalPackage);
  assert.equal(changed.toString(), originalPackage.toString().replace('"2.2.1"', '"2.2.0"'));
  assert.equal(metadataDiff.length, 1); assert.equal(metadataDiff[0].pointer, '/version');
  assert.equal(changed.subarray(metadataDiff[0].byteOffset, metadataDiff[0].byteOffset + 5).toString(), '2.2.0');
  for (const source of [originalPackage.toString().replace('"2.2.1"', '"2.2.0"'), originalPackage.toString().replace('"version":', '"nested":{"version":"2.2.1"},"version":')]) assert.throws(() => versionOnlyDerivative(Buffer.from(source)));
});

test('independent copy rebases contained links, shares no files and rejects escaping links', async t => {
  const f = await fixture(t), source = join(f.root, 'source'), copy = join(f.root, 'copy');
  await mkdir(source); await mkdir(copy); await writeFile(join(source, 'data'), 'frozen'); await symlink(join(source, 'data'), join(source, 'link'));
  await copyIndependent(join(source, 'data'), join(copy, 'data'), source, copy);
  await copyIndependent(join(source, 'link'), join(copy, 'link'), source, copy);
  assert.equal(await realpath(join(copy, 'link')), join(copy, 'data'));
  await writeFile(join(copy, 'data'), 'derived'); assert.equal(await readFile(join(source, 'data'), 'utf8'), 'frozen');
  assert.equal((await lstat(join(copy, 'data'))).nlink, 1);
  await symlink(f.spec.finalInstallerPath, join(source, 'escape'));
  await assert.rejects(copyIndependent(join(source, 'escape'), join(copy, 'escape'), source, copy), /escapes/);
});

test('derivative inventory rejects any non-version change', async t => {
  const f = await fixture(t), copy = join(f.root, 'source-copy');
  await mkdir(dirname(join(copy, PACKAGE_PATH)), { recursive: true }); await mkdir(join(copy, 'connector'));
  await writeFile(join(copy, PACKAGE_PATH), f.derivative.changed, { mode: 0o644 }); await writeFile(join(copy, 'connector/synthetic.txt'), 'same', { mode: 0o644 });
  assert.equal((await derivativeInventory(f.source, copy, f.derivative.metadataDiff)).sourceSha256, f.baseline.derivedSourceSha256);
  await writeFile(join(copy, 'connector/synthetic.txt'), 'mutated');
  await assert.rejects(derivativeInventory(f.source, copy, f.derivative.metadataDiff), /Non-version/);
});

test('Windows retains source executable metadata without claiming POSIX mode verification', async t => {
  const f = await fixture(t), copy = join(f.root, 'windows-source-copy');
  await mkdir(dirname(join(copy, PACKAGE_PATH)), { recursive: true }); await mkdir(join(copy, 'connector'));
  await writeFile(join(copy, PACKAGE_PATH), f.derivative.changed, { mode: 0o644 }); await writeFile(join(copy, 'connector/synthetic.txt'), 'same', { mode: 0o644 });
  const source = { ...f.source, files: f.source.files.map(file => file.path.startsWith('connector/') ? { ...file, executable: true } : file) };
  const inventory = await derivativeInventory(source, copy, f.derivative.metadataDiff, 'win32');
  assert.equal(inventory.files.find(file => file.path.startsWith('connector/')).executable, true);
  if (process.platform !== 'win32') await assert.rejects(derivativeInventory(source, copy, f.derivative.metadataDiff), /Non-version/);
});

test('baseline transfer binds the same harness/run/machine and detects tampering before installation', async t => {
  const f = await fixture(t), output = join(f.root, 'baseline-bundle');
  const harness = { commit: 'd'.repeat(40), runId: 42, runAttempt: 1 };
  const transfer = await sealBaseline(f.spec, f.directory, output, harness);
  assert.equal(transfer.files.length, f.baseline.evidence.length + 2);
  const spec = await transferredRunSpec(f.spec, output, harness);
  assert.equal(spec.baselineReceiptSha256, f.spec.baselineReceiptSha256);
  await assert.rejects(transferredRunSpec(f.spec, output, { ...harness, runAttempt: 2 }), /different harness/);
  await assert.rejects(transferredRunSpec({ ...f.spec, runner: { nativeMachine: 'darwin-x64' } }, output, harness), /machine/);
  await writeFile(join(output, 'unexpected.json'), '{}');
  await assert.rejects(transferredRunSpec(f.spec, output, harness), /Unexpected/);
  await rm(join(output, 'unexpected.json'));
  await writeFile(join(output, f.baseline.artifact.filename), 'tampered');
  await assert.rejects(transferredRunSpec(f.spec, output, harness));
});

test('CI collector preserves raw failure evidence and refuses synthetic native passing claims', async t => {
  const f = await fixture(t), directory = join(f.root, 'synthetic-result'); await mkdir(directory);
  const raw = Buffer.from('actual failure log'); await writeFile(join(directory, 'probe.log'), raw);
  const report = { ...f.spec.expected, schemaVersion: 1, scope: 'native-upgrade-acceptance', evidenceMode: 'synthetic', result: 'simulated',
    nativeMachines: ['darwin-arm64'], checks: { upgradeDataPreserved: false, updateDiscovery: false }, evidence: [{ path: 'probe.log', ...identity(raw) }] };
  await writeFile(join(directory, 'native-upgrade-acceptance.json'), bytes(report));
  await mkdir(join(directory, 'work')); await writeFile(join(directory, 'work/private-temporary-file'), 'not collected');
  const collected = await collectRaw(f.spec, directory, join(f.root, 'collected'), { runId: 42 }, 'run');
  assert.equal(collected.result, 'failed'); assert.match(collected.failures.join(','), /not actually passed/);
  assert.equal(await readFile(join(f.root, 'collected/probe.log'), 'utf8'), raw.toString());
  await assert.rejects(lstat(join(f.root, 'collected/work')), { code: 'ENOENT' });
});

test('spec pins final 2.2.1, original receipt and explicit extraction inputs', async t => {
  const f = await fixture(t); assert.equal(validateSpec(f.spec), f.spec);
  assert.throws(() => validateSpec({ ...f.spec, expected: { ...f.spec.expected, version: '2.2.0' } }));
  const source = { checkout: '/frozen', compiledReceiptPath: '/compiled.json', compiledReceiptSha256: 'a'.repeat(64), mode: 'final-installer-copy', dependencyLockPath: '/resolved-yarn.lock' };
  assert.doesNotThrow(() => validateSpec({ ...f.spec, baselineSource: source }, 'prepare-baseline'));
  assert.throws(() => validateSpec({ ...f.spec, baselineSource: { ...source, dependencyLockPath: undefined } }, 'prepare-baseline'));
});

test('controlled baseline binds source, original final bytes, exact metadata diff and raw evidence', async t => {
  const f = await fixture(t); assert.equal((await bindBaseline(f.spec)).baseline.kind, 'controlled-version-only-derivative');
  await f.updateBaseline({ historicalBaseline: true }); await assert.rejects(bindBaseline(f.spec), /controlled baseline/);
  await f.updateBaseline({ historicalBaseline: false, parentArtifactSha256: '0'.repeat(64) }); await assert.rejects(bindBaseline(f.spec), /different final/);
});

test('changed evidence, changed baseline bytes and path escapes fail before native execution', async t => {
  for (const mutation of ['evidence', 'artifact', 'path']) {
    const f = await fixture(t);
    if (mutation === 'evidence') await writeFile(join(f.directory, 'metadata-diff.json'), '{}');
    if (mutation === 'artifact') await writeFile(join(f.directory, f.baseline.artifact.filename), 'changed');
    if (mutation === 'path') await f.updateBaseline({ artifact: { ...f.baseline.artifact, filename: '../escape.dmg' } });
    await assert.rejects(bindBaseline(f.spec));
  }
});

test('Electron version comes from the SHA-bound resolved lock, not a semver range/guess', () => {
  assert.equal(electronFromLock('"electron@npm:^39.2.7":\n  resolution: "electron@npm:39.2.7"\n'), '39.2.7');
  assert.throws(() => electronFromLock('electron: ^39.2.7'));
  assert.throws(() => electronFromLock('  resolution: "electron@npm:39.2.7"\n  resolution: "electron@npm:40.0.0"\n'));
});

test('small ASAR extraction reuses shipped renderer/runtime bytes and preserves contained resource links', async t => {
  const f = await fixture(t), source = join(f.root, 'asar-input'), raw = join(f.root, 'raw-asar'), resources = join(f.root, 'resources'), copy = join(f.root, 'packaged-copy');
  for (const name of ['dist/electron', 'renderer/out', 'node_modules/synthetic']) await mkdir(join(source, name), { recursive: true });
  await writeFile(join(source, 'dist/electron/main.js'), '/* synthetic; never executed */');
  await writeFile(join(source, 'renderer/out/index.html'), '<p>synthetic</p>');
  await writeFile(join(source, 'node_modules/synthetic/package.json'), '{"name":"synthetic","version":"0.0.0"}');
  for (const name of ['uv', 'python']) { await mkdir(join(resources, name), { recursive: true }); await writeFile(join(resources, name, 'synthetic-data'), 'not executable'); }
  await symlink('synthetic-data', join(resources, 'python/alias'));
  const require = createRequire(import.meta.url), asar = require('@electron/asar'), archive = join(f.root, 'tiny-synthetic.asar');
  await asar.createPackage(source, archive); assert.ok((await lstat(archive)).size < 8192);
  asar.extractAll(archive, raw);
  const subsets = await reuseExtractedRuntime(raw, resources, copy);
  assert.equal(subsets.length, 5);
  for (const name of ['dist', 'renderer/out', 'node_modules']) assert.equal(await fingerprintTree(join(source, name)), await fingerprintTree(join(copy, name)));
  assert.equal(await realpath(join(copy, 'build/python/alias')), join(copy, 'build/python/synthetic-data'));
  await writeFile(join(copy, 'renderer/out/index.html'), 'independent');
  assert.equal(await readFile(join(source, 'renderer/out/index.html'), 'utf8'), '<p>synthetic</p>');
});

test('report rejects Server-coupled discovery, bad signatures, downloads and non-packaged services', () => {
  assert.deepEqual([BASELINE_VERSION, FINAL_VERSION, PATCH_VERSION, SERVER_VERSION], ['2.2.0', '2.2.1', '2.2.2', '2.2.0']);
  assert.doesNotThrow(() => validateDiscovery(discoveryFixture()));
  const coupled = { ...discoveryFixture(), actualVersions: { ...discoveryFixture().actualVersions, serverBefore: '2.2.1', serverAfter: '2.2.1' } };
  assert.throws(() => validateDiscovery(coupled), /version observations/);
  const wrongHealth = discoveryFixture(); wrongHealth.requests.find(r => r.kind === 'health').version = '2.2.1';
  assert.throws(() => validateDiscovery(wrongHealth), /unexpected request/);
  for (const patch of [{ serverVersionUnchanged: false }, { actualVersions: { ...discoveryFixture().actualVersions, serverAfter: '2.2.2' } }, { invalidSignature: { error: null } }, { installerCalls: 1 }, { packaged: false }, { servicePath: '/source/desktop-updates.js' }, { requests: [] }]) assert.throws(() => validateDiscovery({ ...discoveryFixture(), ...patch }));
});

function fakeAdapter(context, { corruptData = false, badDiscovery = false } = {}) {
  let snapshots = 0;
  return { hardware: async () => {}, installBaseline: async () => ({}), seedBaseline: async () => ({ synthetic: true }),
    snapshot: async () => [{ path: 'notes.json', size: 4, sha256: corruptData && ++snapshots > 1 ? '0'.repeat(64) : '1'.repeat(64) }],
    installFinal: async () => ({}), verifyFinal: async () => ({ dataPreserved: true, baselineVersion: '2.2.0', finalVersion: '2.2.1', sameInstallPath: true, sameUserData: true, rendererStoragePreserved: true }),
    discovery: async () => ({ ...discoveryFixture(), installerCalls: badDiscovery ? 1 : 0 }) };
}

test('injected orchestration never claims native passing checks, even if simulated observations pass', async t => {
  const f = await fixture(t), output = join(f.root, 'simulation');
  const report = await runAcceptance(f.spec, output, { adapterFactory: fakeAdapter, isolationVerifier: async () => ({ home: '/synthetic' }) });
  assert.equal(report.result, 'simulated'); assert.equal(report.evidenceMode, 'synthetic');
  assert.deepEqual(report.checks, { upgradeDataPreserved: false, updateDiscovery: false });
  assert.deepEqual(report.simulatedChecks, { upgradeDataPreserved: true, updateDiscovery: true });
  assert.throws(() => validateNativeReport(report, f.spec.expected, 'native-upgrade-acceptance'), /Only passed native reports/);
  for (const item of report.evidence) assert.deepEqual(await fileIdentity(join(output, item.path)), { size: item.size, sha256: item.sha256 });
  await assert.rejects(runAcceptance(f.spec, output));
});

test('data loss and false PATCH observations cannot become passed reports', async t => {
  for (const options of [{ corruptData: true }, { badDiscovery: true }]) {
    const f = await fixture(t), report = await runAcceptance(f.spec, join(f.root, 'failed'), { adapterFactory: context => fakeAdapter(context, options), isolationVerifier: async () => ({ home: '/synthetic' }) });
    assert.equal(report.result, 'failed'); assert.deepEqual(report.checks, { upgradeDataPreserved: false, updateDiscovery: false }); assert.ok(report.failure);
  }
});

test('missing native authorization produces a truthful failed report without installing or launching', async t => {
  if (process.env.GITHUB_ACTIONS === 'true') return t.skip('Local refusal control; native CI uses real authorized mode');
  const f = await fixture(t), report = await runAcceptance(f.spec, join(f.root, 'native-refusal'));
  assert.equal(report.result, 'failed'); assert.equal(report.evidenceMode, 'native');
  assert.deepEqual(report.nativeMachines, []); assert.deepEqual(report.execution, { baselineInstallAttempted: false, finalInstallAttempted: false });
  assert.deepEqual(report.checks, { upgradeDataPreserved: false, updateDiscovery: false });
  await assert.rejects(prepareBaseline({ ...f.spec, baselineSource: { checkout: f.root, compiledReceiptPath: '/compiled', compiledReceiptSha256: 'a'.repeat(64) } }, join(f.root, 'must-not-build')), /GitHub-hosted/);
});

test('serialized probe exercises the real DesktopUpdateService source in synthetic Electron context', async t => {
  const f = await fixture(t), require = createRequire(import.meta.url), ts = require('typescript');
  const checkout = process.env.OSIR_UPGRADE_TEST_SOURCE_ROOT;
  if (process.env.GITHUB_ACTIONS === 'true') assert.ok(checkout, 'CI must explicitly supply the reviewed frozen product test checkout');
  const sources = checkout ? await discoveryTestSources(checkout, reviewedBindings(process.env.OSIR_ACCEPTANCE_BINDINGS, process.env.OSIR_ACCEPTANCE_BINDINGS_SHA256)) : null;
  const electronRoot = fileURLToPath(new URL('../electron/', import.meta.url));
  const cache = new Map();
  const load = name => {
    if (name === './update-installer-native') return { prepareNativeInstaller: async () => { throw new Error('No native calls permitted in this unit fixture'); }, InstallerNativeValidationError: Error };
    if (name.startsWith('node:')) return require(name);
    assert.match(name, /^\.\/[a-z-]+$/);
    if (cache.has(name)) return cache.get(name).exports;
    const file = join(electronRoot, `${name.slice(2)}.ts`), module = { exports: {} }; cache.set(name, module);
    const source = sources ? sources.get(name) : readFileSync(file, 'utf8');
    assert.equal(typeof source, 'string', `Missing reviewed discovery test module: ${name}`);
    const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true } }).outputText;
    vm.runInNewContext('(function(require,module,exports){' + compiled + '\n})', { Buffer, URL, AbortController, TextDecoder, Response, setTimeout, clearTimeout, process }, { filename: file })(load, module, module.exports);
    return module.exports;
  };
  const resourceRoot = process.platform === 'win32' ? 'C:\\controlled\\Resources' : '/controlled/Resources';
  const service = load('./desktop-updates'), servicePath = join(resourceRoot, 'app.asar/dist/electron/desktop-updates.js');
  const probeRequire = name => {
    if (name === 'electron') return { app: { isPackaged: true, getVersion: () => '2.2.1', getPath: () => f.root } };
    if (name === servicePath) return service;
    if (name === './dist/electron/release-manifest.js') return load('./release-manifest');
    if (name === './package.json') return { version: '2.2.1' };
    if (name === 'node:fs') return { ...require(name), readFileSync: (file, ...args) => file === servicePath ? Buffer.from('synthetic-packaged-service-bytes') : require(name).readFileSync(file, ...args) };
    return require(name);
  };
  probeRequire.resolve = name => { assert.equal(name, './dist/electron/desktop-updates.js'); return servicePath; };
  const runtimeProcess = { resourcesPath: resourceRoot, platform: process.platform === 'win32' ? 'win32' : 'darwin', arch: process.arch, versions: { electron: '39.2.7' }, getBuiltinModule: () => ({ createRequire: () => probeRequire }) };
  const result = await vm.runInNewContext(`(${packagedDiscoveryProbe.toString()})()`, { process: runtimeProcess, Response, Buffer });
  assert.deepEqual(Array.from(result.requests, request => `${request.kind}:${request.method}`), ['control-health:GET', 'manifest:GET', 'manifest:GET', 'health:GET', 'manifest:GET', 'control-health:GET']);
  validateDiscovery(JSON.parse(JSON.stringify(result)));
  assert.equal(result.privateKeyPersisted, false); assert.equal(result.installerCalls, 0);
  for (const [i, envelope] of result.envelopes.entries()) {
    assert.equal(verify('RSA-SHA256', Buffer.from(envelope.payload, 'base64'), result.publicKeyPem, Buffer.from(envelope.signature, 'base64')), i < 2);
    assert.equal(JSON.parse(Buffer.from(envelope.payload, 'base64')).minimumServerVersion, '2.2.0');
  }
  assert.ok(result.requests.every(request => request.method === 'GET'));
  assert.equal(result.requests.filter(request => request.kind === 'health').length, 1);
  assert.equal(Object.keys(result).some(key => /privatekey/i.test(key) && key !== 'privateKeyPersisted'), false);
  assert.equal(SEED_SETTINGS.startConnectorOnLaunch, false);
});


test('account-free Mac fixture isolates ad-hoc keychain prompts without claiming credential migration', () => {
  const mac = syntheticUpgradeLaunch('darwin');
  assert.deepEqual(mac.args, ['--inspect=127.0.0.1:0', '--use-mock-keychain']);
  assert.equal(mac.secretStore, 'chromium-mock-keychain-synthetic-only');
  assert.equal(mac.credentialMigrationCovered, false);
  assert.equal(mac.realAccounts, false); assert.equal(mac.realOAuth, false);
  assert.equal(mac.keychainPromptRootCauseProven, false);
  const win = syntheticUpgradeLaunch('win32');
  assert.deepEqual(win.args, ['--inspect=127.0.0.1:0']);
  assert.equal(win.secretStore, 'native-windows');
  assert.throws(() => syntheticUpgradeLaunch('linux'), /Unsupported/);
});
