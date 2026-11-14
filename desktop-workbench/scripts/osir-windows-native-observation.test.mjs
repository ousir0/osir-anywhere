import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { observeSmokeGui } from './osir-native-smoke-provision.mjs';
import { HARNESS_FILES } from './osir-artifact-acceptance-ci.mjs';
import { REVIEW_FILES } from './osir-native-upgrade-acceptance.ci.mjs';
import { command } from './osir-native-smoke.mjs';
import { observeUpgradeGui } from './osir-native-upgrade-acceptance.runtime.mjs';
import { GUI_PHASES, GUI_TIMEOUT_MS, NSIS_OBSERVE_AT_MS, NSIS_TIMEOUT_MS, PROCESS_PROBE_TIMEOUT_MS, observeWindowsGui, runObservedWindowsNsis, runWindowsGuiProbe, windowsGuiPhaseTrace, windowsGuiProbeScript, WINDOWS_PROCESS_OBSERVATION } from './osir-windows-native-observation.mjs';

const probeId = '1234567890abcdef';
const phaseLine = (phase, extra = {}, id = probeId) => JSON.stringify({ schemaVersion: 1, kind: 'windows-native-gui-phase', probeId: id, phase, ...extra }) + '\r\n';
const phasePrefix = count => GUI_PHASES.slice(0, count).map(phase => phaseLine(phase)).join('');

test('phase trace preserves exact bounded CRLF JSON, recognizes every active operation and complete return', () => {
  for (let count = 0; count <= GUI_PHASES.length; count++) {
    const raw = phasePrefix(count), trace = windowsGuiPhaseTrace(raw, probeId);
    assert.equal(trace.rawPhaseJsonl, raw); assert.equal(trace.rawPhaseBytes, Buffer.byteLength(raw));
    assert.equal(trace.traceValid, true); assert.equal(trace.traceComplete, count === GUI_PHASES.length);
    assert.equal(trace.lastPhase, GUI_PHASES[count - 1] ?? null);
    assert.equal(trace.nextUnconfirmedPhase, GUI_PHASES[count] ?? null);
    const last = GUI_PHASES[count - 1];
    assert.equal(trace.activeOperation, last?.endsWith('-before') ? last.slice(0, -7) : null);
    assert.ok(trace.rawPhaseBytes <= 4096);
  }
});

test('phase evidence drops non-protocol secrets, wrong nonce, extra fields, malformed and out-of-order marks', () => {
  const secret = 'mk_synthetic_secret';
  const ignored = windowsGuiPhaseTrace(secret + '\n' + phaseLine('powershell-entered', {}, 'ffffffffffffffff'), probeId);
  assert.equal(ignored.rawPhaseJsonl, ''); assert.equal(ignored.lastPhase, null);
  for (const suffix of [phaseLine('get-process-before'), phaseLine('powershell-entered'),
    phaseLine('add-type-before', { credential: secret }), phaseLine(secret),
    '{"kind":"windows-native-gui-phase","probeId":"1234567890abcdef",broken-json\n']) {
    const trace = windowsGuiPhaseTrace(phasePrefix(1) + suffix, probeId);
    assert.equal(trace.traceValid, false); assert.equal(trace.activeOperation, null); assert.equal(trace.nextUnconfirmedPhase, null);
    assert.doesNotMatch(trace.rawPhaseJsonl, /mk_synthetic|credential|broken-json/);
  }
  const oversized = windowsGuiPhaseTrace(phasePrefix(1) + ' '.repeat(10000) + phaseLine('add-type-before'), probeId);
  assert.equal(oversized.truncated, true); assert.equal(oversized.traceValid, false); assert.ok(oversized.rawPhaseBytes <= 4096);
});

test('probe script marks every original operation without changing the desktop predicate or interpolation boundary', () => {
  const script = windowsGuiProbeScript(2748, probeId);
  let position = -1;
  for (const phase of GUI_PHASES) {
    const next = script.indexOf(`"phase":"${phase}"`); assert.ok(next > position); position = next;
  }
  assert.ok(script.indexOf('powershell-entered') < script.indexOf('Add-Type -TypeDefinition'));
  assert.match(script, /if\(\$s -le 0 -or \$h -eq \[IntPtr\]::Zero -or -not \[Environment\]::UserInteractive\)/);
  assert.match(script, /OpenInputDesktop\(0,\$false,1\)/); assert.match(script, /\$guiProcess=Get-Process -Id 2748;/);
  assert.match(script, /\$s=\$guiProcess.SessionId;/); assert.match(script, /processId=2748/);
  assert.doesNotMatch(script, /Start-Process|Stop-Process|Set-ExecutionPolicy|Get-Credential|Get-CimInstance|CommandLine/);
  assert.equal(GUI_TIMEOUT_MS, 30000);
  assert.throws(() => windowsGuiProbeScript('2748;exit 0', probeId), /PID/);
  assert.throws(() => windowsGuiProbeScript(2748, "x';exit 0"), /observation ID/);
});

function probeRunner({ count = 0, code = 1, stdout = '', spawn = true, fail } = {}) {
  const calls = [];
  const run = async (...args) => {
    calls.push(args); if (spawn) args[2].onSpawn({ pid: 9001 });
    const result = { executable: args[0], args: args[1], code, signal: null, stdout, stderr: phasePrefix(count) };
    if (fail) throw Object.assign(fail, { commandResult: result });
    return result;
  };
  return { run, calls };
}

test('missing entry marker distinguishes observed spawn from launch not observed without claiming an API stalled', async () => {
  for (const spawn of [false, true]) {
    const f = probeRunner({ spawn, fail: Error('Native command timed out') });
    await assert.rejects(runWindowsGuiProbe({}, f.run, 2748, { probeId }), error => {
      assert.equal(error.probeObservation.location, spawn ? 'spawned-before-first-powershell-marker' : 'process-spawn-not-observed');
      assert.equal(error.probeObservation.spawnObserved, spawn); assert.equal(error.probeObservation.lastPhase, null);
      assert.equal(error.probeObservation.rawPhaseJsonl, ''); return true;
    });
    assert.equal(f.calls.length, 1); assert.equal(f.calls[0][2].timeout, 30000);
  }
});

for (const operation of ['add-type', 'get-process', 'session-id', 'open-input-desktop', 'desktop-predicate', 'close-desktop', 'result-json']) {
  test(`timeout attributes only the entered but unreturned ${operation} span`, async () => {
    const count = GUI_PHASES.indexOf(`${operation}-before`) + 1;
    const failure = Error('Native command timed out'), f = probeRunner({ count, code: 0, stdout: JSON.stringify({ processId: 2748, sessionId: 2, interactiveDesktop: true }), fail: failure });
    await assert.rejects(runWindowsGuiProbe({}, f.run, 2748, { probeId }), error => {
      assert.equal(error, failure); assert.equal(error.probeObservation.location, operation);
      assert.equal(error.probeObservation.rawPhaseJsonl, phasePrefix(count)); return true;
    });
    assert.equal(f.calls[0][2].timeout, 30000); assert.equal(f.calls.length, 1);
  });
}

test('completed phases never replace exit/PID/session/interactive checks, and original rejection is not retried', async () => {
  for (const value of [{ processId: 9999, sessionId: 2, interactiveDesktop: true },
    { processId: 2748, sessionId: 0, interactiveDesktop: true }, { processId: 2748, sessionId: 2, interactiveDesktop: false }]) {
    const f = probeRunner({ count: GUI_PHASES.length, code: 0, stdout: JSON.stringify(value) });
    await assert.rejects(runWindowsGuiProbe({}, f.run, 2748, { probeId }), error => {
      assert.match(error.message, /Invalid live Windows GUI/); assert.equal(error.probeObservation.traceComplete, true); return true;
    });
  }
  const f = probeRunner({ count: GUI_PHASES.length, code: 1, stdout: JSON.stringify({ processId: 2748, sessionId: 2, interactiveDesktop: true }) });
  const records = [];
  await assert.rejects(observeWindowsGui(() => runWindowsGuiProbe({}, f.run, 2748, { probeId }), async (_name, raw) => records.push(JSON.parse(raw)), 'runner-gui'), /No native Windows GUI/);
  assert.equal(f.calls.length, 1); assert.equal(records[0].probeObservation.traceComplete, true);
});

test('success keeps original GUI identity, while smoke/recheck and upgrade failures retain raw phase JSON', async t => {
  const value = { platform: 'win32', processId: 2748, sessionId: 2, interactiveDesktop: true, basis: 'live-input-desktop-and-session' };
  const success = probeRunner({ count: GUI_PHASES.length, code: 0, stdout: JSON.stringify(value) });
  const result = await runWindowsGuiProbe({}, success.run, 2748, { probeId });
  const { probeObservation, ...identity } = result; assert.deepEqual(identity, value); assert.equal(probeObservation.traceComplete, true);
  const dir = await mkdtemp(join(tmpdir(), 'osir-gui-phase-unit-')); t.after(() => rm(dir, { recursive: true, force: true }));
  for (const stage of ['runner-gui', 'runner-gui-recheck']) {
    const f = probeRunner({ count: 2, fail: Error('Native command timed out') });
    await assert.rejects(observeSmokeGui({}, dir, stage, { platform: 'win32', probe: () => runWindowsGuiProbe({}, f.run, 2748, { probeId }) }));
    for (const n of [1, 2]) assert.equal(JSON.parse(await readFile(join(dir, `${stage}-attempt-${n}.json`))).probeObservation.location, 'add-type');
    assert.equal(f.calls.length, 2);
  }
  const f = probeRunner({ count: 6, fail: Error('Native command timed out') }), records = [];
  await assert.rejects(observeUpgradeGui({}, async (_name, raw) => records.push(JSON.parse(raw)), () => runWindowsGuiProbe({}, f.run, 2748, { probeId }), 'win32'));
  assert.equal(records.length, 2); assert.ok(records.every(row => row.probeObservation.rawPhaseJsonl === phasePrefix(6)));
});

test('real synthetic Node child proves spawn callback and flushed timeout evidence survive command cleanup', async () => {
  const records = []; const stderr = phasePrefix(2);
  const run = (exe, args, options) => {
    assert.equal(exe, 'powershell.exe'); assert.equal(options.timeout, 30000);
    return command(process.execPath, ['-e', `process.stderr.write(${JSON.stringify(stderr)});setInterval(()=>{},1000)`], { ...options, timeout: 750 });
  };
  await assert.rejects(runWindowsGuiProbe({}, run, process.pid, { probeId }), error => {
    records.push(error.probeObservation); assert.equal(error.message, 'Native command timed out');
    assert.equal(error.probeObservation.spawnObserved, true); assert.equal(error.probeObservation.location, 'add-type');
    assert.equal(error.probeObservation.rawPhaseJsonl, stderr); assert.ok(error.probeObservation.spawned.pid > 0); return true;
  });
  let calls = 0;
  await assert.rejects(command(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { env: {}, timeout: 2000, onSpawn: () => { calls++; throw Error('synthetic observer failure'); } }), /spawn observation failed/);
  assert.equal(calls, 1); assert.equal(records.length, 1);
});

const gui = { platform: 'win32', processId: 2748, sessionId: 2, interactiveDesktop: true };
const timeout = () => Object.assign(Error('Native command timed out'), { commandResult: {
  executable: 'powershell.exe', args: ['-NoProfile', '-NonInteractive', '-Command', 'synthetic probe'],
  code: 1, signal: null, stdout: JSON.stringify(gui), stderr: '' } });
const sink = records => async (name, raw) => { records.push({ name, ...JSON.parse(raw) }); };

test('Windows GUI timeout retains cleanup status and retries only a fresh live probe', async () => {
  const records = []; let calls = 0;
  const result = await observeWindowsGui(async () => { if (++calls === 1) throw timeout(); return gui; }, sink(records), 'runner-gui');
  assert.equal(result, gui); assert.equal(calls, 2);
  assert.equal(records[0].result, 'failed'); assert.equal(records[0].timeoutMs, 30000);
  assert.equal(records[0].command.exitObservedAfterTimeoutCleanup, true);
  assert.equal(records[0].command.code, 1); assert.equal(records[0].command.stdout, JSON.stringify(gui));
  assert.equal(records[1].result, 'passed');
});

test('repeated GUI timeouts never reach a downstream installer and both attempts survive', async () => {
  const records = [], failure = timeout(); let launched = false;
  await assert.rejects(async () => {
    await observeWindowsGui(async () => { throw failure; }, sink(records), 'runner-gui'); launched = true;
  }, error => error === failure);
  assert.equal(launched, false); assert.equal(records.length, 2);
  assert.ok(records.every(row => row.result === 'failed'));
});

for (const message of ['No native Windows GUI: denied', 'Invalid live Windows GUI provenance', 'Native command output exceeded limit', 'spawn powershell.exe ENOENT']) {
  test(`GUI does not retry ${message}`, async () => {
    const records = [], failure = Error(message); let calls = 0;
    await assert.rejects(observeWindowsGui(async () => { calls++; throw failure; }, sink(records), 'runner-gui'), error => error === failure);
    assert.equal(calls, 1); assert.equal(records.length, 1);
  });
}

test('GUI stderr is bounded/redacted, and evidence write failure prevents a retry', async () => {
  const records = [], failure = timeout(); failure.commandResult.stderr = 'mk_synthetic_key ' + 'x'.repeat(20000);
  await assert.rejects(observeWindowsGui(async () => { throw failure; }, sink(records), 'runner-gui'));
  assert.equal(records[0].command.stderr.length, 4096); assert.equal(records[0].command.streamsTruncated, true);
  assert.doesNotMatch(records[0].command.stderr, /mk_synthetic/);
  let calls = 0;
  await assert.rejects(observeWindowsGui(async () => { calls++; throw timeout(); }, async () => { throw Error('disk full'); }, 'runner-gui'), /disk full/);
  assert.equal(calls, 1);
});

test('smoke initial/recheck persist disjoint raw files; Mac probe is unchanged and has no retry', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'osir-windows-observation-unit-')); t.after(() => rm(directory, { recursive: true, force: true }));
  for (const stage of ['runner-gui', 'runner-gui-recheck']) {
    let calls = 0;
    assert.equal(await observeSmokeGui({}, directory, stage, { platform: 'win32', probe: async () => { if (++calls === 1) throw timeout(); return gui; } }), gui);
    assert.equal(JSON.parse(await readFile(join(directory, `${stage}-attempt-1.json`))).result, 'failed');
  }
  assert.equal((await readdir(directory)).length, 4);
  let calls = 0; const failure = timeout();
  await assert.rejects(observeSmokeGui({}, directory, 'runner-gui', { platform: 'darwin', probe: async () => { calls++; throw failure; } }), error => error === failure);
  assert.equal(calls, 1); assert.equal((await readdir(directory)).length, 4);
  await assert.rejects(observeWindowsGui(async () => gui, async () => {}, '../bad-stage'), /Unknown/);
});

function nsisFixture() {
  const records = [], probes = [], runs = [], clock = { value: 0 }; let timer, cancelled = false;
  const adapter = { env: { PATH: 'synthetic-system-path' }, evidence: sink(records),
    run: async (...args) => { runs.push(args); return 'installer completed'; } };
  const observation = { schemaVersion: 1, queryOnly: true, processes: [], matchedCount: 0 };
  const options = { platform: 'win32', now: () => clock.value,
    command: async (...args) => { probes.push(args); return { code: 0, stdout: JSON.stringify(observation), stderr: '' }; },
    schedule: (callback, delay) => { timer = { callback, delay }; return timer; }, cancel: handle => { assert.equal(handle, timer); cancelled = true; } };
  const execute = () => runObservedWindowsNsis(adapter, 'D:\\original\\final.exe', 'D:\\work\\installed', 'final-nsis-install', options);
  return { records, probes, runs, clock, adapter, options, execute, get timer() { return timer; }, get cancelled() { return cancelled; } };
}

test('NSIS keeps exact original install flags, one attempt and the existing 180s bound', async () => {
  const f = nsisFixture(); assert.equal(await f.execute(), 'installer completed');
  assert.equal(f.runs.length, 1);
  assert.deepEqual(f.runs[0], ['D:\\original\\final.exe', ['/S', '/currentuser', '/D=D:\\work\\installed'], 'final-nsis-install', { timeout: 180000 }]);
  assert.equal(f.probes.length, 1); assert.equal(f.cancelled, true);
  assert.equal(f.timer.delay, 150000); assert.equal(NSIS_TIMEOUT_MS, 180000);
  assert.equal(NSIS_OBSERVE_AT_MS + PROCESS_PROBE_TIMEOUT_MS < NSIS_TIMEOUT_MS, true);
  assert.equal(f.records.at(-1).result, 'completed');
});

test('slow NSIS captures scoped process evidence before cleanup and rethrows the exact timeout', async () => {
  const f = nsisFixture(), failure = timeout(); failure.commandResult.executable = 'D:\\original\\final.exe';
  f.adapter.run = async (...args) => { f.runs.push(args); f.clock.value = 150000; f.timer.callback(); await Promise.resolve(); f.clock.value = 180000; throw failure; };
  await assert.rejects(f.execute(), error => error === failure);
  assert.equal(f.runs.length, 1); assert.equal(f.probes.length, 2);
  assert.ok(f.records.some(row => row.phase === 'slow' && row.result === 'observed'));
  assert.equal(f.records.at(-1).commandElapsedMs, 180000);
  assert.equal(f.records.at(-1).command.exitObservedAfterTimeoutCleanup, true);
  for (const [exe, args, options] of f.probes) {
    assert.equal(exe, 'powershell.exe'); assert.equal(args.at(-1), WINDOWS_PROCESS_OBSERVATION);
    assert.equal(options.timeout, 10000); assert.equal(options.env.OSIR_NATIVE_DIAGNOSTIC_INSTALLER, 'D:\\original\\final.exe');
    assert.equal(options.env.OSIR_NATIVE_DIAGNOSTIC_DESTINATION, 'D:\\work\\installed');
  }
});

test('diagnostic timeout cannot certify installation or swallow the original installer failure', async () => {
  const f = nsisFixture(), failure = Error('Native final-nsis-install failed (exit 7)');
  f.options.command = async () => { throw timeout(); };
  f.adapter.run = async (...args) => { f.runs.push(args); throw failure; };
  await assert.rejects(f.execute(), error => error === failure);
  assert.equal(f.records[1].result, 'unavailable'); assert.equal(f.records[1].acceptanceEvidence, false);
  assert.equal(f.records.at(-1).result, 'failed'); assert.equal(f.runs.length, 1);
});

for (const stdout of ['broken-json', JSON.stringify({ schemaVersion: 1, queryOnly: false, processes: [] }),
  JSON.stringify({ schemaVersion: 1, queryOnly: true, processes: Array(129).fill({}) }), 'x'.repeat(65537)]) {
  test(`invalid/oversized diagnostic is explicitly unavailable (${stdout.length} bytes)`, async () => {
    const f = nsisFixture(); f.options.command = async () => ({ code: 0, stdout, stderr: '' });
    await f.execute(); assert.equal(f.records[1].result, 'unavailable'); assert.equal(f.records[1].acceptanceEvidence, false);
    assert.equal(f.runs.length, 1);
  });
}

test('failed diagnostic evidence writes prevent installation; slow write errors cannot mask installer failure', async () => {
  const f = nsisFixture(); f.adapter.evidence = async name => { if (name.includes('processes-')) throw Error('disk full'); };
  await assert.rejects(f.execute(), /disk full/); assert.equal(f.runs.length, 0);
  const g = nsisFixture(), failure = timeout();
  g.adapter.evidence = async (name, raw) => { if (name.endsWith('processes-slow.json')) throw Error('disk full'); await sink(g.records)(name, raw); };
  g.adapter.run = async () => { g.timer.callback(); await Promise.resolve(); throw failure; };
  await assert.rejects(g.execute(), error => error === failure);
  assert.equal(g.records.at(-1).diagnosticFailure, 'disk full');
});

test('native diagnostics stay Windows-only and unknown labels fail before any command', async () => {
  const f = nsisFixture(); f.options.platform = 'darwin';
  await f.execute(); assert.equal(f.probes.length, 0); assert.equal(f.records.length, 0); assert.equal(f.runs.length, 1);
  await assert.rejects(runObservedWindowsNsis(f.adapter, 'a', 'b', 'arbitrary-install', f.options), /Unknown/);
  assert.equal(f.runs.length, 1);
});

test('final stage evidence write failure retains the original installer exception', async () => {
  const f = nsisFixture(), failure = timeout();
  f.adapter.evidence = async (name, raw) => { if (name.endsWith('stage-finish.json')) throw Error('disk full'); await sink(f.records)(name, raw); };
  f.adapter.run = async () => { throw failure; };
  await assert.rejects(f.execute(), error => error === failure);
});

test('read-only process query has finite tree/row bounds and no account, command line or termination query', () => {
  assert.match(WINDOWS_PROCESS_OBSERVATION, /OperationTimeoutSec 5/);
  assert.match(WINDOWS_PROCESS_OBSERVATION, /8192/); assert.match(WINDOWS_PROCESS_OBSERVATION, /-lt 16/);
  assert.match(WINDOWS_PROCESS_OBSERVATION, /-First 128/);
  assert.doesNotMatch(WINDOWS_PROCESS_OBSERVATION, /CommandLine|Stop-Process|taskkill|Win32_Environment|Get-Credential|MainWindowTitle|Invoke-CimMethod/);
});

test('smoke and upgrade Git-byte provenance include the new transitive helper and its tests', () => {
  for (const files of [HARNESS_FILES, REVIEW_FILES]) for (const suffix of ['mjs', 'test.mjs']) {
    assert.ok(files.includes(`desktop-workbench/scripts/osir-windows-native-observation.${suffix}`));
  }
});
