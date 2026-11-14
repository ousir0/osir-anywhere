// External harness observations only: no installer retry, process termination,
// registry changes, command-line enumeration, or product acceptance shortcuts.
import { randomBytes } from 'node:crypto';

export const GUI_TIMEOUT_MS = 30000;
export const GUI_PHASES = Object.freeze(['powershell-entered', 'add-type-before', 'add-type-after',
  'get-process-before', 'get-process-after', 'session-id-before', 'session-id-after',
  'open-input-desktop-before', 'open-input-desktop-after', 'desktop-predicate-before', 'desktop-predicate-after',
  'close-desktop-before', 'close-desktop-after', 'result-json-before', 'result-json-after']);
const PHASE_KIND = 'windows-native-gui-phase';
const PHASE_BYTES = 4096;

function checkProbeId(probeId) {
  if (!/^[a-f0-9]{16}$/.test(probeId)) throw Error('Invalid GUI observation ID');
}

export function windowsGuiProbeScript(targetPid, probeId) {
  checkProbeId(probeId);
  if (!Number.isSafeInteger(targetPid) || targetPid <= 0) throw Error('Invalid GUI target PID');
  // Constant, flushed JSON only: no serialization/compiler/process lookup is
  // needed to emit the first PowerShell marker. Never mix markers into stdout.
  const mark = phase => `[Console]::Error.WriteLine('${JSON.stringify({ schemaVersion: 1, kind: PHASE_KIND, probeId, phase })}');[Console]::Error.Flush();`;
  return mark('powershell-entered') + mark('add-type-before') +
    `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class SmokeDesktop{[DllImport("user32.dll",SetLastError=true)]public static extern IntPtr OpenInputDesktop(uint f,bool i,uint a);[DllImport("user32.dll")]public static extern bool CloseDesktop(IntPtr h);}';` + mark('add-type-after') +
    mark('get-process-before') + `$guiProcess=Get-Process -Id ${targetPid};` + mark('get-process-after') +
    mark('session-id-before') + '$s=$guiProcess.SessionId;' + mark('session-id-after') +
    mark('open-input-desktop-before') + '$h=[SmokeDesktop]::OpenInputDesktop(0,$false,1);' + mark('open-input-desktop-after') +
    mark('desktop-predicate-before') + "if($s -le 0 -or $h -eq [IntPtr]::Zero -or -not [Environment]::UserInteractive){throw 'No accessible interactive Windows desktop/session'};" + mark('desktop-predicate-after') +
    mark('close-desktop-before') + '[void][SmokeDesktop]::CloseDesktop($h);' + mark('close-desktop-after') +
    mark('result-json-before') + `@{platform='win32';processId=${targetPid};sessionId=$s;interactiveDesktop=$true;basis='live-input-desktop-and-session'}|ConvertTo-Json -Compress;` + mark('result-json-after');
}

export function windowsGuiPhaseTrace(stderr, probeId) {
  checkProbeId(probeId);
  const phases = [], raw = []; let rawBytes = 0, invalid = false, truncated = false;
  for (const line of String(stderr).match(/[^\n]*(?:\n|$)/g) ?? []) {
    if (!line.trim()) continue;
    let value;
    try { value = JSON.parse(line); }
    catch { if (line.includes(PHASE_KIND) && line.includes(probeId)) invalid = true; continue; }
    if (value?.kind !== PHASE_KIND || value?.probeId !== probeId) continue;
    // Allowlisted values only; do not retain arbitrary JSON/error text, paths,
    // environment, titles, credentials or an attacker-supplied extra property.
    if (Object.keys(value).sort().join(',') !== 'kind,phase,probeId,schemaVersion' || value.schemaVersion !== 1 || value.phase !== GUI_PHASES[phases.length]) { invalid = true; continue; }
    if (Buffer.byteLength(line) > 512 || rawBytes + Buffer.byteLength(line) > PHASE_BYTES) { truncated = true; invalid = true; continue; }
    phases.push(value.phase); raw.push(line); rawBytes += Buffer.byteLength(line);
  }
  const lastPhase = phases.at(-1) ?? null;
  return { schemaVersion: 1, probeId, traceValid: !invalid, traceComplete: !invalid && phases.length === GUI_PHASES.length,
    phases, lastPhase, activeOperation: !invalid && lastPhase?.endsWith('-before') ? lastPhase.slice(0, -7) : null,
    nextUnconfirmedPhase: !invalid ? GUI_PHASES[phases.length] ?? null : null,
    rawPhaseJsonl: raw.join(''), rawPhaseBytes: rawBytes, phaseBytesLimit: PHASE_BYTES, truncated };
}

export async function runWindowsGuiProbe(env, run, targetPid = process.pid, { probeId = randomBytes(8).toString('hex'), now = Date.now } = {}) {
  const code = windowsGuiProbeScript(targetPid, probeId), requestedAt = now(); let spawned = null, result;
  const observation = () => {
    const trace = windowsGuiPhaseTrace(result?.stderr ?? '', probeId);
    return { ...trace, targetPid, timeoutMs: GUI_TIMEOUT_MS, elapsedMs: now() - requestedAt,
      commandRequestedAt: new Date(requestedAt).toISOString(), spawnObserved: Boolean(spawned), spawned,
      location: !trace.traceValid ? 'invalid-phase-trace' : trace.lastPhase === null
        ? (spawned ? 'spawned-before-first-powershell-marker' : 'process-spawn-not-observed')
        : trace.activeOperation ?? (trace.traceComplete ? 'probe-script-returned' : 'between-phase-markers') };
  };
  try {
    result = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', code], {
      env, timeout: GUI_TIMEOUT_MS, onSpawn: ({ pid }) => { spawned = { pid, elapsedMs: now() - requestedAt }; } });
    // The original exit/PID/desktop/session predicate is unchanged. Phase marks
    // are diagnostic evidence only and can never supply a substitute GUI result.
    if (result.code !== 0) {
      const diagnostic = result.stderr.split(/\r?\n/).filter(line => !line.includes(PHASE_KIND) || !line.includes(probeId)).join('\n');
      throw Error(`No native Windows GUI: ${text(diagnostic).slice(0, 200)}`);
    }
    const gui = JSON.parse(result.stdout);
    if (!(gui.processId === targetPid && gui.interactiveDesktop === true && gui.sessionId > 0)) throw Error('Invalid live Windows GUI provenance');
    return { ...gui, probeObservation: observation() };
  } catch (error) {
    result ??= error.commandResult;
    // Retain exact command streams for non-timeout exit/parse/gate failures too.
    if (result && !error.commandResult) error.commandResult = result;
    error.probeObservation = observation();
    throw error;
  }
}

export const NSIS_TIMEOUT_MS = 180000;
export const NSIS_OBSERVE_AT_MS = 150000;
export const PROCESS_PROBE_TIMEOUT_MS = 10000;
const redact = value => String(value).replace(/mk_[A-Za-z0-9_-]+/g, '[redacted-local-key]');
const text = value => redact(value).slice(0, 4096);
const bytes = value => `${JSON.stringify(value, null, 2)}\n`;

function failedCommand(error) {
  const raw = error.commandResult;
  return raw ? { executable: raw.executable, args: raw.args, code: raw.code, signal: raw.signal,
    stdout: text(raw.stdout ?? ''), stderr: text(raw.stderr ?? ''),
    streamsTruncated: [raw.stdout, raw.stderr].some(value => String(value ?? '').length > 4096),
    // A timeout cleanup exit is not an installer/PowerShell completion result.
    exitObservedAfterTimeoutCleanup: error.message === 'Native command timed out' } : undefined;
}

export async function observeWindowsGui(probe, evidence, stage, now = Date.now) {
  if (!['runner-gui', 'runner-gui-recheck'].includes(stage)) throw Error('Unknown Windows GUI observation stage');
  for (let attempt = 1; attempt <= 2; attempt++) {
    const startedAt = now(); let gui;
    try { gui = await probe(); }
    catch (error) {
      await evidence(`${stage}-attempt-${attempt}.json`, bytes({ stage, attempt, result: 'failed',
        timeoutMs: 30000, elapsedMs: now() - startedAt, failure: text(error.message), command: failedCommand(error),
        ...(error.probeObservation ? { probeObservation: error.probeObservation } : {}) }));
      if (attempt === 2 || error.message !== 'Native command timed out') throw error;
      continue;
    }
    await evidence(`${stage}-attempt-${attempt}.json`, bytes({ stage, attempt, result: 'passed', elapsedMs: now() - startedAt, gui }));
    return gui;
  }
}

// Enumerate paths/ancestry for this installer and installation directory only.
// Do not emit other processes, CommandLine, environment, window titles or users.
export const WINDOWS_PROCESS_OBSERVATION = String.raw`$ErrorActionPreference='Stop';
$installer=$env:OSIR_NATIVE_DIAGNOSTIC_INSTALLER;$destination=$env:OSIR_NATIVE_DIAGNOSTIC_DESTINATION.TrimEnd('\')+'\';
$all=@(Get-CimInstance -ClassName Win32_Process -OperationTimeoutSec 5);
if($all.Count -gt 8192){throw 'Process inventory exceeds observation bound'};
$ids=New-Object 'System.Collections.Generic.HashSet[int]';
foreach($p in $all){if($p.ExecutablePath -and ($p.ExecutablePath -ieq $installer -or $p.ExecutablePath.StartsWith($destination,[StringComparison]::OrdinalIgnoreCase))){[void]$ids.Add([int]$p.ProcessId)}};
$depthLimitReached=$false;
for($depth=0;$depth -lt 16;$depth++){$changed=$false;foreach($p in $all){if($ids.Contains([int]$p.ParentProcessId) -and $ids.Add([int]$p.ProcessId)){$changed=$true}};if(-not $changed){break};if($depth -eq 15){$depthLimitReached=$true}};
$rows=@(foreach($p in @($all|Where-Object {$ids.Contains([int]$_.ProcessId)}|Sort-Object ProcessId|Select-Object -First 128)){
  $live=Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue;
  @{pid=[int]$p.ProcessId;parentPid=[int]$p.ParentProcessId;name=$p.Name;executablePath=$p.ExecutablePath;sessionId=[int]$p.SessionId;mainWindowHandle=if($live){$live.MainWindowHandle.ToInt64()}else{$null};responding=if($live){$live.Responding}else{$null}}
});
@{schemaVersion=1;queryOnly=$true;matchedCount=$ids.Count;truncated=($ids.Count -gt 128);depthLimitReached=$depthLimitReached;processes=$rows}|ConvertTo-Json -Depth 5 -Compress`;

export async function runObservedWindowsNsis(adapter, installer, destination, label,
  { command, platform = process.platform, now = Date.now, schedule = setTimeout, cancel = clearTimeout } = {}) {
  if (!['nsis-install', 'baseline-nsis-install', 'final-nsis-install'].includes(label)) throw Error('Unknown NSIS observation stage');
  const args = ['/S', '/currentuser', `/D=${destination}`];
  // Existing headless tests may call the Windows method with a synthetic run
  // adapter on a Mac/Linux host. Never execute a native process probe there.
  if (platform !== 'win32') return adapter.run(installer, args, label, { timeout: NSIS_TIMEOUT_MS });
  if (typeof command !== 'function') throw Error('Bounded Windows diagnostic command runner required');
  const startedAt = now();
  const snapshot = async phase => {
    const probeStartedAt = now(); let result;
    try {
      const raw = await command('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', WINDOWS_PROCESS_OBSERVATION], {
        env: { ...adapter.env, OSIR_NATIVE_DIAGNOSTIC_INSTALLER: installer, OSIR_NATIVE_DIAGNOSTIC_DESTINATION: destination }, timeout: PROCESS_PROBE_TIMEOUT_MS });
      if (raw.code !== 0) throw Object.assign(Error('Windows process observation failed'), { commandResult: raw });
      if (Buffer.byteLength(raw.stdout) > 65536) throw Error('Windows process observation output exceeds 64 KiB');
      const observation = JSON.parse(raw.stdout);
      if (observation.schemaVersion !== 1 || observation.queryOnly !== true || !Array.isArray(observation.processes) || observation.processes.length > 128) throw Error('Invalid Windows process observation');
      result = { result: 'observed', observation };
    } catch (error) { result = { result: 'unavailable', failure: text(error.message), command: failedCommand(error) }; }
    await adapter.evidence(`${label}-processes-${phase}.json`, bytes({ stage: label, phase, timeoutMs: PROCESS_PROBE_TIMEOUT_MS,
      elapsedMs: now() - probeStartedAt, acceptanceEvidence: false, ...result }));
  };
  await adapter.evidence(`${label}-stage-start.json`, bytes({ stage: label, startedAt: new Date(startedAt).toISOString(),
    executable: installer, args, timeoutMs: NSIS_TIMEOUT_MS, installerAttempts: 1, observeAtMs: NSIS_OBSERVE_AT_MS }));
  await snapshot('before');
  const commandStartedAt = now();
  let observation, diagnosticFailure;
  const timer = schedule(() => { observation = snapshot('slow').catch(error => { diagnosticFailure = error; }); }, NSIS_OBSERVE_AT_MS);
  let value, failure;
  try { value = await adapter.run(installer, args, label, { timeout: NSIS_TIMEOUT_MS }); }
  catch (error) { failure = error; }
  const commandElapsedMs = now() - commandStartedAt;
  cancel(timer); if (observation) await observation;
  try { await adapter.evidence(`${label}-stage-finish.json`, bytes({ stage: label, elapsedMs: now() - startedAt, commandElapsedMs,
    result: failure ? 'failed' : 'completed', timeoutMs: NSIS_TIMEOUT_MS, installerAttempts: 1,
    ...(failure ? { failure: text(failure.message), command: failedCommand(failure) } : {}),
    ...(diagnosticFailure ? { diagnosticFailure: text(diagnosticFailure.message) } : {}) })); }
  catch (error) { throw failure ?? error; }
  if (failure) throw failure;
  if (diagnosticFailure) throw diagnosticFailure;
  return value;
}
