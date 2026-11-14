// External harness observations only: no installer retry, process termination,
// registry changes, command-line enumeration, or product acceptance shortcuts.
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
        timeoutMs: 30000, elapsedMs: now() - startedAt, failure: text(error.message), command: failedCommand(error) }));
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
