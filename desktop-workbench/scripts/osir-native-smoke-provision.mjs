#!/usr/bin/env node
/**
 * CI entry point. No hand-written isolation booleans are accepted as proof.
 *
 * Base spec = osir-native-smoke v1, but runner:{nativeMachine} only. All
 * installer/source/config/commit values must already be reviewed/pinned.
 *
 * ONLINE, separate disposable native dependency job (no Electron launch):
 * node osir-native-smoke-provision.mjs warm-cache --spec /abs/base.json --output /abs/new-prep
 * Export new-prep/cache + new-prep/dependency-cache.json; pin the REPORT FILE's
 * SHA-256 separately. The report binds the cache tree hash to the final package.
 *
 * Disposable clean native GUI runner (public unauthenticated reads permitted):
 * node osir-native-smoke-provision.mjs run --spec /abs/base.json
 *   --cache /abs/downloaded-cache --cache-report /abs/dependency-cache.json
 *   --cache-report-sha256 <64 lowercase hex> --output /abs/new-smoke
 *   --runner-mode disposable-clean-runner
 * Archive BOTH new-smoke/ and new-smoke.provision/. Exit 0 requires smoke and
 * all five product checks passed. This mode records real hosted/OS/GUI
 * provenance and unrestricted-no-product-credentials, without claiming network
 * isolation or full offline execution. Tokens/proxies are not passed to product
 * processes. No sign-in, real project or model request is exercised.
 *
 * Local policy-only proof, no installer/product/account access:
 * node osir-native-smoke-provision.mjs probe --output /abs/new-proof
 *
 * Optional --runner-mode strict-loopback (legacy default), macOS: Seatbelt
 * inherited by the smoke Node process and all ordinary child
 * processes. Real TCP/UDP IPv4/IPv6 + Unix IPC + grandchild probes precede the
 * attestation. Re-probed in the actual smoke process before product execution.
 * No global network settings are changed; outside-process connectivity is
 * checked again at the end, before workflow artifact upload. On hosts where
 * Seatbelt localhost also allows the host's non-loopback interface address,
 * strict preflight FAILS: no attestation/product execution is permitted. The
 * numeric-loopback SBPL syntax is not supported on macOS 15.6. Do not relax
 * these controls merely to turn a CI lane green.
 *
 * Windows: clean-runner is implemented with a live interactive desktop/session
 * check. Strict-loopback run remains BLOCKED, not falsely attested.
 * Per-exe Firewall rules do not cover unknown NSIS temporary children/new
 * environment binaries. A reviewed Windows account/process-tree enforcement
 * implementation with a real GUI runner test is still required. This helper
 * never blocks the runner account or changes its global Firewall profiles.
 */
import net from 'node:net';
import dgram from 'node:dgram';
import { randomBytes } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { homedir, hostname, networkInterfaces, tmpdir, userInfo } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { assertNativeMachine, bindInputs, command, fileIdentity, fingerprintTree, NativeAdapter, runSmoke, smokeEnvironment, validateSpec, verifyCleanAccount } from './osir-native-smoke.mjs';
import { observeWindowsGui } from './osir-windows-native-observation.mjs';

// "localhost" is the supported SBPL selector, not itself proof of loopback-only
// enforcement. Real controls below detect its broader local-interface meaning.
export const MAC_PROFILE = '(version 1)\n(allow default)\n(deny network-outbound (remote ip "*:*"))\n(deny network-inbound (local ip "*:*"))\n(allow network-outbound (remote ip "localhost:*"))\n(allow network-inbound (local ip "localhost:*"))\n';
// Dependency --help needs no IP sockets. Unlike the GUI smoke policy this can
// deny every IP destination, including all host-interface and loopback IPs.
export const MAC_CACHE_PROFILE = '(version 1)\n(allow default)\n(deny network-outbound (remote ip "*:*"))\n(deny network-inbound (local ip "*:*"))\n';
export const WINDOWS_BLOCKER = 'Windows isolation unavailable: program Firewall rules do not inherit into unknown NSIS temporary children or newly created Connector executables; blocking the shared runner account can also interrupt its control plane. No verified disposable GUI account/process-tree provisioner is implemented. No native product process was started and no Firewall profile was changed.';
const SELF = fileURLToPath(import.meta.url);
const SHA = /^[a-f0-9]{64}$/;
const check = (ok, message) => { if (!ok) throw new Error(message); };
const json = async path => JSON.parse(await readFile(path, 'utf8'));
const save = async (path, value) => writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
export const permissionDenied = result => result?.allowed === false && ['EPERM', 'EACCES'].includes(result.error);
const ALLOWED_PROBES = ['tcp4Loopback', 'tcp6Loopback', 'udp4Loopback', 'udp6Loopback', 'unixIpc'];
const NON_LOOPBACK_PROBES = ['tcp4NonLoopback', 'udp4NonLoopback'];
const DENIED_PROBES = [...NON_LOOPBACK_PROBES, 'tcp4TestNet', 'tcp6TestNet', 'udp4TestNet', 'udp6TestNet'];

export function classifyNetworkProbes(probes, isolated, denyLoopback = false) {
  if (denyLoopback) return probes.unixIpc?.allowed === true && [...ALLOWED_PROBES.filter(name => name !== 'unixIpc'), ...DENIED_PROBES].every(name => permissionDenied(probes[name]));
  return ALLOWED_PROBES.every(name => probes[name]?.allowed === true) && (isolated ? DENIED_PROBES.every(name => permissionDenied(probes[name])) : NON_LOOPBACK_PROBES.every(name => probes[name]?.allowed === true));
}

export function isolationFailure(proof) {
  if (NON_LOOPBACK_PROBES.some(name => proof.probes?.[name]?.allowed)) return 'Strict loopback isolation unavailable: Seatbelt localhost permits this host\'s non-loopback interface address. No attestation or product execution permitted; a reviewed stronger OS network policy is required.';
  return 'Strict network/IPC or inherited-child isolation probe failed; see raw network proof. No attestation or product execution permitted.';
}

export function parseArguments(args) {
  const [action, ...rest] = args;
  const modes = {
    'warm-cache': ['spec', 'output'], run: ['spec', 'cache', 'cache-report', 'cache-report-sha256', 'output'],
    probe: ['output'], _stage: ['spec', 'fixture', 'provision', 'output'], _probe: ['fixture', 'mode'],
  };
  const hasRunnerMode = ['run', 'warm-cache'].includes(action) && rest.includes('--runner-mode');
  const keys = modes[action] && [...modes[action], ...(hasRunnerMode ? ['runner-mode'] : [])];
  check(keys && rest.length === keys.length * 2, 'Use --help for exact provision arguments');
  const options = {};
  for (let i = 0; i < rest.length; i += 2) {
    const key = rest[i].slice(2);
    check(rest[i].startsWith('--') && keys.includes(key) && options[key] === undefined, 'Unknown/duplicate provision argument');
    options[key] = rest[i + 1];
    check(key === 'cache-report-sha256' ? SHA.test(options[key]) : key === 'runner-mode' ? ['strict-loopback', 'disposable-clean-runner'].includes(options[key]) : key === 'mode' ? ['baseline', 'isolated', 'leaf', 'no-ip', 'no-ip-leaf'].includes(options[key]) : isAbsolute(options[key]), `Invalid absolute path/value for --${key}`);
  }
  return { action, ...options };
}

export function verifyHostedRunnerEnvironment(env = process.env) {
  check(env.GITHUB_ACTIONS === 'true' && env.RUNNER_ENVIRONMENT === 'github-hosted' && typeof env.GITHUB_RUN_ID === 'string' && /^\d+$/.test(env.GITHUB_RUN_ID), 'A disposable GitHub-hosted native GUI runner is required; local/self-hosted product execution is refused');
}

export function requireIsolationPlatform(platform = process.platform, runnerMode = 'strict-loopback') {
  if (runnerMode === 'disposable-clean-runner') {
    check(['darwin', 'win32'].includes(platform), `Native clean-runner smoke is unsupported on ${platform}`); return;
  }
  check(runnerMode === 'strict-loopback', 'Unknown native runner mode');
  check(platform !== 'win32', WINDOWS_BLOCKER);
  check(platform === 'darwin', `Native isolation is unsupported on ${platform}; no product process was started`);
}

export async function requireHostedRunner(env = process.env) {
  verifyHostedRunnerEnvironment(env);
  await verifyCleanAccount();
}

export function childEnvironment(work, source = process.env) {
  const env = smokeEnvironment(source, homedir(), work);
  // Workflow metadata only, never GITHUB_TOKEN, ACTIONS_RUNTIME_TOKEN, checkout
  // credentials, inherited NODE_OPTIONS, SDK keys or proxy configuration.
  for (const key of ['GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'RUNNER_NAME']) if (source[key]) env[key] = source[key];
  return env;
}

export function hostedRunnerProvenance(env = process.env) {
  verifyHostedRunnerEnvironment(env);
  const fields = ['GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB', 'GITHUB_REPOSITORY', 'GITHUB_WORKFLOW_REF', 'GITHUB_WORKFLOW_SHA', 'RUNNER_NAME', 'RUNNER_ENVIRONMENT', 'RUNNER_OS', 'RUNNER_ARCH', 'ImageOS', 'ImageVersion'];
  return { basis: 'github-provided-environment-and-live-os-checks', metadata: Object.fromEntries(fields.filter(k => env[k]).map(k => [k, env[k]])), cryptographicRunnerAttestation: false };
}

export async function nativeGuiProvenance(env) {
  if (process.platform === 'darwin') {
    const r = await command('/usr/bin/stat', ['-f', '%Su', '/dev/console'], { env, timeout: 10000 });
    check(r.code === 0 && r.stdout.trim() === userInfo().username && !['root', 'loginwindow'].includes(r.stdout.trim()), 'No active Mac GUI console for this clean runner account');
    return { platform: 'darwin', processId: process.pid, consoleUser: r.stdout.trim(), interactiveDesktop: true, basis: 'live-dev-console-owner' };
  }
  check(process.platform === 'win32', 'Unsupported native GUI platform');
  const code = `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class SmokeDesktop{[DllImport("user32.dll",SetLastError=true)]public static extern IntPtr OpenInputDesktop(uint f,bool i,uint a);[DllImport("user32.dll")]public static extern bool CloseDesktop(IntPtr h);}';$s=(Get-Process -Id ${process.pid}).SessionId;$h=[SmokeDesktop]::OpenInputDesktop(0,$false,1);if($s -le 0 -or $h -eq [IntPtr]::Zero -or -not [Environment]::UserInteractive){throw 'No accessible interactive Windows desktop/session'};[void][SmokeDesktop]::CloseDesktop($h);@{platform='win32';processId=${process.pid};sessionId=$s;interactiveDesktop=$true;basis='live-input-desktop-and-session'}|ConvertTo-Json -Compress`;
  const r = await command('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', code], { env, timeout: 30000 });
  check(r.code === 0, `No native Windows GUI: ${r.stderr.slice(0, 200)}`);
  const gui = JSON.parse(r.stdout);
  check(gui.processId === process.pid && gui.interactiveDesktop === true && gui.sessionId > 0, 'Invalid live Windows GUI provenance'); return gui;
}

async function newDirectory(path) {
  check(isAbsolute(path), 'Absolute new output directory required');
  await mkdir(path, { mode: 0o700 }); return realpath(path);
}

function tcpProbe(host, port, nonce) {
  return new Promise(resolve => {
    const socket = net.createConnection({ host, port });
    let data = '', done = false;
    const finish = value => { if (done) return; done = true; socket.destroy(); resolve(value); };
    socket.setTimeout(1800, () => finish({ allowed: false, error: 'TIMEOUT' }));
    socket.on('data', chunk => { data += chunk; if (data === nonce) finish({ allowed: true }); });
    socket.on('error', error => finish({ allowed: false, error: error.code }));
    socket.on('end', () => finish({ allowed: false, error: 'NO_CHALLENGE' }));
  });
}

function udpProbe(host, port, nonce, family, expectEcho = true) {
  return new Promise(resolve => {
    const socket = dgram.createSocket(family);
    let done = false;
    const timer = setTimeout(() => finish({ allowed: false, error: 'TIMEOUT' }), 1800);
    const finish = value => { if (done) return; done = true; clearTimeout(timer); try { socket.close(); } catch {} resolve(value); };
    socket.on('error', error => finish({ allowed: false, error: error.code }));
    socket.on('message', data => finish({ allowed: data.toString() === nonce, ...(data.toString() === nonce ? {} : { error: 'NO_CHALLENGE' }) }));
    socket.send(nonce, port, host, error => {
      if (error) finish({ allowed: false, error: error.code });
      else if (!expectEcho) finish({ allowed: true });
    });
  });
}

function unixProbe(path, nonce) {
  return new Promise(resolve => {
    const socket = net.createConnection(path); let done = false;
    const finish = value => { if (done) return; done = true; socket.destroy(); resolve(value); };
    socket.setTimeout(1800, () => finish({ allowed: false, error: 'TIMEOUT' }));
    socket.on('data', data => finish({ allowed: data.toString() === nonce }));
    socket.on('error', error => finish({ allowed: false, error: error.code }));
  });
}

export async function networkProbe(fixture, isolated, denyLoopback = false) {
  check(fixture.schemaVersion === 1 && /^[a-f0-9]{32}$/.test(fixture.nonce) && net.isIP(fixture.nonLoopback4) === 4 && !fixture.nonLoopback4.startsWith('127.'), 'Invalid local network fixture');
  const { nonce } = fixture;
  const names = ['tcp4Loopback', 'tcp6Loopback', 'udp4Loopback', 'udp6Loopback', 'unixIpc', 'tcp4NonLoopback', 'udp4NonLoopback'];
  const values = await Promise.all([
    tcpProbe('127.0.0.1', fixture.tcp4Port, nonce), tcpProbe('::1', fixture.tcp6Port, nonce),
    udpProbe('127.0.0.1', fixture.udp4Port, nonce, 'udp4'), udpProbe('::1', fixture.udp6Port, nonce, 'udp6'),
    unixProbe(fixture.unixPath, nonce), tcpProbe(fixture.nonLoopback4, fixture.tcp4Port, nonce), udpProbe(fixture.nonLoopback4, fixture.udp4Port, nonce, 'udp4'),
  ]);
  const probes = Object.fromEntries(names.map((name, i) => [name, values[i]]));
  if (isolated) {
    // TEST-NET addresses: only isolated probes attempt these. Success or a
    // routing/timeout error is NOT a denial proof; require actual EPERM/EACCES.
    const [tcp4, tcp6, udp4, udp6] = await Promise.all([
      tcpProbe('192.0.2.1', 9, nonce), tcpProbe('2001:db8::1', 9, nonce),
      udpProbe('192.0.2.1', 9, nonce, 'udp4', false), udpProbe('2001:db8::1', 9, nonce, 'udp6', false),
    ]);
    Object.assign(probes, { tcp4TestNet: tcp4, tcp6TestNet: tcp6, udp4TestNet: udp4, udp6TestNet: udp6 });
  }
  return { schemaVersion: 1, mode: denyLoopback ? 'no-ip' : isolated ? 'isolated' : 'baseline', pid: process.pid, passed: classifyNetworkProbes(probes, isolated, denyLoopback), probes };
}

async function createFixture() {
  const entries = Object.values(networkInterfaces()).flat().filter(v => v && v.family === 'IPv4' && !v.internal);
  check(entries.length > 0, 'No reachable non-loopback IPv4 interface for a positive-control probe');
  const nonce = randomBytes(16).toString('hex'), opened = [], socketDirectory = await mkdtemp(join(tmpdir(), 'osir-net-'));
  const fixture = { schemaVersion: 1, nonce, nonLoopback4: entries[0].address, unixPath: join(await realpath(socketDirectory), 's') };
  const close = async () => {
    for (const value of opened.reverse()) await new Promise(resolve => { try { value.close(() => resolve()); } catch { resolve(); } });
    await rm(socketDirectory, { recursive: true, force: true });
  };
  try {
    for (const [key, host] of [['tcp4Port', '0.0.0.0'], ['tcp6Port', '::1'], ['unix', fixture.unixPath]]) {
      const server = net.createServer(socket => socket.end(nonce)); opened.push(server);
      await new Promise((resolve, reject) => { server.once('error', reject); server.listen(key === 'unix' ? host : { host, port: 0 }, resolve); });
      if (key !== 'unix') fixture[key] = server.address().port;
    }
    for (const [key, family, host] of [['udp4Port', 'udp4', '0.0.0.0'], ['udp6Port', 'udp6', '::1']]) {
      const socket = dgram.createSocket(family); opened.push(socket);
      socket.on('message', (data, remote) => { if (data.toString() === nonce) socket.send(data, remote.port, remote.address); });
      await new Promise((resolve, reject) => { socket.once('error', reject); socket.bind(0, host, resolve); });
      fixture[key] = socket.address().port;
    }
    return { fixture, close };
  } catch (error) { await close(); throw error; }
}

async function commandJson(args, env, timeout = 15000) {
  const r = await command(process.execPath, [SELF, ...args], { env, timeout });
  check([0, 1].includes(r.code) && r.stdout.trim().startsWith('{'), `Network probe subprocess failed: ${r.stderr.slice(0, 240)}`);
  return JSON.parse(r.stdout);
}

async function probeProcess(options) {
  const proof = await networkProbe(await json(options.fixture), options.mode !== 'baseline', options.mode.startsWith('no-ip'));
  if (options.mode === 'isolated' || options.mode === 'no-ip') {
    proof.descendant = await commandJson(['_probe', '--fixture', options.fixture, '--mode', options.mode === 'no-ip' ? 'no-ip-leaf' : 'leaf'], childEnvironment(dirname(options.fixture)));
    proof.passed = proof.passed && proof.descendant.passed;
  }
  return proof;
}

export async function observeSmokeGui(env, provision, stage, { probe = nativeGuiProvenance, platform = process.platform } = {}) {
  if (platform !== 'win32') return probe(env);
  return observeWindowsGui(() => probe(env), (name, raw) => writeFile(join(provision, name), raw, { flag: 'wx', mode: 0o600 }), stage);
}

export async function verifyProvisionedIsolation(record) {
  const e = record.enforcement;
  if (record.runnerMode === 'disposable-clean-runner') {
    verifyHostedRunnerEnvironment();
    check(record.networkPolicy === 'unrestricted-no-product-credentials' && record.networkIsolationClaimed === false && e?.kind === 'github-hosted-clean-runner' && e.processId === process.pid && e.provisionerSha256 === (await fileIdentity(SELF)).sha256 && record.jobId === `${process.env.GITHUB_RUN_ID}/${process.env.GITHUB_RUN_ATTEMPT ?? '1'}`, 'Clean-runner provenance must come from this live GitHub-hosted helper process');
    const metadata = hostedRunnerProvenance();
    check(JSON.stringify(record.hostedRunner) === JSON.stringify(metadata), 'Hosted-runner metadata changed');
    const gui = await observeSmokeGui(childEnvironment(dirname(e.provenancePath)), dirname(e.provenancePath), 'runner-gui-recheck');
    check((await fileIdentity(e.provenancePath)).sha256 === e.provenanceSha256, 'GUI provenance changed');
    return { ...e, liveGuiRecheck: gui };
  }
  check(process.platform === 'darwin' && e?.kind === 'macos-seatbelt' && e.processId === process.pid && e.provisionerSha256 === (await fileIdentity(SELF)).sha256, 'Isolation requires the real provision helper in this sandboxed process; handwritten attestation is refused');
  check((await readFile(e.profilePath, 'utf8')) === MAC_PROFILE && (await fileIdentity(e.profilePath)).sha256 === e.profileSha256, 'Isolation profile changed');
  check((await fileIdentity(e.proofPath)).sha256 === e.proofSha256 && (await fileIdentity(e.baselinePath)).sha256 === e.baselineSha256, 'Raw network evidence hash mismatch');
  const baseline = await json(e.baselinePath), proof = await json(e.proofPath);
  check(baseline.passed && baseline.mode === 'baseline' && proof.passed && proof.mode === 'isolated' && proof.pid === process.pid && proof.descendant?.passed, 'Missing real positive control or inherited isolation proof');
  const live = await networkProbe(await json(e.fixturePath), true);
  check(live.passed, 'Actual smoke process failed live network-isolation probes');
  return { ...e, liveReprobe: live };
}

async function cleanRunnerSmoke(spec, provision, output) {
  await requireHostedRunner();
  const env = childEnvironment(provision); await mkdir(env.TMPDIR, { mode: 0o700 });
  const gui = await observeSmokeGui(env, provision, 'runner-gui'), provenancePath = join(provision, 'gui-provenance.json'); await save(provenancePath, gui);
  const record = { schemaVersion: 1, kind: 'disposable-native-runner', disposable: true, runnerMode: 'disposable-clean-runner', networkPolicy: 'unrestricted-no-product-credentials', networkIsolationClaimed: false,
    user: userInfo().username, home: await realpath(homedir()), hostname: hostname(), nativeMachine: spec.runner.nativeMachine,
    jobId: `${process.env.GITHUB_RUN_ID}/${process.env.GITHUB_RUN_ATTEMPT ?? '1'}`, createdAt: new Date().toISOString(), hostedRunner: hostedRunnerProvenance(),
    boundaries: ['no-product-or-sdk-credentials', 'no-real-account-project-or-model-requests', 'unauthenticated-public-health-or-update-reads-may-occur', 'no-network-isolation-or-full-offline-claim'],
    enforcement: { kind: 'github-hosted-clean-runner', processId: process.pid, provisionerSha256: (await fileIdentity(SELF)).sha256, provenancePath, provenanceSha256: (await fileIdentity(provenancePath)).sha256 } };
  const recordPath = join(provision, 'runner-isolation.json'); await save(recordPath, record);
  const effective = { ...spec, runner: { ...spec.runner, mode: record.runnerMode, isolationEvidencePath: recordPath, isolationEvidenceSha256: (await fileIdentity(recordPath)).sha256 } };
  await save(join(provision, 'effective-spec.json'), effective);
  return runSmoke(effective, output);
}

async function stage(options) {
  await requireHostedRunner();
  const spec = await json(options.spec), fixture = await json(options.fixture), env = childEnvironment(options.provision);
  const proof = await networkProbe(fixture, true);
  proof.descendant = await commandJson(['_probe', '--fixture', options.fixture, '--mode', 'leaf'], env);
  proof.passed = proof.passed && proof.descendant.passed;
  await save(join(options.provision, 'network-proof.json'), proof);
  check(proof.passed, isolationFailure(proof));
  const profilePath = join(options.provision, 'profile.sb'), proofPath = join(options.provision, 'network-proof.json'), baselinePath = join(options.provision, 'network-baseline.json');
  const record = {
    schemaVersion: 1, kind: 'disposable-native-runner', disposable: true, networkPolicy: 'deny-all-except-loopback',
    user: userInfo().username, home: await realpath(homedir()), hostname: hostname(), nativeMachine: spec.runner.nativeMachine,
    jobId: `${process.env.GITHUB_RUN_ID}/${process.env.GITHUB_RUN_ATTEMPT ?? '1'}`, createdAt: new Date().toISOString(),
    enforcement: { kind: 'macos-seatbelt', processId: process.pid, provisionerSha256: (await fileIdentity(SELF)).sha256,
      profilePath, profileSha256: (await fileIdentity(profilePath)).sha256, proofPath, proofSha256: (await fileIdentity(proofPath)).sha256,
      baselinePath, baselineSha256: (await fileIdentity(baselinePath)).sha256, fixturePath: options.fixture },
  };
  const attestation = join(options.provision, 'runner-isolation.json'); await save(attestation, record);
  const effective = { ...spec, runner: { nativeMachine: spec.runner.nativeMachine, isolationEvidencePath: attestation, isolationEvidenceSha256: (await fileIdentity(attestation)).sha256 } };
  await save(join(options.provision, 'effective-spec.json'), effective);
  const report = await runSmoke(effective, options.output);
  console.log(JSON.stringify({ result: report.result, report: join(options.output, 'native-smoke.json') }));
  if (report.result !== 'passed') process.exitCode = 1;
}

export async function validateCacheReport(spec, path, expectedHash, cache) {
  validateSpec(spec, { requireIsolation: false });
  check(SHA.test(expectedHash) && (await fileIdentity(path)).sha256 === expectedHash, 'Dependency report differs from pinned file SHA-256');
  const report = await json(path);
  check(report.schemaVersion === 1 && report.scope === 'native-smoke-dependency-cache' && report.result === 'prepared', 'Dependency preparation did not succeed');
  for (const name of Object.keys(spec.expected)) check(report.expected?.[name] === spec.expected[name], `Dependency cache ${name} differs from final installer/source`);
  check(report.nativeMachine === spec.runner.nativeMachine && SHA.test(report.cache?.sha256) && await fingerprintTree(cache) === report.cache.sha256, 'Dependency cache native architecture/tree fingerprint mismatch');
  const lock = report.evidence?.find(item => item.path === 'connector-resolved-uv.lock');
  check(lock && SHA.test(lock.sha256), 'Dependency report lacks resolved lock evidence');
  const lockPath = join(dirname(path), lock.path), identity = await fileIdentity(lockPath);
  check(identity.sha256 === lock.sha256 && identity.size === lock.size, 'Resolved dependency lock differs from preparation evidence');
  const rehearsal = report.offlineRehearsal;
  check(rehearsal?.result === 'passed' && rehearsal.independentProject === true && rehearsal.independentVenv === true && ['uv-offline-only', 'macos-seatbelt-deny-ip'].includes(rehearsal.mode) && rehearsal.cacheSha256 === report.cache.sha256 && rehearsal.lockSha256 === lock.sha256 && rehearsal.sourceSha256 === report.connectorSourceSha256 && SHA.test(rehearsal.venvConfig?.sha256), 'Dependency cache lacks a successful independent offline reconstruction');
  return { path: cache, sha256: report.cache.sha256, lockPath, lockSha256: identity.sha256 };
}

/** Real macOS policy proof, safe without an installer or an account login. */
export async function proveCachePolicy(directory, env) {
  check(process.platform === 'darwin', 'IP-denial cache policy proof is only implemented on macOS');
  await mkdir(directory, { mode: 0o700 });
  let fixture, failure;
  const result = { schemaVersion: 1, mode: 'macos-seatbelt-deny-ip', passed: false, cleanup: { globalNetworkStateModified: false } };
  try {
    fixture = await createFixture();
    const fixturePath = join(directory, 'fixture.json'), profilePath = join(directory, 'profile.sb');
    await save(fixturePath, fixture.fixture);
    const baseline = await networkProbe(fixture.fixture, false);
    await save(join(directory, 'baseline.json'), baseline); check(baseline.passed, 'Cache policy positive control failed');
    await writeFile(profilePath, MAC_CACHE_PROFILE, { flag: 'wx', mode: 0o600 });
    let r;
    try { r = await command('/usr/bin/sandbox-exec', ['-f', profilePath, process.execPath, SELF, '_probe', '--fixture', fixturePath, '--mode', 'no-ip'], { env, timeout: 30000 }); }
    catch (error) { if (error.commandResult) await save(join(directory, 'sandbox-process.json'), error.commandResult); throw error; }
    await save(join(directory, 'sandbox-process.json'), r);
    check([0, 1].includes(r.code) && r.stdout.trim().startsWith('{'), `Cache policy probe failed: ${r.stderr.slice(0, 240)}`);
    const proof = JSON.parse(r.stdout); await save(join(directory, 'proof.json'), proof);
    check(r.code === 0 && proof.mode === 'no-ip' && proof.passed && proof.descendant?.passed, 'Cache rehearsal policy did not deny all IPv4/IPv6 TCP/UDP sockets');
    result.passed = true; result.profilePath = profilePath; result.profileSha256 = (await fileIdentity(profilePath)).sha256;
  } catch (error) { failure = error; result.failure = String(error.message).slice(0, 400); }
  finally {
    if (fixture) {
      try {
        const after = await networkProbe(fixture.fixture, false); await save(join(directory, 'after.json'), after);
        result.cleanup.parentConnectivityRestored = after.passed;
        check(after.passed, 'Cache policy parent connectivity control failed');
      } catch (error) { failure ??= error; result.passed = false; result.cleanup.failure = String(error.message).slice(0, 300); }
      finally {
        try { await fixture.close(); result.cleanup.fixturesClosed = true; }
        catch (error) { failure ??= error; result.passed = false; result.cleanup.fixturesClosed = false; }
      }
    }
    await save(join(directory, 'policy-report.json'), result);
  }
  if (failure) throw failure;
  return result;
}

/** Rebuild at different paths, without borrowing the online project's venv. */
export async function rehearseOfflineCache({ source, cache, lockPath, uv, python, work, env, run, platform = process.platform, policy }) {
  const root = join(work, 'offline-rehearsal'); await mkdir(root, { mode: 0o700 });
  const project = join(root, 'connector-project'), copiedCache = join(root, 'cache');
  const cacheSha256 = await fingerprintTree(cache), sourceSha256 = await fingerprintTree(source), lock = await fileIdentity(lockPath);
  await cp(source, project, { recursive: true, verbatimSymlinks: true });
  check(await fingerprintTree(project) === sourceSha256, 'Offline rehearsal source differs from packaged Connector');
  await writeFile(join(project, 'uv.lock'), await readFile(lockPath));
  await cp(cache, copiedCache, { recursive: true, verbatimSymlinks: true });
  check(await fingerprintTree(copiedCache) === cacheSha256, 'Offline cache is not portable to a new directory');
  const offlineEnv = { ...env, UV_OFFLINE: '1', UV_CACHE_DIR: copiedCache, UV_PROJECT_ENVIRONMENT: join(root, 'venv'), UV_LINK_MODE: 'copy' };
  const args = ['--offline', '--no-config', 'run', '--locked', '--project', project, '--python', python, '--no-python-downloads', 'anywhere-cli', '--help'];
  let mode = 'uv-offline-only';
  if (platform === 'darwin' && policy) {
    check(policy?.passed === true && policy.mode === 'macos-seatbelt-deny-ip' && await readFile(policy.profilePath, 'utf8') === MAC_CACHE_PROFILE && (await fileIdentity(policy.profilePath)).sha256 === policy.profileSha256, 'Real deny-IP policy proof is required for Mac cache rehearsal');
    await run('/usr/bin/sandbox-exec', ['-f', policy.profilePath, uv, ...args], 'offline-cache-rehearsal', { env: offlineEnv, timeout: 900000 });
    mode = policy.mode;
  } else {
    check(['darwin', 'win32'].includes(platform), 'Unsupported cache rehearsal platform');
    await run(uv, args, 'offline-cache-rehearsal', { env: offlineEnv, timeout: 900000 });
  }
  check(await fingerprintTree(cache) === cacheSha256 && (await fileIdentity(lockPath)).sha256 === lock.sha256, 'Original cache or lock changed during isolated rehearsal');
  const venvConfig = await fileIdentity(join(offlineEnv.UV_PROJECT_ENVIRONMENT, 'pyvenv.cfg'));
  return { result: 'passed', mode, independentProject: true, independentVenv: true, venvConfig, sourceSha256, cacheSha256, lockSha256: lock.sha256 };
}

async function warmCache(options) {
  await requireHostedRunner();
  const spec = await json(options.spec); validateSpec(spec, { requireIsolation: false });
  const inputs = await bindInputs(spec), output = await newDirectory(options.output), work = join(output, 'work'); await mkdir(work);
  const env = childEnvironment(work); delete env.UV_OFFLINE;
  env.UV_CACHE_DIR = join(output, 'cache'); env.UV_LINK_MODE = 'copy';
  for (const key of ['APPDATA', 'LOCALAPPDATA', 'TMPDIR', 'ZDOTDIR', 'AGENT_CONNECTOR_DATA_DIR', 'CODEX_HOME', 'CLAUDE_CONFIG_DIR', 'UV_CACHE_DIR']) await mkdir(env[key], { recursive: true, mode: 0o700 });
  const report = { schemaVersion: 1, scope: 'native-smoke-dependency-cache', result: 'failed', expected: spec.expected, nativeMachine: spec.runner.nativeMachine, provisionerSha256: (await fileIdentity(SELF)).sha256, startedAt: new Date().toISOString(), evidence: [] };
  const evidence = async (name, data) => { await writeFile(join(output, name), data, { flag: 'wx', mode: 0o600 }); report.evidence.push({ path: name, ...(await fileIdentity(join(output, name))) }); };
  try {
    const adapter = new NativeAdapter({ spec, inputs, work, env, evidence });
    const machine = await adapter.hardware(); assertNativeMachine(spec.runner.nativeMachine, process.platform, process.arch, machine.arch, machine.translated);
    const { resources } = await adapter.install();
    const uv = join(resources, 'uv', spec.runner.nativeMachine, process.platform === 'win32' ? 'uv.exe' : 'uv');
    const python = join(resources, 'python', spec.runner.nativeMachine, ...(process.platform === 'win32' ? ['python.exe'] : ['bin', 'python3']));
    report.uv = { path: uv, ...(await fileIdentity(await realpath(uv))) }; report.python = { path: python, ...(await fileIdentity(await realpath(python))) };
    const project = join(work, 'connector-project'); await cp(join(resources, 'connector'), project, { recursive: true, verbatimSymlinks: true });
    report.connectorSourceSha256 = await fingerprintTree(project);
    await adapter.run(uv, ['--no-config', 'run', '--project', project, '--python', python, '--no-python-downloads', 'anywhere-cli', '--help'], 'online-dependency-preparation', { timeout: 900000 });
    await evidence('connector-resolved-uv.lock', await readFile(join(project, 'uv.lock')));
    let policy;
    if (process.platform === 'darwin' && options['runner-mode'] === 'strict-loopback') {
      const directory = join(output, 'offline-policy'); policy = await proveCachePolicy(directory, env);
      for (const name of ['profile.sb', 'baseline.json', 'sandbox-process.json', 'proof.json', 'after.json', 'policy-report.json']) await evidence(`offline-policy-${name}`, await readFile(join(directory, name)));
    }
    report.offlineRehearsal = await rehearseOfflineCache({ source: join(resources, 'connector'), cache: env.UV_CACHE_DIR, lockPath: join(output, 'connector-resolved-uv.lock'), uv, python, work, env, run: adapter.run.bind(adapter), policy });
    report.cache = { path: env.UV_CACHE_DIR, sha256: await fingerprintTree(env.UV_CACHE_DIR) };
    check((await fileIdentity(spec.finalInstallerPath)).sha256 === spec.expected.artifactSha256, 'Installer changed during dependency preparation');
    report.result = 'prepared';
  } catch (error) { report.failure = String(error.message).slice(0, 400); }
  finally { report.completedAt = new Date().toISOString(); await save(join(output, 'dependency-cache.json'), report); }
  console.log(JSON.stringify({ result: report.result, report: join(output, 'dependency-cache.json'), reportSha256: (await fileIdentity(join(output, 'dependency-cache.json'))).sha256, cacheSha256: report.cache?.sha256 }));
  if (report.result !== 'prepared') process.exitCode = 1;
}

async function runProvision(options, probeOnly = false) {
  if (!probeOnly) await requireHostedRunner();
  const provision = await newDirectory(probeOnly ? options.output : `${options.output}.provision`);
  const runnerMode = options['runner-mode'] ?? 'strict-loopback';
  const result = { schemaVersion: 1, scope: 'native-smoke-provision', result: 'failed', platform: process.platform, runnerMode,
    networkPolicy: runnerMode === 'disposable-clean-runner' ? 'unrestricted-no-product-credentials' : 'deny-all-except-loopback', networkIsolationClaimed: false,
    startedAt: new Date().toISOString(), productExecutionState: 'not-attempted', cleanup: { globalNetworkStateModified: false } };
  let fixture, primaryError;
  try {
    requireIsolationPlatform(process.platform, runnerMode);
    let effective;
    if (!probeOnly) {
      const spec = await json(options.spec); validateSpec(spec, { requireIsolation: false }); await bindInputs(spec);
  check(!spec.runner.isolationEvidencePath && !spec.runner.isolationEvidenceSha256, 'Supply a base spec; helper generates live runner evidence for the selected mode');
      effective = { ...spec, dependencyCache: await validateCacheReport(spec, options['cache-report'], options['cache-report-sha256'], options.cache) };
    }
    if (runnerMode === 'disposable-clean-runner') {
      result.productExecutionState = 'unknown-until-smoke-report';
      const smoke = await cleanRunnerSmoke(effective, provision, options.output);
      check(smoke.result === 'passed' && smoke.evidenceMode === 'native', `Native clean-runner smoke failed: ${smoke.failure ?? 'see native-smoke.json'}`);
      result.cleanup.networkPolicyRestorationRequired = false;
    } else {
    fixture = await createFixture(); const fixturePath = join(provision, 'fixture.json'); await save(fixturePath, fixture.fixture);
    const env = childEnvironment(provision), baseline = await networkProbe(fixture.fixture, false);
    await save(join(provision, 'network-baseline.json'), baseline); check(baseline.passed, 'Positive-control network/IPC fixture is not reachable before sandboxing');
    const profile = join(provision, 'profile.sb'); await writeFile(profile, MAC_PROFILE, { flag: 'wx', mode: 0o600 });
    const sandbox = async (args, evidenceName, timeout) => {
      let r;
      try { r = await command('/usr/bin/sandbox-exec', ['-f', profile, process.execPath, SELF, ...args], { env, timeout }); }
      catch (error) {
        if (error.commandResult) await save(join(provision, evidenceName), { ...error.commandResult, failure: String(error.message) });
        throw error;
      }
      await save(join(provision, evidenceName), r); return r;
    };
    const preflight = await sandbox(['_probe', '--fixture', fixturePath, '--mode', 'isolated'], 'sandbox-preflight-process.json', 30000);
    check([0, 1].includes(preflight.code) && preflight.stdout.trim().startsWith('{'), `Seatbelt preflight could not run: ${preflight.stderr.slice(0, 240)}`);
    const proof = JSON.parse(preflight.stdout);
    await save(join(provision, probeOnly ? 'network-proof.json' : 'network-preflight-proof.json'), proof);
    check(preflight.code === 0 && proof.passed && proof.descendant?.passed, isolationFailure(proof));
    if (!probeOnly) {
      const specPath = join(provision, 'base-with-cache.json'); await save(specPath, effective);
      result.productExecutionState = 'unknown-until-smoke-report';
      const r = await sandbox(['_stage', '--spec', specPath, '--fixture', fixturePath, '--provision', provision, '--output', options.output], 'sandbox-process.json', 900000);
      check(r.code === 0, 'Sandboxed native smoke failed; inspect sandbox-process.json');
      const smoke = await json(join(options.output, 'native-smoke.json'));
      check(smoke.result === 'passed' && smoke.evidenceMode === 'native', 'Native smoke did not pass');
    }
    result.networkIsolationClaimed = true;
    }
    result.result = 'passed';
  } catch (error) {
    primaryError = error; result.failure = String(error.message).slice(0, 600);
  }
  finally {
    if (!probeOnly && result.productExecutionState !== 'not-attempted') {
      try {
        const smoke = await json(join(options.output, 'native-smoke.json'));
        result.productExecutionState = smoke.checks.launch ? 'window-observed' : smoke.execution?.launchAttempted ? 'launch-attempted' : smoke.execution?.installAttempted ? 'install-attempted' : 'not-attempted';
      } catch { /* A missing report cannot prove the child did not execute. */ }
    }
    if (fixture) {
      try {
        const after = await networkProbe(fixture.fixture, false);
        result.cleanup.parentConnectivityRestored = after.passed;
        await save(join(provision, 'network-after.json'), after);
        check(after.passed, 'Parent connectivity control failed after sandboxing');
      } catch (error) { result.result = 'failed'; result.cleanup.failure = String(error.message).slice(0, 300); }
      finally {
        try { await fixture.close(); result.cleanup.fixturesClosed = true; }
        catch (error) { result.result = 'failed'; result.cleanup.fixturesClosed = false; result.cleanup.failure ??= String(error.message).slice(0, 300); }
      }
    }
    result.completedAt = new Date().toISOString(); await save(join(provision, 'provision-report.json'), result);
  }
  console.log(JSON.stringify({ ...result, provisionReport: join(provision, 'provision-report.json'), ...(probeOnly ? {} : { smokeReport: join(options.output, 'native-smoke.json') }) }));
  if (primaryError || result.result !== 'passed') process.exitCode = 1;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') {
    console.log('warm-cache --spec ABS --output NEW_ABS\nrun --spec ABS --cache ABS --cache-report ABS --cache-report-sha256 SHA256 --output NEW_ABS [--runner-mode disposable-clean-runner|strict-loopback]\nprobe --output NEW_ABS\nBoth native modes require a disposable GitHub-hosted native GUI runner; archive OUTPUT and OUTPUT.provision. disposable-clean-runner allows unauthenticated public health/update reads, reports unrestricted-no-product-credentials, and claims neither offline execution nor network isolation. strict-loopback remains the default; macOS 15.6 localhost fails strict controls and Windows native run is blocked in strict mode. Warm cache is a separate online job; dependency reconstruction uses a pinned cache/lock. See osir-native-smoke-provision.md for CI commands and fields.'); return;
  }
  const options = parseArguments(args);
  if (options.action === 'warm-cache') await warmCache(options);
  else if (options.action === 'run') await runProvision(options);
  else if (options.action === 'probe') await runProvision(options, true);
  else if (options.action === '_stage') await stage(options);
  else if (options.action === '_probe') {
    const result = await probeProcess(options);
    console.log(JSON.stringify(result)); if (!result.passed) process.exitCode = 1;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main().catch(error => { console.error(`OSIR native provision: ${String(error.message).slice(0, 600)}`); process.exitCode = 1; });
