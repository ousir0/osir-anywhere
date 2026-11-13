import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { command, fileIdentity, fingerprintTree, validateSpec } from './osir-native-smoke.mjs';
import { childEnvironment, classifyNetworkProbes, hostedRunnerProvenance, isolationFailure, networkProbe, parseArguments, permissionDenied, rehearseOfflineCache, requireHostedRunner, requireIsolationPlatform, validateCacheReport, verifyHostedRunnerEnvironment, verifyProvisionedIsolation, WINDOWS_BLOCKER } from './osir-native-smoke-provision.mjs';

// Offline unit tests only. The real local-interface/sandbox test is the explicit
// `probe --output ABS` CLI invocation, never run implicitly by this test suite.
const sha = 'a'.repeat(64), commit = 'b'.repeat(40);
async function temporary(t) {
  const path = await mkdtemp(join(tmpdir(), 'osir-provision-unit-'));
  t.after(() => rm(path, { recursive: true, force: true })); return path;
}
async function fixture(t) {
  const root = await temporary(t), cache = join(root, 'cache'); await mkdir(cache);
  await writeFile(join(cache, 'synthetic-wheel'), 'fixture only, no runtime dependencies');
  const lockPath = join(root, 'connector-resolved-uv.lock'); await writeFile(lockPath, 'version = 1\n');
  const spec = { schemaVersion: 1, buildReceiptPath: join(root, 'receipt.json'), finalInstallerPath: join(root, 'synthetic.dmg'), systemSignatureReportPath: join(root, 'signature.json'),
    expected: { sourceSha256: sha, configSha256: sha, checkoutHead: commit, upstreamGitHead: commit, version: '2.1.9', target: 'darwin-universal', artifactSha256: sha, artifactSize: 123, systemSignatureReportSha256: sha },
    runner: { nativeMachine: 'darwin-arm64' } };
  const report = { schemaVersion: 1, scope: 'native-smoke-dependency-cache', result: 'prepared', expected: { ...spec.expected }, nativeMachine: spec.runner.nativeMachine,
    cache: { sha256: await fingerprintTree(cache) }, evidence: [{ path: 'connector-resolved-uv.lock', ...(await fileIdentity(lockPath)) }] };
  report.connectorSourceSha256 = sha;
  report.offlineRehearsal = { result: 'passed', mode: 'uv-offline-only', independentProject: true, independentVenv: true, sourceSha256: sha, cacheSha256: report.cache.sha256, lockSha256: report.evidence[0].sha256, venvConfig: { sha256: sha, size: 1 } };
  const reportPath = join(root, 'dependency-cache.json');
  const persist = async () => { await writeFile(reportPath, JSON.stringify(report)); return (await fileIdentity(reportPath)).sha256; };
  return { root, cache, spec, report, reportPath, lockPath, persist, reportHash: await persist() };
}

test('CLI keeps action separate from internal probe mode and accepts full concrete run flags', () => {
  assert.deepEqual(parseArguments(['_probe', '--fixture', '/abs/fixture.json', '--mode', 'baseline']), { action: '_probe', fixture: '/abs/fixture.json', mode: 'baseline' });
  assert.deepEqual(parseArguments(['probe', '--output', '/abs/new']), { action: 'probe', output: '/abs/new' });
  const run = parseArguments(['run', '--spec', '/abs/spec.json', '--cache', '/abs/cache', '--cache-report', '/abs/report.json', '--cache-report-sha256', sha, '--output', '/abs/output']);
  assert.equal(run.action, 'run'); assert.equal(run['cache-report-sha256'], sha);
  assert.equal(parseArguments(['run', '--spec', '/abs/spec.json', '--cache', '/abs/cache', '--cache-report', '/abs/report.json', '--cache-report-sha256', sha, '--output', '/abs/output', '--runner-mode', 'disposable-clean-runner'])['runner-mode'], 'disposable-clean-runner');
  assert.equal(parseArguments(['warm-cache', '--spec', '/abs/spec.json', '--output', '/abs/output', '--runner-mode', 'strict-loopback'])['runner-mode'], 'strict-loopback');
  for (const args of [[], ['run'], ['probe', '--output', 'relative'], ['probe', '--unknown', '/abs'], ['_probe', '--fixture', '/abs', '--mode', 'passed'], ['_probe', '--fixture', '/abs', '--fixture', '/other'], ['probe', '--output', '/abs', '--extra', '/abs']]) assert.throws(() => parseArguments(args), /argument|path|value/);
});

test('local and self-hosted execution cannot claim disposable GitHub-hosted runner', async () => {
  const hosted = { GITHUB_ACTIONS: 'true', RUNNER_ENVIRONMENT: 'github-hosted', GITHUB_RUN_ID: '42' };
  assert.doesNotThrow(() => verifyHostedRunnerEnvironment(hosted));
  for (const env of [{}, { ...hosted, RUNNER_ENVIRONMENT: 'self-hosted' }, { ...hosted, GITHUB_RUN_ID: 'fake' }, { ...hosted, GITHUB_ACTIONS: 'false' }]) await assert.rejects(requireHostedRunner(env), /GitHub-hosted/);
});

test('Windows platform gate has a specific inheritance blocker; no firewall or process mutation', () => {
  assert.throws(() => requireIsolationPlatform('win32'), error => error.message === WINDOWS_BLOCKER && /NSIS.*Connector/.test(error.message));
  assert.throws(() => requireIsolationPlatform('linux'), /unsupported on linux/);
  assert.doesNotThrow(() => requireIsolationPlatform('darwin'));
  assert.doesNotThrow(() => requireIsolationPlatform('win32', 'disposable-clean-runner'));
  assert.doesNotThrow(() => requireIsolationPlatform('darwin', 'disposable-clean-runner'));
  assert.throws(() => requireIsolationPlatform('linux', 'disposable-clean-runner'), /unsupported/);
  assert.throws(() => requireIsolationPlatform('win32', 'fake-isolation'), /Unknown native runner mode/);
});

test('hosted-runner provenance is an honest metadata record, without token values or a cryptographic attestation claim', () => {
  const env = { GITHUB_ACTIONS: 'true', RUNNER_ENVIRONMENT: 'github-hosted', GITHUB_RUN_ID: '42', GITHUB_JOB: 'native', RUNNER_OS: 'Windows', GITHUB_TOKEN: 'canary', OAUTH_TOKEN: 'canary', CSC_KEY_PASSWORD: 'canary' };
  const p = hostedRunnerProvenance(env);
  assert.equal(p.metadata.RUNNER_OS, 'Windows'); assert.equal(p.metadata.GITHUB_JOB, 'native');
  assert.equal(p.cryptographicRunnerAttestation, false); assert.ok(!JSON.stringify(p).includes('canary'));
  assert.throws(() => hostedRunnerProvenance({ ...env, RUNNER_ENVIRONMENT: 'self-hosted' }), /GitHub-hosted/);
});

test('workflow metadata survives but tokens, proxy, overrides and account credentials do not enter child environment', () => {
  const env = childEnvironment('/synthetic/work', { GITHUB_ACTIONS: 'true', GITHUB_RUN_ID: '42', RUNNER_ENVIRONMENT: 'github-hosted', GITHUB_TOKEN: 'canary', ACTIONS_RUNTIME_TOKEN: 'canary', NODE_OPTIONS: '--require=canary', HTTPS_PROXY: 'canary', SSH_AUTH_SOCK: '/canary', UV_OFFLINE: 'false', OPENAI_API_KEY: 'canary' });
  assert.equal(env.GITHUB_RUN_ID, '42'); assert.equal(env.UV_OFFLINE, '1');
  for (const key of ['GITHUB_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'NODE_OPTIONS', 'HTTPS_PROXY', 'SSH_AUTH_SOCK', 'OPENAI_API_KEY']) assert.equal(env[key], undefined);
  assert.ok(!JSON.stringify(env).includes('canary'));
});

test('only actual permission errors count as enforcement, not timeout/routing/connectivity failure', () => {
  for (const error of ['EPERM', 'EACCES']) assert.equal(permissionDenied({ allowed: false, error }), true);
  for (const error of ['TIMEOUT', 'ENETUNREACH', 'EHOSTUNREACH', 'ECONNREFUSED', 'NO_CHALLENGE', undefined]) assert.equal(permissionDenied({ allowed: false, error }), false);
  assert.equal(permissionDenied({ allowed: true, error: 'EPERM' }), false); assert.equal(permissionDenied(undefined), false);
});

test('strict network proof requires every loopback/IPC positive and non-loopback negative control', () => {
  const probes = Object.fromEntries(['tcp4Loopback', 'tcp6Loopback', 'udp4Loopback', 'udp6Loopback', 'unixIpc'].map(k => [k, { allowed: true }]));
  for (const name of ['tcp4NonLoopback', 'udp4NonLoopback', 'tcp4TestNet', 'tcp6TestNet', 'udp4TestNet', 'udp6TestNet']) probes[name] = { allowed: false, error: 'EPERM' };
  assert.equal(classifyNetworkProbes(probes, true), true);
  for (const name of Object.keys(probes)) {
    const broken = { ...probes, [name]: { allowed: false, error: 'TIMEOUT' } };
    assert.equal(classifyNetworkProbes(broken, true), false, name);
  }
  const broadLocalhost = { ...probes, tcp4NonLoopback: { allowed: true }, udp4NonLoopback: { allowed: true } };
  assert.equal(classifyNetworkProbes(broadLocalhost, true), false);
  assert.equal(classifyNetworkProbes(broadLocalhost, false), true);
  assert.match(isolationFailure({ probes: broadLocalhost }), /non-loopback interface.*No attestation/);
});

test('invalid fixture is refused before any network operation', async () => {
  for (const fixture of [{}, { schemaVersion: 1, nonce: 'a'.repeat(32), nonLoopback4: '127.0.0.1' }]) await assert.rejects(networkProbe(fixture, true), /Invalid local network fixture/);
});

test('handwritten process-looking proof cannot establish real live enforcement', async () => {
  await assert.rejects(verifyProvisionedIsolation({ enforcement: { kind: 'externally-attested-vm-or-firewall' } }), /real provision helper/);
  await assert.rejects(verifyProvisionedIsolation({ enforcement: { kind: 'macos-seatbelt', processId: process.pid, provisionerSha256: sha } }), /real provision helper/);
  await assert.rejects(verifyProvisionedIsolation({ runnerMode: 'disposable-clean-runner', networkPolicy: 'unrestricted-no-product-credentials', enforcement: { kind: 'github-hosted-clean-runner', processId: process.pid, provisionerSha256: sha } }), /GitHub-hosted|live GitHub-hosted/);
});

for (const platform of ['win32', 'darwin']) test(`${platform} cache rehearsal uses a different source/cache/venv and labels UV-only evidence honestly`, async t => {
  const f = await fixture(t), work = join(f.root, 'work'), source = join(f.root, 'packaged-connector'); await mkdir(work); await mkdir(source);
  await writeFile(join(source, 'pyproject.toml'), '[project]\nname="synthetic-connector"\n');
  let invoked = false;
  const result = await rehearseOfflineCache({ source, cache: f.cache, lockPath: f.lockPath, uv: '/bundled/uv', python: '/bundled/python', work, env: { UV_OFFLINE: 'false', UV_PROJECT_ENVIRONMENT: '/online/venv' }, platform,
    run: async (exe, args, label, extra) => {
      invoked = true; assert.equal(exe, '/bundled/uv'); assert.ok(args.includes('--offline') && args.includes('--locked')); assert.equal(label, 'offline-cache-rehearsal');
      assert.equal(extra.env.UV_OFFLINE, '1'); assert.ok(extra.env.UV_PROJECT_ENVIRONMENT.startsWith(join(work, 'offline-rehearsal')));
      assert.notEqual(extra.env.UV_CACHE_DIR, f.cache); assert.equal(await fingerprintTree(extra.env.UV_CACHE_DIR), f.report.cache.sha256);
      assert.equal(await readFile(join(args[args.indexOf('--project') + 1], 'uv.lock'), 'utf8'), 'version = 1\n');
      await writeFile(join(extra.env.UV_CACHE_DIR, 'rehearsal-only'), 'not in transferred original');
      await mkdir(extra.env.UV_PROJECT_ENVIRONMENT); await writeFile(join(extra.env.UV_PROJECT_ENVIRONMENT, 'pyvenv.cfg'), 'synthetic-config\n');
    } });
  assert.equal(invoked, true); assert.equal(result.result, 'passed'); assert.equal(result.mode, 'uv-offline-only');
  assert.equal(result.independentProject, true); assert.equal(result.independentVenv, true);
  assert.equal(await fingerprintTree(f.cache), f.report.cache.sha256);
});

test('cache rehearsal command failure or mutation of the original cache cannot produce successful preparation', async t => {
  const f = await fixture(t), source = join(f.root, 'source'); await mkdir(source); await writeFile(join(source, 'pyproject.toml'), 'synthetic');
  for (const [name, run, error] of [
    ['command', async () => { throw new Error('synthetic offline build failed'); }, /offline build failed/],
    ['mutate', async () => { await writeFile(join(f.cache, 'synthetic-wheel'), 'mutated'); }, /Original cache or lock changed/],
  ]) {
    const work = join(f.root, name); await mkdir(work);
    await assert.rejects(rehearseOfflineCache({ source, cache: f.cache, lockPath: f.lockPath, uv: '/synthetic/uv', python: '/synthetic/python', work, env: {}, platform: 'win32', run }), error);
  }
});

test('prepared cache requires pinned report bytes and carries resolved lock into offline spec', async t => {
  const f = await fixture(t), verified = await validateCacheReport(f.spec, f.reportPath, f.reportHash, f.cache);
  assert.deepEqual(verified, { path: f.cache, sha256: f.report.cache.sha256, lockPath: f.lockPath, lockSha256: f.report.evidence[0].sha256 });
  assert.doesNotThrow(() => validateSpec({ ...f.spec, dependencyCache: verified }, { requireIsolation: false }));
  assert.throws(() => validateSpec({ ...f.spec, dependencyCache: { ...verified, lockPath: 'relative' } }, { requireIsolation: false }), /Pinned resolved dependency lock/);
  await assert.rejects(validateCacheReport(f.spec, f.reportPath, 'c'.repeat(64), f.cache), /pinned file/);
  await writeFile(f.reportPath, `${await readFile(f.reportPath, 'utf8')}\n`);
  await assert.rejects(validateCacheReport(f.spec, f.reportPath, f.reportHash, f.cache), /pinned file/);
});

test('cache mutations and missing/different resolved lock evidence cannot pass', async t => {
  const f = await fixture(t);
  await writeFile(f.lockPath, 'mutated');
  await assert.rejects(validateCacheReport(f.spec, f.reportPath, f.reportHash, f.cache), /lock differs/);
  await writeFile(f.lockPath, 'version = 1\n'); await writeFile(join(f.cache, 'synthetic-wheel'), 'mutated');
  await assert.rejects(validateCacheReport(f.spec, f.reportPath, f.reportHash, f.cache), /tree fingerprint/);
  f.report.cache.sha256 = await fingerprintTree(f.cache); f.report.evidence = [];
  await assert.rejects(validateCacheReport(f.spec, f.reportPath, await f.persist(), f.cache), /lacks resolved lock/);
});

for (const field of ['sourceSha256', 'configSha256', 'checkoutHead', 'upstreamGitHead', 'version', 'target', 'artifactSha256', 'artifactSize', 'systemSignatureReportSha256']) test(`cache provenance mismatch cannot be repinned past final ${field}`, async t => {
  const f = await fixture(t); f.report.expected[field] = 'different';
  await assert.rejects(validateCacheReport(f.spec, f.reportPath, await f.persist(), f.cache), new RegExp(`cache ${field} differs`));
});

test('failed prep or wrong native architecture cannot be reused', async t => {
  const f = await fixture(t); f.report.result = 'failed';
  await assert.rejects(validateCacheReport(f.spec, f.reportPath, await f.persist(), f.cache), /did not succeed/);
  f.report.result = 'prepared'; f.report.nativeMachine = 'darwin-x64';
  await assert.rejects(validateCacheReport(f.spec, f.reportPath, await f.persist(), f.cache), /native architecture/);
});

test('missing or failed independent offline reconstruction cannot be reused as prepared cache', async t => {
  const f = await fixture(t); delete f.report.offlineRehearsal;
  await assert.rejects(validateCacheReport(f.spec, f.reportPath, await f.persist(), f.cache), /independent offline reconstruction/);
  f.report.offlineRehearsal = { result: 'failed' };
  await assert.rejects(validateCacheReport(f.spec, f.reportPath, await f.persist(), f.cache), /independent offline reconstruction/);
});

test('CLI help exposes real blockers; invalid fixture routing fails instead of silently exiting zero', async t => {
  const root = await temporary(t), script = fileURLToPath(new URL('./osir-native-smoke-provision.mjs', import.meta.url));
  const help = await command(process.execPath, [script, '--help'], { timeout: 5000 });
  assert.equal(help.code, 0); assert.match(help.stdout, /--cache-report-sha256/); assert.match(help.stdout, /Windows native run is blocked/);
  const path = join(root, 'invalid.json'); await writeFile(path, '{}');
  const probe = await command(process.execPath, [script, '_probe', '--fixture', path, '--mode', 'leaf'], { timeout: 5000 });
  assert.equal(probe.code, 1); assert.match(probe.stderr, /Invalid local network fixture/);
  for (const mode of [[], ['--runner-mode', 'disposable-clean-runner']]) {
    const fake = await command(process.execPath, [script, 'run', '--spec', path, '--cache', root, '--cache-report', path, '--cache-report-sha256', sha, '--output', join(root, 'output'), ...mode], { env: {}, timeout: 5000 });
    assert.equal(fake.code, 1); assert.match(fake.stderr, /GitHub-hosted/);
  }
});
