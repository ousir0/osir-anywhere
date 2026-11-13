import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { asarJson, assertNativeMachine, binaryArchitectures, bindInputs, command, connectorReady, fileIdentity, fingerprintTree, runSmoke, smokeEnvironment, validateSpec, validateWindow, validateWindowsMetadata, validateWelcome, verifyCleanAccount, verifyIsolation } from './osir-native-smoke.mjs';
import { nativeAcceptance } from './osir-anywhere-release.mjs';

const hash = data => createHash('sha256').update(data).digest('hex');
const sha = 'a'.repeat(64), commit = 'b'.repeat(40);
async function temporary(t) {
  const root = await mkdtemp(join(tmpdir(), 'osir-smoke-unit-'));
  t.after(() => rm(root, { recursive: true, force: true })); return root;
}
async function fixture(t) {
  const root = await temporary(t), installer = Buffer.from('synthetic final installer, never executable');
  const signature = { schemaVersion: 1, platform: 'darwin', artifactSha256: hash(installer), systemSignature: 'unsigned' };
  const receipt = { schemaVersion: 1, plan: { target: 'darwin-universal', version: '2.1.9', sourceSha256: sha, configSha256: sha, checkoutHead: commit, upstreamGitHead: commit },
    artifact: { filename: 'OSIR Anywhere.dmg', sha256: hash(installer), size: installer.length, systemSignature: 'unsigned' }, systemSignatureReportSha256: hash(JSON.stringify(signature)) };
  const spec = { schemaVersion: 1, buildReceiptPath: join(root, 'build-receipt.json'), finalInstallerPath: join(root, receipt.artifact.filename), systemSignatureReportPath: join(root, 'signature.json'),
    expected: { ...receipt.plan, artifactSha256: receipt.artifact.sha256, artifactSize: installer.length, systemSignatureReportSha256: receipt.systemSignatureReportSha256 },
    runner: { nativeMachine: 'darwin-arm64', isolationEvidencePath: join(root, 'isolation.json'), isolationEvidenceSha256: sha } };
  await writeFile(spec.finalInstallerPath, installer); await writeFile(spec.buildReceiptPath, JSON.stringify(receipt)); await writeFile(spec.systemSignatureReportPath, JSON.stringify(signature));
  return { root, spec, receipt };
}
const syntheticIsolation = async spec => ({ home: tmpdir(), nativeMachine: spec.runner.nativeMachine, synthetic: true });
function syntheticAdapter(context, overrides = {}) {
  return { hardware: async () => ({ platform: 'darwin', nodeArch: 'arm64', arch: 'arm64', translated: false }),
    install: async () => context.evidence('synthetic-installer.json', '{"synthetic":true}'), launch: async () => {},
    runtimes: async () => { Object.assign(context.checks, { uv: true, python: true, connector: true }); }, ...overrides };
}

test('binds final bytes, source/commit/config and signature evidence to explicitly reviewed values', async t => {
  const { spec } = await fixture(t);
  const inputs = await bindInputs(spec);
  assert.equal(inputs.artifact.sha256, spec.expected.artifactSha256);
  assert.equal(inputs.receipt.plan.checkoutHead, commit);
});

test('refuses wrong final bytes even with a matching installer filename', async t => {
  const { spec } = await fixture(t); await writeFile(spec.finalInstallerPath, 'changed final bytes');
  await assert.rejects(bindInputs(spec), /hash\/size mismatch/);
});

for (const key of ['sourceSha256', 'configSha256', 'checkoutHead', 'upstreamGitHead', 'version', 'target']) test(`refuses mismatched reviewed ${key}`, async t => {
  const { spec } = await fixture(t);
  spec.expected[key] = key === 'target' ? 'win32-arm64' : key === 'version' ? '2.1.8' : key.endsWith('Head') ? 'c'.repeat(40) : 'c'.repeat(64);
  if (key === 'target') spec.runner.nativeMachine = 'win32-arm64';
  await assert.rejects(bindInputs(spec), new RegExp(`receipt ${key} mismatch`));
});

test('refuses changed signature report, unsupported signature policy and unknown expectation injection', async t => {
  const { spec } = await fixture(t);
  await writeFile(spec.systemSignatureReportPath, '{}'); await assert.rejects(bindInputs(spec), /Signature report hash mismatch/);
  spec.expected.result = 'passed'; assert.throws(() => validateSpec(spec), /provenance fields/);
});

test('refuses symlink installers', async t => {
  const { root, spec } = await fixture(t); const real = join(root, 'real.dmg');
  await writeFile(real, await readFile(spec.finalInstallerPath)); await rm(spec.finalInstallerPath); await symlink(real, spec.finalInstallerPath);
  await assert.rejects(bindInputs(spec), /regular file/);
});

test('native machine checks reject Rosetta, Windows emulation, wrong runner and unsupported platform', () => {
  assert.doesNotThrow(() => assertNativeMachine('darwin-arm64', 'darwin', 'arm64', 'arm64', false));
  assert.doesNotThrow(() => assertNativeMachine('darwin-x64', 'darwin', 'x64', 'x64', false));
  assert.doesNotThrow(() => assertNativeMachine('win32-arm64', 'win32', 'arm64', 'arm64', false));
  for (const args of [['darwin-x64', 'darwin', 'x64', 'arm64', true], ['win32-x64', 'win32', 'x64', 'arm64', true], ['darwin-arm64', 'darwin', 'arm64', 'arm64', true], ['win32-arm64', 'win32', 'arm64', 'x64', false], ['linux-x64', 'linux', 'x64', 'x64', false]]) assert.throws(() => assertNativeMachine(...args), /mismatch|Unsupported/);
});

test('environment drops inherited secrets, proxy, Python and app overrides', () => {
  const env = smokeEnvironment({ PATH: '/developer/bin', HOME: '/real-user', OPENAI_API_KEY: 'secret', GH_TOKEN: 'secret', HTTPS_PROXY: 'http://prod', PYTHONPATH: '/developer/site', WORKBENCH_CONNECTOR_DIR: '/developer', OSIR_CONNECTOR_M0: '1', ELECTRON_RUN_AS_NODE: '1', NODE_OPTIONS: '--require=/bad', SystemRoot: 'C:\\Windows' }, '/isolated', '/work', 'win32');
  for (const k of ['OPENAI_API_KEY', 'GH_TOKEN', 'HTTPS_PROXY', 'PYTHONPATH', 'WORKBENCH_CONNECTOR_DIR', 'OSIR_CONNECTOR_M0', 'ELECTRON_RUN_AS_NODE', 'NODE_OPTIONS']) assert.equal(env[k], undefined);
  assert.equal(env.HOME, '/isolated'); assert.equal(env.UV_OFFLINE, '1'); assert.equal(env.UV_PYTHON_DOWNLOADS, 'never');
  assert.equal(env.SystemRoot, 'C:\\Windows'); assert.ok(!env.PATH.includes('developer'));
});

test('ASAR metadata parser checks its real header/offset and refuses indirect entries', async t => {
  const root = await temporary(t), path = join(root, 'app.asar');
  const body = Buffer.from('{"version":"2.1.9"}');
  const index = Buffer.from(JSON.stringify({ files: { 'package.json': { offset: '0', size: body.length }, 'bad.json': { link: 'package.json' } } }));
  const header = Buffer.alloc(16); header.writeUInt32LE(4, 0); header.writeUInt32LE(index.length + 8, 4); header.writeUInt32LE(index.length + 4, 8); header.writeUInt32LE(index.length, 12);
  await writeFile(path, Buffer.concat([header, index, body]));
  assert.deepEqual(await asarJson(path, 'package.json'), { version: '2.1.9' });
  await assert.rejects(asarJson(path, 'bad.json'), /indirect/);
  await assert.rejects(asarJson(path, '../package.json'), /Unsafe/);
  await writeFile(path, Buffer.alloc(16)); await assert.rejects(asarJson(path, 'package.json'), /header size/);
});

test('parses native universal Mach-O and Windows PE, rejects malformed/unknown CPUs', () => {
  const mac = Buffer.alloc(128); mac.writeUInt32BE(0xcafebabe); mac.writeUInt32BE(2, 4); mac.writeUInt32BE(0x01000007, 8); mac.writeUInt32BE(0x0100000c, 28);
  assert.deepEqual(binaryArchitectures(mac), ['arm64', 'x64']);
  const pe = Buffer.alloc(128); pe.writeUInt16LE(0x5a4d); pe.writeUInt32LE(64, 60); pe.writeUInt32LE(0x4550, 64); pe.writeUInt16LE(0xaa64, 68);
  assert.deepEqual(binaryArchitectures(pe), ['arm64']);
  pe.writeUInt16LE(0x14c, 68); assert.throws(() => binaryArchitectures(pe), /Unsupported/);
  pe.writeUInt32LE(9999, 60); assert.throws(() => binaryArchitectures(pe), /Invalid PE/);
  mac.writeUInt32BE(16, 4); assert.throws(() => binaryArchitectures(mac), /Invalid fat/);
});

test('PE numeric zero revision is accepted, while changed product/version/revision is rejected', () => {
  const actual = { ProductName: 'OSIR Anywhere', ProductVersion: '2.2.0.0', FileVersion: '2.2.0' };
  validateWindowsMetadata(actual, '2.2.0');
  for (const patch of [{ ProductName: 'Other app' }, { ProductVersion: '2.2.0.1' }, { FileVersion: '2.1.0' }, { ProductVersion: '2.2.0-beta' }])
    assert.throws(() => validateWindowsMetadata({ ...actual, ...patch }, '2.2.0'), /product\/version mismatch/);
});

test('a loading screen or disabled sign-in action cannot count as renderer readiness', () => {
  const actual = { ready: true, branded: true, action: { text: 'Sign in to OSIR Anywhere', enabled: true, visible: true } };
  validateWelcome(actual);
  for (const patch of [{ ready: false }, { branded: false }, { action: null }, { action: { ...actual.action, enabled: false } }, { action: { ...actual.action, visible: false } }])
    assert.throws(() => validateWelcome({ ...actual, ...patch }), /welcome action/);
});

test('visible loaded packaged window is required; PID, loading/hidden/external windows never count', () => {
  const expected = { version: '2.1.9', nativeMachine: 'darwin-arm64', resources: '/isolated/app/Resources', accountHome: '/isolated/home', allowedDataRoots: ['/isolated/home/Library/Application Support'], pid: 123 };
  const state = { name: 'OSIR Anywhere', version: '2.1.9', pid: 123, packaged: true, electron: '39.2.7', platform: 'darwin', arch: 'arm64', resources: expected.resources, home: expected.accountHome, userData: '/isolated/home/Library/Application Support/OSIR Anywhere', windows: [{ id: 1, visible: true, destroyed: false, loading: false, width: 1000, height: 700, rendererPid: 456, url: 'osir-anywhere-workbench://web/' }] };
  assert.equal(validateWindow(state, expected).id, 1);
  for (const patch of [{ visible: false }, { loading: true }, { rendererPid: 0 }, { destroyed: true }, { url: 'https://production.test/' }, { width: 20 }]) assert.throws(() => validateWindow({ ...state, windows: [{ ...state.windows[0], ...patch }] }, expected), /no visible/);
  for (const patch of [{ userData: '/real-user/accounts' }, { arch: 'x64' }, { pid: 124 }, { packaged: false }, { resources: '/developer/resources' }, { home: '/real-user' }]) assert.throws(() => validateWindow({ ...state, ...patch }, expected), /mismatch|escaped/);
});

test('reviewed cache fingerprint detects changes, accepts empty files and rejects escaping links', async t => {
  const root = await temporary(t), cache = join(root, 'cache'); await mkdir(cache);
  await writeFile(join(cache, 'empty'), ''); await writeFile(join(cache, 'wheel'), 'synthetic-wheel');
  const first = await fingerprintTree(cache); assert.equal(first, await fingerprintTree(cache));
  await writeFile(join(cache, 'wheel'), 'changed-wheel'); assert.notEqual(first, await fingerprintTree(cache));
  await writeFile(join(root, 'outside'), 'outside'); await symlink(join(root, 'outside'), join(cache, 'escape'));
  await assert.rejects(fingerprintTree(cache), /escapes/);
});

test('handwritten attestation is refused even when account/time/hash match; SSH directory is tolerated without reading credentials', async t => {
  const { root, spec } = await fixture(t), home = join(root, 'native-home'); await mkdir(home);
  // Canonicalize /var -> /private/var on macOS, like real OS home paths.
  const { realpath } = await import('node:fs/promises'); const canonicalHome = await realpath(home);
  const record = { schemaVersion: 1, kind: 'disposable-native-runner', disposable: true, networkPolicy: 'deny-all-except-loopback', user: 'smoke', home: canonicalHome, hostname: 'isolated-vm', nativeMachine: 'darwin-arm64', jobId: 'job-42', createdAt: new Date().toISOString() };
  await writeFile(spec.runner.isolationEvidencePath, JSON.stringify(record)); spec.runner.isolationEvidenceSha256 = (await fileIdentity(spec.runner.isolationEvidencePath)).sha256;
  const actual = { user: 'smoke', home: canonicalHome, hostname: 'isolated-vm' };
  await mkdir(join(home, '.ssh')); await writeFile(join(home, '.ssh/id_canary'), 'canary-do-not-read', { mode: 0o000 });
  assert.deepEqual(await verifyCleanAccount(actual), actual);
  await assert.rejects(verifyIsolation(spec, actual), /real provision helper/);
  await assert.rejects(verifyIsolation(spec, { ...actual, user: 'real-user' }), /not the attested/);
  await mkdir(join(home, '.codex')); await writeFile(join(home, '.codex/auth.json'), 'canary-do-not-read');
  await assert.rejects(verifyIsolation(spec, actual), /existing credentials/);
  assert.equal(await readFile(join(home, '.codex/auth.json'), 'utf8'), 'canary-do-not-read');
});

test('synthetic orchestration reports simulated, retains uncovered checks and cannot satisfy publisher gate', async t => {
  const { root, spec, receipt } = await fixture(t), output = join(root, 'evidence');
  const report = await runSmoke(spec, output, { isolationVerifier: syntheticIsolation, adapterFactory: syntheticAdapter });
  assert.equal(report.result, 'simulated'); assert.equal(report.evidenceMode, 'synthetic');
  assert.equal(report.releaseAcceptance, 'incomplete'); assert.equal(report.checks.launch, true);
  assert.equal(report.checks.upgradeDataPreserved, false); assert.equal(report.checks.updateDiscovery, false);
  assert.deepEqual(report.nativeMachines, ['darwin-arm64']); assert.ok(report.uncovered.includes('real-account-login-and-oauth'));
  assert.throws(() => nativeAcceptance(report, receipt), /acceptance missing/);
  for (const evidence of report.evidence) assert.deepEqual(await fileIdentity(join(output, evidence.path)), { size: evidence.size, sha256: evidence.sha256 });
  await assert.rejects(runSmoke(spec, output, { adapterFactory: syntheticAdapter }), /EEXIST/);
});

test('clean-runner orchestration reports unrestricted networking, never relabels synthetic execution or claims full offline', async t => {
  const { root, spec } = await fixture(t);
  const report = await runSmoke(spec, join(root, 'clean-evidence'), { adapterFactory: syntheticAdapter,
    isolationVerifier: async () => ({ home: tmpdir(), runnerMode: 'disposable-clean-runner', networkPolicy: 'unrestricted-no-product-credentials', networkIsolationClaimed: false, hostedRunner: { basis: 'synthetic-fixture' }, boundaries: ['no-product-credentials'] }) });
  assert.equal(report.result, 'simulated'); assert.equal(report.evidenceMode, 'synthetic');
  assert.equal(report.runnerMode, 'disposable-clean-runner'); assert.equal(report.networkPolicy, 'unrestricted-no-product-credentials');
  assert.equal(report.networkIsolationClaimed, false); assert.equal(report.fullSmokeOfflineClaimed, false);
  assert.ok(report.uncovered.includes('network-isolation-and-full-offline-execution'));
});

for (const name of ['.cc-switch', 'Library/Application Support/OSIR Client', 'AppData/Roaming/OSIR Anywhere']) test(`existing ${name} prevents clean-runner product launch without reading account files`, async t => {
  const root = await temporary(t), { realpath } = await import('node:fs/promises');
  await mkdir(join(root, name), { recursive: true }); await writeFile(join(root, name, 'canary'), 'synthetic-account-do-not-read', { mode: 0o000 });
  await assert.rejects(verifyCleanAccount({ home: await realpath(root) }), /existing credentials\/product data/);
});

for (const stage of ['hardware', 'install', 'launch', 'runtimes']) test(`native ${stage} failure records failed report and stops later stages`, async t => {
  const { root, spec } = await fixture(t); const calls = [];
  const report = await runSmoke(spec, join(root, 'evidence'), { isolationVerifier: syntheticIsolation, adapterFactory: ctx => syntheticAdapter(ctx, {
    [stage]: async () => { calls.push(stage); throw new Error(`synthetic ${stage} failure`); },
  }) });
  assert.equal(report.result, 'failed'); assert.match(report.failure, new RegExp(stage)); assert.equal(calls.length, 1);
  assert.equal(report.checks.upgradeDataPreserved, false);
  assert.equal(report.checks.launch, ['runtimes'].includes(stage));
});

test('installer identity failure prevents isolation/native adapter execution but preserves failure report', async t => {
  const { root, spec } = await fixture(t); await writeFile(spec.finalInstallerPath, 'tampered'); let invoked = false;
  const report = await runSmoke(spec, join(root, 'evidence'), { isolationVerifier: async () => { invoked = true; }, adapterFactory: () => { invoked = true; } });
  assert.equal(report.result, 'failed'); assert.equal(invoked, false); assert.deepEqual(report.nativeMachines, []);
});

test('unknown expected fields cannot forge report success or acceptance scope', async t => {
  const { root, spec } = await fixture(t);
  Object.assign(spec.expected, { result: 'passed', releaseAcceptance: 'complete', scope: 'full-release', productId: 'other-product' });
  const report = await runSmoke(spec, join(root, 'evidence'), { adapterFactory: syntheticAdapter });
  assert.equal(report.result, 'failed'); assert.equal(report.releaseAcceptance, 'incomplete');
  assert.equal(report.scope, 'native-smoke'); assert.equal(report.productId, 'osir-anywhere');
  assert.match(report.failure, /provenance fields/);
});

test('reviewed cache copies preserve relative symlinks without pointing at source cache', async t => {
  const { cp } = await import('node:fs/promises');
  const root = await temporary(t), cache = join(root, 'cache'), copied = join(root, 'copied'); await mkdir(cache);
  await writeFile(join(cache, 'wheel'), 'wheel'); await symlink('wheel', join(cache, 'link'));
  const expected = await fingerprintTree(cache);
  await cp(cache, copied, { recursive: true, verbatimSymlinks: true });
  assert.equal(await fingerprintTree(copied), expected);
});

test('offline runtime incompleteness is not silently accepted', async t => {
  const { root, spec } = await fixture(t);
  const report = await runSmoke(spec, join(root, 'evidence'), { isolationVerifier: syntheticIsolation, adapterFactory: ctx => syntheticAdapter(ctx, { runtimes: async () => { ctx.checks.uv = true; ctx.checks.python = true; } }) });
  assert.equal(report.result, 'failed'); assert.match(report.failure, /runtime smoke incomplete/);
});

test('post-smoke installer mutation fails the report', async t => {
  const { root, spec } = await fixture(t);
  const report = await runSmoke(spec, join(root, 'evidence'), { isolationVerifier: syntheticIsolation, adapterFactory: ctx => syntheticAdapter(ctx, { runtimes: async () => { Object.assign(ctx.checks, { uv: true, python: true, connector: true }); await writeFile(spec.finalInstallerPath, 'mutated'); } }) });
  assert.equal(report.result, 'failed'); assert.match(report.failure, /changed during smoke/);
});

test('bounded command runner preserves literal arguments without shell expansion', async () => {
  const r = await command(process.execPath, ['-e', 'process.stdout.write(process.argv[1])', '$(do-not-run) `literal` spaces'], { timeout: 5000 });
  assert.equal(r.code, 0); assert.equal(r.stdout, '$(do-not-run) `literal` spaces');
  await assert.rejects(command(process.execPath, ['-e', 'console.log("synthetic-timeout-evidence");setInterval(()=>{},1000)'], { timeout: 300 }), error => {
    assert.match(error.message, /timed out/); assert.match(error.commandResult.stdout, /synthetic-timeout-evidence/); return true;
  });
  await assert.rejects(command(process.execPath, ['-e', 'process.stdout.write("x".repeat(3*1024*1024));setInterval(()=>{},1000)'], { timeout: 5000 }), /output exceeded/);
});

test('CLI accepts exact absolute spec/output arguments, exits nonzero on failure and preserves failed report', async t => {
  const { root, spec } = await fixture(t), input = join(root, 'spec.json'), output = join(root, 'cli-evidence');
  await writeFile(spec.finalInstallerPath, 'tampered-before-cli');
  await writeFile(input, JSON.stringify(spec));
  const script = fileURLToPath(new URL('osir-native-smoke.mjs', import.meta.url));
  const result = await command(process.execPath, [script, '--spec', input, '--output', output], { timeout: 10000 });
  assert.equal(result.code, 1);
  const summary = JSON.parse(result.stdout), report = JSON.parse(await readFile(join(output, 'native-smoke.json'), 'utf8'));
  assert.equal(summary.result, 'failed'); assert.equal(report.releaseAcceptance, 'incomplete');
  assert.match(report.failure, /hash\/size mismatch/); assert.deepEqual(report.nativeMachines, []);
  const second = await command(process.execPath, [script, '--spec', input, '--output', output], { timeout: 10000 });
  assert.equal(second.code, 1); assert.deepEqual(JSON.parse(await readFile(join(output, 'native-smoke.json'), 'utf8')), report);
});

test('CLI help is read-only and malformed argument shapes are rejected before native operations', async () => {
  const script = fileURLToPath(new URL('osir-native-smoke.mjs', import.meta.url));
  const help = await command(process.execPath, [script, '--help'], { timeout: 10000 });
  assert.equal(help.code, 0); assert.match(help.stdout, /partial native smoke/);
  const bad = await command(process.execPath, [script, '--output', 'relative', '--spec', 'relative'], { timeout: 10000 });
  assert.equal(bad.code, 1); assert.match(bad.stderr, /Use --help/);
});

test('Connector synthetic ready protocol uses real descriptor shape, redacts key and awaits clean EOF', async t => {
  const root = await temporary(t), code = join(root, 'synthetic-rpc.cjs');
  await writeFile(code, `console.log(JSON.stringify({kind:'connector.ready',version:1,key:'mk_host_synthetic_secret',pid:process.pid,endpoint:{unixPath:'/synthetic/socket'}}));process.stdin.resume();process.stdin.on('end',()=>process.exit(0));`);
  const result = await connectorReady(process.execPath, [code], { cwd: root, env: {}, timeout: 5000 });
  assert.equal(result.kind, 'connector.ready'); assert.equal(result.cleanShutdown, true); assert.ok(!JSON.stringify(result).includes('secret'));
});

test('Connector missing-ready/invalid-ready/unclean EOF fail rather than count process existence', async t => {
  const root = await temporary(t);
  for (const [name, code, error] of [
    ['exit', 'process.exit(2)', /exited before/],
    ['bad', "console.log('{}');setInterval(()=>{},1000)", /Invalid Connector/],
    ['unclean', "console.log(JSON.stringify({kind:'connector.ready',version:1,key:'mk_host_secret',pid:process.pid,endpoint:{pipe:'synthetic'}}));process.stdin.resume();process.stdin.on('end',()=>process.exit(2));", /shut down cleanly/],
  ]) { const path = join(root, `${name}.cjs`); await writeFile(path, code); await assert.rejects(connectorReady(process.execPath, [path], { cwd: root, env: {}, timeout: 2000 }), error); }
});
