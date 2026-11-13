import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bytes, digest, fingerprint, inspect } from './osir-anywhere-release-common.mjs';
import { fingerprintTree } from './osir-native-smoke.mjs';
import { parseArguments as provisionArguments } from './osir-native-smoke-provision.mjs';
import { REPOSITORY, STDERR_LIMIT, acceptanceMatrix, bindDownloadedArtifact, boundedArchiveCommand, cacheArchiveArguments, collectEvidence, githubMetadata, reviewedBindings, sanitizedStderr, sealCache, unpackCache, unpackProductArchive, verifyHarness, verifyHarnessFiles, verifyProducer, verifyRemoteArtifacts, verifySmokeReport } from './osir-artifact-acceptance-ci.mjs';

const A = 'a'.repeat(40), B = 'b'.repeat(40), H = 'c'.repeat(40), X = '1'.repeat(64);
const harness = { repository: REPOSITORY, commit: H, runId: 77, runAttempt: 2 };
const clone = value => structuredClone(value);

test('Windows drive paths and spaces cannot become a remote tar archive; process runs in the output cwd', async t => {
  const prep = 'D:\\a\\_temp\\warm cache';
  assert.deepEqual(cacheArchiveArguments(prep, ['dependency-cache.json']), ['-cf', 'offline-cache.tar', '-C', prep, 'cache', 'dependency-cache.json']);
  const root = await mkdtemp(join(tmpdir(), 'osir-tar-cwd-')); t.after(() => rm(root, { recursive: true, force: true }));
  const result = await boundedArchiveCommand(process.execPath, ['-e', 'process.stderr.write(process.cwd())'], { cwd: root });
  assert.equal(result.status, 0); assert.equal(result.stderr, execFileSync(process.execPath, ['-e', 'process.stdout.write(process.cwd())'], { cwd: root }).toString());
});

test('archive diagnostics preserve exact ordinary stderr, sanitize credentials and bound noisy failures', async () => {
  const stderr = 'tar: cache/file: Cannot stat: No such file or directory\r\ntar: Error exit delayed from previous errors.\r\n';
  const result = await boundedArchiveCommand(process.execPath, ['-e', 'process.stderr.write(process.argv[1]); process.exitCode=1', stderr]);
  assert.equal(result.status, 1); assert.equal(result.stderr, stderr); assert.equal(result.stderrBytes, Buffer.byteLength(stderr)); assert.equal(result.stderrTruncated, false);
  const secret = 'private-fixture-token';
  assert.equal(sanitizedStderr(Buffer.from(`tar: ${secret} Bearer abc123 https://user:password@example.invalid/?token=abc123\u001b[31m\u0000`), { GH_TOKEN: secret }), 'tar: [REDACTED] [REDACTED authorization] https://[REDACTED]@example.invalid/?token=[REDACTED]');
  const noisy = await boundedArchiveCommand(process.execPath, ['-e', 'process.stderr.write("x".repeat(100000));process.exitCode=1']);
  assert.equal(noisy.stderr.length, STDERR_LIMIT); assert.equal(noisy.stderrBytes, 100000); assert.equal(noisy.stderrTruncated, true);
  const missing = await boundedArchiveCommand('osir-missing-archive-tool-fixture', []);
  assert.equal(missing.spawnFailed, true); assert.equal(missing.stderr, '');
  const timeout = await boundedArchiveCommand(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { timeout: 50 });
  assert.equal(timeout.timedOut, true);
});

test('workflow clean-runner flags are accepted by the actual provision CLI without relaxing native checks', () => {
  const base = join(tmpdir(), 'osir-cli-contract');
  const args = ['run', '--spec', join(base, 'base.json'), '--cache', join(base, 'cache'), '--cache-report', join(base, 'report.json'), '--cache-report-sha256', X,
    '--output', join(base, 'smoke'), '--runner-mode', 'disposable-clean-runner'];
  const parsed = provisionArguments(args); assert.equal(parsed.action, 'run'); assert.equal(parsed['runner-mode'], 'disposable-clean-runner'); assert.equal(parsed['cache-report-sha256'], X);
});

async function fixture(t, target = 'darwin-universal') {
  const root = await mkdtemp(join(tmpdir(), 'osir-independent-harness-')); t.after(() => rm(root, { recursive: true, force: true }));
  const original = join(root, 'original'); await mkdir(original);
  // Deliberately not a native package. These exercise identity/transfer
  // validation only; no product installation, signature probe or GUI is run.
  const installer = Buffer.from('synthetic identity fixture; not an installer'), lock = Buffer.from('# fixture dependency lock\n');
  const files = [{ path: 'osir-build-recipe.json', sha256: digest('{}\n'), size: 3, executable: false }];
  const source = { schemaVersion: 1, upstreamGitHead: B, files, sourceSha256: fingerprint(files) };
  const p = { schemaVersion: 1, releaseId: 'fixture', version: '2.2.0', target, sourceSha256: source.sourceSha256, configSha256: X, recipeSha256: files[0].sha256, checkoutHead: A, upstreamGitHead: B, dependencies: { lockSha256: digest(lock), installStateSha256: X, node: 'v22.23.2' } };
  const platform = target.split('-')[0], filename = `osir-anywhere-2.2.0-${target}.${platform === 'darwin' ? 'dmg' : 'exe'}`;
  const signature = { schemaVersion: 1, platform, artifactSha256: digest(installer), systemSignature: 'unsigned', probes: platform === 'darwin' ? {
    image: { tool: 'hdiutil', status: 0 }, identity: { tool: 'codesign', status: 1, stdout: '', stderr: 'code object is not signed at all' },
  } : { authenticode: { tool: 'powershell.exe', status: 0, stdout: 'NotSigned' } } };
  const receipt = { schemaVersion: 1, plan: p, artifact: { filename, size: installer.length, sha256: digest(installer), systemSignature: 'unsigned' }, systemSignatureReportSha256: digest(bytes(signature)), sourceProvenanceSha256: digest(bytes(source)), runner: { runId: '123', os: platform, arch: target === 'win32-x64' ? 'x64' : 'arm64' } };
  await Promise.all(Object.entries({ [filename]: installer, 'resolved-yarn.lock': lock, 'source-provenance.json': bytes(source), 'compiled.json': bytes({ planSha256: fingerprint(p), outputsSha256: X }), 'system-signature.json': bytes(signature), 'build-receipt.json': bytes(receipt) }).map(([name, data]) => writeFile(join(original, name), data)));
  const artifact = { target, runId: 123, runAttempt: 1, artifactId: 456, archiveSha256: X, receiptSha256: digest(bytes(receipt)), artifactSha256: digest(installer), artifactSize: installer.length, systemSignatureReportSha256: digest(bytes(signature)) };
  const bindings = { schemaVersion: 1, repository: REPOSITORY, sourceCommit: A, sourceSha256: source.sourceSha256, configSha256: X, recipeSha256: files[0].sha256, dependencyLockSha256: digest(lock), version: '2.2.0', artifacts: [artifact] };
  const machine = target === 'darwin-universal' ? 'darwin-arm64' : target;
  const spec = await bindDownloadedArtifact(bindings, machine, original, join(root, 'spec.json'));
  return { root, original, p, source, receipt, artifact, bindings, spec, machine, filename };
}

function metadata(bindings, a) {
  const label = a.target === 'darwin-universal' ? 'macos-15' : a.target === 'win32-x64' ? 'windows-2022' : 'windows-11-arm';
  return {
    run: { id: a.runId, run_attempt: a.runAttempt, head_sha: bindings.sourceCommit, event: 'workflow_dispatch', path: '.github/workflows/osir-anywhere-native-build.yml', status: 'completed', conclusion: 'failure', repository: { full_name: REPOSITORY, private: true, id: 100 }, head_repository: { full_name: REPOSITORY } },
    remote: { id: a.artifactId, expired: false, name: `osir-anywhere-${a.target}-${bindings.sourceCommit}-${a.runAttempt}`, size_in_bytes: 1234, digest: `sha256:${a.archiveSha256}`, workflow_run: { id: a.runId, head_sha: bindings.sourceCommit, repository_id: 100, head_repository_id: 100 } },
    jobs: [{ name: `build (${a.target}, ${label})`, run_id: a.runId, run_attempt: a.runAttempt, head_sha: bindings.sourceCommit, status: 'completed', conclusion: 'success', labels: [label] }],
  };
}

test('reviewed raw bindings and independent harness commit pin exact identity; all excludes unreviewed ARM', async t => {
  const f = await fixture(t), other = { ...f.artifact, target: 'win32-x64', artifactId: 457 };
  const b = { ...f.bindings, artifacts: [f.artifact, other] }, raw = bytes(b);
  assert.deepEqual(reviewedBindings(raw, digest(raw)), b);
  assert.throws(() => reviewedBindings(Buffer.concat([raw, Buffer.from('\n')]), digest(raw)), /raw-byte/);
  assert.throws(() => reviewedBindings(bytes({ ...b, token: 'forbidden' }), digest(bytes({ ...b, token: 'forbidden' }))), /fields/);
  const matrix = acceptanceMatrix(b); assert.deepEqual(matrix.map(m => m.machine), ['darwin-arm64', 'darwin-x64', 'win32-x64']);
  assert.equal(matrix[0].artifactId, matrix[1].artifactId);
  assert.throws(() => acceptanceMatrix(b, 'win32-arm64'), /no reviewed/);
  const arm = { ...f.artifact, target: 'win32-arm64', artifactId: 458 };
  assert.throws(() => reviewedBindings(bytes({ ...b, artifacts: [arm] }), digest(bytes({ ...b, artifacts: [arm] }))), /bindings/);
  const env = { GITHUB_ACTIONS: 'true', RUNNER_ENVIRONMENT: 'github-hosted', GITHUB_REPOSITORY: REPOSITORY, OSIR_HARNESS_COMMIT: H, GITHUB_WORKFLOW_SHA: H, GITHUB_RUN_ID: '77', GITHUB_RUN_ATTEMPT: '2' };
  assert.deepEqual(verifyHarness(env, H), harness); assert.notEqual(H, b.sourceCommit);
  assert.throws(() => verifyHarness({ ...env, GITHUB_WORKFLOW_SHA: A }, H), /harness SHA/);
});

test('producer permits a successful original target in a failed run, rejects wrong repository/archive/job/attempt', async t => {
  const f = await fixture(t), m = metadata(f.bindings, f.artifact);
  assert.equal(verifyProducer(f.bindings, f.artifact, m.run, m.remote, m.jobs).runConclusion, 'failure');
  const running = { ...m.run, status: 'in_progress', conclusion: null };
  assert.equal(verifyProducer(f.bindings, f.artifact, running, m.remote, m.jobs).runStatus, 'in_progress');
  const edits = [v => { v.run.repository.private = false; }, v => { v.remote.digest = `sha256:${'2'.repeat(64)}`; }, v => { v.remote.workflow_run.repository_id = 200; }, v => { v.jobs[0].conclusion = 'failure'; }, v => { v.jobs[0].run_attempt = 2; }, v => { v.run.head_sha = H; }];
  for (const edit of edits) { const v = clone(m); edit(v); assert.throws(() => verifyProducer(f.bindings, f.artifact, v.run, v.remote, v.jobs)); }
  const get = async path => path.endsWith('/artifacts/456') ? m.remote : path.includes('/jobs?') ? { total_count: 1, jobs: m.jobs } : m.run;
  assert.equal((await verifyRemoteArtifacts(f.bindings, acceptanceMatrix(f.bindings, 'darwin-universal'), 'ephemeral', get)).length, 1);
});

test('harness checkout byte verification rejects CRLF conversion and local edits despite unchanged HEAD', async t => {
  const root = await mkdtemp(join(tmpdir(), 'osir-harness-git-')); t.after(() => rm(root, { recursive: true, force: true }));
  const git = args => execFileSync('git', args, { cwd: root, stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
  git(['init']); git(['config', 'core.autocrlf', 'false']); git(['config', 'user.email', 'fixture@example.invalid']); git(['config', 'user.name', 'Fixture']);
  await writeFile(join(root, 'harness.mjs'), 'const x = 1;\n'); git(['add', 'harness.mjs']); git(['commit', '-m', 'fixture']);
  const head = git(['rev-parse', 'HEAD']); assert.equal((await verifyHarnessFiles(head, root, ['harness.mjs'])).length, 1);
  await writeFile(join(root, 'harness.mjs'), 'const x = 1;\r\n');
  await assert.rejects(verifyHarnessFiles(head, root, ['harness.mjs']), /line-ending/);
});

test('GitHub requests have fixed origin, timeout and sanitized diagnostics; no response headers/body/error secrets leak', async () => {
  const path = `/repos/${REPOSITORY}/actions/artifacts/1`, secret = 'TOP_SECRET'; let options;
  const ok = await githubMetadata(path, secret, async (url, init) => { assert.equal(url, `https://api.github.com${path}`); options = init; return new Response('{"id":1}'); });
  assert.equal(ok.id, 1); assert.equal(options.redirect, 'error'); assert.ok(options.signal); assert.equal(options.headers.Authorization, `Bearer ${secret}`);
  for (const fetcher of [async () => { throw Error(`headers Authorization ${secret}`); }, async () => new Response(secret, { status: 403, headers: { secret } }), async () => new Response('x'.repeat(4 * 1024 * 1024 + 1))]) {
    await assert.rejects(githubMetadata(path, secret, fetcher), error => !error.message.includes(secret));
  }
  await assert.rejects(githubMetadata('/repos/other/repo/actions/artifacts/1', secret), /Fixed repository/);
});

test('downloaded original bytes bind receipt/source/config/lock/signature and reject substitutions or extra files', async t => {
  const f = await fixture(t);
  assert.equal((await bindDownloadedArtifact(f.bindings, 'darwin-x64', f.original, join(f.root, 'intel.json'))).expected.artifactSha256, f.spec.expected.artifactSha256);
  await writeFile(join(f.original, 'extra.json'), '{}');
  await assert.rejects(bindDownloadedArtifact(f.bindings, f.machine, f.original, join(f.root, 'extra-spec.json')), /unexpected/);
  await rm(join(f.original, 'extra.json'));
  await writeFile(join(f.original, f.filename), 'replaced');
  await assert.rejects(bindDownloadedArtifact(f.bindings, f.machine, f.original, join(f.root, 'bad-spec.json')), /hash\/size/);
});

test('a self-consistent forged receipt still cannot change reviewed source/config/lock identity', async t => {
  const f = await fixture(t); f.receipt.plan.configSha256 = '3'.repeat(64);
  const raw = bytes(f.receipt); await writeFile(join(f.original, 'build-receipt.json'), raw); f.artifact.receiptSha256 = digest(raw);
  await assert.rejects(bindDownloadedArtifact(f.bindings, f.machine, f.original, join(f.root, 'changed-config.json')), /reviewed product/);
});

async function zipOriginal(f, source = f.original, name = 'product.zip') {
  const download = join(f.root, name.replace('.', '-')); await mkdir(download);
  const archive = join(download, name);
  execFileSync('python3', ['-I', '-c', 'import os,sys,zipfile\nwith zipfile.ZipFile(sys.argv[2],"w") as z:\n for n in sorted(os.listdir(sys.argv[1])): z.write(os.path.join(sys.argv[1],n),n)\n', source, archive]);
  f.artifact.archiveSha256 = (await inspect(archive)).sha256; return { archive, download };
}

test('full original archive hash is checked before safe extraction; only exact product inputs are allowed', async t => {
  const f = await fixture(t), { archive, download } = await zipOriginal(f);
  const output = join(f.root, 'extracted'); await unpackProductArchive(f.bindings, f.machine, download, output);
  assert.deepEqual((await readdir(output)).sort(), (await readdir(f.original)).sort());
  await writeFile(archive, 'bad archive');
  await assert.rejects(unpackProductArchive(f.bindings, f.machine, download, join(f.root, 'bad-archive')), /archive digest/);
});

test('even digest-pinned product zip traversal is refused without writing outside the new extraction root', async t => {
  const f = await fixture(t), download = join(f.root, 'hostile'); await mkdir(download);
  const archive = join(download, 'bad.zip');
  execFileSync('python3', ['-I', '-c', 'import sys,zipfile\nwith zipfile.ZipFile(sys.argv[1],"w") as z:z.writestr("../escape.txt","bad")\n', archive]);
  f.artifact.archiveSha256 = (await inspect(archive)).sha256;
  await assert.rejects(unpackProductArchive(f.bindings, f.machine, download, join(f.root, 'hostile-out')), /extraction failed/);
  await assert.rejects(readFile(join(f.root, 'escape.txt')), { code: 'ENOENT' });
});

async function prepFixture(f) {
  const prep = join(f.root, 'warm'); await mkdir(join(prep, 'cache', 'archive'), { recursive: true });
  await writeFile(join(prep, 'cache', 'archive', 'payload'), 'wheel cache'); await symlink('archive/payload', join(prep, 'cache', 'alias'));
  const lock = Buffer.from('# exact resolved Python dependencies\n'); await writeFile(join(prep, 'connector-resolved-uv.lock'), lock);
  const report = { schemaVersion: 1, scope: 'native-smoke-dependency-cache', result: 'prepared', nativeMachine: f.machine, expected: f.spec.expected,
    cache: { sha256: await fingerprintTree(join(prep, 'cache')) }, evidence: [{ path: 'connector-resolved-uv.lock', ...await inspect(join(prep, 'connector-resolved-uv.lock')) }] };
  await writeFile(join(prep, 'dependency-cache.json'), bytes(report)); return { prep, report };
}

test('separate-job cache transfer preserves symlinks, raw evidence and exact resolved lock with native/harness binding', async t => {
  const f = await fixture(t), { prep, report } = await prepFixture(f), bundle = join(f.root, 'bundle'), offline = join(f.root, 'offline');
  const sealed = await sealCache(f.spec, prep, bundle, harness);
  const diagnostic = JSON.parse(await readFile(join(prep, 'cache-archive-command.json')));
  assert.equal(diagnostic.result, 'passed'); assert.equal(diagnostic.status, 0); assert.deepEqual(diagnostic.harness, harness);
  assert.equal(diagnostic.archivePathMode, 'relative-to-output-cwd');
  assert.deepEqual((await readdir(bundle)).sort(), ['cache-transfer.json', 'offline-cache.tar']);
  assert.equal(sealed.cacheSha256, report.cache.sha256);
  await unpackCache(f.spec, bundle, offline, harness);
  assert.equal(await fingerprintTree(join(offline, 'cache')), report.cache.sha256);
  assert.equal((await inspect(join(offline, 'connector-resolved-uv.lock'))).sha256, report.evidence[0].sha256);
  await assert.rejects(unpackCache(f.spec, bundle, join(f.root, 'other-harness'), { ...harness, commit: A }), /another reviewed harness/);
  const changedSpec = clone(f.spec); changedSpec.runner.nativeMachine = 'darwin-x64';
  await assert.rejects(unpackCache(changedSpec, bundle, join(f.root, 'other-machine'), harness), /architecture/);
});

test('failed cache transfer remains failed even when warm preparation succeeded, preserving tar stderr', async t => {
  const f = await fixture(t), { prep } = await prepFixture(f);
  const diagnostic = { schemaVersion: 1, scope: 'native-cache-archive-command', result: 'failed', status: 1, stderr: 'tar: exact failure\n' };
  await writeFile(join(prep, 'cache-archive-command.json'), bytes(diagnostic));
  const evidence = join(f.root, 'failed-cache-evidence');
  const result = await collectEvidence(f.spec, { warm: prep }, evidence, harness, 'warm');
  assert.equal(result.result, 'failed');
  assert.equal(result.releaseAcceptance, 'incomplete');
  assert.deepEqual(JSON.parse(await readFile(join(evidence, 'warm', 'cache-archive-command.json'))), diagnostic);
});

test('corrupt cache archive cannot be unpacked; modified report lock/cache cannot be sealed', async t => {
  const f = await fixture(t), { prep } = await prepFixture(f), bundle = join(f.root, 'bundle');
  await sealCache(f.spec, prep, bundle, harness); await writeFile(join(bundle, 'offline-cache.tar'), 'corrupt');
  await assert.rejects(unpackCache(f.spec, bundle, join(f.root, 'offline'), harness), /SHA-256/);
  await writeFile(join(prep, 'connector-resolved-uv.lock'), 'changed resolution');
  await assert.rejects(sealCache(f.spec, prep, join(f.root, 'bad-bundle'), harness), /SHA-256/);
});

test('digest-pinned tar cannot extract an escaping cache symlink', async t => {
  const f = await fixture(t), { prep } = await prepFixture(f), bundle = join(f.root, 'bundle');
  const transfer = await sealCache(f.spec, prep, bundle, harness);
  const archive = join(bundle, 'offline-cache.tar');
  execFileSync('python3', ['-I', '-c', 'import sys,tarfile\nwith tarfile.open(sys.argv[1],"w") as t:\n i=tarfile.TarInfo("cache/escape");i.type=tarfile.SYMTYPE;i.linkname="../../../escape";t.addfile(i)\n', archive]);
  transfer.archive = await inspect(archive); await writeFile(join(bundle, 'cache-transfer.json'), bytes(transfer));
  await assert.rejects(unpackCache(f.spec, bundle, join(f.root, 'hostile-cache'), harness), /extraction failed/);
  await assert.rejects(readFile(join(f.root, 'escape')), { code: 'ENOENT' });
});

function nativeReport(f) {
  return { ...f.spec.expected, schemaVersion: 1, scope: 'native-smoke', evidenceMode: 'native', result: 'passed', releaseAcceptance: 'incomplete', nativeMachines: [f.machine],
    runnerMode: 'disposable-clean-runner', networkPolicy: 'unrestricted-no-product-credentials', networkIsolationClaimed: false, fullSmokeOfflineClaimed: false,
    checks: { installer: true, launch: true, connector: true, python: true, uv: true, upgradeDataPreserved: false, updateDiscovery: false }, evidence: [{ path: 'probe.json', size: 2, sha256: digest('{}') }] };
}

test('partial smoke validation rejects synthetic, wrong package/machine and invented lifecycle flags', async t => {
  const f = await fixture(t), report = nativeReport(f); verifySmokeReport(report, f.spec);
  for (const patch of [{ evidenceMode: 'synthetic' }, { artifactSha256: X }, { nativeMachines: ['darwin-x64'] }, { checks: { ...report.checks, upgradeDataPreserved: true } }, { checks: { ...report.checks, python: false } }, { networkIsolationClaimed: true }, { fullSmokeOfflineClaimed: true }, { networkPolicy: 'deny-all-except-loopback' }]) assert.throws(() => verifySmokeReport({ ...report, ...patch }, f.spec));
});

test('raw report collection excludes installed work, preserves failures, and never promotes to release acceptance', async t => {
  const f = await fixture(t), smoke = join(f.root, 'smoke'), provision = join(f.root, 'provision'); await mkdir(join(smoke, 'work'), { recursive: true }); await mkdir(provision);
  await writeFile(join(smoke, 'work', 'do-not-copy'), 'runtime account data'); await writeFile(join(smoke, 'probe.json'), '{}');
  await writeFile(join(smoke, 'native-smoke.json'), bytes(nativeReport(f)));
  await writeFile(join(provision, 'provision-report.json'), bytes({ result: 'passed', runnerMode: 'disposable-clean-runner', networkPolicy: 'unrestricted-no-product-credentials', networkIsolationClaimed: false, cleanup: { networkPolicyRestorationRequired: false, globalNetworkStateModified: false } }));
  const paths = { smoke, provision };
  const ok = await collectEvidence(f.spec, paths, join(f.root, 'raw-evidence'), harness, 'smoke');
  assert.equal(ok.result, 'passed'); assert.equal(ok.releaseAcceptance, 'incomplete'); assert.ok(ok.evidence.some(e => e.path === 'smoke/probe.json')); assert.ok(!ok.evidence.some(e => e.path.includes('work')));
  await writeFile(join(provision, 'provision-report.json'), bytes({ result: 'failed', failure: 'actual isolation blocked' }));
  const blocked = await collectEvidence(f.spec, paths, join(f.root, 'blocked-evidence'), harness, 'smoke');
  assert.equal(blocked.result, 'failed'); assert.equal(blocked.releaseAcceptance, 'incomplete'); assert.ok(blocked.evidence.some(e => e.path === 'provision/provision-report.json'));
});
