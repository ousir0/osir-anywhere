import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { bytes, digest, fingerprint, json } from './osir-anywhere-release-common.mjs';
import { assertCompiledBuild, assertCompiledRevision, buildEnvironment, buildPlan, outputsFingerprint, verifyWindowsArm64Evidence } from './osir-anywhere-build.mjs';
import { sourcePath, sourcePlan, sourcePrepare, verifySource } from './osir-anywhere-source.mjs';

const git = (root, args) => execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
async function sourceFixture(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'anywhere-source-test-'))); t.after(() => rm(root, { recursive: true, force: true }));
  const checkout = join(root, 'checkout'); await mkdir(checkout); git(checkout, ['init', '-q']);
  await writeFile(join(checkout, 'hello.txt'), 'reviewed input');
  git(checkout, ['add', 'hello.txt']); git(checkout, ['-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture']);
  return { root, checkout, gitHead: git(checkout, ['rev-parse', 'HEAD']) };
}
test('explicit source allowlist exports only reviewed paths, preserves provenance, refuses whole-tree/wildcard/secret/link input', async t => {
  const f = await sourceFixture(t);
  await writeFile(join(f.checkout, 'private.txt'), 'not in snapshot');
  const spec = { checkout: f.checkout, gitHead: f.gitHead, files: ['hello.txt'], outputDirectory: join(f.root, 'snapshot') };
  const plan = await sourcePlan(spec); assert.equal(plan.files.length, 1);
  await sourcePrepare(spec); assert.equal(await readFile(join(spec.outputDirectory, 'hello.txt'), 'utf8'), 'reviewed input');
  await assert.rejects(readFile(join(spec.outputDirectory, 'private.txt')), { code: 'ENOENT' });
  for (const path of ['osir-source.json', '../escape', '.env', 'key.pem', 'a/../b', '/absolute', '.git/config', 'desktop-workbench/**']) assert.throws(() => sourcePath(path), /forbidden/);
  await symlink(join(f.checkout, 'private.txt'), join(f.checkout, 'link.txt'));
  await assert.rejects(sourcePlan({ ...spec, files: ['link.txt'] }), /regular/);
});
test('frozen source rejects drift and extra unreviewed tracked or untracked inputs', async t => {
  const f = await sourceFixture(t), plan = await sourcePlan({ ...f, files: ['hello.txt'] });
  await writeFile(join(f.checkout, 'osir-source.json'), bytes(plan));
  assert.equal((await verifySource(f.checkout)).sourceSha256, plan.sourceSha256);
  await writeFile(join(f.checkout, 'extra.ts'), 'unreviewed');
  await assert.rejects(verifySource(f.checkout), /Unreviewed/); await rm(join(f.checkout, 'extra.ts'));
  await writeFile(join(f.checkout, 'hello.txt'), 'modified'); await assert.rejects(verifySource(f.checkout), /changed/);
});
test('build environment excludes signing/storage/API secrets, injection flags and inherited PYTHONPATH', () => {
  const clean = buildEnvironment({ PATH: '/bin', HOME: '/home/test', CSC_LINK: 'secret', WIN_CERT_P12_BASE64: 'secret', AWS_SECRET_ACCESS_KEY: 'secret',
    OSIR_MANIFEST_SIGNING_KEY: 'secret', GH_TOKEN: 'secret', PYTHONPATH: '/injected', NODE_OPTIONS: '--require malicious', arbitrary: 'secret' },
  { OSIR_ANYWHERE_API_ORIGIN: 'https://example.test' });
  assert.equal(clean.PATH, '/bin'); assert.equal(clean.OSIR_ANYWHERE_API_ORIGIN, 'https://example.test');
  assert.equal(JSON.stringify(clean).includes('secret'), false); assert.equal(clean.NODE_OPTIONS, undefined); assert.equal(clean.PYTHONPATH, undefined);
  assert.throws(() => buildEnvironment({}, { GH_TOKEN: 'secret' }), /Unknown/);
});
test('Windows ARM64 plan blocks without native runner and native dependencies evidence', async () => {
  await assert.rejects(buildPlan({}, 'win32-arm64'), /ARM64 requires/);
  await assert.rejects(buildPlan({ windowsArm64Evidence: { runner: 'windows-11-arm', electron: true, python: true, uv: true, nativeDependencies: true } }, 'win32-arm64'), /report/);
});
test('Windows ARM64 evidence binds actual native report raw hash and exact dependency source bytes', async t => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'osir-arm-evidence-'))); t.after(() => rm(root, { recursive: true, force: true }));
  const inputs = ['desktop-workbench/package.json', 'desktop-workbench/renderer/package.json', 'connector/pyproject.toml', 'desktop-workbench/scripts/prepare-uv.mjs', 'desktop-workbench/scripts/prepare-python.mjs'].map(path => ({ path, sha256: digest(path) }));
  const report = { schemaVersion: 1, result: 'passed', runner: { label: 'windows-11-arm', platform: 'win32', arch: 'arm64', runId: 'synthetic', runAttempt: '1' }, checks: { electron: true, python: true, uv: true, nativeDependencies: true }, inputs };
  const raw = bytes(report), evidence = { reportPath: 'arm-report.json', reportSha256: digest(raw) }, source = { files: [...inputs, { path: evidence.reportPath, sha256: evidence.reportSha256 }] };
  await writeFile(join(root, evidence.reportPath), raw);
  assert.equal(await verifyWindowsArm64Evidence(root, source, evidence), evidence.reportSha256);
  const drifted = structuredClone(source); drifted.files[0].sha256 = digest('changed dependencies');
  await assert.rejects(verifyWindowsArm64Evidence(root, drifted, evidence), /inputs differ/);
  await writeFile(join(root, evidence.reportPath), bytes({ ...report, runner: { ...report.runner, arch: 'x64' } }));
  await assert.rejects(verifyWindowsArm64Evidence(root, source, evidence), /report changed/);
});
for (const releaseRevision of [undefined, 3]) test(`--skip-build binds source, recipe revision ${releaseRevision ?? 'legacy zero'}, dependencies and compiled bytes`, async t => {
  const f = await sourceFixture(t), root = join(f.checkout, 'desktop-workbench');
  await mkdir(root);
  await writeFile(join(f.checkout, '.gitignore'), 'desktop-workbench/dist/\ndesktop-workbench/renderer/out/\ndesktop-workbench/build/uv/\ndesktop-workbench/build/python/\nnode_modules/\nyarn.lock\n');
  await writeFile(join(root, 'package.json'), JSON.stringify({ version: '2.1.1' }));
  await writeFile(join(root, 'config.json'), await readFile(new URL('../config.json', import.meta.url)));
  const recipe = releaseRevision === undefined ? undefined : bytes({ releaseRevision });
  if (recipe) await writeFile(join(f.checkout, 'osir-build-recipe.json'), recipe);
  git(f.checkout, ['add', '.gitignore', 'desktop-workbench']); git(f.checkout, ['-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'build fixture']);
  const gitHead = git(f.checkout, ['rev-parse', 'HEAD']);
  const source = await sourcePlan({ checkout: f.checkout, gitHead, files: ['.gitignore', 'hello.txt', 'desktop-workbench/package.json', 'desktop-workbench/config.json', ...(recipe ? ['osir-build-recipe.json'] : [])] });
  await writeFile(join(f.checkout, 'osir-source.json'), bytes(source));
  await mkdir(join(root, 'node_modules')); await writeFile(join(root, 'node_modules/.yarn-state.yml'), 'installed state');
  await writeFile(join(root, 'yarn.lock'), 'resolved dependencies');
  for (const name of ['dist', 'renderer/out', 'build/uv', 'build/python']) {
    await mkdir(join(root, name), { recursive: true }); await writeFile(join(root, name, 'payload'), 'compiled bytes');
  }
  const spec = { checkout: f.checkout, checkoutHead: gitHead, sourceSha256: source.sourceSha256, dependencyLockSha256: digest('resolved dependencies'), releaseId: 'test-release', version: '2.1.1', stateDirectory: join(f.root, 'state'),
    releaseRevision, recipeSha256: recipe ? digest(recipe) : undefined,
    config: { OSIR_ANYWHERE_OAUTH_CONTRACT_VERIFIED: '1' } };
  const state = join(spec.stateDirectory, 'darwin-universal'); await mkdir(state, { recursive: true });
  const specPath = join(state, 'build-spec.json'); await writeFile(specPath, bytes(spec));
  const plan = await buildPlan(spec, 'darwin-universal');
  assert.equal(plan.releaseRevision, releaseRevision ?? 0);
  if (recipe) {
    await assert.rejects(buildPlan({ ...spec, releaseRevision: 0 }, 'darwin-universal'), /differs from reviewed recipe/);
    await assert.rejects(buildPlan({ ...spec, recipeSha256: digest('wrong') }, 'darwin-universal'), /recipe.*hash/);
  } else await assert.rejects(buildPlan({ ...spec, releaseRevision: 1 }, 'darwin-universal'), /requires.*recipe/);
  const info = { productId: 'osir-anywhere', desktopVersion: spec.version, revision: plan.releaseRevision, serverVersion: '2.2.0' };
  await writeFile(join(root, 'dist/build-info.json'), bytes(info));
  await writeFile(join(state, 'compiled.json'), bytes({ planSha256: fingerprint(plan), outputsSha256: await outputsFingerprint(root) }));
  const env = { OSIR_ANYWHERE_BUILD_SPEC: specPath };
  await assertCompiledBuild(root, 'darwin-universal', env);
  await writeFile(join(root, 'dist/build-info.json'), bytes({ ...info, revision: plan.releaseRevision + 1 }));
  await writeFile(join(state, 'compiled.json'), bytes({ planSha256: fingerprint(plan), outputsSha256: await outputsFingerprint(root) }));
  await assert.rejects(assertCompiledBuild(root, 'darwin-universal', env), /version\/revision/, 'a matching byte fingerprint cannot bless a wrong revision');
  await writeFile(join(root, 'dist/build-info.json'), bytes(info));
  await writeFile(join(state, 'compiled.json'), bytes({ planSha256: fingerprint(plan), outputsSha256: await outputsFingerprint(root) }));
  await assert.rejects(assertCompiledBuild(root, 'darwin-universal', {}), /requires OSIR/);
  await writeFile(join(root, 'dist/payload'), 'changed bytes'); await assert.rejects(assertCompiledBuild(root, 'darwin-universal', env), /fingerprint/);
  await writeFile(join(root, 'dist/payload'), 'compiled bytes');
  await writeFile(join(root, 'yarn.lock'), 'other dependency resolution'); await assert.rejects(assertCompiledBuild(root, 'darwin-universal', env), /dependency lock/);
  await writeFile(join(root, 'yarn.lock'), 'resolved dependencies');
  await writeFile(specPath, bytes({ ...spec, config: { ...spec.config, OSIR_ANYWHERE_API_ORIGIN: 'https://other.example.test' } }));
  await assert.rejects(assertCompiledBuild(root, 'darwin-universal', env), /fingerprint/);
  await writeFile(specPath, bytes(spec)); await writeFile(join(f.checkout, 'hello.txt'), 'changed source');
  await assert.rejects(assertCompiledBuild(root, 'darwin-universal', env), /changed/);
});
test('final compiled revision gate rejects missing, legacy, malformed or mismatched packaged metadata', async t => {
  const root = await mkdtemp(join(tmpdir(), 'osir-compiled-revision-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'dist'));
  const plan = { version: '2.2.1', releaseRevision: 2 }, file = join(root, 'dist/build-info.json');
  await assert.rejects(assertCompiledRevision(root, plan), { code: 'ENOENT' });
  const info = { productId: 'osir-anywhere', desktopVersion: '2.2.1', revision: 2, serverVersion: '2.2.0' };
  for (const value of [{ serverVersion: '2.2.0' }, { ...info, revision: 0 }, { ...info, revision: '2' }, { ...info, revision: 65536 },
    { ...info, productId: 'other' }, { ...info, desktopVersion: '2.2.0' }, { ...info, releaseRevision: 2 }]) {
    await writeFile(file, bytes(value)); await assert.rejects(assertCompiledRevision(root, plan), /revision/);
  }
  await writeFile(file, bytes(info)); await assertCompiledRevision(root, plan);
});
test('manifest public key ships at the exact Electron resources path and version is not rewritten', async () => {
  const pkg = await json(new URL('../package.json', import.meta.url));
  assert.ok(pkg.build.extraResources.some(r => r.from === 'build/release-public.pub' && r.to === 'build/release-public.pub'));
});
