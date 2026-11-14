import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { bytes, digest } from './osir-anywhere-release-common.mjs';
import { sourcePlan } from './osir-anywhere-source.mjs';
import { reviewedRecipe, runnerEnvironment, verifyOAuthEvidence } from './osir-anywhere-ci.mjs';

test('reviewed recipe binds raw bytes and rejects sourceSha self-reference and secrets', () => {
  const raw = Buffer.from('{ "releaseId": "test", "config": {"OSIR_ANYWHERE_OAUTH_CONTRACT_VERIFIED":"1"} }\n');
  assert.equal(reviewedRecipe(raw, digest(raw)).releaseId, 'test');
  assert.throws(() => reviewedRecipe(Buffer.from(JSON.stringify(JSON.parse(raw))), digest(raw)), /raw-byte/);
  for (const extra of [{ sourceSha256: 'cycle' }, { checkout: '/tmp/injection' }, { signingKey: '/private' }]) {
    const invalid = bytes({ ...JSON.parse(raw), ...extra });
    assert.throws(() => reviewedRecipe(invalid, digest(invalid)), /cannot contain/);
  }
  const secret = bytes({ releaseId: 'test', config: { AWS_SECRET_ACCESS_KEY: 'synthetic' } });
  assert.throws(() => reviewedRecipe(secret, digest(secret)), /configuration/);
  for (const releaseRevision of [0, 2, 65535]) {
    const revised = bytes({ ...JSON.parse(raw), releaseRevision });
    assert.equal(reviewedRecipe(revised, digest(revised)).releaseRevision, releaseRevision);
  }
  for (const releaseRevision of [-1, 65536, 1.5, '2', null]) {
    const revised = bytes({ ...JSON.parse(raw), releaseRevision });
    assert.throws(() => reviewedRecipe(revised, digest(revised)), /releaseRevision/);
  }
});

test('CI spec stays outside frozen source, exports runner paths and retains one resolution on failed-job reruns', async t => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'osir-ci-contract-'))); t.after(() => rm(root, { recursive: true, force: true }));
  const checkout = join(root, 'checkout'), temp = join(root, 'runner'); await mkdir(checkout); await mkdir(temp);
  const git = args => execFileSync('git', args, { cwd: checkout, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  git(['init', '-q']); await mkdir(join(checkout, 'desktop-workbench/build'), { recursive: true });
  await writeFile(join(checkout, '.gitignore'), 'yarn.lock\n');
  await writeFile(join(checkout, 'desktop-workbench/package.json'), '{"version":"2.2.0"}');
  await writeFile(join(checkout, 'desktop-workbench/build/release-public.pub'), 'PUBLIC KEY fixture only');
  const documents = ['docs/OSIR-ANYWHERE-CONNECTION-VERIFICATION-2026-11-13.md', 'docs/OSIR-ANYWHERE-ALIYUN-ROLLOUT-2026-11-13.md'];
  await mkdir(join(checkout, 'docs'));
  for (const document of documents) await writeFile(join(checkout, document), `synthetic fixture ${document}`);
  const recipe = bytes({ releaseId: 'fixture-2.2.0', releaseRevision: 2, config: { OSIR_ANYWHERE_OAUTH_CONTRACT_VERIFIED: '1' },
    oauthEvidence: { basis: 'prior-contract-real-desktop-and-browser-verification', scope: 'candidate-build-only', requiresFinalPackageReverification: true,
      documents: documents.map(path => ({ path, sha256: digest(`synthetic fixture ${path}`) })) } });
  await writeFile(join(checkout, 'osir-build-recipe.json'), recipe);
  git(['add', '.']); git(['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'reviewed source']);
  const head = git(['rev-parse', 'HEAD']);
  const source = await sourcePlan({ checkout, gitHead: head, files: ['.gitignore', 'desktop-workbench/package.json', 'desktop-workbench/build/release-public.pub', 'osir-build-recipe.json', ...documents] });
  await writeFile(join(checkout, 'osir-source.json'), bytes(source));
  const envPath = join(temp, 'environment'), outputPath = join(temp, 'outputs');
  const env = { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, RUNNER_TEMP: temp, GITHUB_ENV: envPath, GITHUB_OUTPUT: outputPath,
    GITHUB_RUN_ID: 'fixture-run', GITHUB_RUN_ATTEMPT: '1', GITHUB_WORKFLOW_SHA: head, OSIR_SOURCE_COMMIT: head, OSIR_SOURCE_SHA256: source.sourceSha256, OSIR_RECIPE_SHA256: digest(recipe) };
  const tool = fileURLToPath(new URL('osir-anywhere-ci.mjs', import.meta.url));
  const run = (args, extra = {}) => spawnSync(process.execPath, [tool, ...args], { cwd: checkout, env: { ...env, ...extra }, encoding: 'utf8' });
  assert.notEqual(run([], { GITHUB_WORKFLOW_SHA: 'f'.repeat(40) }).status, 0, 'A different workflow commit cannot act as the reviewed build');
  assert.equal(run([]).status, 0);
  assert.equal(JSON.parse(await readFile(join(temp, 'build-spec.json'), 'utf8')).releaseRevision, 2);
  assert.match(await readFile(envPath, 'utf8'), /OSIR_BUILD_SPEC=.*build-spec.json/);
  const lock = 'one reviewed dependency resolution\n'; await writeFile(join(checkout, 'desktop-workbench/yarn.lock'), lock);
  assert.equal(run(['lock']).status, 0);
  const originalOutput = await readFile(outputPath, 'utf8');
  assert.match(originalOutput, /lock_artifact_name=osir-anywhere-resolved-lock-fixture-run-1/);
  assert.ok(originalOutput.includes(`lock_sha256=${digest(lock)}`));
  assert.equal(await readFile(join(temp, 'resolved-yarn.lock'), 'utf8'), lock);
  const drift = run(['lock'], { GITHUB_RUN_ATTEMPT: '2' }); assert.equal(drift.status, 0);
  assert.ok((await readFile(outputPath, 'utf8')).startsWith(originalOutput));
  const changedRecipe = Buffer.concat([recipe, Buffer.from(' ')]); await writeFile(join(checkout, 'osir-build-recipe.json'), changedRecipe);
  assert.notEqual(run([]).status, 0, 'Frozen raw recipe drift must fail before any build');
  assert.equal((await readFile(join(temp, 'build-spec.json'), 'utf8')).includes(source.sourceSha256), true);
});

test('OAuth candidate gate rejects synthetic-only claims, absent evidence and edited real-verification documents', async t => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'osir-oauth-evidence-'))); t.after(() => rm(root, { recursive: true, force: true }));
  const recipe = { config: { OSIR_ANYWHERE_OAUTH_CONTRACT_VERIFIED: '1' } };
  await assert.rejects(verifyOAuthEvidence(root, { files: [] }, recipe), /real-verification/);
  recipe.oauthEvidence = { basis: 'synthetic AUTH tests', scope: 'candidate-build-only', requiresFinalPackageReverification: true, documents: [] };
  await assert.rejects(verifyOAuthEvidence(root, { files: [] }, recipe), /real-verification/);
  await mkdir(join(root, 'docs'));
  const paths = ['docs/OSIR-ANYWHERE-CONNECTION-VERIFICATION-2026-11-13.md', 'docs/OSIR-ANYWHERE-ALIYUN-ROLLOUT-2026-11-13.md'];
  for (const path of paths) await writeFile(join(root, path), 'fixture evidence');
  const documents = paths.map(path => ({ path, sha256: digest('fixture evidence') }));
  recipe.oauthEvidence = { basis: 'prior-contract-real-desktop-and-browser-verification', scope: 'candidate-build-only', requiresFinalPackageReverification: true, documents };
  await verifyOAuthEvidence(root, { files: documents }, recipe);
  await writeFile(join(root, paths[0]), 'edited evidence');
  await assert.rejects(verifyOAuthEvidence(root, { files: documents }, recipe), /bytes changed/);
});

test('runner environment paths are generated from actual native temp without invalid job expressions', () => {
  assert.equal(runnerEnvironment(tmpdir()).OSIR_BUILD_SPEC, join(tmpdir(), 'build-spec.json'));
  assert.throws(() => runnerEnvironment('/tmp/evil\nINJECT=true'), /absolute/);
});

test('reviewed input bytes survive a runner with autocrlf enabled', async t => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'osir-ci-checkout-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const git = args => execFileSync('git', args, { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
  git(['init', '-q']);
  git(['config', 'core.autocrlf', 'true']);
  await writeFile(join(root, '.gitattributes'), await readFile(new URL('../../.gitattributes', import.meta.url)));
  const input = Buffer.from('name: reviewed build\non:\n  workflow_dispatch:\n');
  await writeFile(join(root, 'candidate.yml'), input);
  git(['add', '.']);
  await rm(join(root, 'candidate.yml'));
  git(['checkout-index', '-f', '--', 'candidate.yml']);
  assert.deepEqual(await readFile(join(root, 'candidate.yml')), input);
});
