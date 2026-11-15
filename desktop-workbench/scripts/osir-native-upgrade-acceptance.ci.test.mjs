import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DISCOVERY_TEST_MODULES, TOOL_VERSIONS, UPGRADE_PRODUCT, discoveryTestSources, linkTools, prepareSpec, verifyUpgradeProduct, verifyUpgradeReceipt } from './osir-native-upgrade-acceptance.ci.mjs';
import { bytes, digest, fingerprint } from './osir-anywhere-release-common.mjs';

test('upgrade plan binds frozen 2.2.1 source/recipe/version while archive/run/lock remain reviewed inputs', () => {
  assert.deepEqual(UPGRADE_PRODUCT, {
    sourceCommit: 'b66bc2ac1f94c4fb868e66c452cc8364d7cd301e',
    sourceSha256: 'dde3f6be0c791818fb65af26023e64712f9b8035bd4c2013bcfda008a1f28b12',
    recipeSha256: '5d92fb0f008fabf3dab99d445c4c3f7d74248c886b1f656eb73e9c5a036594c8',
    version: '2.2.1',
  });
  const bindings = { ...UPGRADE_PRODUCT, configSha256: 'a'.repeat(64), dependencyLockSha256: 'b'.repeat(64) };
  assert.equal(verifyUpgradeProduct(bindings), bindings);
  for (const key of Object.keys(UPGRADE_PRODUCT)) assert.throws(() => verifyUpgradeProduct({ ...bindings, [key]: 'different' }), /frozen 2.2.1/);
});

test('upgrade product rejects the previous r2 product and any mixture of old and new pins', () => {
  const previous = {
    sourceCommit: 'b95e4498b418eb582c37ae17284fa0699ef1345c',
    sourceSha256: 'd2f00392890f4b7f38d0d4faad82e5d900206eba9440b7674d1488cf9126ba66',
    recipeSha256: 'e9c517add26144970e288de50d882935fe09ec9283db420bd3228370711b07d9',
  };
  assert.throws(() => verifyUpgradeProduct({ ...UPGRADE_PRODUCT, ...previous }), /frozen 2.2.1/);
  for (const [key, value] of Object.entries(previous)) {
    assert.throws(() => verifyUpgradeProduct({ ...UPGRADE_PRODUCT, [key]: value }), /frozen 2.2.1/);
  }
});

async function fixture(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'osir-upgrade-ci-unit-')));
  t.after(() => rm(root, { force: true, recursive: true }));
  const checkout = join(root, 'checkout'), original = join(root, 'original');
  await mkdir(checkout); await mkdir(original);
  await writeFile(join(original, 'source-provenance.json'), '{"syntheticSource":true}\n');
  await writeFile(join(original, 'compiled.json'), '{"syntheticCompiled":true}\n');
  const base = { schemaVersion: 1, buildReceiptPath: join(original, 'build-receipt.json'), finalInstallerPath: join(original, 'final.dmg'), systemSignatureReportPath: join(original, 'system-signature.json'),
    expected: { sourceSha256: 'a'.repeat(64), configSha256: 'b'.repeat(64), checkoutHead: 'c'.repeat(40), upstreamGitHead: 'd'.repeat(40), version: '2.2.1', target: 'darwin-universal', artifactSha256: 'e'.repeat(64), artifactSize: 1, systemSignatureReportSha256: 'f'.repeat(64) },
    runner: { nativeMachine: 'darwin-arm64' } };
  return { root, checkout, original, base };
}

test('prepare spec reuses original receipt paths and preserves existing exact source provenance', async t => {
  const f = await fixture(t), raw = await readFile(join(f.original, 'source-provenance.json'));
  const spec = await prepareSpec(f.base, f.checkout, f.original);
  assert.deepEqual(spec.expected, f.base.expected); assert.equal(spec.runner.mode, 'disposable-clean-runner');
  assert.equal(spec.baselineSource.mode, 'final-installer-copy');
  assert.deepEqual(await readFile(join(f.checkout, 'osir-source.json')), raw);
  assert.deepEqual(await prepareSpec(f.base, f.checkout, f.original), spec);
});

test('prepare spec refuses differing frozen provenance instead of overwriting it', async t => {
  const f = await fixture(t); await writeFile(join(f.checkout, 'osir-source.json'), 'existing source');
  await assert.rejects(prepareSpec(f.base, f.checkout, f.original));
  assert.equal(await readFile(join(f.checkout, 'osir-source.json'), 'utf8'), 'existing source');
});

test('independent tools require pinned versions and never replace existing harness dependencies', async t => {
  const f = await fixture(t), tools = join(f.root, 'tools'); await mkdir(join(f.checkout, 'desktop-workbench'));
  for (const [name, version] of Object.entries(TOOL_VERSIONS)) {
    const directory = join(tools, 'node_modules', name); await mkdir(directory, { recursive: true });
    await writeFile(join(directory, 'package.json'), bytes({ name, version }));
  }
  await linkTools(f.checkout, tools);
  assert.equal(await realpath(join(f.checkout, 'desktop-workbench/node_modules')), join(tools, 'node_modules'));
  await assert.rejects(linkTools(f.checkout, tools), /refusing replacement/);
  await assert.rejects(linkTools(f.checkout, join(f.checkout, 'tools')), /independent/);
});

test('a wrong tool version cannot silently use an unreviewed packager', async t => {
  const f = await fixture(t), tools = join(f.root, 'tools');
  await mkdir(join(tools, 'node_modules/electron-builder'), { recursive: true });
  await writeFile(join(tools, 'node_modules/electron-builder/package.json'), '{"version":"0.0.0"}');
  await assert.rejects(linkTools(f.checkout, tools), /version mismatch/);
});

test('sparse frozen discovery inputs require the reviewed commit, inventory and exact module bytes', async t => {
  const f = await fixture(t), electron = join(f.checkout, 'desktop-workbench/electron'); await mkdir(electron, { recursive: true });
  const files = [];
  for (const name of DISCOVERY_TEST_MODULES) {
    const raw = Buffer.from(`// synthetic ${name}; never product execution\n`);
    await writeFile(join(electron, `${name}.ts`), raw);
    files.push({ path: `desktop-workbench/electron/${name}.ts`, size: raw.length, sha256: digest(raw), executable: false });
  }
  const source = { schemaVersion: 1, sourceSha256: fingerprint(files), files };
  await writeFile(join(f.checkout, 'osir-source.json'), bytes(source));
  const git = args => execFileSync('git', args, { cwd: f.checkout, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  git(['init', '--quiet']); git(['add', '.']);
  git(['-c', 'user.name=Upgrade unit fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '--no-gpg-sign', '-m', 'synthetic source fixture']);
  const bindings = { sourceCommit: git(['rev-parse', 'HEAD']).trim(), sourceSha256: source.sourceSha256 };
  assert.equal((await discoveryTestSources(f.checkout, bindings)).size, DISCOVERY_TEST_MODULES.length);
  await assert.rejects(discoveryTestSources(f.checkout, { ...bindings, sourceCommit: '0'.repeat(40) }), /reviewed product commit/);
  await assert.rejects(discoveryTestSources(f.checkout, { ...bindings, sourceSha256: '0'.repeat(64) }), /inventory/);
  await writeFile(join(electron, 'desktop-updates.ts'), '// changed source');
  await assert.rejects(discoveryTestSources(f.checkout, bindings), /source changed/);
});

test('upgrade receipt requires the exact revision 3 release and frozen product identity', () => {
  const { sourceCommit, ...product } = UPGRADE_PRODUCT;
  const receipt = { plan: { ...product, checkoutHead: sourceCommit, releaseRevision: 3, releaseId: 'osir-anywhere-2.2.1-20261116-r3' } };
  assert.equal(verifyUpgradeReceipt(receipt), receipt);
  for (const patch of [{ releaseRevision: undefined }, { releaseRevision: 0 }, { releaseRevision: 1 }, { releaseRevision: 2 }, { releaseRevision: 4 }, { releaseRevision: '3' },
    { releaseId: 'osir-anywhere-2.2.1-20261115-r2' }, { releaseId: 'legacy' },
    ...Object.keys(receipt.plan).map(key => ({ [key]: 'different' }))]) {
    assert.throws(() => verifyUpgradeReceipt({ plan: { ...receipt.plan, ...patch } }));
  }
  assert.throws(() => verifyUpgradeReceipt({}));
});
