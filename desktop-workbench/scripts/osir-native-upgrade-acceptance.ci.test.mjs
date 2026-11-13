import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TOOL_VERSIONS, linkTools, prepareSpec } from './osir-native-upgrade-acceptance.ci.mjs';
import { bytes } from './osir-anywhere-release-common.mjs';

async function fixture(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'osir-upgrade-ci-unit-')));
  t.after(() => rm(root, { force: true, recursive: true }));
  const checkout = join(root, 'checkout'), original = join(root, 'original');
  await mkdir(checkout); await mkdir(original);
  await writeFile(join(original, 'source-provenance.json'), '{"syntheticSource":true}\n');
  await writeFile(join(original, 'compiled.json'), '{"syntheticCompiled":true}\n');
  const base = { schemaVersion: 1, buildReceiptPath: join(original, 'build-receipt.json'), finalInstallerPath: join(original, 'final.dmg'), systemSignatureReportPath: join(original, 'system-signature.json'),
    expected: { sourceSha256: 'a'.repeat(64), configSha256: 'b'.repeat(64), checkoutHead: 'c'.repeat(40), upstreamGitHead: 'd'.repeat(40), version: '2.2.0', target: 'darwin-universal', artifactSha256: 'e'.repeat(64), artifactSize: 1, systemSignatureReportSha256: 'f'.repeat(64) },
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
