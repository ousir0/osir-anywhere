import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { chmod, link, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { buildPayload, prepareTrust, trust } from './osir-handoff-trust.mjs';
import { fingerprintTree } from './osir-native-smoke.mjs';
import { digest } from './osir-anywhere-release-common.mjs';

const now = Date.parse('2026-11-15T00:00:00Z');
const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
async function fixture(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'osir-handoff-trust-test-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const bundle = join(root, 'Final.app'); await mkdir(join(bundle, 'Contents', 'MacOS'), { recursive: true });
  await writeFile(join(bundle, 'Contents', 'MacOS', 'app'), 'synthetic final application');
  await writeFile(join(bundle, 'Contents', 'empty'), '');
  await writeFile(join(bundle, 'z-final'), 'last');
  await symlink('Contents/MacOS/app', join(bundle, 'first-link'));
  await mkdir(join(bundle, 'empty-dir'));
  const treeSha256 = await fingerprintTree(bundle);
  const receipt = { schemaVersion: 1, reviewed: true, bundleStage: 'final-installed', bundlePath: bundle,
    productId: 'osir-client', version: '0.1.11+10', releaseId: 'prod-0.1.11.build.10', platform: 'darwin', treeSha256 };
  const receiptPath = join(root, 'review.json'); await writeFile(receiptPath, JSON.stringify(receipt));
  const publicKeyPath = join(root, 'public.pub'), keyPath = join(root, 'synthetic-private.pem');
  await writeFile(publicKeyPath, keys.publicKey.export({ type: 'spki', format: 'pem' }));
  await writeFile(keyPath, keys.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  const entry = { productId: receipt.productId, version: receipt.version, releaseId: receipt.releaseId,
    platform: receipt.platform, bundlePath: bundle, reviewReceiptPath: receiptPath, reviewReceiptSha256: digest(await readFile(receiptPath)) };
  const spec = { schemaVersion: 1, publishedAt: '2026-11-15T00:00:00Z', validUntil: '2026-12-15T00:00:00Z', publicKeyPath, builds: [entry] };
  return { root, bundle, receipt, receiptPath, spec, keyPath };
}

test('production trust and native-smoke hash exactly the same sorted tree, bytes, empty files and symlinks', async t => {
  const { bundle, spec } = await fixture(t);
  assert.equal(await trust.handoffBundleFingerprint(bundle), await fingerprintTree(bundle));
  const hash = await trust.handoffBundleFingerprint(bundle);
  await chmod(join(bundle, 'z-final'), 0o700);
  assert.equal(await trust.handoffBundleFingerprint(bundle), hash, 'modes are outside the existing native-smoke format');
  await writeFile(join(bundle, 'Contents', 'MacOS', 'app'), 'changed');
  assert.notEqual(await trust.handoffBundleFingerprint(bundle), hash);
  await assert.rejects(buildPayload(spec, now), /differs from review/);
});

test('bundle rejects empty roots, root/parent links, escaped/dangling links and hardlinks', async t => {
  const { root, bundle } = await fixture(t);
  const empty = join(root, 'Empty.app'); await mkdir(empty);
  await assert.rejects(trust.handoffBundleFingerprint(empty));
  const alias = join(root, 'Alias.app'); await symlink(bundle, alias);
  await assert.rejects(trust.handoffBundleFingerprint(alias));
  const parentAlias = join(root, 'AliasParent'); await symlink(join(bundle, 'Contents'), parentAlias);
  await assert.rejects(trust.handoffBundleFingerprint(join(parentAlias, 'MacOS')));
  const bad = join(bundle, 'bad'); await symlink('../review.json', bad);
  await assert.rejects(trust.handoffBundleFingerprint(bundle)); await rm(bad);
  await symlink('missing', bad); await assert.rejects(trust.handoffBundleFingerprint(bundle)); await rm(bad);
  await link(join(bundle, 'z-final'), bad); await assert.rejects(trust.handoffBundleFingerprint(bundle));
});

test('build requires final installed receipt, exact identity, pinned receipt bytes and nonduplicated builds', async t => {
  const { spec, receipt, receiptPath, bundle } = await fixture(t);
  const payload = await buildPayload(spec, now);
  assert.equal(payload.builds[0].treeSha256, await fingerprintTree(bundle));
  assert.equal((await trust.verifyHandoffBundle(bundle, 'osir-client', payload)).version, '0.1.11+10');
  await assert.rejects(trust.verifyHandoffBundle(bundle, 'osir-anywhere', payload));
  for (const patch of [{ reviewed: false }, { bundleStage: 'source-checkout' }, { bundleStage: 'test-only-baseline' },
    { version: '0.1.11' }, { releaseId: 'other' }, { platform: 'win32' }, { productId: 'osir-anywhere' },
    { treeSha256: 'b'.repeat(64) }, { bundlePath: '/different.app' }, { extra: true }]) {
    await writeFile(receiptPath, JSON.stringify({ ...receipt, ...patch }));
    const candidate = structuredClone(spec); candidate.builds[0].reviewReceiptSha256 = digest(await readFile(receiptPath));
    await assert.rejects(buildPayload(candidate, now));
  }
  await assert.rejects(buildPayload(spec, now), /receipt SHA-256 mismatch/);
  await writeFile(receiptPath, JSON.stringify(receipt));
  await assert.rejects(buildPayload({ ...spec, builds: [spec.builds[0], spec.builds[0]] }, now));
  await assert.rejects(buildPayload({ ...spec, extra: true }, now));
  await assert.rejects(buildPayload({ ...spec, builds: [{ ...spec.builds[0], bundlePath: 'relative.app' }] }, now));
});

test('payload never reads a signing key; explicit signing verifies with the consumer and cannot overwrite output', async t => {
  const { root, spec, keyPath } = await fixture(t);
  const payloadOutput = join(root, 'payload');
  assert.equal((await prepareTrust(spec, payloadOutput, undefined, now)).stage, 'payload-local');
  await assert.rejects(readFile(join(payloadOutput, 'handoff-trust.json')));
  const output = join(root, 'signed');
  assert.equal((await prepareTrust(spec, output, keyPath, now)).stage, 'signed-local');
  const envelope = JSON.parse(await readFile(join(output, 'handoff-trust.json')));
  const verified = trust.verifyHandoffTrust(envelope, await readFile(spec.publicKeyPath, 'utf8'), now);
  assert.deepEqual(verified, await buildPayload(spec, now));
  assert.ok(Buffer.from(envelope.payload, 'base64').equals(await readFile(join(output, 'handoff-trust-payload.json'))));
  await assert.rejects(prepareTrust(spec, output, keyPath, now), /EEXIST/);
  await assert.rejects(prepareTrust(spec, join(spec.builds[0].bundlePath, 'output'), undefined, now), /independent/);
});

test('sign refuses mismatched keys, unsafe private permissions and symlinked receipts before output', async t => {
  const { root, spec, keyPath, receiptPath } = await fixture(t);
  const output = join(root, 'bad-output');
  const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
  await writeFile(keyPath, other.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  await assert.rejects(prepareTrust(spec, output, keyPath, now), /differs from packaged/);
  await assert.rejects(readFile(join(output, 'handoff-trust.json')));
  if (process.platform !== 'win32') {
    await chmod(keyPath, 0o644);
    await assert.rejects(prepareTrust(spec, output, keyPath, now), /owner-only/);
  }
  const alias = join(root, 'receipt-alias.json'); await symlink(receiptPath, alias);
  const candidate = structuredClone(spec); candidate.builds[0].reviewReceiptPath = alias;
  await assert.rejects(buildPayload(candidate, now), /regular file without links/);
});

test('CLI rejects publish, implicit key lookup, unknown options and relative inputs without network operations', () => {
  const script = new URL('./osir-handoff-trust.mjs', import.meta.url);
  for (const args of [['publish', '/unused/spec.json'], ['sign', '/unused/spec.json', '--output', '/unused/out'],
    ['payload', 'relative.json'], ['payload', '/unused/spec.json', '--output', '/unused/out', '--secret', '/unused/key'],
    ['payload', '/unused/spec.json', '--output', '/unused/out', '--signing-key', '/unused/key']]) {
    const run = spawnSync(process.execPath, [script.pathname, ...args], { encoding: 'utf8' });
    assert.equal(run.status, 1); assert.match(run.stderr, /OSIR:/);
  }
});

test('CLI signs only synthetic explicit inputs and writes a consumer-verifiable local envelope', async t => {
  const { root, spec, keyPath } = await fixture(t);
  spec.publishedAt = new Date().toISOString();
  spec.validUntil = new Date(Date.now() + 86400000).toISOString();
  const specPath = join(root, 'spec.json'); await writeFile(specPath, JSON.stringify(spec));
  const output = join(root, 'cli-output');
  const result = spawnSync(process.execPath, [new URL('./osir-handoff-trust.mjs', import.meta.url).pathname,
    'sign', specPath, '--output', output, '--signing-key', keyPath], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).stage, 'signed-local');
  assert.equal(trust.verifyHandoffTrust(JSON.parse(await readFile(join(output, 'handoff-trust.json'))),
    await readFile(spec.publicKeyPath, 'utf8')).builds[0].version, '0.1.11+10');
});
