import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BASE, CURRENT, bytes, digest, fingerprint, inspect, json, manifest } from './osir-anywhere-release-common.mjs';
import { nativeAcceptance, prepare, publish, releasePlan, restore, upload } from './osir-anywhere-release.mjs';

const keys = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
class FakeStorage {
  constructor() { this.objects = new Map(); this.stable = null; this.etag = null; this.puts = 0; this.casCalls = 0; this.publicReads = []; }
  async current() { return { body: this.stable, etag: this.etag }; }
  async immutable(key, path, expected) {
    const body = await readFile(path); assert.equal(digest(body), expected.sha256);
    if (this.objects.has(key)) assert.deepEqual(this.objects.get(key), body);
    else { this.objects.set(key, body); this.puts++; }
  }
  async public(url, expected, destination) {
    this.publicReads.push({ url, backup: Boolean(destination) });
    const body = url === CURRENT ? this.stable : this.objects.get(url.slice(BASE.length + 1));
    assert.ok(body); assert.equal(body.length, expected.size); assert.equal(digest(body), expected.sha256);
    if (this.failRead) throw new Error('Simulated readback failure');
    if (destination) {
      if (this.failBackup) throw new Error('Simulated independent backup failure');
      await writeFile(destination, body, { flag: 'wx', mode: 0o600 });
    }
  }
  async cas(body, etag) {
    this.casCalls++;
    if (this.race) { this.stable = Buffer.from('another writer'); this.etag = 'other-etag'; }
    assert.equal(etag, this.etag, 'CAS expected ETag differs');
    this.stable = body; this.etag = 'new-etag';
    if (this.loseResponse) throw new Error('Simulated lost response after successful CAS');
  }
}
async function fixture(t, releaseRevision) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'anywhere-release-test-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const key = join(root, 'key.pem'), pub = join(root, 'public.pub');
  await writeFile(key, keys.privateKey, { mode: 0o600 }); await writeFile(pub, keys.publicKey);
  const spec = { schemaVersion: 1, channel: 'stable', releaseId: 'test-release-1', version: '2.1.1',
    publishedAt: '2026-11-14T02:00:00.000Z', sourceSha256: 'a'.repeat(64), upstreamGitHead: 'b'.repeat(40), expectedCurrent: { releaseId: null, sha256: null },
    stagingDirectory: join(root, 'stage'), backupDirectory: join(root, 'backup'), restoreDirectory: join(root, 'restore'),
    publicKeyPath: pub, allowUnsigned: true, unsignedReason: 'Reviewed unsigned candidate; no system signing certificate', builds: [] };
  const sourceProvenance = { schemaVersion: 1, upstreamGitHead: spec.upstreamGitHead, files: [{ path: 'fixture.js', size: 1, sha256: digest('x'), executable: false }] };
  if (releaseRevision !== undefined) spec.releaseRevision = releaseRevision;
  sourceProvenance.sourceSha256 = fingerprint(sourceProvenance.files); spec.sourceSha256 = sourceProvenance.sourceSha256;
  for (const target of ['darwin-universal', 'win32-x64']) {
    const directory = join(root, target); await mkdir(directory);
    const filename = `${target}.${target.startsWith('darwin') ? 'dmg' : 'exe'}`;
    await writeFile(join(directory, filename), `Final bytes for ${target}`);
    await writeFile(join(directory, 'resolved-yarn.lock'), 'resolved dependency lock');
    const lock = await inspect(join(directory, 'resolved-yarn.lock'));
    const artifact = { filename, ...await inspect(join(directory, filename)), systemSignature: 'unsigned' };
    const signatureReport = { schemaVersion: 1, platform: target.startsWith('darwin') ? 'darwin' : 'win32', artifactSha256: artifact.sha256, systemSignature: 'unsigned',
      probes: target.startsWith('darwin') ? { image: { tool: 'hdiutil', status: 0 }, identity: { tool: 'codesign', status: 0, stdout: '', stderr: 'Signature=adhoc' }, verify: { tool: 'codesign', status: 0 } } :
        { authenticode: { tool: 'powershell.exe', status: 0, stdout: 'NotSigned', stderr: '' } } };
    await writeFile(join(directory, 'system-signature.json'), bytes(signatureReport));
    await writeFile(join(directory, 'source-provenance.json'), bytes(sourceProvenance));
    const receipt = { schemaVersion: 1, artifact, signing: { status: 'unsigned', notarized: false }, sourceProvenanceSha256: digest(bytes(sourceProvenance)), systemSignatureReportSha256: digest(bytes(signatureReport)), plan: {
      releaseId: spec.releaseId, version: spec.version, target, sourceSha256: spec.sourceSha256, upstreamGitHead: spec.upstreamGitHead,
      ...(releaseRevision !== undefined ? { releaseRevision } : {}),
      checkoutHead: 'c'.repeat(40), configSha256: 'd'.repeat(64), dependencies: { lockSha256: lock.sha256, installStateSha256: 'e'.repeat(64) } } };
    await writeFile(join(directory, 'build-receipt.json'), bytes(receipt));
    await writeFile(join(directory, 'smoke.log'), `Synthetic test evidence ${target}; never real acceptance`);
    const report = { schemaVersion: 1, sourceSha256: spec.sourceSha256, configSha256: receipt.plan.configSha256, target, artifactSha256: artifact.sha256, systemSignatureReportSha256: receipt.systemSignatureReportSha256,
      result: 'passed', nativeMachines: target.startsWith('darwin') ? ['darwin-arm64', 'darwin-x64'] : [target],
      checks: Object.fromEntries(['installer', 'launch', 'connector', 'python', 'uv', 'upgradeDataPreserved', 'updateDiscovery'].map(k => [k, true])),
      evidence: [{ path: 'smoke.log', ...await inspect(join(directory, 'smoke.log')) }] };
    const acceptancePath = join(directory, 'acceptance.json'); await writeFile(acceptancePath, bytes(report));
    spec.builds.push({ directory, acceptancePath, acceptanceSha256: digest(bytes(report)) });
  }
  return { root, spec, key, storage: new FakeStorage() };
}

test('offline plan/prepare -> immutable upload -> independent public backup/restore -> CAS; repeat publish reconciles', async t => {
  const { spec, key, storage } = await fixture(t);
  assert.equal((await releasePlan(spec)).payload.artifacts.length, 2);
  assert.equal(storage.puts, 0);
  await prepare(spec, key); await prepare(spec, key);
  const payload = manifest(await json(join(spec.stagingDirectory, 'manifest.json')), keys.publicKey);
  assert.equal(Object.hasOwn(payload, 'revision'), false, 'Legacy signed payload remains unchanged');
  assert.equal(payload.productId, 'osir-anywhere'); assert.equal(payload.artifacts[0].arch, 'universal');
  await upload(spec, storage); const puts = storage.puts;
  await upload(spec, storage); assert.equal(storage.puts, puts, 'Successful objects must be reused');
  const result = await publish(spec, storage); assert.equal(result.stage, 'published');
  assert.equal(storage.casCalls, 1);
  assert.ok(storage.publicReads.filter(r => r.backup).length > 2, 'Backup must fetch bytes independently');
  const reconciled = await publish(spec, storage); assert.equal(reconciled.reconciled, true); assert.equal(storage.casCalls, 1);
  const recovery = await restore(result.recovery.backup, join(spec.restoreDirectory, 'offline-recovery'), spec.publicKeyPath);
  assert.ok(recovery.files > 2); assert.equal(recovery.signaturesVerified, true);
});

test('same public version revision is signed, bound to build evidence and preserved through offline restore', async t => {
  const { spec, key, storage, root } = await fixture(t, 2);
  // Updating fixture public versions changes no application/package version.
  spec.version = '2.2.1';
  for (const build of spec.builds) {
    const receiptPath = join(build.directory, 'build-receipt.json'), receipt = await json(receiptPath);
    receipt.plan.version = spec.version; await writeFile(receiptPath, bytes(receipt));
  }
  const previousPayload = (await releasePlan(spec)).payload;
  previousPayload.releaseId = 'previous-revision'; previousPayload.revision = 1;
  for (const artifact of previousPayload.artifacts) artifact.url = `${BASE}/previous-revision/${artifact.filename}`;
  const previousBytes = bytes(previousPayload);
  storage.stable = bytes({ payload: previousBytes.toString('base64'), signature: sign('RSA-SHA256', previousBytes, keys.privateKey).toString('base64') });
  storage.etag = 'previous-etag'; spec.expectedCurrent = { releaseId: 'previous-revision', sha256: digest(storage.stable) };
  await prepare(spec, key);
  const envelope = await json(join(spec.stagingDirectory, 'manifest.json'));
  const payload = manifest(envelope, keys.publicKey);
  assert.equal(payload.version, '2.2.1'); assert.equal(payload.revision, 2);
  assert.throws(() => manifest({ ...envelope, payload: bytes({ ...payload, revision: 3 }).toString('base64') }, keys.publicKey), /signature/);
  await upload(spec, storage); const published = await publish(spec, storage);
  assert.equal(manifest(JSON.parse(storage.stable), keys.publicKey).revision, 2);
  const restored = join(root, 'restored-revision');
  await restore(published.recovery.backup, restored, spec.publicKeyPath);
  assert.equal(manifest(await json(join(restored, 'manifest.json')), keys.publicKey).revision, 2);
  assert.equal(manifest(await json(join(restored, 'previous-stable.json')), keys.publicKey).revision, 1);
});

test('invalid revision and build revision drift are rejected before staging', async t => {
  const { spec } = await fixture(t);
  for (const releaseRevision of [-1, 0.5, null, '1', true, 65536, Number.MAX_SAFE_INTEGER + 1]) {
    await assert.rejects(releasePlan({ ...spec, releaseRevision }), /revision/i);
    const payload = bytes({ schemaVersion: 1, productId: 'osir-anywhere', channel: 'stable', releaseId: 'r', version: '2.2.1', revision: releaseRevision });
    assert.throws(() => manifest({ payload: payload.toString('base64'), signature: sign('RSA-SHA256', payload, keys.privateKey).toString('base64') }, keys.publicKey), /revision/i);
  }
  await assert.rejects(releasePlan({ ...spec, releaseRevision: 1 }), /provenance/);
  const path = join(spec.builds[0].directory, 'build-receipt.json'), receipt = await json(path);
  receipt.plan.releaseRevision = 2; await writeFile(path, bytes(receipt));
  await assert.rejects(releasePlan(spec), /provenance/);
  await assert.rejects(readFile(join(spec.stagingDirectory, 'manifest.json')), { code: 'ENOENT' });
});

test('same-version revisions require a new immutable release identity', async t => {
  const { spec } = await fixture(t, 2);
  spec.expectedCurrent = { releaseId: spec.releaseId, sha256: 'f'.repeat(64) };
  await assert.rejects(releasePlan(spec), /new immutable releaseId/);
});

test('modified final bytes and mismatched source fail before staging/upload', async t => {
  const { spec } = await fixture(t);
  await writeFile(join(spec.builds[0].directory, 'darwin-universal.dmg'), 'tampered');
  await assert.rejects(releasePlan(spec), /mismatch/);
});
test('required Windows build, native Intel and final-hash-bound acceptance cannot be omitted', async t => {
  const { spec } = await fixture(t);
  const build = await json(join(spec.builds[0].directory, 'build-receipt.json'));
  const report = await json(spec.builds[0].acceptancePath);
  report.nativeMachines = ['darwin-arm64'];
  assert.throws(() => nativeAcceptance(report, build), /architecture/);
  report.nativeMachines.push('darwin-x64'); report.artifactSha256 = 'f'.repeat(64);
  assert.throws(() => nativeAcceptance(report, build), /final bytes/);
  spec.builds.pop(); await assert.rejects(releasePlan(spec), /required/);
});
test('unsigned is a reviewed disclosure, never silently accepted or called notarized', async t => {
  const { spec } = await fixture(t); spec.allowUnsigned = false;
  await assert.rejects(releasePlan(spec), /Unsigned/);
});
test('no native smoke report and no headless substitution', async t => {
  const { spec } = await fixture(t);
  const report = await json(spec.builds[0].acceptancePath); report.checks.connector = false;
  await writeFile(spec.builds[0].acceptancePath, bytes(report)); spec.builds[0].acceptanceSha256 = digest(bytes(report));
  await assert.rejects(releasePlan(spec), /Native installer/);
});
test('private key mismatch, permissive key file, source drift and backup nesting are rejected', async t => {
  const { spec, key } = await fixture(t);
  await chmod(key, 0o644);
  if (process.platform !== 'win32') await assert.rejects(prepare(spec, key), /owner-only/);
  spec.backupDirectory = join(spec.stagingDirectory, 'nested');
  await assert.rejects(releasePlan(spec), /independent/);
});
test('failed public readback does not create upload receipt or switch current', async t => {
  const { spec, key, storage } = await fixture(t); await prepare(spec, key);
  storage.failRead = true;
  await assert.rejects(upload(spec, storage), /readback/); assert.equal(storage.casCalls, 0);
  await assert.rejects(json(join(spec.stagingDirectory, 'upload-receipt.json')), { code: 'ENOENT' });
  storage.failRead = false; await upload(spec, storage);
});
test('independent backup failure prevents CAS, successful uploaded packages survive', async t => {
  const { spec, key, storage } = await fixture(t); await prepare(spec, key); await upload(spec, storage);
  const puts = storage.puts; storage.failBackup = true;
  await assert.rejects(publish(spec, storage), /backup failure/); assert.equal(storage.casCalls, 0);
  storage.failBackup = false; await publish(spec, storage); assert.equal(storage.puts, puts);
});
test('corrupt independent backup cannot be reused or restored', async t => {
  const { spec, key, storage, root } = await fixture(t); await prepare(spec, key); await upload(spec, storage);
  const result = await publish(spec, storage);
  await writeFile(join(result.recovery.backup, 'darwin-universal.dmg'), 'corrupted backup');
  await assert.rejects(restore(result.recovery.backup, join(root, 'broken-recovery'), spec.publicKeyPath), /mismatch/);
});
test('independent recovery requires external trusted key and rejects an attacker rewriting both backup and checksum index', async t => {
  const { spec, key, storage, root } = await fixture(t); await prepare(spec, key); await upload(spec, storage);
  const result = await publish(spec, storage), backup = result.recovery.backup;
  await assert.rejects(restore(backup, join(root, 'no-trusted-key')), /trusted-public/);
  const filename = 'darwin-universal.dmg'; await writeFile(join(backup, filename), 'tampered installer with matching forged index');
  const index = await json(join(backup, 'backup-index.json')); Object.assign(index.files.find(f => f.filename === filename), await inspect(join(backup, filename)));
  await writeFile(join(backup, 'backup-index.json'), bytes(index));
  await assert.rejects(restore(backup, join(root, 'forged-index'), spec.publicKeyPath), /mismatch|signed provenance/);
});
test('reviewed expected current is checked before upload and again before publication', async t => {
  const { spec, key, storage } = await fixture(t); await prepare(spec, key);
  storage.stable = Buffer.from('unexpected current'); storage.etag = 'unexpected';
  await assert.rejects(upload(spec, storage), /Expected current/); assert.equal(storage.puts, 0);
  storage.stable = null; storage.etag = null; await upload(spec, storage);
  storage.stable = Buffer.from('changed current'); storage.etag = 'changed';
  await assert.rejects(publish(spec, storage), /Expected current/); assert.equal(storage.casCalls, 0);
});
test('conditional switch race is rejected, uncertain attempt cannot blindly retry', async t => {
  const { spec, key, storage } = await fixture(t); await prepare(spec, key); await upload(spec, storage);
  storage.race = true; await assert.rejects(publish(spec, storage), /CAS expected/);
  assert.equal(storage.casCalls, 1);
  await assert.rejects(publish(spec, storage), /uncertain/); assert.equal(storage.casCalls, 1);
});
test('lost CAS response reconciles exact candidate without a second write', async t => {
  const { spec, key, storage } = await fixture(t); await prepare(spec, key); await upload(spec, storage);
  storage.loseResponse = true; await assert.rejects(publish(spec, storage), /lost response/);
  const result = await publish(spec, storage); assert.equal(result.reconciled, true); assert.equal(storage.casCalls, 1);
});
test('existing signed current is backed up and hash-bound, enabling reviewable rollback', async t => {
  const { spec, key, storage } = await fixture(t);
  const p = (await releasePlan(spec)).payload; p.releaseId = 'previous';
  for (const a of p.artifacts) a.url = `${BASE}/previous/${a.filename}`;
  const data = bytes(p), previous = bytes({ payload: data.toString('base64'), signature: sign('RSA-SHA256', data, keys.privateKey).toString('base64') });
  storage.stable = previous; storage.etag = 'old-etag'; spec.expectedCurrent = { releaseId: 'previous', sha256: digest(previous) };
  await prepare(spec, key); await upload(spec, storage); const result = await publish(spec, storage);
  assert.deepEqual(await readFile(join(result.recovery.backup, 'previous-stable.json')), previous);
});
test('signatures reject modified payload and foreign product; stages reject spec drift', async t => {
  const { spec, key, storage } = await fixture(t); await prepare(spec, key);
  const envelope = await json(join(spec.stagingDirectory, 'manifest.json'));
  envelope.payload = bytes({ productId: 'other' }).toString('base64');
  assert.throws(() => manifest(envelope, keys.publicKey), /signature/);
  spec.minimumServerVersion = '2.1.0'; await assert.rejects(upload(spec, storage), /Prepared plan/);
});
