import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { copyFile, lstat, mkdir, mkdtemp, readFile, readdir, realpath } from 'node:fs/promises';
import { constants } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { BASE, CURRENT, SHA, TARGETS, bytes, canonical, check, cli, digest, fingerprint, immutableFile, inspect, isMain, json, manifest, matches, privateFile, safe, separate, verifyEnvelope, within } from './osir-anywhere-release-common.mjs';
import { RainStorage, storageConfig } from './osir-anywhere-storage.mjs';
import { systemSignature } from './osir-anywhere-system-signature.mjs';

export const CONTRACT = { schemaVersion: 1, productId: 'osir-anywhere', channel: 'stable', manifestUrl: CURRENT, commands: ['plan', 'prepare', 'upload', 'publish', 'restore'] };
const TOOL_FILES = ['osir-anywhere-release.mjs', 'osir-anywhere-release-common.mjs', 'osir-anywhere-storage.mjs', 'osir-anywhere-build.mjs', 'osir-anywhere-source.mjs', 'osir-anywhere-system-signature.mjs', 'dist-desktop.mjs', 'release-credentials.mjs', 'desktop-build-config.mjs', 'desktop-package-config.mjs'];
export async function toolsFingerprint() {
  return fingerprint(await Promise.all(TOOL_FILES.map(async name => ({ name, sha256: digest(await readFile(new URL(name, import.meta.url))) }))));
}
export async function directory(path) {
  check(isAbsolute(path), 'Directory must be absolute');
  const stat = await lstat(path);
  check(stat.isDirectory() && !stat.isSymbolicLink() && await realpath(path) === resolve(path), 'Directory must not traverse symlinks');
  return path;
}
async function reportArtifact(path, expected) {
  check(isAbsolute(path), 'Evidence path must be absolute');
  await matches(path, expected);
  return json(path);
}
export function nativeAcceptance(report, build) {
  check(report.schemaVersion === 1 && report.sourceSha256 === build.plan.sourceSha256 && report.configSha256 === build.plan.configSha256 &&
    report.target === build.plan.target && report.artifactSha256 === build.artifact.sha256 && report.systemSignatureReportSha256 === build.systemSignatureReportSha256,
    'Native acceptance is not bound to these final bytes/signature report');
  const required = ['installer', 'launch', 'connector', 'python', 'uv', 'upgradeDataPreserved', 'updateDiscovery'];
  check(required.every(k => report.checks?.[k] === true) && report.result === 'passed', 'Native installer/Connector/upgrade acceptance missing');
  const machines = build.plan.target === 'darwin-universal' ? ['darwin-arm64', 'darwin-x64'] : [build.plan.target];
  check(machines.every(target => report.nativeMachines?.includes(target)), 'Native acceptance missing required hardware architecture');
  check(Array.isArray(report.evidence) && report.evidence.length > 0 && report.evidence.every(e => typeof e.path === 'string' && SHA.test(e.sha256) && Number.isSafeInteger(e.size) && e.size > 0), 'Acceptance must preserve raw smoke evidence');
}
export async function releasePlan(spec) {
  check(spec.schemaVersion === 1 && spec.channel === 'stable' && SHA.test(spec.sourceSha256) && /^[a-f0-9]{40}$/.test(spec.upstreamGitHead), 'Invalid release source contract');
  safe(spec.releaseId); safe(spec.version);
  check(typeof spec.publishedAt === 'string' && new Date(spec.publishedAt).toISOString() === spec.publishedAt, 'publishedAt must be fixed UTC ISO timestamp');
  check(spec.expectedCurrent && ((spec.expectedCurrent.releaseId === null && spec.expectedCurrent.sha256 === null) ||
    (typeof spec.expectedCurrent.releaseId === 'string' && safe(spec.expectedCurrent.releaseId) && SHA.test(spec.expectedCurrent.sha256))), 'Expected current requires reviewed release ID AND exact envelope SHA-256, or both null');
  separate(spec.stagingDirectory, spec.backupDirectory, spec.restoreDirectory);
  check(isAbsolute(spec.publicKeyPath), 'Public key path must be absolute');
  const pub = await readFile(spec.publicKeyPath);
  check(createPublicKey(pub).asymmetricKeyType === 'rsa', 'Manifest public key must be RSA');
  check(Array.isArray(spec.builds) && spec.builds.length >= 2, 'Both Mac Universal and Windows x64 are required');
  const artifacts = [], provenance = [], targets = new Set(), filenames = new Set(), configs = new Set(), locks = new Set();
  for (const entry of spec.builds) {
    await directory(entry.directory);
    for (const output of [spec.stagingDirectory, spec.backupDirectory, spec.restoreDirectory]) separate(entry.directory, output);
    const receiptPath = join(entry.directory, 'build-receipt.json');
    const receipt = await json(receiptPath), p = receipt.plan, a = receipt.artifact;
    check(receipt.schemaVersion === 1 && p?.sourceSha256 === spec.sourceSha256 && p.upstreamGitHead === spec.upstreamGitHead && p.releaseId === spec.releaseId && p.version === spec.version &&
      ['darwin-universal', 'win32-x64', 'win32-arm64'].includes(p.target) && SHA.test(p.configSha256) && SHA.test(p.dependencies?.lockSha256) &&
      SHA.test(p.dependencies?.installStateSha256) && /^[a-f0-9]{40}$/.test(p.checkoutHead), 'Build source/config/dependency provenance mismatch');
    check(!targets.has(p.target), 'Duplicate build target'); targets.add(p.target);
    configs.add(p.configSha256);
    locks.add(p.dependencies.lockSha256);
    safe(a.filename); check(!filenames.has(a.filename), 'Duplicate installer filename'); filenames.add(a.filename);
    check(a.filename.endsWith(p.target.startsWith('darwin') ? '.dmg' : '.exe'), 'Installer extension differs from platform');
    await matches(join(entry.directory, a.filename), a);
    const signatureReportPath = join(entry.directory, 'system-signature.json');
    const signatureReportIdentity = await inspect(signatureReportPath);
    check(signatureReportIdentity.sha256 === receipt.systemSignatureReportSha256, 'System signature report differs from build receipt');
    const signatureReport = await json(signatureReportPath);
    const classification = systemSignature(signatureReport);
    check(signatureReport.artifactSha256 === a.sha256 && signatureReport.platform === p.target.split('-')[0] && classification === a.systemSignature && signatureReport.systemSignature === classification,
      'System signature is not bound to this final installer');
    const sourceProvenancePath = join(entry.directory, 'source-provenance.json');
    const sourceIdentity = await inspect(sourceProvenancePath), sourceProvenance = await json(sourceProvenancePath);
    check(sourceIdentity.sha256 === receipt.sourceProvenanceSha256 && sourceProvenance.schemaVersion === 1 && sourceProvenance.sourceSha256 === spec.sourceSha256 &&
      sourceProvenance.upstreamGitHead === spec.upstreamGitHead && fingerprint(sourceProvenance.files) === spec.sourceSha256, 'Source file inventory provenance missing or stale');
    check(['signed', 'unsigned'].includes(receipt.signing?.status) && typeof receipt.signing.notarized === 'boolean', 'Signing status missing');
    const nonNotarized = p.target.startsWith('darwin') && !receipt.signing.notarized;
    if (receipt.signing.status === 'unsigned' || nonNotarized)
      check(spec.allowUnsigned === true && typeof spec.unsignedReason === 'string' && spec.unsignedReason.trim().length >= 12, 'Unsigned/unnotarized release requires explicit reviewed reason');
    check(isAbsolute(entry.acceptancePath) && SHA.test(entry.acceptanceSha256), 'Native acceptance report and reviewed hash required');
    const acceptanceIdentity = await inspect(entry.acceptancePath);
    check(acceptanceIdentity.sha256 === entry.acceptanceSha256, 'Acceptance report changed since review');
    const report = await json(entry.acceptancePath);
    nativeAcceptance(report, receipt);
    const evidence = [];
    for (const item of report.evidence) {
      check(!isAbsolute(item.path) && item.path.split(/[\\/]/).every(p => p && p !== '..' && p !== '.'), 'Unsafe smoke evidence path');
      const file = join(dirname(entry.acceptancePath), item.path);
      check(within(dirname(entry.acceptancePath), await realpath(file)), 'Smoke evidence escaped report directory');
      await matches(file, item);
      evidence.push({ path: file, filename: safe(`${p.target}-smoke-${evidence.length}.bin`), size: item.size, sha256: item.sha256 });
    }
    const deps = await inspect(join(entry.directory, 'resolved-yarn.lock'));
    check(deps.sha256 === p.dependencies.lockSha256, 'Resolved dependency lock evidence missing or changed');
    const [platform, arch] = p.target.split('-');
    artifacts.push({ platform, arch, url: `${BASE}/${spec.releaseId}/${a.filename}`, ...a });
    provenance.push({ receipt, receiptSha256: digest(await readFile(receiptPath)), sourceProvenanceSha256: sourceIdentity.sha256, signatureReportSha256: signatureReportIdentity.sha256, acceptanceSha256: entry.acceptanceSha256,
      acceptance: report, dependencyLock: { filename: `${p.target}-resolved-yarn.lock`, ...deps }, evidence });
  }
  check(TARGETS.every(t => targets.has(t)), 'Release must include Mac Universal and Windows x64');
  check(configs.size === 1, 'Platforms were built with different effective endpoint configuration');
  check(locks.size === 1, 'Platforms were built with different dependency locks');
  artifacts.sort((a, b) => a.filename.localeCompare(b.filename));
  const payload = { schemaVersion: 1, productId: 'osir-anywhere', channel: 'stable', releaseId: spec.releaseId, version: spec.version, publishedAt: spec.publishedAt,
    ...(spec.minimumClientVersion ? { minimumClientVersion: safe(spec.minimumClientVersion) } : {}),
    ...(spec.minimumServerVersion ? { minimumServerVersion: safe(spec.minimumServerVersion) } : {}), artifacts };
  return { ...CONTRACT, releaseId: spec.releaseId, toolsSha256: await toolsFingerprint(), specSha256: fingerprint(spec), publicKeySha256: digest(pub), payload, provenance };
}
async function copyImmutable(source, dest, expected) {
  await mkdir(dirname(dest), { recursive: true, mode: 0o700 });
  try { await copyFile(source, dest, constants.COPYFILE_EXCL); }
  catch (error) { if (error.code !== 'EEXIST') throw error; }
  await matches(dest, expected);
}
function signedEnvelope(payload, key) {
  const encoded = bytes(payload);
  return { payload: encoded.toString('base64'), signature: sign('RSA-SHA256', encoded, key).toString('base64') };
}
function provenancePayload(spec, plan) {
  return { schemaVersion: 1, releaseId: spec.releaseId, sourceSha256: spec.sourceSha256, upstreamGitHead: spec.upstreamGitHead,
    planSha256: fingerprint(plan), toolsSha256: plan.toolsSha256, signingDisclosure: { allowUnsigned: spec.allowUnsigned === true, reason: spec.unsignedReason ?? null }, builds: plan.provenance };
}
export async function prepare(spec, signingKeyPath) {
  const plan = await releasePlan(spec), root = spec.stagingDirectory;
  await mkdir(root, { recursive: true, mode: 0o700 }); await directory(root);
  await immutableFile(join(root, 'plan.json'), bytes(plan));
  for (const entry of spec.builds) {
    const receipt = await json(join(entry.directory, 'build-receipt.json'));
    await copyImmutable(join(entry.directory, receipt.artifact.filename), join(root, receipt.artifact.filename), receipt.artifact);
    await immutableFile(join(root, `${receipt.plan.target}-build-receipt.json`), await readFile(join(entry.directory, 'build-receipt.json')));
    await immutableFile(join(root, `${receipt.plan.target}-acceptance.json`), await readFile(entry.acceptancePath));
    await immutableFile(join(root, `${receipt.plan.target}-system-signature.json`), await readFile(join(entry.directory, 'system-signature.json')));
    await immutableFile(join(root, `${receipt.plan.target}-source-provenance.json`), await readFile(join(entry.directory, 'source-provenance.json')));
    await immutableFile(join(root, `${receipt.plan.target}-resolved-yarn.lock`), await readFile(join(entry.directory, 'resolved-yarn.lock')));
  }
  for (const p of plan.provenance) for (const e of p.evidence) await copyImmutable(e.path, join(root, e.filename), e);
  const privateKey = createPrivateKey(await privateFile(signingKeyPath));
  check(privateKey.asymmetricKeyType === 'rsa' && privateKey.asymmetricKeyDetails.modulusLength >= 2048, 'RSA signing key required');
  const publicKey = await readFile(spec.publicKeyPath);
  check(createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).equals(createPublicKey(publicKey).export({ type: 'spki', format: 'der' })), 'Signing key does not match packaged public key');
  const envelope = signedEnvelope(plan.payload, privateKey); manifest(envelope, publicKey);
  await immutableFile(join(root, 'manifest.json'), bytes(envelope));
  const provenance = provenancePayload(spec, plan);
  await immutableFile(join(root, 'provenance.json'), bytes(signedEnvelope(provenance, privateKey)));
  const allowed = new Set(['plan.json', 'manifest.json', 'provenance.json', ...plan.payload.artifacts.map(a => a.filename),
    ...plan.provenance.flatMap(p => [`${p.receipt.plan.target}-build-receipt.json`, `${p.receipt.plan.target}-acceptance.json`, `${p.receipt.plan.target}-system-signature.json`, `${p.receipt.plan.target}-source-provenance.json`, p.dependencyLock.filename, ...p.evidence.map(e => e.filename)])]);
  const files = [];
  for (const name of (await readdir(root)).sort()) if (!['inventory.json', 'upload-receipt.json', 'publish-intent.json', 'publish-receipt.json'].includes(name)) {
    check(allowed.has(name), 'Staging contains unreviewed file; use a new directory');
    safe(name); files.push({ filename: name, ...await inspect(join(root, name)) });
  }
  await immutableFile(join(root, 'inventory.json'), bytes({ planSha256: fingerprint(plan), files }));
  return { stage: 'prepared', planSha256: fingerprint(plan), manifestSha256: digest(bytes(envelope)), artifacts: plan.payload.artifacts };
}
async function prepared(spec) {
  const plan = await releasePlan(spec), root = spec.stagingDirectory;
  await directory(root);
  check(canonical(await json(join(root, 'plan.json'))) === canonical(plan), 'Prepared plan differs; re-plan in a new staging directory');
  const inventory = await json(join(root, 'inventory.json'));
  check(inventory.planSha256 === fingerprint(plan), 'Inventory plan mismatch');
  const allowed = new Set(['plan.json', 'manifest.json', 'provenance.json', ...plan.payload.artifacts.map(a => a.filename),
    ...plan.provenance.flatMap(p => [`${p.receipt.plan.target}-build-receipt.json`, `${p.receipt.plan.target}-acceptance.json`, `${p.receipt.plan.target}-system-signature.json`, `${p.receipt.plan.target}-source-provenance.json`, p.dependencyLock.filename, ...p.evidence.map(e => e.filename)])]);
  const seen = new Set();
  for (const f of inventory.files) { safe(f.filename); check(allowed.has(f.filename) && !seen.has(f.filename), 'Unreviewed or duplicate inventory file'); seen.add(f.filename); await matches(join(root, f.filename), f); }
  check(seen.size === allowed.size, 'Release inventory evidence incomplete');
  for (const p of plan.provenance) {
    const target = p.receipt.plan.target;
    const bound = [[`${target}-build-receipt.json`, p.receiptSha256], [`${target}-acceptance.json`, p.acceptanceSha256], [`${target}-system-signature.json`, p.signatureReportSha256], [`${target}-source-provenance.json`, p.sourceProvenanceSha256], [p.dependencyLock.filename, p.dependencyLock.sha256], ...p.evidence.map(e => [e.filename, e.sha256])];
    for (const [filename, sha256] of bound) check(inventory.files.find(f => f.filename === filename)?.sha256 === sha256, 'Inventory evidence differs from reviewed plan');
  }
  const publicKey = await readFile(spec.publicKeyPath);
  const provenance = verifyEnvelope(await json(join(root, 'provenance.json')), publicKey);
  check(canonical(provenance) === canonical(provenancePayload(spec, plan)), 'Signed provenance differs from plan');
  const envelope = await readFile(join(root, 'manifest.json'));
  check(canonical(manifest(JSON.parse(envelope), publicKey)) === canonical(plan.payload), 'Prepared manifest differs from plan');
  for (const artifact of plan.payload.artifacts) check(inventory.files.some(f => f.filename === artifact.filename && f.sha256 === artifact.sha256 && f.size === artifact.size), 'Installer missing from inventory');
  check(['plan.json', 'manifest.json', 'provenance.json'].every(f => seen.has(f)), 'Required release evidence missing');
  return { plan, inventory, envelope };
}
export function expectedCurrent(current, expected, publicKey) {
  if (current.body === null) { check(expected.releaseId === null && expected.sha256 === null && current.etag === null, 'Expected current differs from absent current'); return; }
  check(typeof current.etag === 'string' && digest(current.body) === expected.sha256, 'Expected current envelope hash mismatch');
  check(manifest(JSON.parse(current.body), publicKey).releaseId === expected.releaseId, 'Expected current release mismatch');
}
export async function upload(spec, storage) {
  const p = await prepared(spec), pub = await readFile(spec.publicKeyPath);
  expectedCurrent(await storage.current(), spec.expectedCurrent, pub);
  // Retrying verifies ALL objects, including existing successful objects. No
  // mutable progress flag can substitute for public byte verification.
  for (const f of p.inventory.files) {
    await storage.immutable(`${spec.releaseId}/${f.filename}`, join(spec.stagingDirectory, f.filename), f);
    await storage.public(`${BASE}/${spec.releaseId}/${f.filename}`, f);
  }
  const inventoryIdentity = await inspect(join(spec.stagingDirectory, 'inventory.json'));
  await storage.immutable(`${spec.releaseId}/inventory.json`, join(spec.stagingDirectory, 'inventory.json'), inventoryIdentity);
  await storage.public(`${BASE}/${spec.releaseId}/inventory.json`, inventoryIdentity);
  const receipt = { schemaVersion: 1, stage: 'uploaded', planSha256: fingerprint(p.plan), manifestSha256: digest(p.envelope), inventory: inventoryIdentity, objectStorageVerified: true };
  await immutableFile(join(spec.stagingDirectory, 'upload-receipt.json'), bytes(receipt));
  return receipt;
}
export async function restore(backupDirectory, restoreDirectory, publicKeyPath) {
  separate(backupDirectory, restoreDirectory); await directory(backupDirectory);
  check(isAbsolute(publicKeyPath ?? ''), 'Independent restore requires --public-key /absolute/trusted-public.pub');
  const publicKey = await readFile(publicKeyPath);
  await mkdir(restoreDirectory, { recursive: false, mode: 0o700 }); await directory(restoreDirectory);
  const index = await json(join(backupDirectory, 'backup-index.json'));
  check(index.schemaVersion === 1 && Array.isArray(index.files) && index.files.length > 0, 'Invalid backup index');
  const seen = new Set();
  for (const f of index.files) {
    safe(f.filename); check(!seen.has(f.filename), 'Duplicate backup index entry'); seen.add(f.filename);
    await matches(join(backupDirectory, f.filename), f);
    await copyImmutable(join(backupDirectory, f.filename), join(restoreDirectory, f.filename), f);
  }
  const plan = await json(join(restoreDirectory, 'plan.json'));
  const signed = verifyEnvelope(await json(join(restoreDirectory, 'provenance.json')), publicKey);
  check(signed.planSha256 === fingerprint(plan) && index.planSha256 === fingerprint(plan) && signed.releaseId === plan.releaseId &&
    canonical(signed.builds) === canonical(plan.provenance), 'Restored signed provenance/plan mismatch');
  const payload = manifest(await json(join(restoreDirectory, 'manifest.json')), publicKey);
  check(canonical(payload) === canonical(plan.payload), 'Restored signed manifest differs from plan');
  const inventory = await json(join(restoreDirectory, 'inventory.json'));
  check(inventory.planSha256 === fingerprint(plan), 'Restored inventory plan mismatch');
  const bound = [['plan.json', digest(bytes(plan))], ...plan.payload.artifacts.map(a => [a.filename, a.sha256])];
  for (const p of plan.provenance) {
    const target = p.receipt.plan.target;
    bound.push([`${target}-build-receipt.json`, p.receiptSha256], [`${target}-acceptance.json`, p.acceptanceSha256],
      [`${target}-system-signature.json`, p.signatureReportSha256], [`${target}-source-provenance.json`, p.sourceProvenanceSha256],
      [p.dependencyLock.filename, p.dependencyLock.sha256], ...p.evidence.map(e => [e.filename, e.sha256]));
  }
  const required = new Set(['manifest.json', 'provenance.json', ...bound.map(([name]) => name)]), inventorySeen = new Set();
  for (const f of inventory.files) {
    check(required.has(f.filename) && !inventorySeen.has(f.filename), 'Restored inventory contains unreviewed/duplicate entry'); inventorySeen.add(f.filename);
    check(seen.has(f.filename), 'Restored inventory file missing'); await matches(join(restoreDirectory, f.filename), f);
  }
  check(inventorySeen.size === required.size && seen.size === required.size + 2 + (seen.has('previous-stable.json') ? 1 : 0) && seen.has('inventory.json') && seen.has('binding.json'), 'Independent backup evidence incomplete or unexpected');
  for (const [filename, sha256] of bound) check(inventory.files.find(f => f.filename === filename)?.sha256 === sha256, 'Restored evidence differs from signed provenance');
  const binding = await json(join(restoreDirectory, 'binding.json'));
  const envelope = await readFile(join(restoreDirectory, 'manifest.json'));
  check(binding.planSha256 === fingerprint(plan) && binding.manifestSha256 === digest(envelope), 'Backup binding differs from signed candidate');
  if (seen.has('previous-stable.json')) {
    const previous = await readFile(join(restoreDirectory, 'previous-stable.json'));
    expectedCurrent({ body: previous, etag: 'offline-backup' }, binding.expectedCurrent, publicKey);
  } else check(binding.expectedCurrent?.releaseId === null && binding.expectedCurrent.sha256 === null, 'Previous stable backup missing');
  return { stage: 'restored', signaturesVerified: true, releaseId: payload.releaseId, backupIndexSha256: digest(await readFile(join(backupDirectory, 'backup-index.json'))), files: index.files.length };
}
async function backupRestore(spec, p, storage, current) {
  await mkdir(spec.backupDirectory, { recursive: true, mode: 0o700 }); await directory(spec.backupDirectory);
  await mkdir(spec.restoreDirectory, { recursive: true, mode: 0o700 }); await directory(spec.restoreDirectory);
  const backup = join(spec.backupDirectory, spec.releaseId);
  await mkdir(backup, { recursive: true, mode: 0o700 }); await directory(backup);
  await immutableFile(join(backup, 'binding.json'), bytes({ planSha256: fingerprint(p.plan), manifestSha256: digest(p.envelope), expectedCurrent: spec.expectedCurrent }));
  const files = [];
  for (const f of [...p.inventory.files, { filename: 'inventory.json', ...await inspect(join(spec.stagingDirectory, 'inventory.json')) }]) {
    const dest = join(backup, f.filename);
    // This is a second independent PUBLIC fetch, never copied from stage or
    // re-used from upload verification. Existing backups must match exactly.
    let exists = false;
    try { await matches(dest, f); exists = true; } catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (!exists) await storage.public(`${BASE}/${spec.releaseId}/${f.filename}`, f, dest);
    await matches(dest, f); files.push(f);
  }
  if (current.body) {
    await immutableFile(join(backup, 'previous-stable.json'), current.body);
    files.push({ filename: 'previous-stable.json', size: current.body.length, sha256: digest(current.body) });
  }
  const binding = await inspect(join(backup, 'binding.json')); files.push({ filename: 'binding.json', ...binding });
  const index = { schemaVersion: 1, planSha256: fingerprint(p.plan), files };
  await immutableFile(join(backup, 'backup-index.json'), bytes(index));
  const parent = await mkdtemp(join(spec.restoreDirectory, `${spec.releaseId}-`));
  const restored = join(parent, 'restored');
  const report = await restore(backup, restored, spec.publicKeyPath);
  const restoredManifest = await json(join(restored, 'manifest.json'));
  manifest(restoredManifest, await readFile(spec.publicKeyPath));
  check(digest(await readFile(join(restored, 'manifest.json'))) === digest(p.envelope), 'Restored manifest differs');
  await immutableFile(join(parent, 'restore-receipt.json'), bytes(report));
  return { backup, restored, ...report };
}
export async function publish(spec, storage) {
  const p = await prepared(spec), root = spec.stagingDirectory;
  const uploadReceipt = await json(join(root, 'upload-receipt.json'));
  check(uploadReceipt.objectStorageVerified === true && uploadReceipt.planSha256 === fingerprint(p.plan) && uploadReceipt.manifestSha256 === digest(p.envelope), 'Verified upload receipt missing or stale');
  const pub = await readFile(spec.publicKeyPath), current = await storage.current();
  let intent;
  try { intent = await json(join(root, 'publish-intent.json')); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  if (intent) {
    check(intent.planSha256 === fingerprint(p.plan) && intent.manifestSha256 === digest(p.envelope), 'Publication intent differs');
    check(current.body?.equals(p.envelope), 'Prior publication attempt is uncertain; reconcile current before further action');
    await storage.public(CURRENT, { size: p.envelope.length, sha256: digest(p.envelope) });
    return { stage: 'published', reconciled: true, releaseId: spec.releaseId, manifestSha256: digest(p.envelope) };
  }
  expectedCurrent(current, spec.expectedCurrent, pub);
  for (const f of p.inventory.files) await storage.public(`${BASE}/${spec.releaseId}/${f.filename}`, f);
  const recovery = await backupRestore(spec, p, storage, current);
  // Fresh authoritative read directly from S3, not cached public metadata.
  const beforeSwitch = await storage.current(); expectedCurrent(beforeSwitch, spec.expectedCurrent, pub);
  check(beforeSwitch.etag === current.etag, 'Current ETag changed during verification');
  const publication = { planSha256: fingerprint(p.plan), manifestSha256: digest(p.envelope), previousEtag: beforeSwitch.etag, recovery };
  await immutableFile(join(root, 'publish-intent.json'), bytes(publication));
  await storage.cas(p.envelope, beforeSwitch.etag);
  const after = await storage.current();
  check(after.body?.equals(p.envelope), 'Publication result uncertain; inspect authoritative current');
  await storage.public(CURRENT, { size: p.envelope.length, sha256: digest(p.envelope) });
  const receipt = { schemaVersion: 1, stage: 'published', releaseId: spec.releaseId, manifestSha256: digest(p.envelope), recovery };
  await immutableFile(join(root, 'publish-receipt.json'), bytes(receipt));
  return receipt;
}
if (isMain(import.meta.url)) await cli(async () => {
  const [command, path, option, value, keyPath] = process.argv.slice(2);
  check(CONTRACT.commands.includes(command) && isAbsolute(path ?? ''), 'Usage: osir-anywhere-release.mjs <plan|prepare|upload|publish> /absolute/spec.json [--signing-key /absolute/key.pem] | restore /absolute/backup /absolute/new-restore --public-key /absolute/trusted-public.pub');
  if (command === 'restore') { check(isAbsolute(option ?? '') && value === '--public-key' && isAbsolute(keyPath ?? ''), 'Restore requires new absolute output and --public-key'); console.log(JSON.stringify(await restore(path, option, keyPath), null, 2)); return; }
  const spec = await json(path);
  let result;
  if (command === 'plan') result = await releasePlan(spec);
  if (command === 'prepare') {
    check(option === '--signing-key' && isAbsolute(value ?? ''), 'prepare requires --signing-key /absolute/key.pem');
    result = await prepare(spec, value);
  }
  if (['upload', 'publish'].includes(command)) {
    check(!option, 'Storage credentials only use the fixed private config; no CLI key arguments');
    const storage = new RainStorage(await storageConfig());
    result = await (command === 'upload' ? upload : publish)(spec, storage);
  }
  console.log(JSON.stringify(result, null, 2));
});
