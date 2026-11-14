#!/usr/bin/env node
/** Offline only. No download, publication, environment key lookup or dist build.
 * payload /absolute/spec.json --output /new/directory
 * sign /absolute/spec.json --output /new/directory --signing-key /absolute/key.pem
 *
 * Spec: {schemaVersion:1,publishedAt,validUntil,publicKeyPath,builds:[{
 *   productId,version,releaseId,platform:'darwin',bundlePath,
 *   reviewReceiptPath,reviewReceiptSha256
 * }]}. Each pinned human review receipt has EXACTLY these fields:
 * {schemaVersion:1,reviewed:true,bundleStage:'final-installed',bundlePath,
 *  productId,version,releaseId,platform:'darwin',treeSha256}.
 * The receipt binds an explicitly reviewed installed tree, not a source checkout,
 * archive or unsigned intermediate. It is not native installer acceptance.
 */
import { constants, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import ts from 'typescript';
import { bytes, check, cli, digest, isMain, privateFile, separate, SHA } from './osir-anywhere-release-common.mjs';

// Compile only this dependency-free trust module in memory. Never use potentially
// stale dist output, emit build files, or duplicate its security/tree algorithm.
const source = await readFile(new URL('../electron/osir-handoff-trust.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, { compilerOptions: {
  module: ts.ModuleKind.ES2022, target: ts.ScriptTarget.ES2022,
} }).outputText;
export const trust = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);

function exact(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}
async function reviewedFile(file, limit = 256 * 1024) {
  check(typeof file === 'string' && isAbsolute(file), 'Explicit absolute input path required');
  const before = await lstat(file);
  check(before.isFile() && before.nlink === 1 && before.size > 0 && before.size <= limit &&
    await realpath(file) === resolve(file), 'Input must be a bounded regular file without links');
  const data = await readFile(file);
  const after = await lstat(file);
  check(before.ino === after.ino && before.size === after.size && before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs,
    'Reviewed input changed');
  return data;
}
const parse = data => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data));

export async function buildPayload(spec, now = Date.now()) {
  check(exact(spec, ['schemaVersion', 'publishedAt', 'validUntil', 'publicKeyPath', 'builds']) && spec.schemaVersion === 1,
    'Unknown trust spec fields/schema');
  check(typeof spec.publicKeyPath === 'string' && isAbsolute(spec.publicKeyPath), 'Explicit packaged publicKeyPath required');
  check(Array.isArray(spec.builds) && spec.builds.length > 0 && spec.builds.length <= 128, 'Expected 1..128 reviewed builds');
  const builds = [];
  for (const build of spec.builds) {
    check(exact(build, ['productId', 'version', 'releaseId', 'platform', 'bundlePath', 'reviewReceiptPath', 'reviewReceiptSha256']),
      'Unknown build fields; installed bundle and pinned review receipt required');
    check(typeof build.bundlePath === 'string' && isAbsolute(build.bundlePath) && SHA.test(build.reviewReceiptSha256),
      'Explicit installed bundle and review receipt SHA-256 required');
    separate(build.bundlePath, build.reviewReceiptPath, spec.publicKeyPath);
    const data = await reviewedFile(build.reviewReceiptPath);
    check(digest(data) === build.reviewReceiptSha256, 'Review receipt SHA-256 mismatch');
    const receipt = parse(data);
    check(exact(receipt, ['schemaVersion', 'reviewed', 'bundleStage', 'bundlePath', 'productId', 'version', 'releaseId', 'platform', 'treeSha256']) &&
      receipt.schemaVersion === 1 && receipt.reviewed === true && receipt.bundleStage === 'final-installed',
      'Receipt must explicitly approve the final installed bundle');
    for (const key of ['bundlePath', 'productId', 'version', 'releaseId', 'platform'])
      check(receipt[key] === build[key], `Reviewed ${key} mismatch`);
    check(typeof receipt.treeSha256 === 'string' && SHA.test(receipt.treeSha256), 'Reviewed installed tree hash required');
    const entry = { productId: build.productId, version: build.version, releaseId: build.releaseId,
      platform: build.platform, treeSha256: receipt.treeSha256 };
    // Reject invalid metadata before hashing potentially large trees.
    trust.validateHandoffTrust({ schemaVersion: 1, productId: 'osir-desktop-handoff-trust',
      publishedAt: spec.publishedAt, validUntil: spec.validUntil, builds: [entry] }, now);
    check(await trust.handoffBundleFingerprint(build.bundlePath) === receipt.treeSha256, 'Final installed bundle tree differs from review');
    builds.push(entry);
  }
  return trust.validateHandoffTrust({ schemaVersion: 1, productId: 'osir-desktop-handoff-trust',
    publishedAt: spec.publishedAt, validUntil: spec.validUntil, builds }, now);
}

export async function prepareTrust(spec, output, signingKeyPath, now = Date.now()) {
  check(typeof output === 'string' && isAbsolute(output), 'Explicit new absolute output directory required');
  check(await realpath(resolve(output, '..')) === resolve(output, '..'), 'Output parent must not traverse symlinks');
  for (const build of spec.builds ?? []) separate(output, build.bundlePath, build.reviewReceiptPath);
  separate(output, spec.publicKeyPath);
  if (signingKeyPath !== undefined) {
    separate(output, signingKeyPath, spec.publicKeyPath);
    for (const build of spec.builds ?? []) separate(signingKeyPath, build.bundlePath, build.reviewReceiptPath);
  }
  const payload = await buildPayload(spec, now);
  const encoded = bytes(payload);
  check(encoded.toString('base64').length <= 180_000, 'Trust payload exceeds consumer limit');
  let envelope;
  if (signingKeyPath !== undefined) {
    // Only this explicit operation reads the specified private key. Same path,
    // owner/permissions and key-match gates as release-common/prepare.
    const key = createPrivateKey(await privateFile(signingKeyPath));
    const bits = key.asymmetricKeyDetails?.modulusLength ?? 0;
    check(key.asymmetricKeyType === 'rsa' && bits >= 2048 && bits <= 8192, 'RSA signing key must be 2048..8192 bits');
    const publicKey = (await reviewedFile(spec.publicKeyPath, 32768)).toString('utf8');
    check(createPublicKey(key).export({ type: 'spki', format: 'der' }).equals(
      createPublicKey(publicKey).export({ type: 'spki', format: 'der' })), 'Signing key differs from packaged public key');
    envelope = { payload: encoded.toString('base64'), signature: sign('RSA-SHA256', encoded,
      { key, padding: constants.RSA_PKCS1_PADDING }).toString('base64') };
    trust.verifyHandoffTrust(envelope, publicKey, now);
  }
  // New directory only: no overwrite, merge, implicit upload or existing feed read.
  await mkdir(output, { mode: 0o700 });
  await writeFile(join(output, 'handoff-trust-payload.json'), encoded, { flag: 'wx', mode: 0o600 });
  if (envelope) await writeFile(join(output, 'handoff-trust.json'), bytes(envelope), { flag: 'wx', mode: 0o600 });
  return { stage: envelope ? 'signed-local' : 'payload-local', builds: payload.builds.length, payloadSha256: digest(encoded) };
}

if (isMain(import.meta.url)) await cli(async () => {
  const [command, specPath, ...args] = process.argv.slice(2);
  check(['payload', 'sign'].includes(command) && isAbsolute(specPath ?? ''),
    'Usage: osir-handoff-trust.mjs <payload|sign> /absolute/spec.json --output /new/directory [--signing-key /absolute/key.pem]');
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    const name = args[i];
    check(['--output', '--signing-key'].includes(name) && !Object.hasOwn(options, name) && isAbsolute(args[i + 1] ?? ''), 'Unknown/duplicate option or nonabsolute path');
    options[name] = args[i + 1];
  }
  check(options['--output'] && (command === 'sign' ? options['--signing-key'] : !options['--signing-key']), 'Only sign accepts/requires an explicit signing key');
  separate(options['--output'], specPath);
  const spec = parse(await reviewedFile(specPath));
  console.log(JSON.stringify(await prepareTrust(spec, options['--output'], options['--signing-key'])));
});
