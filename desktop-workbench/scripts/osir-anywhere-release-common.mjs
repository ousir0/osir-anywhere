import { createHash, createPublicKey, verify } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

export const BASE = 'https://osirvedio.cn-nb1.rains3.com/osir-anywhere/releases';
export const CURRENT = `${BASE}/stable.json`;
export const PREFIX = 'osir-anywhere/releases';
export const TARGETS = ['darwin-universal', 'win32-x64'];
export const SHA = /^[a-f0-9]{64}$/;
export function check(value, message) { if (!value) throw new Error(message); }
/** Omission or explicit zero is legacy. Match the Client installer's u16 bound. */
export function releaseRevision(value) {
  check(value === undefined || (Number.isSafeInteger(value) && value >= 0 && value <= 65535), 'releaseRevision/revision must be an integer in 0..65535 when supplied');
  return value ?? 0;
}
export function safe(value) {
  check(typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$/.test(value) && !value.includes('..'), 'Invalid release/file identity');
  return value;
}
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(v => canonical(v) ?? 'null').join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).filter(k => value[k] !== undefined).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}
export const digest = value => createHash('sha256').update(value).digest('hex');
export const fingerprint = value => digest(canonical(value));
export const json = async path => JSON.parse(await readFile(path, 'utf8'));
export const bytes = value => Buffer.from(`${canonical(value)}\n`);
export async function immutableFile(path, data) {
  await mkdir(resolve(path, '..'), { recursive: true, mode: 0o700 });
  try { await writeFile(path, data, { flag: 'wx', mode: 0o600 }); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    check((await readFile(path)).equals(Buffer.from(data)), 'Immutable local file collision');
  }
}
export async function inspect(path) {
  const before = await lstat(path);
  check(before.isFile() && !before.isSymbolicLink() && before.nlink === 1 && before.size > 0, 'Expected nonempty regular file without links');
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  const after = await lstat(path);
  check(before.ino === after.ino && before.size === after.size && before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs, 'File changed while hashing');
  return { size: after.size, sha256: hash.digest('hex') };
}
export async function matches(path, expected) {
  const actual = await inspect(path);
  check(actual.size === expected.size && actual.sha256 === expected.sha256, 'File size or SHA-256 mismatch');
  return actual;
}
export async function privateFile(path) {
  check(isAbsolute(path), 'Private file path must be absolute');
  const stat = await lstat(path);
  check(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && stat.size < 32768 &&
    (process.platform === 'win32' || (stat.uid === process.getuid() && (stat.mode & 0o077) === 0)), 'Private file must be owner-only regular file');
  check(await realpath(path) === resolve(path), 'Private file path must not traverse symlinks');
  return readFile(path);
}
export function within(root, child) {
  const rel = relative(resolve(root), resolve(child));
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel));
}
export function separate(...paths) {
  for (const path of paths) check(typeof path === 'string' && isAbsolute(path), 'Directories must be absolute');
  for (let i = 0; i < paths.length; i++) for (let j = i + 1; j < paths.length; j++)
    check(!within(paths[i], paths[j]) && !within(paths[j], paths[i]), 'Directories must be independent, without nesting');
}
export function verifyEnvelope(envelope, publicKey) {
  check(Object.keys(envelope).sort().join(',') === 'payload,signature', 'Invalid signature envelope');
  for (const key of ['payload', 'signature']) check(typeof envelope[key] === 'string' && Buffer.from(envelope[key], 'base64').toString('base64') === envelope[key], 'Noncanonical Base64');
  const payloadBytes = Buffer.from(envelope.payload, 'base64');
  const key = createPublicKey(publicKey);
  check(key.asymmetricKeyType === 'rsa' && key.asymmetricKeyDetails.modulusLength >= 2048, 'RSA public key required');
  check(verify('RSA-SHA256', payloadBytes, key, Buffer.from(envelope.signature, 'base64')), 'Manifest signature rejected');
  return JSON.parse(payloadBytes);
}
export function manifest(envelope, publicKey) {
  const p = verifyEnvelope(envelope, publicKey);
  check(p.schemaVersion === 1 && p.productId === 'osir-anywhere' && p.channel === 'stable', 'Manifest product/channel mismatch');
  safe(p.releaseId); safe(p.version);
  releaseRevision(p.revision);
  check(!Number.isNaN(Date.parse(p.publishedAt)) && Array.isArray(p.artifacts) && p.artifacts.length > 0, 'Invalid manifest');
  const seen = new Set();
  for (const a of p.artifacts) {
    check(['darwin', 'win32'].includes(a.platform) && ['universal', 'arm64', 'x64'].includes(a.arch) && !(a.platform === 'win32' && a.arch === 'universal'), 'Invalid artifact platform');
    const id = `${a.platform}-${a.arch}`;
    check(!seen.has(id), 'Duplicate platform artifact'); seen.add(id);
    safe(a.filename);
    check(['unsigned', 'developer-id-notarized', 'authenticode'].includes(a.systemSignature) &&
      !(a.platform === 'darwin' && a.systemSignature === 'authenticode') && !(a.platform === 'win32' && a.systemSignature === 'developer-id-notarized'), 'Invalid system signature classification');
    check(a.url === `${BASE}/${p.releaseId}/${a.filename}` && SHA.test(a.sha256) && Number.isSafeInteger(a.size) && a.size > 0, 'Invalid immutable artifact');
  }
  return p;
}
export const isMain = url => process.argv[1] && url === pathToFileURL(resolve(process.argv[1])).href;
export async function cli(main) {
  try { await main(); } catch (error) {
    // HTTPS/OpenSSL errors can carry paths/headers or credential-bearing text.
    // Emit only our bounded, single-line diagnostics; never dump an error object.
    const message = String(error.message ?? 'Operation failed').split(/[\r\n]/)[0].slice(0, 280);
    console.error(`OSIR: ${message.replace(/(Credential=|Authorization[=:]|secret_access_key["\s:=]+)\S+/gi, '$1[redacted]')}`);
    process.exitCode = 1;
  }
}
