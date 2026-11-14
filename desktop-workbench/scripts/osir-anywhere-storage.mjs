// Native HTTPS + SigV4, deliberately independent of the Client uploader.
// Only this module reads storage credentials; no child process receives them.
import { createHash, createHmac } from 'node:crypto';
import { request } from 'node:https';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, readFile, rename } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { BASE, PREFIX, check, digest, inspect, matches, privateFile, safe } from './osir-anywhere-release-common.mjs';

const ENDPOINT = 'https://cn-nb1.rains3.com';
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
// Only validated object paths and bounded response fields enter diagnostics.
// Never include query strings, credentials, request headers, or response bodies.
function responseError(message, method, url, res) {
  let path = '[invalid-object-path]';
  try {
    const parts = new URL(url).pathname.replace(/^\/osirvedio\//, '/').split('/').slice(1);
    if (parts[0] === 'osir-anywhere' && parts[1] === 'releases' &&
      ((parts.length === 3 && parts[2] === 'stable.json') ||
        (parts.length === 4 && parts.slice(2).every(p => /^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$/.test(p) && !p.includes('..')))))
      path = `/${parts.join('/')}`;
  } catch { /* Unknown context is never copied into the message. */ }
  if (path.length > 120) path = `${path.slice(0, 57)}...${path.slice(-60)}`;
  const status = Number.isInteger(res?.statusCode) ? res.statusCode : 'unknown';
  const length = res?.headers['content-length'];
  const encoding = res?.headers['content-encoding'];
  const fields = `status=${status} length=${/^\d{1,20}$/.test(length ?? '') ? length : 'missing-or-invalid'} encoding=${encoding === undefined ? 'none' : /^(gzip|br|deflate|identity|compress|x-gzip)$/.test(encoding) ? encoding : 'present'}`;
  return new Error(`${method} ${path} ${fields}: ${message}`);
}
const hmac = (key, text, encoding) => createHmac('sha256', key).update(text).digest(encoding);
export function sigv4(method, url, headers, payloadSha256, credentials, now = new Date()) {
  const date = now.toISOString().replace(/[:-]|\.\d{3}/g, ''), day = date.slice(0, 8);
  const signed = { ...headers, host: url.host, 'x-amz-date': date, 'x-amz-content-sha256': payloadSha256 };
  const names = Object.keys(signed).sort();
  const scope = `${day}/cn-nb1/s3/aws4_request`;
  const canonical = [method, url.pathname, '', names.map(k => `${k}:${String(signed[k]).trim().replace(/\s+/g, ' ')}\n`).join(''), names.join(';'), payloadSha256].join('\n');
  const signingKey = hmac(hmac(hmac(hmac(`AWS4${credentials.secret_access_key}`, day), 'cn-nb1'), 's3'), 'aws4_request');
  const signature = hmac(signingKey, `AWS4-HMAC-SHA256\n${date}\n${scope}\n${digest(canonical)}`, 'hex');
  return { ...signed, authorization: `AWS4-HMAC-SHA256 Credential=${credentials.access_key_id}/${scope}, SignedHeaders=${names.join(';')}, Signature=${signature}` };
}
export async function storageConfig(path = join(homedir(), '.config/osir-client-release/rains3.json')) {
  let config;
  try { config = JSON.parse(await privateFile(path)); }
  catch { throw new Error('Storage configuration must be a valid private owner-only JSON file'); }
  const expected = { endpoint: ENDPOINT, bucket: 'osirvedio', region: 'cn-nb1', prefix: 'osir-client/releases', public_base: 'https://osirvedio.cn-nb1.rains3.com/osir-client/releases' };
  check(Object.entries(expected).every(([k, v]) => config[k] === v), 'Storage file differs from approved shared bucket configuration');
  check(['access_key_id', 'secret_access_key'].every(k => typeof config[k] === 'string' && config[k].trim()), 'Missing storage credentials');
  // Do not mutate or propagate config.prefix/public_base. Fixed Anywhere-only
  // paths are constructed below after validating the original Client config.
  return { access_key_id: config.access_key_id, secret_access_key: config.secret_access_key };
}
function open(url, { method = 'GET', headers = {}, body, path, totalMs = 45 * 60_000 } = {}) {
  return new Promise((resolve, reject) => {
    const req = request(url, { method, headers }, res => {
      res.on('close', () => { clearTimeout(total); source?.destroy(); });
      resolve(res);
    });
    let source;
    const total = setTimeout(() => req.destroy(new Error('Object request total timeout')), totalMs);
    req.setTimeout(90_000, () => req.destroy(new Error('Object request stalled')));
    req.on('error', () => { clearTimeout(total); source?.destroy(); reject(responseError('Object HTTPS transport failed or timed out; remote state may require reconciliation', method, url)); });
    if (path) { source = createReadStream(path); source.on('error', error => req.destroy(error)); source.pipe(req); }
    else req.end(body);
  });
}
async function small(res, max = 512 * 1024) {
  const chunks = []; let size = 0;
  for await (const chunk of res) {
    size += chunk.length;
    if (size > max) { res.destroy(); throw new Error('Metadata exceeds size limit'); }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
export async function consumePublic(res, expected, destination, url) {
  if (!(res.statusCode === 200 && !res.headers['content-encoding'] && Number(res.headers['content-length']) === expected.size))
    throw responseError('Object readback must be direct uncompressed HTTPS 200 of exact size', 'GET', url, res);
  const hash = createHash('sha256'); let size = 0;
  const meter = new Transform({ transform(chunk, _encoding, callback) {
    size += chunk.length;
    if (size > expected.size) return callback(responseError('Object exceeds expected size', 'GET', url, res));
    hash.update(chunk); callback(null, chunk);
  } });
  if (destination) {
    await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
    // Keep partial attempts for diagnosis; a retry always creates a fresh file.
    const partial = `${destination}.${process.pid}.${Date.now()}.partial`;
    await pipeline(res, meter, createWriteStream(partial, { flags: 'wx', mode: 0o600 }));
    if (!(size === expected.size && hash.digest('hex') === expected.sha256)) throw responseError('Public object SHA-256 mismatch', 'GET', url, res);
    await rename(partial, destination);
  } else {
    meter.resume(); await pipeline(res, meter);
    if (!(size === expected.size && hash.digest('hex') === expected.sha256)) throw responseError('Public object SHA-256 mismatch', 'GET', url, res);
  }
  return { size, sha256: expected.sha256 };
}
export class RainStorage {
  constructor(credentials, { smallRequestIntervalMs = Number(process.env.OSIR_ANYWHERE_STORAGE_INTERVAL_MS ?? 600), smallObjectMaxBytes = 1024 * 1024 } = {}) {
    check(Number.isSafeInteger(smallRequestIntervalMs) && smallRequestIntervalMs >= 0 && smallRequestIntervalMs <= 60_000, 'Invalid small-object request interval');
    check(Number.isSafeInteger(smallObjectMaxBytes) && smallObjectMaxBytes >= 0 && smallObjectMaxBytes <= 5 * 1024 ** 3, 'Invalid small-object threshold');
    this.credentials = credentials;
    this.smallRequestIntervalMs = smallRequestIntervalMs;
    this.smallObjectMaxBytes = smallObjectMaxBytes;
    this.nextSmallRequestAt = 0;
  }
  async pace(smallObject) {
    if (!smallObject || !this.smallRequestIntervalMs) return;
    const now = Date.now(), at = Math.max(now, this.nextSmallRequestAt);
    this.nextSmallRequestAt = at + this.smallRequestIntervalMs;
    if (at > now) await delay(at - now);
  }
  // At most two retries, only for reads with explicit delta-seconds 0..60.
  // Other statuses, missing/invalid/long Retry-After and transport errors fail closed.
  async read(url, options, smallObject, key) {
    const method = options.method ?? 'GET';
    check(['GET', 'HEAD'].includes(method), 'Only GET/HEAD may use read retry');
    for (let attempt = 0; ; attempt++) {
      await this.pace(smallObject);
      // Refresh SigV4 after pacing/backoff; do not reuse an aged signature.
      const headers = key === undefined ? options.headers : this.signed(method, key, options.headers).headers;
      const res = await open(url, { ...options, headers });
      const seconds = res.headers['retry-after'];
      if (!(res.statusCode === 503 && attempt < 2 && typeof seconds === 'string' && /^(0|[1-9]\d{0,2})$/.test(seconds) && Number(seconds) <= 60)) return res;
      res.destroy(); // Release the rejected response and its timeout before waiting.
      await delay(Number(seconds) * 1000);
    }
  }
  url(key) {
    check(key === 'stable.json' || (key.split('/').length === 2 && key.split('/').every(p => safe(p))), 'Invalid Anywhere object key');
    return new URL(`${ENDPOINT}/osirvedio/${PREFIX}/${key}`);
  }
  signed(method, key, headers = {}, content = digest('')) {
    const url = this.url(key);
    return { url, headers: sigv4(method, url, headers, content, this.credentials) };
  }
  async current() {
    const res = await this.read(this.url('stable.json'), { headers: { 'cache-control': 'no-cache' }, totalMs: 120_000 }, true, 'stable.json');
    const body = await small(res);
    if (res.statusCode === 404) return { body: null, etag: null };
    if (!(res.statusCode === 200 && typeof res.headers.etag === 'string')) throw responseError('Authoritative current read failed', 'GET', this.url('stable.json'), res);
    return { body, etag: res.headers.etag };
  }
  async immutable(key, path, expected) {
    check(key !== 'stable.json', 'Current cannot be written as immutable artifact');
    await matches(path, expected);
    check(expected.size <= 5 * 1024 ** 3, 'Artifact exceeds immutable single PUT limit');
    const existing = await this.read(this.url(key), { method: 'HEAD' }, true, key); existing.resume();
    if (existing.statusCode === 200) {
      if (Number(existing.headers['content-length']) !== expected.size) throw responseError('Immutable object collision', 'HEAD', this.url(key), existing);
      return; // Caller always performs a fresh full PUBLIC readback.
    }
    if (existing.statusCode !== 404) throw responseError('Object existence check failed', 'HEAD', this.url(key), existing);
    const metadata = { 'content-length': String(expected.size), 'content-type': key.endsWith('.json') ? 'application/json' : 'application/octet-stream',
      'if-none-match': '*', 'cache-control': 'public, max-age=31536000, immutable',
      'content-disposition': `attachment; filename="${safe(key.split('/')[1])}"`, 'x-amz-meta-sha256': expected.sha256 };
    await this.pace(expected.size <= this.smallObjectMaxBytes);
    const { url, headers } = this.signed('PUT', key, metadata, expected.sha256);
    const res = await open(url, { method: 'PUT', headers, path }); await small(res);
    if (![200, 201, 412].includes(res.statusCode)) throw responseError('Immutable PUT failed; inspect remote state before retry', 'PUT', url, res);
    await matches(path, expected);
  }
  async public(url, expected, destination) {
    check(url.startsWith(`${BASE}/`) && new URL(url).origin === new URL(BASE).origin && !new URL(url).search && !new URL(url).hash, 'Public URL escaped Anywhere storage');
    const res = await this.read(url, { headers: { 'accept-encoding': 'identity', 'cache-control': 'no-cache' } }, expected.size <= this.smallObjectMaxBytes);
    try { return await consumePublic(res, expected, destination, url); }
    finally { res.destroy(); }
  }
  async cas(body, etag) {
    const condition = etag === null ? { 'if-none-match': '*' } : { 'if-match': etag };
    await this.pace(true);
    const { url, headers } = this.signed('PUT', 'stable.json', { ...condition, 'content-length': String(body.length), 'content-type': 'application/json', 'cache-control': 'no-store, max-age=0' }, digest(body));
    const res = await open(url, { method: 'PUT', headers, body, totalMs: 120_000 }); await small(res);
    if (![200, 201].includes(res.statusCode)) throw responseError('Current conditional PUT rejected; no unconditional fallback', 'PUT', url, res);
  }
}
