import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { BASE, PREFIX, digest } from './osir-anywhere-release-common.mjs';
import { RainStorage, consumePublic, sigv4, storageConfig } from './osir-anywhere-storage.mjs';

function response(body, headers = {}, statusCode = 200) {
  const stream = Readable.from([body]); stream.headers = { 'content-length': String(body.length), ...headers }; stream.statusCode = statusCode; return stream;
}
test('streaming readback verifies every byte and independently writes backup; redirect/encoding/truncation rejected', async t => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'anywhere-storage-test-'))); t.after(() => rm(root, { recursive: true, force: true }));
  const body = Buffer.from('public artifact bytes'), expected = { size: body.length, sha256: digest(body) };
  await consumePublic(response(body), expected);
  const dest = join(root, 'backup.bin'); await consumePublic(response(body), expected, dest); assert.deepEqual(await readFile(dest), body);
  await assert.rejects(consumePublic(response(body, {}, 302), expected), /direct/);
  await assert.rejects(consumePublic(response(body, { 'content-encoding': 'gzip' }), expected), /uncompressed/);
  await assert.rejects(consumePublic(response(body, { 'content-length': '200' }), expected), /size/);
  await assert.rejects(consumePublic(response(Buffer.from('bad'), { 'content-length': String(body.length) }), expected), /SHA-256/);
  await assert.rejects(consumePublic(response(body), { ...expected, sha256: 'a'.repeat(64) }), /SHA-256/);
});
test('storage adapter derives only Anywhere namespace; no Client prefix mutation, direct fixed key URL', async t => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'anywhere-config-test-'))); t.after(() => rm(root, { recursive: true, force: true }));
  const config = { endpoint: 'https://cn-nb1.rains3.com', bucket: 'osirvedio', region: 'cn-nb1', prefix: 'osir-client/releases',
    public_base: 'https://osirvedio.cn-nb1.rains3.com/osir-client/releases', access_key_id: 'synthetic-access', secret_access_key: 'synthetic-secret' };
  const path = join(root, 'storage.json'), original = JSON.stringify(config); await writeFile(path, original, { mode: 0o600 });
  const credentials = await storageConfig(path); assert.deepEqual(Object.keys(credentials).sort(), ['access_key_id', 'secret_access_key']);
  assert.equal(await readFile(path, 'utf8'), original);
  const storage = new RainStorage(credentials);
  assert.equal(storage.url('release-a/file.dmg').href, `https://cn-nb1.rains3.com/osirvedio/${PREFIX}/release-a/file.dmg`);
  assert.throws(() => storage.url('../osir-client/file.exe'), /Invalid/);
  await assert.rejects(storage.immutable('stable.json', 'unused', {}), /Current cannot/);
  await assert.rejects(storage.public('https://osirclaw.com/bytes', {}), /escaped/);
  await assert.rejects(storage.public(`${BASE}/r/a?access=secret`, {}), /escaped/);
  config.prefix = PREFIX; await writeFile(path, JSON.stringify(config)); await assert.rejects(storageConfig(path), /approved/);
});
test('SigV4 binds conditional headers and full payload hash deterministically', () => {
  const credentials = { access_key_id: 'synthetic-access', secret_access_key: 'synthetic-secret' };
  const url = new URL('https://cn-nb1.rains3.com/osirvedio/osir-anywhere/releases/stable.json'), now = new Date('2026-11-14T02:03:04.000Z');
  const signed = sigv4('PUT', url, { 'if-match': '"etag"', 'content-length': '4' }, digest('body'), credentials, now);
  assert.equal(signed['x-amz-date'], '20261114T020304Z');
  assert.match(signed.authorization, /SignedHeaders=content-length;host;if-match;x-amz-content-sha256;x-amz-date/);
  assert.equal(signed['x-amz-content-sha256'], digest('body'));
  assert.notEqual(signed.authorization, sigv4('PUT', url, { 'if-match': '"other"', 'content-length': '4' }, digest('body'), credentials, now).authorization);
  assert.equal(signed.authorization.includes('synthetic-secret'), false);
});
