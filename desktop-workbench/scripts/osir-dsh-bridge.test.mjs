import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { spawnSync } from 'node:child_process';
import { outputsFingerprint } from './osir-anywhere-build.mjs';
import { auditLoaders, buildHostPackage, ustarGzip, verifyResources } from './osir-dsh-bridge.mjs';

const desktop = resolve(fileURLToPath(new URL('..', import.meta.url)));
const repository = resolve(desktop, '..');
const peers = process.env.OSIR_DSH_TEST_NODE_MODULES;
const tarName = 'osir-dsh-bridge.tgz';

function unpack(bytes) {
  const raw = gunzipSync(bytes), files = new Map();
  for (let offset = 0; raw[offset];) {
    const head = raw.subarray(offset, offset + 512);
    const text = (a, b) => head.subarray(a, b).toString('ascii').split('\0')[0];
    assert.equal(text(257, 263), 'ustar'); assert.equal(text(263, 265), '00');
    assert.equal(text(156, 157), '0', 'only regular files');
    assert.equal(text(157, 257), '', 'no links'); assert.equal(text(345, 500), '', 'no long path prefix');
    const name = text(0, 100);
    assert.ok(/^package\/[\w./-]+$/.test(name) && !name.split('/').includes('..'));
    assert.ok(!files.has(name));
    const sum = [...head].reduce((s, b, i) => s + (i >= 148 && i < 156 ? 32 : b), 0);
    assert.equal(parseInt(text(148, 156).trim(), 8), sum);
    const size = parseInt(text(124, 136), 8);
    files.set(name, raw.subarray(offset + 512, offset + 512 + size));
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return files;
}

function candidate(t) {
  mkdirSync(join(desktop, 'dist'), { recursive: true });
  const out = mkdtempSync(join(desktop, 'dist/osir-dsh-test-'));
  t.after(() => rmSync(out, { recursive: true, force: true }));
  const info = buildHostPackage(out);
  return { out, info, bytes: readFileSync(join(out, tarName)) };
}

test('reproducible USTAR contains only host closure and the fixed consumer contract', t => {
  const a = candidate(t), b = candidate(t);
  assert.deepEqual(a.bytes, b.bytes);
  const files = unpack(a.bytes);
  const pkg = JSON.parse(files.get('package/package.json'));
  assert.equal(pkg.name, '@osir/anywhere-dsh-bridge'); assert.equal(pkg.version, '2.2.1');
  assert.equal(pkg.main, './lib/index.js'); assert.equal(pkg.exports['.'], pkg.main);
  assert.equal(pkg.private, true); assert.equal(pkg.scripts, undefined); assert.equal(pkg.dsh.client, undefined);
  assert.deepEqual(pkg.dependencies, { meshcall: '0.3.0' });
  assert.equal(files.get('package/cordis.patch.yml').toString(), "- insert:\n    - id: osir-anywhere-dsh-bridge\n      name: '@osir/anywhere-dsh-bridge'\n      config: {}\n");
  for (const path of files.keys()) assert.ok(!/node_modules|account\/|onboarding\/|rpc\/|client\/|config\.ts|\.map$|\.env|\.npmrc/.test(path), path);
  const runtime = files.get('package/lib/host/dsh-runtime/index.js').toString();
  assert.ok(runtime.includes('../osir-config.js')); assert.ok(!runtime.includes("'../config.js'"));
  const config = files.get('package/lib/host/osir-config.js').toString();
  assert.ok(!config.includes("from 'node:os'")); assert.ok(!config.includes('.agents-anywhere'));
  const service = files.get('package/lib/host/dsh-runtime/bridge-service.js').toString();
  assert.ok(service.includes('@osir/anywhere-dsh-bridge/package.json'));
  assert.ok(!service.includes('@agents-anywhere/dsh-bridge-next/package.json'));
  const receipt = JSON.parse(readFileSync(join(a.out, 'osir-build-receipt.json')));
  assert.equal(receipt.compiler.name, 'typescript'); assert.equal(receipt.resource.sha256, a.info.sha256);
  for (const input of receipt.inputs) assert.ok(existsSync(join(repository, input.path)));
  const desktopPackage = JSON.parse(readFileSync(join(desktop, 'package.json')));
  assert.ok(desktopPackage.scripts.build.endsWith('yarn bundle:dsh-bridge'));
  assert.deepEqual(desktopPackage.build.extraResources.find(r => r.to === 'dsh-bridge'), {
    from: 'dist/dsh-bridge', to: 'dsh-bridge', filter: [tarName, 'package-info.json'],
  });
});

test('resource verification rejects original package byte tampering', t => {
  const a = candidate(t);
  assert.equal(verifyResources(a.out).sha256, a.info.sha256);
  writeFileSync(join(a.out, tarName), Buffer.concat([a.bytes, Buffer.from('changed')]));
  assert.throws(() => verifyResources(a.out), /metadata\/hash mismatch/);
});

test('release outputsFingerprint binds both shipped resource bytes', async t => {
  const a = candidate(t);
  const root = mkdtempSync(join(tmpdir(), 'osir-dsh-fingerprint-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const path of ['dist/dsh-bridge', 'renderer/out', 'build/uv', 'build/python']) {
    mkdirSync(join(root, path), { recursive: true });
  }
  const resource = join(root, 'dist/dsh-bridge');
  writeFileSync(join(resource, tarName), a.bytes);
  const metadata = readFileSync(join(a.out, 'package-info.json'));
  writeFileSync(join(resource, 'package-info.json'), metadata);
  const original = await outputsFingerprint(root);
  writeFileSync(join(resource, tarName), Buffer.concat([a.bytes, Buffer.from('tampered')]));
  assert.notEqual(await outputsFingerprint(root), original);
  writeFileSync(join(resource, tarName), a.bytes);
  assert.equal(await outputsFingerprint(root), original);
  writeFileSync(join(resource, 'package-info.json'), Buffer.concat([metadata, Buffer.from(' ')]));
  assert.notEqual(await outputsFingerprint(root), original);
});

test('unreviewed dynamic imports, loaders and non-short tar paths fail closed', () => {
  for (const source of ["import('./hidden.js')", 'const load = require; load(variable)',
    "import { createRequire } from 'node:module'; createRequire(import.meta.url)(variable)",
    'new URL("./asset.json", import.meta.url)', 'module.require(variable)', 'eval(code)']) {
    assert.throws(() => auditLoaders(source, 'host/dsh-runtime/test.ts'));
  }
  assert.throws(() => ustarGzip(new Map([['package/' + 'x'.repeat(100), 'x']])), /short path/);
  assert.throws(() => ustarGzip(new Map([['package/../escape', 'x']])), /short path/);
});

test('packed entry imports real DSH peers, reports self 2.2.1, blocks duplicate ID/service and uses explicit root',
  { skip: !peers && 'Set OSIR_DSH_TEST_NODE_MODULES to an existing disposable DSH dependency environment', timeout: 30000 }, t => {
  const a = candidate(t);
  const scratch = mkdtempSync(join(tmpdir(), 'osir-dsh-import-'));
  t.after(() => rmSync(scratch, { recursive: true, force: true }));
  for (const [name, bytes] of unpack(a.bytes)) {
    const target = join(scratch, name); mkdirSync(dirname(target), { recursive: true }); writeFileSync(target, bytes);
  }
  symlinkSync(resolve(peers), join(scratch, 'node_modules'), process.platform === 'win32' ? 'junction' : 'dir');
  const script = `
    import assert from 'node:assert/strict';
    import { readFileSync, existsSync } from 'node:fs';
    import { join } from 'node:path';
    import { createRequire } from 'node:module';
    import * as host from './package/lib/index.js';
    import { bridgeDirectory, legacyBridgeDirectory } from './package/lib/host/osir-config.js';
    import { BridgeService } from './package/lib/host/dsh-runtime/bridge-service.js';
    import { BridgeConnection } from './package/lib/host/dsh-runtime/connection.js';
    import { Context } from '@deepseek-ai/cordis';
    import * as IncludeModule from '@deepseek-ai/cordis-plugin-include';
    import * as LoaderModule from '@deepseek-ai/cordis-plugin-loader';
    import { load } from 'js-yaml';
    const Include = IncludeModule.default ?? IncludeModule;
    const Loader = LoaderModule.default ?? LoaderModule;
    const require = createRequire(import.meta.url);
    assert.equal(require('./package/package.json').version, '2.2.1');
    assert.equal(host.name, 'osir-anywhere-dsh-bridge');
    for (const config of [{}, {osirConnectorDataDir:''}, {osirConnectorDataDir:'relative'}, {osirConnectorDataDir:'a\\0b'}]) {
      assert.throws(() => host.apply(new Context(), config), /OSIR_DSH_ROOT_REQUIRED/);
    }
    assert.throws(() => host.Config({}), /required/i);
    const root = join(process.cwd(), 'synthetic-connector');
    const config = {osirConnectorDataDir:root};
    assert.equal(bridgeDirectory(config), join(root, 'dsh-bridge'));
    assert.equal(legacyBridgeDirectory(config), undefined);
    for (const name of ['agentsAnywhereRuntime','agentsAnywhereOnboarding']) {
      const ctx = new Context();
      ctx.provide(name, {});
      assert.throws(() => host.apply(ctx, config), /OSIR_DSH_BRIDGE_CONFLICT/);
      await ctx.fiber.dispose();
    }
    const ctx = new Context();
    host.apply(ctx, config); // Waiting for native session dependencies; no account/launcher starts.
    assert.throws(() => host.apply(ctx, config), /OSIR_DSH_BRIDGE_CONFLICT/);
    assert.equal(ctx.get('agentsAnywhereOnboarding', false), undefined);
    await ctx.fiber.dispose();
    const backend = { reader:{query:{},status:()=>undefined}, transportFor:()=>{throw Error('unused')} };
    const bridge = new BridgeService(backend);
    const handshake = await bridge.initialize({protocolVersion:'2.0',runtime:'dsh'});
    assert.equal(handshake.identity.bridgeVersion, '2.2.1');
    assert.equal(handshake.identity.runtimeVersion, '0.2.1-rc.2');
    bridge.close();
    // Original cross-process manager lease remains active in the packaged runtime.
    const reader = { query:{listSessions:async()=>[],readSession:async()=>{throw Error('unused')},readTitleSnapshots:async()=>[]}, status:()=>undefined };
    const path = join(root, 'dsh-bridge', 'connector.json');
    const first = new BridgeConnection(path, reader, undefined, 20);
    const second = new BridgeConnection(path, reader, undefined, 20);
    try {
      await first.start();
      await assert.rejects(second.start(), e=>e.code==='MANAGER_LOCK_HELD');
    } finally { await first.close(); await second.close(); }
    // Official Loader/Include consumes the single insert and keeps one fixed plugin ID.
    const loaded = new Context();
    try {
      await loaded.plugin(Loader).await();
      const patches = load(readFileSync('./package/cordis.patch.yml','utf8'));
      assert.equal(patches[0].insert[0].id, host.name);
      // Resolve local tar package exactly as the official plugin installation would.
      patches[0].insert[0].name = new URL('./package/lib/index.js', import.meta.url).href;
      await loaded.plugin(Include, {path:new URL('./fixture.cordis.yml',import.meta.url).href,initial:[],patches:[
        ...patches,{id:host.name,config}
      ]}).await();
      await loaded.loader.await();
      assert.equal(loaded.get('agentsAnywhereOnboarding',false), undefined);
    } finally { await loaded.fiber.dispose(); }
    console.log('real-import/self-version/duplicate-service/manager-lock/official-loader: passed');
  `;
  writeFileSync(join(scratch, 'smoke.mjs'), script);
  const result = spawnSync(process.execPath, ['smoke.mjs'], { cwd: scratch, encoding: 'utf8', timeout: 20000,
    env: Object.fromEntries(['PATH','SystemRoot','SYSTEMROOT','TMPDIR','TEMP','TMP'].filter(k=>process.env[k]).map(k=>[k,process.env[k]])) });
  assert.equal(result.status, 0, result.stderr + result.stdout + (result.error?.message ?? ''));
  assert.match(result.stdout, /official-loader: passed/);
});
