import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Inspector, packagedSmokeWindowState, waitForSmokeWindow } from './osir-native-smoke.mjs';

test('smoke startup records exact bootstrap phases without swallowing packaged exceptions', () => {
  const source = `(${packagedSmokeWindowState.toString()})()`;
  assert.equal(vm.runInNewContext(source, {}).reason, 'node-process-not-ready');
  let ready = false, failure = Object.assign(new Error("Cannot find module 'electron'\nRequire stack: synthetic"), { code: 'MODULE_NOT_FOUND' });
  const electron = { app: { isReady: () => ready, getName: () => 'OSIR Anywhere', getVersion: () => '2.2.1', isPackaged: true, getPath: () => '/synthetic' }, BrowserWindow: { getAllWindows: () => [] } };
  const process = { versions: { electron: '39.8.10' }, resourcesPath: '/synthetic', getBuiltinModule: () => ({ createRequire: () => () => { if (failure) throw failure; return electron; } }) };
  const evaluate = () => vm.runInNewContext(source, { process });
  assert.equal(evaluate().reason, 'electron-browser-not-ready'); process.type = 'browser';
  assert.equal(evaluate().reason, 'electron-module-not-ready');
  failure = Object.assign(new Error("Cannot find module 'other-dependency'"), { code: 'MODULE_NOT_FOUND' }); assert.throws(evaluate, /other-dependency/);
  failure = new Error('Unexpected packaged failure'); assert.throws(evaluate, /Unexpected packaged failure/);
  failure = null; assert.equal(evaluate().reason, 'electron-app-not-ready');
  ready = true; assert.equal(evaluate().ready, true); assert.equal(evaluate().state.version, '2.2.1');
});

test('smoke inspector reads synchronous startup without awaiting a V8 promise and still awaits renderer work', async () => {
  const socket = new EventTarget(); socket.requests = []; socket.readyState = 1;
  socket.send = raw => socket.requests.push(JSON.parse(raw)); socket.close = () => { socket.readyState = 3; };
  const inspector = new Inspector(socket), reply = value => socket.dispatchEvent(new MessageEvent('message', { data: JSON.stringify(value) }));
  try {
    const sync = inspector.evaluate('(packagedSmokeWindowState)()', { awaitPromise: false });
    assert.equal(socket.requests[0].params.awaitPromise, false); assert.equal(socket.requests[0].params.returnByValue, true);
    reply({ id: 1, result: { result: { value: { ready: false, reason: 'node-process-not-ready' } } } }); assert.equal((await sync).ready, false);
    const asyncProbe = inspector.evaluate('Promise.resolve(true)'); assert.equal(socket.requests[1].params.awaitPromise, true);
    reply({ id: 2, result: { result: { value: true } } }); assert.equal(await asyncProbe, true);
    const failed = assert.rejects(inspector.evaluate('unexpected'), /inspector expression failed/);
    reply({ id: 3, result: { exceptionDetails: { exception: { description: 'unexpected' } } } }); await failed;
    await assert.rejects(inspector.evaluate('ignored', { awaitPromise: 'false' }), /must be boolean/); assert.equal(socket.requests.length, 3);
  } finally { inspector.close(); }
});

test('smoke startup retains observations and requires the real loaded window with unchanged identity gates', async () => {
  const root = join(tmpdir(), 'synthetic-smoke-startup'), resources = join(root, 'resources');
  const context = { version: '2.2.1', nativeMachine: `${process.platform}-${process.arch}`, resources, accountHome: root, allowedDataRoots: [root], pid: 42 };
  const window = { id: 7, visible: true, destroyed: false, loading: false, width: 900, height: 600, url: 'osir-anywhere-workbench://web/', rendererPid: 43 };
  const state = { pid: 42, packaged: true, electron: '39.8.10', name: 'OSIR Anywhere', version: '2.2.1', platform: process.platform, arch: process.arch, resources, home: root, userData: join(root, 'data'), windows: [window] };
  const observations = [{ ready: false, reason: 'electron-module-not-ready' }, { ready: true, state: { ...state, windows: [{ ...window, loading: true }] } }, { ready: true, state }];
  let count = 0, recorded;
  const result = await waitForSmokeWindow({ evaluate: async (_source, options) => { assert.deepEqual(options, { awaitPromise: false }); return observations[count++]; } }, context, Date.now() + 2500, value => { recorded = value; });
  assert.deepEqual(result, { state, window }); assert.deepEqual(recorded, observations);
  const unexpected = new Error('Unexpected packaged exception'); let failed;
  await assert.rejects(waitForSmokeWindow({ evaluate: async () => { throw unexpected; } }, context, Date.now() + 1000, value => { failed = value; }), error => error === unexpected); assert.deepEqual(failed, []);
  await assert.rejects(waitForSmokeWindow({ evaluate: async () => ({ ready: false, reason: 'unknown' }) }, context, Date.now() + 1000), /Invalid packaged startup/);
  await assert.rejects(waitForSmokeWindow({ evaluate: async () => ({ ready: true, state: { ...state, version: 'wrong' } }) }, context, Date.now() + 20), /identity\/version/);
  await assert.rejects(waitForSmokeWindow({ evaluate: async () => ({ ready: false, reason: 'electron-app-not-ready' }) }, context, Date.now() + 20), /readiness timed out/);
});
