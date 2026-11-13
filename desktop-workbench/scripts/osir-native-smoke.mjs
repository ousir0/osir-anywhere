#!/usr/bin/env node
/**
 * Final-installer native smoke, NOT a complete release acceptance report.
 *
 * node scripts/osir-native-smoke.mjs --spec /absolute/smoke.json --output /new/evidence
 * Spec v1: buildReceiptPath, finalInstallerPath, systemSignatureReportPath;
 * expected: sourceSha256, configSha256, checkoutHead, upstreamGitHead, version,
 * target, artifactSha256, artifactSize, systemSignatureReportSha256;
 * runner: nativeMachine, isolationEvidencePath, isolationEvidenceSha256.
 * Optional dependencyCache: {path, sha256} (fingerprintTree below).
 *
 * Enter via osir-native-smoke-provision.mjs run --runner-mode
 * disposable-clean-runner on a disposable GitHub-hosted native GUI runner.
 * The helper checks the live OS user/GUI and creates process-bound provenance;
 * this mode explicitly does not claim offline execution or network isolation.
 * Optional strict-loopback re-probes real inherited isolation before execution.
 * Handwritten attestations and HOME overrides do not establish either mode.
 *
 * Dependencies must be available offline in a reviewed uv cache, prepared in a
 * separate dependency job. No system Python, developer venv, inherited secrets,
 * real login or SDK session is used. Unauthenticated public health/update reads
 * can occur in clean-runner mode. Missing dependencies
 * fail Connector smoke. Do not use this report to relax publisher gates.
 * Prepare cache separately with the exact bundled native uv/Python and copied
 * Connector: uv --no-config run --project COPY --python BUNDLED_PYTHON
 * --no-python-downloads anywhere-cli --help (UV_CACHE_DIR=NEW_CACHE). That
 * preparation may fetch public Python dependencies; native smoke never does.
 * Use provision helper warm-cache in the separate online job; pin the report
 * SHA-256 and transfer cache + report + resolved uv.lock evidence together.
 */
import { spawn } from 'node:child_process';
import { createReadStream } from 'node:fs';
import { cp, lstat, mkdir, open, readFile, readdir, realpath, readlink, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { homedir, hostname, userInfo } from 'node:os';
import { basename, isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { inspectSystemSignature } from './osir-anywhere-system-signature.mjs';

const SHA = /^[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;
const PRODUCT = 'OSIR Anywhere';
const APP_ID = 'com.osir.anywhere.desktop';
const TARGETS = ['darwin-universal', 'win32-x64', 'win32-arm64'];
const LIMIT = 2 * 1024 * 1024;
const check = (ok, message) => { if (!ok) throw new Error(message); };
const json = async path => JSON.parse(await readFile(path, 'utf8'));
const digest = value => createHash('sha256').update(value).digest('hex');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const within = (root, path) => resolve(path) === resolve(root) || resolve(path).startsWith(`${resolve(root)}${process.platform === 'win32' ? '\\' : '/'}`);

export async function fileIdentity(path, allowEmpty = false) {
  const before = await lstat(path);
  check(before.isFile() && !before.isSymbolicLink() && (allowEmpty || before.size > 0), 'Expected a nonempty regular file');
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  const after = await lstat(path);
  check(before.size === after.size && before.ino === after.ino && before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs, 'Evidence changed while hashing');
  return { size: after.size, sha256: hash.digest('hex') };
}

export async function fingerprintTree(root) {
  const entries = [];
  const base = await realpath(root);
  async function walk(path, name) {
    const stat = await lstat(path);
    if (stat.isSymbolicLink()) {
      check(within(base, await realpath(path)), 'Dependency cache symlink escapes its root');
      entries.push({ path: name, link: await readlink(path) });
    } else if (stat.isDirectory()) {
      for (const child of (await readdir(path)).sort()) await walk(join(path, child), name ? `${name}/${child}` : child);
    } else {
      check(stat.isFile(), 'Unsupported dependency cache entry');
      entries.push({ path: name, ...(await fileIdentity(path, true)) });
    }
  }
  check((await lstat(root)).isDirectory(), 'Dependency cache must be a directory');
  await walk(root, '');
  check(entries.length > 0, 'Dependency cache is empty');
  return digest(JSON.stringify(entries));
}

export function validateSpec(spec, { requireIsolation = true } = {}) {
  check(spec?.schemaVersion === 1, 'Unknown smoke spec schema');
  for (const key of ['buildReceiptPath', 'finalInstallerPath', 'systemSignatureReportPath']) check(typeof spec[key] === 'string' && isAbsolute(spec[key]), `Absolute ${key} required`);
  const e = spec.expected;
  check(e && Object.keys(e).sort().join(',') === ['sourceSha256', 'configSha256', 'checkoutHead', 'upstreamGitHead', 'version', 'target', 'artifactSha256', 'artifactSize', 'systemSignatureReportSha256'].sort().join(','), 'Unknown/missing expected provenance fields');
  check(e && TARGETS.includes(e.target) && /^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/.test(e.version), 'Invalid expected target/version');
  for (const key of ['sourceSha256', 'configSha256', 'artifactSha256', 'systemSignatureReportSha256']) check(SHA.test(e[key]), `Expected ${key} required`);
  for (const key of ['checkoutHead', 'upstreamGitHead']) check(COMMIT.test(e[key]), `Expected ${key} required`);
  check(Number.isSafeInteger(e.artifactSize) && e.artifactSize > 0, 'Expected installer size required');
  const r = spec.runner;
  check(r && ['darwin-arm64', 'darwin-x64', 'win32-x64', 'win32-arm64'].includes(r.nativeMachine), 'Native runner identity required');
  if (requireIsolation) check(isAbsolute(r.isolationEvidencePath ?? '') && SHA.test(r.isolationEvidenceSha256), 'Proven runner isolation evidence required');
  check(e.target === 'darwin-universal' ? r.nativeMachine.startsWith('darwin-') : r.nativeMachine === e.target, 'Native machine differs from installer target');
  if (spec.dependencyCache) {
    check(isAbsolute(spec.dependencyCache.path ?? '') && SHA.test(spec.dependencyCache.sha256), 'Reviewed offline dependency cache required');
    if (spec.dependencyCache.lockPath || spec.dependencyCache.lockSha256) check(isAbsolute(spec.dependencyCache.lockPath ?? '') && SHA.test(spec.dependencyCache.lockSha256), 'Pinned resolved dependency lock required');
  }
  return spec;
}

export async function bindInputs(spec) {
  validateSpec(spec, { requireIsolation: false });
  const receipt = await json(spec.buildReceiptPath), e = spec.expected, p = receipt.plan, a = receipt.artifact;
  check(receipt.schemaVersion === 1 && p && a, 'Invalid build receipt');
  for (const key of ['target', 'version', 'sourceSha256', 'configSha256', 'checkoutHead', 'upstreamGitHead']) check(p[key] === e[key], `Build receipt ${key} mismatch`);
  check(basename(spec.finalInstallerPath) === a.filename && a.filename.endsWith(e.target.startsWith('darwin') ? '.dmg' : '.exe'), 'Final installer filename/type mismatch');
  const artifact = await fileIdentity(spec.finalInstallerPath);
  check(artifact.sha256 === e.artifactSha256 && artifact.size === e.artifactSize && a.sha256 === artifact.sha256 && a.size === artifact.size, 'Final installer hash/size mismatch');
  const signature = await fileIdentity(spec.systemSignatureReportPath);
  check(signature.sha256 === e.systemSignatureReportSha256 && receipt.systemSignatureReportSha256 === signature.sha256, 'Signature report hash mismatch');
  const signed = await json(spec.systemSignatureReportPath);
  check(signed.artifactSha256 === artifact.sha256 && signed.systemSignature === a.systemSignature && signed.platform === e.target.split('-')[0], 'Signature report installer/platform mismatch');
  check((signed.platform === 'darwin' ? ['unsigned', 'developer-id-notarized'] : ['unsigned', 'authenticode']).includes(a.systemSignature), 'Unsupported system signature classification');
  return { receipt, artifact, signature, receiptIdentity: await fileIdentity(spec.buildReceiptPath) };
}

export function assertNativeMachine(expected, platform, nodeArch, hardwareArch, translated = false) {
  check(['darwin', 'win32'].includes(platform), 'Unsupported native smoke platform');
  check(['arm64', 'x64'].includes(hardwareArch) && expected === `${platform}-${hardwareArch}` && nodeArch === hardwareArch && !translated, 'Native hardware/Node architecture mismatch or translated job');
}

export function smokeEnvironment(source, accountHome, work, platform = process.platform) {
  const keys = platform === 'win32' ? ['SystemRoot', 'SYSTEMROOT', 'COMSPEC', 'PATHEXT', 'WINDIR'] : [];
  const systemRoot = source.SystemRoot || source.SYSTEMROOT || 'C:\\Windows';
  return {
    ...Object.fromEntries(keys.filter(k => source[k] !== undefined).map(k => [k, source[k]])),
    PATH: platform === 'win32' ? `${systemRoot}\\System32;${systemRoot};${systemRoot}\\System32\\WindowsPowerShell\\v1.0` : '/usr/bin:/bin:/usr/sbin:/sbin',
    HOME: accountHome, USERPROFILE: accountHome, USER: userInfo().username, LOGNAME: userInfo().username,
    APPDATA: join(work, 'appdata'), LOCALAPPDATA: join(work, 'localappdata'),
    XDG_CONFIG_HOME: join(work, 'config'), XDG_DATA_HOME: join(work, 'data'), XDG_CACHE_HOME: join(work, 'cache'),
    TMPDIR: join(work, 'tmp'), TMP: join(work, 'tmp'), TEMP: join(work, 'tmp'),
    CODEX_HOME: join(work, 'codex'), CLAUDE_CONFIG_DIR: join(work, 'claude'),
    ZDOTDIR: join(work, 'shell'), SHELL: '/bin/zsh',
    AGENT_CONNECTOR_DATA_DIR: join(work, 'connector-data'),
    UV_PROJECT_ENVIRONMENT: join(work, 'connector-venv'), UV_CACHE_DIR: join(work, 'uv-cache'),
    UV_OFFLINE: '1', UV_PYTHON_DOWNLOADS: 'never', UV_NO_CONFIG: '1',
    PYTHONNOUSERSITE: '1', PYTHONDONTWRITEBYTECODE: '1', PYTHONUNBUFFERED: '1',
    LANG: 'en_US.UTF-8', LC_ALL: 'en_US.UTF-8', CI: '1',
  };
}

/** Read only bounded metadata from ASAR; never execute its JS to inspect it. */
export async function asarJson(archive, name) {
  check(name.split('/').every(p => p && p !== '.' && p !== '..'), 'Unsafe ASAR metadata path');
  const handle = await open(archive, 'r');
  try {
    const prefix = Buffer.alloc(16);
    check((await handle.read(prefix, 0, 16, 0)).bytesRead === 16, 'Truncated ASAR header');
    const headerSize = prefix.readUInt32LE(4), jsonSize = prefix.readUInt32LE(12);
    check(headerSize >= 8 && headerSize < 32 * 1024 * 1024 && jsonSize > 0 && jsonSize <= headerSize - 8, 'Invalid ASAR header size');
    const data = Buffer.alloc(jsonSize);
    check((await handle.read(data, 0, data.length, 16)).bytesRead === data.length, 'Truncated ASAR index');
    let entry = JSON.parse(data).files;
    for (const [i, part] of name.split('/').entries()) {
      entry = entry?.[part];
      check(entry && !entry.link && !entry.unpacked, 'Missing or indirect ASAR metadata');
      if (i < name.split('/').length - 1) entry = entry.files;
    }
    const offset = Number(entry.offset);
    check(Number.isSafeInteger(offset) && offset >= 0 && Number.isSafeInteger(entry.size) && entry.size > 0 && entry.size <= LIMIT, 'Invalid ASAR metadata range');
    const bytes = Buffer.alloc(entry.size);
    check((await handle.read(bytes, 0, bytes.length, 8 + headerSize + offset)).bytesRead === bytes.length, 'Truncated ASAR metadata');
    return JSON.parse(bytes);
  } finally { await handle.close(); }
}

export function binaryArchitectures(bytes) {
  check(bytes.length >= 64, 'Truncated executable');
  const cpu = code => ({ 0x01000007: 'x64', 0x0100000c: 'arm64', 0x8664: 'x64', 0xaa64: 'arm64' })[code];
  if (bytes.readUInt16LE(0) === 0x5a4d) {
    const offset = bytes.readUInt32LE(60);
    check(offset >= 64 && offset + 6 <= bytes.length && bytes.readUInt32LE(offset) === 0x4550, 'Invalid PE executable');
    const arch = cpu(bytes.readUInt16LE(offset + 4));
    check(arch, 'Unsupported PE architecture'); return [arch];
  }
  if (bytes.readUInt32LE(0) === 0xfeedfacf) {
    const arch = cpu(bytes.readUInt32LE(4)); check(arch, 'Unsupported Mach-O architecture'); return [arch];
  }
  const magic = bytes.readUInt32BE(0), fat64 = magic === 0xcafebabf;
  check(magic === 0xcafebabe || fat64, 'Unsupported native executable');
  const count = bytes.readUInt32BE(4), stride = fat64 ? 32 : 20;
  check(count > 0 && count <= 16 && 8 + count * stride <= bytes.length, 'Invalid fat Mach-O architecture table');
  const arches = Array.from({ length: count }, (_, i) => cpu(bytes.readUInt32BE(8 + i * stride)));
  check(arches.every(Boolean) && new Set(arches).size === count, 'Unsupported/duplicate Mach-O slices');
  return arches.sort();
}

async function executableArches(path) {
  const handle = await open(path, 'r');
  try { const bytes = Buffer.alloc(65536); const r = await handle.read(bytes, 0, bytes.length, 0); return binaryArchitectures(bytes.subarray(0, r.bytesRead)); }
  finally { await handle.close(); }
}

/** No shell interpolation. Every subprocess has a bounded lifetime/output. */
export async function command(executable, args, { env, cwd, timeout = 60000, input } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { env, cwd, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], detached: process.platform !== 'win32' });
    let stdout = '', stderr = '', failure, cleanup;
    const abort = message => {
      if (failure) return;
      failure = new Error(message);
      cleanup = stopOwned(child).catch(() => { child.kill('SIGKILL'); });
    };
    const timer = setTimeout(() => abort('Native command timed out'), timeout);
    child.on('error', error => { clearTimeout(timer); reject(error); });
    for (const [name, stream] of [['stdout', child.stdout], ['stderr', child.stderr]]) stream.on('data', chunk => {
      if (failure) return;
      if (name === 'stdout') stdout += chunk; else stderr += chunk;
      if (Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > LIMIT) abort('Native command output exceeded limit');
    });
    child.on('close', async (code, signal) => {
      clearTimeout(timer);
      if (cleanup) await cleanup;
      const result = { executable, args, code, signal, stdout, stderr };
      if (failure) { failure.commandResult = result; reject(failure); } else resolve(result);
    });
    child.stdin.on('error', () => {}); child.stdin.end(input);
  });
}

class Inspector {
  constructor(socket) {
    this.socket = socket; this.next = 0; this.pending = new Map();
    socket.addEventListener('message', event => {
      const value = JSON.parse(event.data), pending = this.pending.get(value.id);
      if (!pending) return;
      this.pending.delete(value.id); clearTimeout(pending.timer);
      if (value.error) pending.reject(new Error('Electron inspector command failed')); else pending.resolve(value.result);
    });
    socket.addEventListener('close', () => this.close());
  }
  static async connect(url) {
    check(/^ws:\/\/127\.0\.0\.1:\d+\/[a-f0-9-]+$/.test(url), 'Inspector must bind loopback');
    const socket = new WebSocket(url);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { socket.close(); reject(new Error('Electron inspector connection timed out')); }, 10000);
      socket.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
      socket.addEventListener('error', () => { clearTimeout(timer); reject(new Error('Electron inspector unavailable')); }, { once: true });
    });
    return new Inspector(socket);
  }
  async evaluate(expression) {
    const id = ++this.next;
    const value = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error('Electron inspector evaluation timed out')); }, 10000);
      this.pending.set(id, { resolve, reject, timer });
      this.socket.send(JSON.stringify({ id, method: 'Runtime.evaluate', params: { expression, awaitPromise: true, returnByValue: true } }));
    });
    check(!value.exceptionDetails, 'Electron inspector expression failed');
    return value.result?.value;
  }
  close() {
    for (const pending of this.pending.values()) { clearTimeout(pending.timer); pending.reject(new Error('Electron inspector closed')); }
    this.pending.clear(); if (this.socket.readyState < 2) this.socket.close();
  }
}

const ELECTRON = "process.getBuiltinModule('module').createRequire(process.resourcesPath + '/app.asar/package.json')('electron')";
export function validateWindow(state, { version, nativeMachine, resources, accountHome, allowedDataRoots, pid }) {
  check(state && state.pid === pid && state.packaged && state.electron && state.name === PRODUCT && state.version === version && `${state.platform}-${state.arch}` === nativeMachine, 'Launched Electron identity/version/architecture mismatch');
  check(resolve(state.resources) === resolve(resources) && resolve(state.home) === resolve(accountHome) && allowedDataRoots.some(root => within(root, state.userData)), 'Electron escaped isolated home/data or installed resources');
  const window = state.windows?.find(w => w.visible && !w.destroyed && !w.loading && w.width >= 300 && w.height >= 200 && w.rendererPid > 0 && /^osir-anywhere-workbench:\/\/web\//.test(w.url));
  check(window, 'Packaged Electron has no visible loaded application window');
  return window;
}

async function launchWindow(executable, resources, context) {
  const child = spawn(executable, ['--inspect=127.0.0.1:0'], { cwd: context.work, env: context.env, stdio: ['ignore', 'pipe', 'pipe'], detached: process.platform !== 'win32' });
  let log = '', url, error;
  child.on('error', value => { error = value; });
  for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => {
    if (log.length < LIMIT) log += chunk;
    url ??= /Debugger listening on (ws:\/\/127\.0\.0\.1:\d+\/[a-f0-9-]+)/.exec(log)?.[1];
  });
  let inspector;
  try {
    const deadline = Date.now() + 45000;
    while (!url) {
      check(!error && child.exitCode === null && child.signalCode === null, 'Installed Electron exited before inspector startup');
      check(Date.now() < deadline, 'Packaged Electron inspector not available'); await pause(100);
    }
    inspector = await Inspector.connect(url);
    let state, window;
    while (Date.now() < deadline) {
      state = await inspector.evaluate(`(() => { const {app,BrowserWindow}=${ELECTRON}; return {pid:process.pid,name:app.getName(),version:app.getVersion(),packaged:app.isPackaged,electron:process.versions.electron,arch:process.arch,platform:process.platform,resources:process.resourcesPath,home:app.getPath('home'),userData:app.getPath('userData'),windows:BrowserWindow.getAllWindows().map(w=>({id:w.id,visible:w.isVisible(),destroyed:w.isDestroyed(),loading:w.webContents.isLoading(),width:w.getBounds().width,height:w.getBounds().height,url:w.webContents.getURL(),rendererPid:w.webContents.getOSProcessId()}))}; })()`);
      try { window = validateWindow(state, { ...context, resources, pid: child.pid }); break; }
      catch { await pause(250); }
    }
    window = validateWindow(state, { ...context, resources, pid: child.pid });
    const screenshot = await inspector.evaluate(`(async()=>{const w=${ELECTRON}.BrowserWindow.fromId(${window.id});const image=await w.webContents.capturePage();return image.isEmpty()?null:image.toPNG().toString('base64');})()`);
    check(typeof screenshot === 'string' && screenshot.length > 100, 'Electron window capture is empty');
    const png = Buffer.from(screenshot, 'base64');
    check(png.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])), 'Invalid Electron window screenshot');
    await context.evidence('window.png', png);
    await context.evidence('electron-window.json', JSON.stringify(state, null, 2));
  } finally {
    if (inspector) { await inspector.evaluate(`${ELECTRON}.app.quit(); true`).catch(() => {}); inspector.close(); }
    await stopOwned(child);
    await context.evidence('electron-startup.log', log || String(error?.message ?? 'No Electron output'));
  }
}

async function stopOwned(child) {
  if (!child.pid) return;
  if (process.platform === 'win32') {
    // Only target the owned PID while it is alive, never a product name.
    if (child.exitCode === null && child.signalCode === null) {
      const root = process.env.SystemRoot || 'C:\\Windows';
      const code = await new Promise((resolve, reject) => {
        const killer = spawn(join(root, 'System32/taskkill.exe'), ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
        const timer = setTimeout(() => { killer.kill(); reject(new Error('Owned process tree cleanup timed out')); }, 5000);
        killer.on('error', error => { clearTimeout(timer); reject(error); });
        killer.on('exit', code => { clearTimeout(timer); resolve(code); });
      });
      check(code === 0 || child.exitCode !== null, 'Could not stop owned native smoke process tree');
    }
  } else {
    try { process.kill(-child.pid, 'SIGTERM'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
    await pause(300);
    try { process.kill(-child.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
  }
}

export async function connectorReady(executable, args, options) {
  const child = spawn(executable, args, { env: options.env, cwd: options.cwd, stdio: ['pipe', 'pipe', 'pipe'], detached: process.platform !== 'win32' });
  let pending = '', stderr = '';
  child.stdin.on('error', () => {});
  try {
    const ready = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Offline Connector RPC ready timed out; dependencies may be missing')), options.timeout ?? 120000);
      const fail = message => { clearTimeout(timer); reject(new Error(message)); };
      child.once('error', () => fail('Bundled Connector could not start'));
      child.once('exit', () => fail('Bundled Connector exited before RPC ready'));
      child.stderr.on('data', chunk => { if (stderr.length > LIMIT) return; stderr += chunk; if (stderr.length > LIMIT) fail('Connector stderr exceeded limit'); });
      child.stdout.on('data', chunk => {
        pending += chunk;
        if (pending.length > 65536) return fail('Connector ready exceeded limit');
        const newline = pending.indexOf('\n'); if (newline < 0) return;
        try {
          const value = JSON.parse(pending.slice(0, newline));
          check(value.kind === 'connector.ready' && value.version === 1 && value.endpoint && typeof value.key === 'string' && value.key.startsWith('mk_host_') && value.pid > 0 && (typeof value.endpoint.pipe === 'string' || typeof value.endpoint.unixPath === 'string'), 'Invalid Connector RPC ready');
          // The private host API key never enters evidence.
          clearTimeout(timer); resolve({ kind: value.kind, version: value.version, transport: value.endpoint.pipe ? 'named-pipe' : 'unix', pid: child.pid });
        } catch { fail('Invalid Connector RPC ready line'); }
      });
    });
    child.stdin.end();
    const exited = child.exitCode !== null ? child.exitCode : await new Promise(resolve => {
      const timer = setTimeout(() => resolve(null), 10000);
      child.once('exit', code => { clearTimeout(timer); resolve(code); });
    });
    check(exited === 0, 'Connector did not shut down cleanly on stdin EOF');
    return { ...ready, cleanShutdown: true };
  } finally {
    child.stdin.end(); await stopOwned(child);
    await options.onStderr?.(stderr.replace(/mk_[A-Za-z0-9_-]+/g, '[redacted-local-key]') || 'No Connector stderr');
  }
}

export class NativeAdapter {
  constructor(context) { Object.assign(this, context); }
  async run(executable, args, label, extra = {}) {
    let r;
    try { r = await command(executable, args, { env: this.env, cwd: this.work, ...extra }); }
    catch (error) {
      await this.evidence(`${label}.json`, JSON.stringify({ ...(error.commandResult ?? { executable, args }), failure: String(error.message) }, null, 2));
      throw error;
    }
    await this.evidence(`${label}.json`, JSON.stringify(r, null, 2));
    check(r.code === 0, `Native ${label} failed (exit ${r.code})`); return r.stdout.trim();
  }
  async hardware() {
    if (process.platform === 'darwin') {
      const machine = await this.run('/usr/bin/uname', ['-m'], 'hardware-machine');
      const translated = await command('/usr/sbin/sysctl', ['-n', 'sysctl.proc_translated'], { env: this.env });
      await this.evidence('hardware-translation.json', JSON.stringify(translated));
      check(translated.code === 0 || /unknown oid|unknown key/i.test(translated.stderr), 'Cannot establish native translation status');
      return { arch: ({ arm64: 'arm64', x86_64: 'x64' })[machine], translated: translated.stdout.trim() === '1' };
    }
    const code = `$ErrorActionPreference='Stop';Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class NativeMachine{[DllImport("kernel32.dll",SetLastError=true)]public static extern bool IsWow64Process2(IntPtr h,out ushort p,out ushort n);}';[System.UInt16]$p=0;[System.UInt16]$n=0;if(-not [NativeMachine]::IsWow64Process2((Get-Process -Id ${process.pid}).Handle,[ref]$p,[ref]$n)){throw 'IsWow64Process2 failed'};@{processMachine=[int]$p;nativeMachine=[int]$n}|ConvertTo-Json -Compress`;
    const machine = JSON.parse(await this.run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', code], 'hardware-machine'));
    return { arch: ({ 34404: 'x64', 43620: 'arm64' })[machine.nativeMachine], translated: machine.processMachine !== 0 };
  }
  async install() {
    const installer = this.spec.finalInstallerPath, expected = this.spec.expected;
    const signature = await inspectSystemSignature(process.platform, installer, expected.artifactSha256, this.env);
    check(signature.systemSignature === this.inputs.receipt.artifact.systemSignature, 'Final native signature differs from reviewed build');
    await this.evidence('native-system-signature.json', JSON.stringify(signature, null, 2));
    const destination = join(this.work, 'installed'); await mkdir(destination);
    let executable, resources, metadata;
    if (process.platform === 'darwin') {
      const mount = join(this.work, 'mount'); await mkdir(mount);
      let attached = false;
      try {
        await this.run('/usr/bin/hdiutil', ['attach', '-readonly', '-nobrowse', '-noautoopen', '-mountpoint', mount, installer], 'dmg-mount'); attached = true;
        const apps = (await readdir(mount)).filter(name => name.endsWith('.app'));
        check(apps.length === 1 && apps[0] === `${PRODUCT}.app`, 'DMG product bundle mismatch');
        const app = join(destination, apps[0]);
        await this.run('/usr/bin/ditto', [join(mount, apps[0]), app], 'dmg-copy');
        const plist = JSON.parse(await this.run('/usr/bin/plutil', ['-convert', 'json', '-o', '-', join(app, 'Contents/Info.plist')], 'bundle-metadata'));
        check(plist.CFBundleIdentifier === APP_ID && plist.CFBundleName === PRODUCT && plist.CFBundleDisplayName === PRODUCT && plist.CFBundlePackageType === 'APPL' && plist.CFBundleShortVersionString === expected.version && plist.CFBundleExecutable === PRODUCT, 'Installed Mac product/version mismatch');
        executable = join(app, 'Contents/MacOS', plist.CFBundleExecutable); resources = join(app, 'Contents/Resources'); metadata = plist;
      } finally { if (attached) await this.run('/usr/bin/hdiutil', ['detach', mount], 'dmg-detach'); }
    } else {
      // NSIS /D= must be the final argument. Run the actual installer, not 7zip.
      await this.run(installer, ['/S', '/currentuser', `/D=${destination}`], 'nsis-install', { timeout: 180000 });
      executable = join(destination, `${PRODUCT}.exe`); resources = join(destination, 'resources');
      const env = { ...this.env, OSIR_SMOKE_EXE: executable };
      metadata = JSON.parse(await this.run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', '$v=(Get-Item -LiteralPath $env:OSIR_SMOKE_EXE).VersionInfo;@{ProductName=$v.ProductName;ProductVersion=$v.ProductVersion;FileVersion=$v.FileVersion}|ConvertTo-Json -Compress'], 'installed-pe-metadata', { env }));
      check(metadata.ProductName === PRODUCT && metadata.ProductVersion === expected.version, 'Installed Windows product/version mismatch');
    }
    const pkg = await asarJson(join(resources, 'app.asar'), 'package.json');
    check(pkg.name === 'osir-anywhere-desktop-workbench' && pkg.version === expected.version && pkg.productName === PRODUCT && pkg.main === 'dist/electron/main.js', 'Installed ASAR product/version mismatch');
    const arches = await executableArches(executable);
    check(expected.target === 'darwin-universal' ? arches.join(',') === 'arm64,x64' : arches.join(',') === process.arch, 'Installed Electron architecture mismatch');
    const config = await asarJson(join(resources, 'app.asar'), 'dist/config.json');
    const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(',')}]` : value && typeof value === 'object' ? `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}` : JSON.stringify(value);
    check(digest(canonical(config)) === expected.configSha256, 'Installed endpoint configuration differs from receipt');
    await this.evidence('installed-product.json', JSON.stringify({ executable, resources, metadata, pkg, arches, executableIdentity: await fileIdentity(executable) }, null, 2));
    this.installed = { executable, resources }; return this.installed;
  }
  async launch() { await launchWindow(this.installed.executable, this.installed.resources, this); }
  async runtimes() {
    const target = this.spec.runner.nativeMachine, root = this.installed.resources;
    const uv = join(root, 'uv', target, process.platform === 'win32' ? 'uv.exe' : 'uv');
    const python = join(root, 'python', target, ...(process.platform === 'win32' ? ['python.exe'] : ['bin', 'python3']));
    for (const [label, executable] of [['uv', uv], ['python', python]]) {
      const actual = await realpath(executable);
      check(within(await realpath(root), actual), `Bundled ${label} executable escapes packaged resources`);
      check((await executableArches(executable)).includes(process.arch), `Bundled ${label} native architecture missing`);
      await this.evidence(`${label}-identity.json`, JSON.stringify({ requestedPath: executable, actualPath: actual, ...(await fileIdentity(actual)) }));
    }
    const version = await this.run(uv, ['--version'], 'uv-version'); check(/^uv \d+\./.test(version), 'Bundled uv version invalid'); this.checks.uv = true;
    const py = JSON.parse(await this.run(python, ['-I', '-c', 'import json,platform,sys;print(json.dumps({"version":list(sys.version_info[:3]),"machine":platform.machine(),"executable":sys.executable}))'], 'python-runtime'));
    check(py.version[0] === 3 && py.version[1] >= 12 && ({ arm64: 'arm64', aarch64: 'arm64', ARM64: 'arm64', AMD64: 'x64', x86_64: 'x64' })[py.machine] === process.arch && await realpath(py.executable) === await realpath(python), 'Bundled Python identity/version mismatch'); this.checks.python = true;
    const project = join(this.work, 'connector-project');
    await cp(join(root, 'connector'), project, { recursive: true, errorOnExist: true, force: false });
    if (this.spec.dependencyCache?.lockPath) {
      check((await fileIdentity(this.spec.dependencyCache.lockPath)).sha256 === this.spec.dependencyCache.lockSha256, 'Resolved dependency lock changed');
      await writeFile(join(project, 'uv.lock'), await readFile(this.spec.dependencyCache.lockPath));
    }
    const ready = await connectorReady(uv, ['--offline', '--no-config', 'run', ...(this.spec.dependencyCache?.lockPath ? ['--locked'] : []), '--project', project, '--python', python, '--no-python-downloads', 'anywhere-cli', 'rpc', '--config', join(this.work, 'no-account.json')], { env: this.env, cwd: this.work,
      onStderr: text => this.evidence('connector-stderr.log', text) });
    await this.evidence('connector-rpc.json', JSON.stringify(ready, null, 2)); this.checks.connector = true;
    await this.evidence('connector-resolved-uv.lock', await readFile(join(project, 'uv.lock')));
  }
}

export async function verifyCleanAccount(actual = { home: homedir(), user: userInfo().username, hostname: hostname() }) {
  check(await realpath(actual.home) === resolve(actual.home), 'Isolated OS home must be canonical');
  // .ssh is deliberately neither listed nor opened: checkout runners may have
  // an empty directory or checkout credentials. No credential file is read.
  for (const name of ['.codex', '.claude', '.aws', '.cc-switch', '.osir-client', '.agents-anywhere', '.config/agents-anywhere', '.config/OSIR Anywhere', '.config/OSIR Client', 'Library/Application Support/OSIR Anywhere', 'Library/Application Support/OSIR Client', 'Library/Application Support/Agents Anywhere', 'AppData/Roaming/OSIR Anywhere', 'AppData/Roaming/OSIR Client', '.local/share/agents-anywhere']) {
    let stat;
    try { stat = await lstat(join(actual.home, name)); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    check(!stat, 'Isolated account contains existing credentials/product data; refusing to launch');
  }
  return actual;
}

export async function verifyIsolation(spec, actual = { home: homedir(), user: userInfo().username, hostname: hostname() }) {
  const identity = await fileIdentity(spec.runner.isolationEvidencePath);
  check(identity.sha256 === spec.runner.isolationEvidenceSha256, 'Isolation attestation hash mismatch');
  const record = await json(spec.runner.isolationEvidencePath);
  const policyMatches = record.runnerMode === 'disposable-clean-runner'
    ? record.networkPolicy === 'unrestricted-no-product-credentials' && record.networkIsolationClaimed === false && spec.runner.mode === record.runnerMode
    : record.networkPolicy === 'deny-all-except-loopback' && spec.runner.mode !== 'disposable-clean-runner';
  check(record.schemaVersion === 1 && record.kind === 'disposable-native-runner' && record.disposable === true && policyMatches && record.nativeMachine === spec.runner.nativeMachine && record.user === actual.user && record.hostname === actual.hostname && typeof record.jobId === 'string' && record.jobId.length > 0 && resolve(record.home) === resolve(actual.home), 'Runner is not the attested isolated native account');
  const age = Date.now() - Date.parse(record.createdAt);
  check(Number.isFinite(age) && age >= -60000 && age <= 12 * 3600000, 'Isolation evidence is stale');
  await verifyCleanAccount(actual);
  const { verifyProvisionedIsolation } = await import('./osir-native-smoke-provision.mjs');
  const verified = await verifyProvisionedIsolation(record);
  return { ...record, enforcement: verified, identity };
}

export async function runSmoke(spec, output, { adapterFactory, isolationVerifier = verifyIsolation } = {}) {
  check(isAbsolute(output), 'Absolute new evidence directory required');
  // mkdir without recursive/exist-ok refuses mixing or overwriting job evidence.
  await mkdir(output, { mode: 0o700 });
  output = await realpath(output);
  const work = join(output, 'work'); await mkdir(work, { mode: 0o700 });
  const synthetic = Boolean(adapterFactory || isolationVerifier !== verifyIsolation);
  const report = {
    ...(spec?.expected ?? {}),
    schemaVersion: 1, scope: 'native-smoke', result: 'failed', releaseAcceptance: 'incomplete',
    evidenceMode: synthetic ? 'synthetic' : 'native', productId: 'osir-anywhere',
    launchInstrumentation: 'packaged-electron-loopback-node-inspector',
    runnerMode: 'unverified', networkPolicy: 'unverified', networkIsolationClaimed: false, fullSmokeOfflineClaimed: false,
    nativeMachines: [], checks: { installer: false, launch: false, connector: false, python: false, uv: false, upgradeDataPreserved: false, updateDiscovery: false },
    execution: { installAttempted: false, launchAttempted: false },
    uncovered: ['real-account-login-and-oauth', 'production-server-and-model-integration', 'upgradeDataPreserved', 'updateDiscovery', 'interactive-os-install-confirmation'],
    evidence: [], startedAt: new Date().toISOString(),
  };
  const evidence = async (name, data) => {
    check(basename(name) === name, 'Unsafe evidence filename');
    await writeFile(join(output, name), data, { flag: 'wx', mode: 0o600 });
    report.evidence.push({ path: name, ...(await fileIdentity(join(output, name))) });
  };
  try {
    validateSpec(spec);
    const inputs = await bindInputs(spec);
    report.buildReceiptSha256 = inputs.receiptIdentity.sha256;
    report.scriptSha256 = (await fileIdentity(new URL(import.meta.url))).sha256;
    await evidence('smoke-spec.json', JSON.stringify(spec, null, 2));
    await evidence('build-receipt.json', await readFile(spec.buildReceiptPath));
    await evidence('reviewed-system-signature.json', await readFile(spec.systemSignatureReportPath));
    const isolation = await isolationVerifier(spec);
    report.runnerMode = isolation.runnerMode ?? (synthetic ? 'synthetic' : 'strict-loopback');
    report.networkPolicy = isolation.networkPolicy ?? 'synthetic';
    report.networkIsolationClaimed = isolation.enforcement?.kind === 'macos-seatbelt';
    if (report.runnerMode === 'disposable-clean-runner') {
      report.hostedRunner = isolation.hostedRunner;
      report.boundaries = isolation.boundaries;
      report.uncovered.push('network-isolation-and-full-offline-execution');
    }
    await evidence('runner-isolation.json', JSON.stringify(isolation, null, 2));
    if (isolation.enforcement?.kind === 'macos-seatbelt') {
      for (const [name, path] of [['network-proof.json', isolation.enforcement.proofPath], ['network-baseline.json', isolation.enforcement.baselinePath], ['network-profile.sb', isolation.enforcement.profilePath]]) await evidence(name, await readFile(path));
    }
    const accountHome = isolation.home;
    const env = smokeEnvironment(process.env, accountHome, work);
    for (const key of ['APPDATA', 'LOCALAPPDATA', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TMPDIR', 'CODEX_HOME', 'CLAUDE_CONFIG_DIR', 'ZDOTDIR', 'AGENT_CONNECTOR_DATA_DIR', 'UV_CACHE_DIR']) await mkdir(env[key], { recursive: true, mode: 0o700 });
    if (spec.dependencyCache) {
      check(await fingerprintTree(spec.dependencyCache.path) === spec.dependencyCache.sha256, 'Dependency cache fingerprint mismatch');
      await cp(spec.dependencyCache.path, env.UV_CACHE_DIR, { recursive: true, verbatimSymlinks: true });
      check(await fingerprintTree(env.UV_CACHE_DIR) === spec.dependencyCache.sha256, 'Copied dependency cache differs');
    }
    const context = { spec, inputs, work, env, evidence, checks: report.checks, accountHome, version: spec.expected.version, nativeMachine: spec.runner.nativeMachine,
      allowedDataRoots: process.platform === 'win32' ? [env.APPDATA, join(accountHome, 'AppData/Roaming')] : [join(accountHome, 'Library/Application Support')] };
    const adapter = adapterFactory ? adapterFactory(context) : new NativeAdapter(context);
    const machine = await adapter.hardware();
    assertNativeMachine(spec.runner.nativeMachine, machine.platform ?? process.platform, machine.nodeArch ?? process.arch, machine.arch, machine.translated);
    report.nativeMachines.push(spec.runner.nativeMachine);
    report.execution.installAttempted = true; await adapter.install(); report.checks.installer = true;
    report.execution.launchAttempted = true; await adapter.launch(); report.checks.launch = true;
    await adapter.runtimes();
    check(['uv', 'python', 'connector'].every(k => report.checks[k]), 'Bundled runtime smoke incomplete');
    const after = await fileIdentity(spec.finalInstallerPath);
    check(after.sha256 === inputs.artifact.sha256 && after.size === inputs.artifact.size, 'Final installer changed during smoke');
    report.result = synthetic ? 'simulated' : 'passed';
  } catch (error) {
    report.failure = String(error.message ?? 'Native smoke failed').slice(0, 400);
  } finally {
    // Preserve the dedicated account/installed app for runner disposal and failure
    // inspection. Never uninstall by product name, recurse into a mounted image,
    // remove quarantine, change SmartScreen/Gatekeeper or delete real user data.
    report.completedAt = new Date().toISOString();
    await writeFile(join(output, 'native-smoke.json'), `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  }
  return report;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') {
    console.log('Usage: node osir-native-smoke.mjs --spec /absolute/spec.json --output /new/evidence-directory\nEnter via the provision helper on a disposable GitHub-hosted native GUI runner, with live runner provenance and pinned uv dependency cache. Clean-runner permits unauthenticated public reads and claims no network isolation. See script header for spec. This is partial native smoke, never complete release acceptance.'); return;
  }
  check(args.length === 4 && args[0] === '--spec' && args[2] === '--output' && isAbsolute(args[1]) && isAbsolute(args[3]), 'Use --help for the native smoke contract');
  const report = await runSmoke(await json(args[1]), args[3]);
  console.log(JSON.stringify({ result: report.result, releaseAcceptance: report.releaseAcceptance, report: join(args[3], 'native-smoke.json'), failure: report.failure }));
  if (report.result !== 'passed') process.exitCode = 1;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main().catch(error => { console.error(`OSIR native smoke: ${String(error.message).slice(0, 400)}`); process.exitCode = 1; });
