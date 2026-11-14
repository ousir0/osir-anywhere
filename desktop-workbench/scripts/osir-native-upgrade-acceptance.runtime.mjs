// Native-only execution for the standalone acceptance helper. No product edits.
import { spawn } from 'node:child_process';
import { homedir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { mkdir, open, readdir, realpath, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { asarJson, assertNativeMachine, binaryArchitectures, command, fileIdentity, NativeAdapter, smokeEnvironment, validateWindow, validateWindowsMetadata, validateWelcome } from './osir-native-smoke.mjs';
import { hostedRunnerProvenance, nativeGuiProvenance, requireHostedRunner } from './osir-native-smoke-provision.mjs';
import { inspectSystemSignature } from './osir-anywhere-system-signature.mjs';
import { bytes, check, fingerprint, within } from './osir-anywhere-release-common.mjs';
import { BASELINE_VERSION, FINAL_VERSION, observeUpgradeHardware, runAcceptance } from './osir-native-upgrade-acceptance.mjs';

const SELF = fileURLToPath(new URL('./osir-native-upgrade-acceptance.mjs', import.meta.url));
const RUNTIME = fileURLToPath(import.meta.url);
const PRODUCT = 'OSIR Anywhere', APP_ID = 'com.osir.anywhere.desktop';
const LIMIT = 2 * 1024 * 1024;
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

// Keep the shared live desktop/session gate. One Windows timeout may be
// retried, but every failure survives and no failed observation is accepted.
export async function observeUpgradeGui(env, evidence, probe = nativeGuiProvenance, platform = process.platform) {
  for (let attempt = 1; attempt <= 2; attempt++) {
    let gui;
    try {
      gui = await probe(env);
    } catch (error) {
      await evidence(`runner-gui-attempt-${attempt}.json`, bytes({ result: 'failed', failure: String(error.message), ...(error.commandResult ? { command: error.commandResult } : {}) }));
      if (platform !== 'win32' || attempt === 2 || error.message !== 'Native command timed out') throw error;
      continue;
    }
    await evidence(`runner-gui-attempt-${attempt}.json`, bytes({ result: 'passed', gui }));
    return gui;
  }
}

// The coordinator explicitly authorizes disposable clean native GUI runners.
// Public network may be reachable. No network-denial/offline claim is made.
export async function verifyUpgradeIsolation(spec, { output, evidence }) {
  await requireHostedRunner();
  check(`${process.platform}-${process.arch}` === spec.runner.nativeMachine, 'Clean runner native machine mismatch');
  const preflight = join(output, 'runner-preflight'); await mkdir(preflight, { mode: 0o700 });
  const env = smokeEnvironment(process.env, homedir(), preflight); await mkdir(env.TMPDIR, { mode: 0o700 });
  const gui = await observeUpgradeGui(env, evidence);
  return { schemaVersion: 1, kind: 'disposable-native-runner', runnerMode: 'disposable-clean-runner', disposable: true,
    networkPolicy: 'unrestricted-no-product-credentials', offline: false,
    networkIsolationClaimed: false, hostedRunner: hostedRunnerProvenance(), gui,
    publicNetworkMayBeReachable: true, productCredentials: false,
    childEnvironment: 'allowlist', home: await realpath(homedir()),
    nativeMachine: spec.runner.nativeMachine, helperSha256: (await fileIdentity(SELF)).sha256,
    runtimeSha256: (await fileIdentity(RUNTIME)).sha256,
    runId: process.env.GITHUB_RUN_ID, runAttempt: process.env.GITHUB_RUN_ATTEMPT ?? '1' };
}

export async function provisionUpgrade(spec, options) {
  return runAcceptance(spec, options.output);
}

class Inspector {
  constructor(socket) {
    this.socket = socket; this.id = 0; this.pending = new Map();
    socket.addEventListener('message', event => {
      const message = JSON.parse(event.data), pending = this.pending.get(message.id); if (!pending) return;
      clearTimeout(pending.timer); this.pending.delete(message.id);
      if (message.error) pending.reject(new Error('Electron inspector command failed')); else pending.resolve(message.result);
    });
    socket.addEventListener('close', () => this.close());
  }
  static async connect(url) {
    check(/^ws:\/\/127\.0\.0\.1:\d+\/[a-f0-9-]+$/.test(url), 'Inspector endpoint must be loopback');
    const socket = new WebSocket(url);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { socket.close(); reject(new Error('Inspector connection timed out')); }, 10000);
      socket.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
      socket.addEventListener('error', () => { clearTimeout(timer); reject(new Error('Inspector connection failed')); }, { once: true });
    }); return new Inspector(socket);
  }
  async evaluate(expression) {
    const id = ++this.id;
    const result = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error('Inspector evaluation timed out')); }, 20000);
      this.pending.set(id, { resolve, reject, timer });
      this.socket.send(JSON.stringify({ id, method: 'Runtime.evaluate', params: { expression, returnByValue: true, awaitPromise: true } }));
    });
    check(!result.exceptionDetails, `Packaged Electron evaluation failed: ${result.exceptionDetails?.exception?.description?.slice(0, 400) ?? ''}`);
    return result.result?.value;
  }
  close() {
    for (const pending of this.pending.values()) { clearTimeout(pending.timer); pending.reject(new Error('Inspector closed')); }
    this.pending.clear(); if (this.socket.readyState < 2) this.socket.close();
  }
}

const REQUIRE = "process.getBuiltinModule('module').createRequire(process.resourcesPath+'/app.asar/package.json')";
const ELECTRON = `${REQUIRE}('electron')`;
export const SEED_SETTINGS = { openAtLogin: false, startConnectorOnLaunch: false, silentLaunch: false, notificationsEnabled: false,
  uvPath: '', pythonPath: '', uvPypiIndexUrl: '', uvPythonInstallMirror: '', logRetentionDays: 37, logRetainChunks: 13, logChunkSizeKb: 768 };

// The Node inspector can accept commands before Electron installs its module
// loader. Serialize the probe into the real packaged process; do not retry
// arbitrary evaluation exceptions or substitute a harness Electron module.
export function packagedWindowState() {
  const phase = { processType: process.type ?? null, electron: process.versions.electron ?? null };
  if (process.type !== 'browser' || !process.versions.electron) return { ready: false, reason: 'electron-browser-not-ready', phase };
  const require = process.getBuiltinModule('module').createRequire(process.resourcesPath + '/app.asar/package.json');
  let electron;
  try { electron = require('electron'); }
  catch (error) {
    if (error.code === 'MODULE_NOT_FOUND' && error.message.split('\n')[0] === "Cannot find module 'electron'") return { ready: false, reason: 'electron-module-not-ready', phase, error: { code: error.code, message: error.message.slice(0, 400) } };
    throw error;
  }
  const { app, BrowserWindow } = electron;
  if (!app.isReady()) return { ready: false, reason: 'electron-app-not-ready', phase };
  return { ready: true, state: { pid: process.pid, name: app.getName(), version: app.getVersion(), packaged: app.isPackaged,
    electron: process.versions.electron, arch: process.arch, platform: process.platform, resources: process.resourcesPath,
    home: app.getPath('home'), userData: app.getPath('userData'),
    windows: BrowserWindow.getAllWindows().map(w => ({ id: w.id, visible: w.isVisible(), destroyed: w.isDestroyed(), loading: w.webContents.isLoading(),
      width: w.getBounds().width, height: w.getBounds().height, url: w.webContents.getURL(), rendererPid: w.webContents.getOSProcessId() })) } };
}

export async function waitForUpgradeWindow(inspector, context, deadline, observe = async () => {}) {
  const observations = []; let state;
  try {
    while (Date.now() < deadline) {
      const observation = await inspector.evaluate(`(${packagedWindowState.toString()})()`);
      observations.push(observation);
      if (observation?.ready === true) {
        state = observation.state;
        try { return { state, window: validateWindow(state, context) }; } catch { /* A window may still be loading. */ }
      } else check(observation?.ready === false && ['electron-browser-not-ready', 'electron-module-not-ready', 'electron-app-not-ready'].includes(observation.reason), 'Invalid packaged startup observation');
      await pause(250);
    }
    if (state) validateWindow(state, context);
    throw new Error('Packaged Electron startup readiness timed out');
  } finally { await observe(observations); }
}

// Use the existing trusted-renderer API, which calls the product's complete
// requestQuit() cleanup. app.quit() alone asks for confirmation. Schedule the
// API call so the inspector receives an acknowledgement before the window is
// destroyed; an IPC reply from that destroyed renderer is not an exit proof.
export async function requestUpgradeQuit(inspector, windowId) {
  check(Number.isSafeInteger(windowId) && windowId > 0, 'Owned window ID required for graceful quit');
  const renderer = `(() => { if(typeof window.desktopWorkbench?.ownership?.quit !== 'function') throw new Error('Packaged ownership.quit API missing'); setTimeout(() => { Promise.resolve(window.desktopWorkbench.ownership.quit()).catch(() => {}); }, 100); return {requested:true,route:'desktopWorkbench.ownership.quit'}; })()`;
  const result = await inspector.evaluate(`(()=>{const w=${ELECTRON}.BrowserWindow.fromId(${windowId});return w.webContents.executeJavaScript(${JSON.stringify(renderer)});})()`);
  check(result?.requested === true && result.route === 'desktopWorkbench.ownership.quit', 'Packaged graceful quit was not requested');
  return result;
}

// Same renderer observation and shared validator as the corrected smoke launch.
// A visible Electron window alone cannot certify that the welcome page loaded.
export async function waitForUpgradeWelcome(inspector, windowId, deadline, observe = async () => {}) {
  let welcome;
  try {
    while (Date.now() < deadline) {
      welcome = await inspector.evaluate(`(async()=>{const w=${ELECTRON}.BrowserWindow.fromId(${windowId});return w.webContents.executeJavaScript(${JSON.stringify("(() => { const h=document.querySelector('h1'); const b=document.querySelector('button'); const r=b?.getBoundingClientRect(); const s=b&&getComputedStyle(b); return {ready:document.readyState==='complete',branded:!!h?.textContent?.includes('OSIR Anywhere'),action:b?{text:b.textContent?.trim(),enabled:!b.disabled,visible:!!r&&r.width>0&&r.height>0&&s.display!=='none'&&s.visibility==='visible'}:null}; })()")});})()`);
      try { validateWelcome(welcome); return welcome; } catch { await pause(250); }
    }
    validateWelcome(welcome);
  } finally { await observe(welcome ?? { ready: false, branded: false, action: null }); }
}

export async function ownedExit(child, inspector, graceful, env, { windowId, observe = async () => {}, graceMs = 10000 } = {}) {
  let exited = child.exitCode !== null || child.signalCode !== null;
  let request, quitError, forced = false;
  const wait = async milliseconds => {
    const end = Date.now() + milliseconds;
    while (!exited && Date.now() < end) { await pause(100); exited = child.exitCode !== null || child.signalCode !== null; }
  };
  if (inspector) {
    try {
      if (graceful) request = await requestUpgradeQuit(inspector, windowId);
      else await inspector.evaluate(`${ELECTRON}.app.quit();true`);
    } catch (error) { quitError = String(error.message); }
    finally { inspector.close(); }
    await wait(graceMs);
  }
  const clean = exited && child.exitCode === 0;
  let cleanupError;
  try {
    if (!exited && child.pid) {
      forced = true;
      // Only the process group we spawned; no product-name shutdown or OS bypass.
      if (process.platform === 'win32') {
        const result = await command(join(process.env.SystemRoot || 'C:\\Windows', 'System32/taskkill.exe'), ['/PID', String(child.pid), '/T', '/F'], { env, timeout: 10000 });
        check(result.code === 0 || child.exitCode !== null, 'Could not stop owned Electron PID'); await wait(3000);
      } else {
        try { process.kill(-child.pid, 'SIGTERM'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
        await wait(1000);
        if (!exited) { try { process.kill(-child.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; } await wait(3000); }
      }
    }
  } catch (error) { cleanupError = String(error.message); throw error; }
  finally {
    await observe({ route: graceful ? 'desktopWorkbench.ownership.quit' : 'app.quit', requested: request ?? null, requestError: quitError ?? null,
      exitCode: child.exitCode, signal: child.signalCode, clean, forced, cleanupError: cleanupError ?? null });
  }
  check(!graceful || (request?.requested === true && !quitError && clean && !forced), 'Owned Electron did not exit cleanly; data durability unproven');
}

export class UpgradeAdapter extends NativeAdapter {
  async hardware() {
    const machine = await observeUpgradeHardware(this);
    assertNativeMachine(this.spec.runner.nativeMachine, process.platform, process.arch, machine.arch, machine.translated);
  }
  async installBaseline() {
    this.baselineInstalled = await this.installVersion(this.controlled.artifactPath, this.controlled.baseline.artifact, BASELINE_VERSION, 'baseline');
    return this.baselineInstalled;
  }
  async installFinal() {
    this.finalInstalled = await this.installVersion(this.spec.finalInstallerPath, this.inputs.receipt.artifact, FINAL_VERSION, 'final');
    check(this.finalInstalled.executable === this.baselineInstalled.executable, 'Final install destination changed'); return this.finalInstalled;
  }
  async installVersion(installer, artifact, version, label) {
    const identity = await fileIdentity(installer); check(identity.sha256 === artifact.sha256 && identity.size === artifact.size, 'Installer changed before installation');
    const signature = await inspectSystemSignature(process.platform, installer, identity.sha256, this.env);
    check(signature.systemSignature === artifact.systemSignature, 'Actual installer signature differs from receipt');
    await this.evidence(`${label}-system-signature.json`, bytes(signature));
    if (process.platform === 'win32') return this.installWindows(installer, artifact, version, label);
    const stage = join(this.work, `${label}-stage`), mount = join(this.work, `${label}-mount`);
    await mkdir(stage); await mkdir(mount); let attached = false;
    const destination = join(this.work, 'installed'), app = join(destination, `${PRODUCT}.app`);
    await mkdir(destination, { recursive: true });
    try {
      await this.run('/usr/bin/hdiutil', ['attach', '-readonly', '-nobrowse', '-noautoopen', '-mountpoint', mount, installer], `${label}-mount`); attached = true;
      const apps = (await readdir(mount)).filter(name => name.endsWith('.app'));
      check(apps.length === 1 && apps[0] === `${PRODUCT}.app`, 'DMG contains wrong product');
      await this.run('/usr/bin/ditto', [join(mount, apps[0]), join(stage, apps[0])], `${label}-copy`);
    } finally { if (attached) await this.run('/usr/bin/hdiutil', ['detach', mount], `${label}-detach`); }
    const staged = join(stage, `${PRODUCT}.app`);
    const metadata = JSON.parse(await this.run('/usr/bin/plutil', ['-convert', 'json', '-o', '-', join(staged, 'Contents/Info.plist')], `${label}-metadata`));
    check(metadata.CFBundleIdentifier === APP_ID && metadata.CFBundleName === PRODUCT && metadata.CFBundleDisplayName === PRODUCT && metadata.CFBundlePackageType === 'APPL' && metadata.CFBundleExecutable === PRODUCT && metadata.CFBundleShortVersionString === version, 'DMG bundle identity/version mismatch');
    if (label === 'final') {
      const previous = join(this.work, 'baseline-app-before-replacement'); await rename(app, previous);
      try { await rename(staged, app); } catch (error) { await rename(previous, app); throw error; }
    } else await rename(staged, app);
    const resources = join(app, 'Contents/Resources'), executable = join(app, 'Contents/MacOS', PRODUCT);
    const pkg = await asarJson(join(resources, 'app.asar'), 'package.json');
    check(pkg.name === 'osir-anywhere-desktop-workbench' && pkg.productName === PRODUCT && pkg.version === version && pkg.main === 'dist/electron/main.js', 'Installed ASAR identity/version mismatch');
    check(fingerprint(await asarJson(join(resources, 'app.asar'), 'dist/config.json')) === this.spec.expected.configSha256, 'Installed config differs from final receipt');
    const handle = await open(executable, 'r'); let arches;
    try { const buffer = Buffer.alloc(1024 * 1024); const read = await handle.read(buffer, 0, buffer.length, 0); arches = binaryArchitectures(buffer.subarray(0, read.bytesRead)).sort(); }
    finally { await handle.close(); }
    check(arches.join(',') === 'arm64,x64', 'Installed baseline/final must be the original universal target');
    const installed = { executable, resources, version, pkg, metadata, arches };
    await this.evidence(`${label}-installed.json`, bytes(installed));
    check((await fileIdentity(installer)).sha256 === artifact.sha256, 'Installer changed during installation');
    return installed;
  }
  async installWindows(installer, artifact, version, label) {
    const destination = join(this.work, 'installed'); await mkdir(destination, { recursive: true });
    await this.run(installer, ['/S', '/currentuser', `/D=${destination}`], `${label}-nsis-install`, { timeout: 180000 });
    const executable = join(destination, `${PRODUCT}.exe`), resources = join(destination, 'resources');
    const env = { ...this.env, OSIR_UPGRADE_EXE: executable };
    const metadata = JSON.parse(await this.run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', "$ErrorActionPreference='Stop';$v=(Get-Item -LiteralPath $env:OSIR_UPGRADE_EXE).VersionInfo;@{ProductName=$v.ProductName;ProductVersion=$v.ProductVersion;FileVersion=$v.FileVersion}|ConvertTo-Json -Compress"], `${label}-pe-metadata`, { env }));
    validateWindowsMetadata(metadata, version);
    const pkg = await asarJson(join(resources, 'app.asar'), 'package.json');
    check(pkg.name === 'osir-anywhere-desktop-workbench' && pkg.productName === PRODUCT && pkg.version === version && pkg.main === 'dist/electron/main.js', 'NSIS ASAR product/version mismatch');
    check(fingerprint(await asarJson(join(resources, 'app.asar'), 'dist/config.json')) === this.spec.expected.configSha256, 'NSIS installed config mismatch');
    const handle = await open(executable, 'r'); let arches;
    try { const buffer = Buffer.alloc(1024 * 1024); const read = await handle.read(buffer, 0, buffer.length, 0); arches = binaryArchitectures(buffer.subarray(0, read.bytesRead)); }
    finally { await handle.close(); }
    check(arches.join(',') === process.arch, 'NSIS executable native architecture mismatch');
    check((await fileIdentity(installer)).sha256 === artifact.sha256, 'NSIS installer changed during installation');
    const installed = { executable, resources, version, pkg, metadata, arches };
    await this.evidence(`${label}-installed.json`, bytes(installed)); return installed;
  }
  async session(installed, label, action) {
    const child = spawn(installed.executable, ['--inspect=127.0.0.1:0'], { cwd: this.work, env: this.env, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'] });
    let log = '', url, error, inspector, window, completed = false;
    child.on('error', value => { error = value; });
    for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => {
      if (Buffer.byteLength(log) < LIMIT) log += chunk;
      url ??= /Debugger listening on (ws:\/\/127\.0\.0\.1:\d+\/[a-f0-9-]+)/.exec(log)?.[1];
    });
    try {
      const deadline = Date.now() + 60000;
      while (!url) { check(!error && child.exitCode === null && child.signalCode === null && Date.now() < deadline, 'Installed Electron failed to start'); await pause(100); }
      inspector = await Inspector.connect(url);
      const ready = await waitForUpgradeWindow(inspector, { ...this, version: installed.version, nativeMachine: this.spec.runner.nativeMachine, resources: installed.resources, pid: child.pid }, deadline,
        observations => this.evidence(`${label}-startup-observations.json`, bytes(observations)));
      const state = ready.state; window = ready.window;
      check(state.userData === this.expectedUserData, 'App userData is not the clean runner product directory');
      await waitForUpgradeWelcome(inspector, window.id, deadline, welcome => this.evidence(`${label}-renderer-welcome.json`, bytes(welcome)));
      const png = await inspector.evaluate(`(async()=>{const w=${ELECTRON}.BrowserWindow.fromId(${window.id});return(await w.webContents.capturePage()).toPNG().toString('base64')})()`);
      const image = Buffer.from(png, 'base64'); check(image.length > 100 && image.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10])), 'Native window screenshot missing');
      await this.evidence(`${label}-window.png`, image); await this.evidence(`${label}-window.json`, bytes(state));
      const result = await action(inspector, state, window); completed = true; return result;
    } finally {
      try { await ownedExit(child, inspector, completed, this.env, { windowId: window?.id, observe: result => this.evidence(`${label}-exit.json`, bytes(result)) }); }
      finally { await this.evidence(`${label}-startup.log`, log || String(error?.message ?? 'No output')); }
    }
  }
  async seedBaseline(installed) {
    const nonce = randomBytes(24).toString('hex');
    const synthetic = { schemaVersion: 1, kind: 'account-free-native-upgrade-sentinel', nonce, notes: ['保留合成便签', 'No account or model'] };
    const seed = await this.session(installed, 'baseline', async (inspector, state, window) => {
      const expected = JSON.stringify(synthetic);
      const result = await inspector.evaluate(`(async()=>{const r=${REQUIRE},fs=r('node:fs'),path=r('node:path'),{app,BrowserWindow}=r('electron');const userData=app.getPath('userData');const Settings=r('./dist/electron/desktop-settings.js').DesktopSettingsStore;const settings=new Settings(path.join(userData,'desktop-settings.json'),[]).save(${JSON.stringify(SEED_SETTINGS)});const dir=path.join(userData,'native-upgrade-synthetic');fs.mkdirSync(dir,{recursive:false});fs.writeFileSync(path.join(dir,'notes.json'),${JSON.stringify(expected)},{flag:'wx'});fs.writeFileSync(path.join(dir,'sentinel.bin'),Buffer.from(${JSON.stringify(nonce)},'hex'),{flag:'wx'});const w=BrowserWindow.fromId(${window.id});await w.webContents.executeJavaScript(${JSON.stringify(`localStorage.setItem('osir.native-upgrade.synthetic',${JSON.stringify(expected)});localStorage.getItem('osir.native-upgrade.synthetic')`)});w.webContents.session.flushStorageData();return{userData,settings,origin:w.webContents.getURL(),localStorage:${JSON.stringify(expected)}}})()`);
      check(fingerprint(result.settings) === fingerprint(SEED_SETTINGS), 'Synthetic settings were not accepted by the packaged store');
      return { ...result, synthetic, relativePaths: ['desktop-settings.json', 'native-upgrade-synthetic/notes.json', 'native-upgrade-synthetic/sentinel.bin'], baselineVersion: state.version };
    });
    await this.evidence('synthetic-seed.json', bytes(seed)); this.seed = seed; return seed;
  }
  async snapshot(seed) {
    check(seed.userData === this.expectedUserData, 'Snapshot escaped clean runner product directory');
    const result = [];
    for (const name of seed.relativePaths) {
      const path = join(seed.userData, name);
      check(within(await realpath(seed.userData), await realpath(path)), 'Seeded data symlink escaped isolated product directory');
      result.push({ path: name, ...await fileIdentity(path) });
    } return result;
  }
  async verifyFinal(installed, seed) {
    return this.session(installed, 'final', async (inspector, state, window) => {
      check(state.userData === seed.userData, 'Final app changed userData directory');
      const observed = await inspector.evaluate(`(async()=>{const r=${REQUIRE},fs=r('node:fs'),path=r('node:path'),{app,BrowserWindow}=r('electron');const userData=app.getPath('userData');const settings=r('./dist/electron/desktop-settings.js').readDesktopSettings(path.join(userData,'desktop-settings.json'));const w=BrowserWindow.fromId(${window.id});return{settings,notes:JSON.parse(fs.readFileSync(path.join(userData,'native-upgrade-synthetic/notes.json'),'utf8')),sentinel:fs.readFileSync(path.join(userData,'native-upgrade-synthetic/sentinel.bin')).toString('hex'),origin:w.webContents.getURL(),localStorage:await w.webContents.executeJavaScript("localStorage.getItem('osir.native-upgrade.synthetic')")}})()`);
      check(fingerprint(observed.settings) === fingerprint(seed.settings) && fingerprint(observed.notes) === fingerprint(seed.synthetic) && observed.sentinel === seed.synthetic.nonce && observed.localStorage === seed.localStorage && observed.origin === seed.origin, 'Final native app did not preserve seeded preferences/files/renderer storage');
      return { dataPreserved: true, baselineVersion: seed.baselineVersion, finalVersion: state.version, sameInstallPath: installed.executable === this.baselineInstalled.executable, sameUserData: true, rendererStoragePreserved: true, observed };
    });
  }
  async discovery() {
    return this.session(this.finalInstalled, 'discovery', async inspector => inspector.evaluate(`(${packagedDiscoveryProbe.toString()})()`));
  }
}

export async function createUpgradeAdapter(context) {
  const work = join(context.output, 'work'); await mkdir(work, { mode: 0o700 });
  const env = smokeEnvironment(process.env, context.accountHome, work);
  // This authorized mode makes no offline/network isolation claim.
  delete env.UV_OFFLINE;
  for (const key of ['APPDATA', 'LOCALAPPDATA', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TMPDIR', 'CODEX_HOME', 'CLAUDE_CONFIG_DIR', 'ZDOTDIR', 'AGENT_CONNECTOR_DATA_DIR', 'UV_CACHE_DIR']) await mkdir(env[key], { recursive: true, mode: 0o700 });
  const appData = process.platform === 'win32' ? env.APPDATA : join(context.accountHome, 'Library/Application Support');
  return new UpgradeAdapter({ ...context, work, env, expectedUserData: join(appData, PRODUCT), allowedDataRoots: [appData] });
}

/** Serialized into the real packaged Electron MAIN inspector, not Node mocks. */
export async function packagedDiscoveryProbe() {
  const require = process.getBuiltinModule('module').createRequire(process.resourcesPath + '/app.asar/package.json');
  const { app } = require('electron'), fs = require('node:fs'), path = require('node:path');
  const { createHash, generateKeyPairSync, sign } = require('node:crypto');
  const servicePath = require.resolve('./dist/electron/desktop-updates.js');
  if (!app.isPackaged || app.getVersion() !== '2.2.0' || servicePath !== path.join(process.resourcesPath, 'app.asar/dist/electron/desktop-updates.js')) throw new Error('Expected final packaged native service');
  const { DesktopUpdateService } = require(servicePath), { RELEASE_MANIFEST_URL } = require('./dist/electron/release-manifest.js');
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const requests = [], stages = [], envelopes = []; let installerCalls = 0, version = '2.2.0', invalid = false, healthControl = 'before';
  const server = { serverUrl: 'http://127.0.0.1:47139', apiNamespace: '/api/v2', oauthWebOrigin: 'http://127.0.0.1:47139' };
  const directory = fs.mkdtempSync(path.join(app.getPath('userData'), 'native-patch-discovery-'));
  const fetcher = async (input, init) => {
    const url = String(input), method = init?.method ?? 'GET';
    if (url === RELEASE_MANIFEST_URL) {
      const extension = process.platform === 'darwin' ? 'dmg' : 'exe', arch = process.platform === 'darwin' ? 'universal' : process.arch;
      const filename = `synthetic-desktop-${version}-${arch}.${extension}`;
      const payload = Buffer.from(JSON.stringify({ schemaVersion: 1, productId: 'osir-anywhere', channel: 'stable', releaseId: 'native-acceptance', version,
        publishedAt: '2026-11-14T00:00:00Z', minimumServerVersion: '2.2.0', artifacts: [{ platform: process.platform, arch, filename,
          url: `https://osirvedio.cn-nb1.rains3.com/osir-anywhere/releases/native-acceptance/${filename}`, size: 1,
          sha256: createHash('sha256').update('x').digest('hex'), systemSignature: 'unsigned' }] }));
      const signature = sign('RSA-SHA256', payload, privateKey); if (invalid) signature[0] ^= 1;
      const envelope = { payload: payload.toString('base64'), signature: signature.toString('base64') };
      envelopes.push(envelope); requests.push({ kind: 'manifest', url, method, version, transport: 'synthetic-fetcher', invalidSignature: invalid });
      return Response.json(envelope);
    }
    if (url === server.serverUrl + '/api/v2/health') {
      requests.push({ kind: healthControl ? 'control-health' : 'health', purpose: healthControl ?? 'service-compatibility', url, method, version: '2.2.0', transport: 'synthetic-fetcher' });
      return Response.json({ status: 'ok', version: '2.2.0' });
    }
    throw new Error('Unexpected request; no network fallback');
  };
  const service = new DesktopUpdateService({ directory, currentVersion: app.getVersion(), manifestUrl: RELEASE_MANIFEST_URL, publicKeyPem,
    platform: process.platform, arch: process.arch, fetcher, onState: state => stages.push(state),
    prepareInstaller: async () => { installerCalls++; throw new Error('Downloads are forbidden in discovery'); },
    openInstaller: async () => { installerCalls++; throw new Error('Installer opening is forbidden in discovery'); } });
  try {
    const serverBefore = await (await fetcher(server.serverUrl + '/api/v2/health')).json(); healthControl = null;
    const baseline = await service.check(server); version = '2.2.1';
    const patch = await service.check(server); invalid = true;
    const invalidSignature = await service.check(server);
    healthControl = 'after'; const serverAfter = await (await fetcher(server.serverUrl + '/api/v2/health')).json();
    return { kind: 'packaged-native-service-integration', syntheticManifest: true, temporaryTestKey: true,
      serverVersionUnchanged: serverBefore.version === serverAfter.version,
      actualVersions: { desktop: app.getVersion(), manifestBaseline: baseline.latestVersion, manifestPatch: patch.latestVersion, serverBefore: serverBefore.version, serverAfter: serverAfter.version },
      packageVersion: require('./package.json').version, packaged: app.isPackaged, electron: process.versions.electron,
      servicePath, serviceSha256: createHash('sha256').update(fs.readFileSync(servicePath)).digest('hex'),
      baseline, patch, invalidSignature, requests, states: stages, installerCalls, publicKeyPem, envelopes, privateKeyPersisted: false };
  } finally { service.dispose(); }
}
