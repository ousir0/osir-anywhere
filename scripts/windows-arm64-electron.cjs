const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { app, BrowserWindow } = require('electron');

assert.equal(process.platform, 'win32');
assert.equal(process.arch, 'arm64');
assert.equal(process.versions.electron, '39.2.7');
app.disableHardwareAcceleration();
app.setPath('userData', path.join(process.env.OSIR_PREFLIGHT_ROOT, 'electron-user-data'));
const timer = setTimeout(() => app.exit(1), 60_000);
app.whenReady().then(async () => {
  const window = new BrowserWindow({ show: false, webPreferences: { sandbox: true, contextIsolation: true } });
  await window.loadURL('data:text/html,<title>OSIR ARM64 renderer preflight</title><p>local dependency probe</p>');
  const title = await window.webContents.executeJavaScript('document.title');
  assert.equal(title, 'OSIR ARM64 renderer preflight');
  const result = {
    platform: process.platform, arch: process.arch, versions: process.versions,
    windowId: window.id, rendererProcessId: window.webContents.getOSProcessId(), rendererTitle: title,
  };
  assert.ok(result.rendererProcessId > 0);
  fs.writeFileSync(path.join(process.env.OSIR_PREFLIGHT_ROOT, 'evidence', 'electron-runtime.json'), JSON.stringify(result, null, 2));
  clearTimeout(timer);
  window.destroy();
  app.quit();
}).catch((error) => {
  console.error(error);
  clearTimeout(timer);
  app.exit(1);
});
