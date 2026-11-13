// Reuse compilation from the byte-pinned FINAL installer, never rebuild it.
import { createRequire } from 'node:module';
import { mkdir, readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { asarJson, command, fileIdentity, fingerprintTree, validateWindowsMetadata } from './osir-native-smoke.mjs';
import { check, bytes, fingerprint } from './osir-anywhere-release-common.mjs';
import { copyIndependent, FINAL_VERSION } from './osir-native-upgrade-acceptance.mjs';

export function electronFromLock(text) {
  const versions = [...text.matchAll(/^\s+resolution:\s*["']?electron@npm:(\d+\.\d+\.\d+)["']?\s*$/gm)].map(match => match[1]);
  check(versions.length > 0 && new Set(versions).size === 1, 'Reviewed lock must resolve exactly one Electron version');
  return versions[0];
}

export function validateElectronFramework(metadata, electronVersion) {
  check(metadata.CFBundleIdentifier === 'com.github.Electron.framework' && metadata.CFBundlePackageType === 'FMWK', 'Original Electron framework identity mismatch');
  // The shipped Electron framework declares CFBundleVersion only. A present
  // marketing version must agree too; neither field may hide a wrong runtime.
  check(metadata.CFBundleVersion === electronVersion && (metadata.CFBundleShortVersionString === undefined || metadata.CFBundleShortVersionString === electronVersion), 'Packaged Electron differs from reviewed dependency lock');
}

export async function reuseExtractedRuntime(raw, resources, root) {
  for (const name of ['dist', 'renderer/out', 'node_modules']) await copyIndependent(join(raw, name), join(root, name), raw, root);
  for (const name of ['uv', 'python']) await copyIndependent(join(resources, name), join(root, 'build', name), resources, join(root, 'build'));
  const subsets = [];
  for (const name of ['dist', 'renderer/out', 'node_modules', 'build/uv', 'build/python']) subsets.push({ path: name, sha256: await fingerprintTree(join(root, name)) });
  return subsets;
}

export async function extractPackagedOutputs({ spec, inputs, root, output, env, evidence }) {
  const source = spec.baselineSource;
  check(source.dependencyLockPath, 'Final-installer-copy needs the artifact resolved-yarn.lock path');
  check((await fileIdentity(source.dependencyLockPath)).sha256 === inputs.receipt.plan.dependencies.lockSha256, 'Resolved dependency lock differs from final build');
  const electronVersion = electronFromLock(await readFile(source.dependencyLockPath, 'utf8'));
  if (source.electronVersion) check(source.electronVersion === electronVersion, 'Explicit Electron version differs from reviewed dependency lock');
  const run = async (executable, args, label, extra = {}) => {
    const result = await command(executable, args, { env, cwd: output, ...extra });
    await evidence(`${label}.json`, bytes(result)); check(result.code === 0, `Final package extraction ${label} failed`); return result.stdout;
  };
  let resources, mount, attached = false;
  try {
    if (process.platform === 'darwin') {
      mount = join(output, 'final-readonly-mount'); await mkdir(mount);
      await run('/usr/bin/hdiutil', ['attach', '-readonly', '-nobrowse', '-noautoopen', '-mountpoint', mount, spec.finalInstallerPath], 'extract-final-mount'); attached = true;
      const apps = (await readdir(mount)).filter(name => name.endsWith('.app'));
      check(apps.length === 1 && apps[0] === 'OSIR Anywhere.app', 'Original final DMG product mismatch');
      const contents = join(mount, apps[0], 'Contents'); resources = join(contents, 'Resources');
      const plist = JSON.parse(await run('/usr/bin/plutil', ['-convert', 'json', '-o', '-', join(contents, 'Info.plist')], 'extract-final-bundle'));
      check(plist.CFBundleIdentifier === 'com.osir.anywhere.desktop' && plist.CFBundleShortVersionString === FINAL_VERSION, 'Original final bundle identity/version mismatch');
      const framework = JSON.parse(await run('/usr/bin/plutil', ['-convert', 'json', '-o', '-', join(contents, 'Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist')], 'extract-electron-version'));
      validateElectronFramework(framework, electronVersion);
    } else {
      const destination = join(output, 'final-extraction-install');
      await run(spec.finalInstallerPath, ['/S', '/currentuser', `/D=${destination}`], 'extract-final-nsis', { timeout: 180000 });
      resources = join(destination, 'resources');
      const installedEnv = { ...env, OSIR_BASELINE_EXTRACT_EXE: join(destination, 'OSIR Anywhere.exe') };
      const metadata = JSON.parse(await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', "$ErrorActionPreference='Stop';$v=(Get-Item -LiteralPath $env:OSIR_BASELINE_EXTRACT_EXE).VersionInfo;@{ProductName=$v.ProductName;ProductVersion=$v.ProductVersion;FileVersion=$v.FileVersion}|ConvertTo-Json -Compress"], 'extract-final-pe', { env: installedEnv }));
      validateWindowsMetadata(metadata, FINAL_VERSION);
    }
    const archive = join(resources, 'app.asar'), pkg = await asarJson(archive, 'package.json');
    check(pkg.name === 'osir-anywhere-desktop-workbench' && pkg.version === FINAL_VERSION && pkg.productName === 'OSIR Anywhere' && pkg.main === 'dist/electron/main.js', 'Original ASAR identity/version mismatch');
    check(fingerprint(await asarJson(archive, 'dist/config.json')) === spec.expected.configSha256, 'Original ASAR endpoint configuration mismatch');
    const require = createRequire(import.meta.url), asar = require('@electron/asar');
    const raw = join(output, 'final-asar-extracted'); await mkdir(raw);
    asar.extractAll(archive, raw);
    // This is the exact shipped runtime subset, not the excluded tests/compiler
    // outputs represented by the original compiled.json whole-tree fingerprint.
    const subsets = await reuseExtractedRuntime(raw, resources, root);
    const record = { mode: 'final-installer-copy', finalArtifactSha256: inputs.artifact.sha256, finalAsar: await fileIdentity(archive),
      electronVersion, dependencyLockSha256: inputs.receipt.plan.dependencies.lockSha256, subsets,
      scope: 'final-packaged-runtime-subset', excludedCompilerAndTestOutputsReconstructed: false, rendererRebuilt: false };
    await evidence('extracted-runtime-subsets.json', bytes(record));
    return record;
  } finally { if (attached) await run('/usr/bin/hdiutil', ['detach', mount], 'extract-final-detach'); }
}
