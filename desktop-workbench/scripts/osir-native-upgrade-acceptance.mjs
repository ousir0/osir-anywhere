#!/usr/bin/env node
// Test-only installer retention + packaged Desktop PATCH discovery. No release.
import { constants } from 'node:fs';
import { chmod, copyFile, lstat, mkdir, readFile, readdir, readlink, realpath, symlink, writeFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { assertNativeMachine, bindInputs, command, fileIdentity, fingerprintTree, NativeAdapter, validateSpec as validateSmokeSpec } from './osir-native-smoke.mjs';
import { buildEnvironment, dependencies, outputsFingerprint } from './osir-anywhere-build.mjs';
import { verifySource } from './osir-anywhere-source.mjs';
import { inspectSystemSignature } from './osir-anywhere-system-signature.mjs';
import { createDesktopPackageConfig } from './desktop-package-config.mjs';
import { desktopRuntimePackagePaths } from './desktop-runtime-packages.mjs';
import { nativeGuiProvenance, requireHostedRunner } from './osir-native-smoke-provision.mjs';
import { SHA, bytes, check, digest, fingerprint, json, separate, within } from './osir-anywhere-release-common.mjs';

export const BASELINE_VERSION = '2.1.0';
export const FINAL_VERSION = '2.2.0';
export const PATCH_VERSION = '2.2.1';
export const PACKAGE_PATH = 'desktop-workbench/package.json';
const SELF = fileURLToPath(import.meta.url);
export const BOUNDARIES = [
  'Controlled version-only derivative tests installer cross-version data protection; it is not a published 2.1.0 release or historical schema migration.',
  'Discovery executes the final packaged DesktopUpdateService with a constructor-injected synthetic RSA feed and unchanged synthetic Server; it does not certify production feed/key/network or renderer update UI.',
  'No real accounts, models, OAuth, interactive installation confirmation or bypass of OS protections is tested.',
  'macOS account-free cross-version fixture uses Chromium mock keychain for the ad-hoc baseline/final pair; real secret-store permissions and encrypted credential migration are not covered. Final production UI/SSO acceptance launches without this argument.',
];

// Reuse the shared native probe verbatim. A Windows timeout remains failed
// evidence, even if it contains exit 0 / JSON; only a fresh completed probe can
// establish hardware identity. This also covers preparation, before packaging.
export async function observeUpgradeHardware(context, { Adapter = NativeAdapter, platform = process.platform } = {}) {
  if (platform !== 'win32') return new Adapter(context).hardware();
  for (let attempt = 1; attempt <= 2; attempt++) {
    const probe = new Adapter({ ...context, evidence: (name, raw) => context.evidence(`hardware-attempt-${attempt}-${name}`, raw) });
    const run = probe.run.bind(probe);
    probe.run = (executable, args, label, extra = {}) => run(executable, args, label, {
      ...extra, ...(label === 'hardware-machine' ? { timeout: attempt === 1 ? 60000 : 120000 } : {}),
    });
    try { return await probe.hardware(); }
    catch (error) {
      if (attempt === 2 || error.message !== 'Native command timed out') throw error;
    }
  }
}

export function validateSpec(spec, mode = 'run') {
  validateSmokeSpec(spec, { requireIsolation: false });
  check(spec.expected.version === FINAL_VERSION, 'This controlled acceptance requires final Desktop 2.2.0');
  check(spec.runner.mode === undefined || spec.runner.mode === 'disposable-clean-runner', 'Upgrade helper only supports the explicitly authorized disposable-clean-runner policy');
  if (mode === 'prepare-baseline') {
    const source = spec.baselineSource;
    check(source && isAbsolute(source.checkout ?? '') && isAbsolute(source.compiledReceiptPath ?? '') && SHA.test(source.compiledReceiptSha256), 'Pinned frozen checkout and compiled receipt required');
    check(source.mode === undefined || ['compiled-checkout', 'final-installer-copy'].includes(source.mode), 'Unknown baseline compilation source');
    if (source.mode === 'final-installer-copy') check(isAbsolute(source.dependencyLockPath ?? ''), 'Artifact resolved dependency lock required');
  } else {
    check(isAbsolute(spec.baselineReceiptPath ?? '') && SHA.test(spec.baselineReceiptSha256), 'Pinned controlled baseline receipt required');
  }
  return spec;
}

/** Replace exactly one token while retaining every other source byte. */
export function versionOnlyDerivative(original) {
  const text = original.toString('utf8'), parsed = JSON.parse(text);
  check(parsed.version === FINAL_VERSION && parsed.name === 'osir-anywhere-desktop-workbench' && parsed.productName === 'OSIR Anywhere', 'Frozen package identity/version mismatch');
  const candidates = [...text.matchAll(/"version"\s*:\s*"2\.2\.0"/g)];
  check(candidates.length === 1, 'Ambiguous version token; refusing broad metadata rewrite');
  const token = candidates[0], offset = token.index + token[0].lastIndexOf(FINAL_VERSION);
  const changed = Buffer.from(`${text.slice(0, offset)}${BASELINE_VERSION}${text.slice(offset + FINAL_VERSION.length)}`);
  check(fingerprint({ ...JSON.parse(changed), version: FINAL_VERSION }) === fingerprint(parsed), 'Derivative changed non-version metadata');
  const byteOffset = Buffer.byteLength(text.slice(0, offset));
  check(original.subarray(0, byteOffset).equals(changed.subarray(0, byteOffset)) && original.subarray(byteOffset + FINAL_VERSION.length).equals(changed.subarray(byteOffset + BASELINE_VERSION.length)), 'Derivative changed other bytes');
  return { changed, metadataDiff: [{ path: PACKAGE_PATH, pointer: '/version', before: FINAL_VERSION, after: BASELINE_VERSION,
    byteOffset, beforeSha256: digest(original), afterSha256: digest(changed), beforeSize: original.length, afterSize: changed.length }] };
}

/** No hardlinks/shared dependency links: all symlinks are rebased into the copy. */
export async function copyIndependent(source, destination, sourceRoot, destinationRoot) {
  const stat = await lstat(source);
  check(within(sourceRoot, await realpath(source)), 'Copy input escapes frozen checkout');
  if (stat.isSymbolicLink()) {
    const target = resolve(dirname(source), await readlink(source));
    check(within(sourceRoot, target), 'Copy symlink escapes frozen checkout');
    const rebased = join(destinationRoot, relative(sourceRoot, target));
    await symlink(relative(dirname(destination), rebased), destination, process.platform === 'win32' ? ((await lstat(await realpath(source))).isDirectory() ? 'junction' : 'file') : undefined);
  } else if (stat.isDirectory()) {
    await mkdir(destination, { recursive: true, mode: stat.mode & 0o777 });
    for (const child of (await readdir(source)).sort()) await copyIndependent(join(source, child), join(destination, child), sourceRoot, destinationRoot);
  } else {
    check(stat.isFile(), 'Unsupported copy input');
    await mkdir(dirname(destination), { recursive: true });
    await copyFile(source, destination, constants.COPYFILE_EXCL);
    await chmod(destination, stat.mode & 0o777);
  }
}

export async function derivativeInventory(source, checkout, metadataDiff, platform = process.platform) {
  const entries = [];
  check(Array.isArray(metadataDiff) && metadataDiff.length === 1 && metadataDiff[0].path === PACKAGE_PATH, 'Only one source metadata difference allowed');
  for (const original of source.files) {
    const path = join(checkout, original.path), stat = await lstat(path);
    check(stat.isFile() && !stat.isSymbolicLink() && within(checkout, await realpath(path)), 'Derivative source must be a contained regular file');
    const identity = await fileIdentity(path, true);
    const expected = original.path === PACKAGE_PATH ? { sha256: metadataDiff[0].afterSha256, size: metadataDiff[0].afterSize } : original;
    // NTFS does not expose Git/POSIX executable bits. Retain the original Git
    // metadata in the inventory; only claim an on-disk mode check on POSIX.
    check(identity.sha256 === expected.sha256 && identity.size === expected.size && (platform === 'win32' || Boolean(stat.mode & 0o111) === original.executable), `Non-version derivative change: ${original.path}`);
    entries.push({ ...original, ...identity });
  }
  check(entries.some(file => file.path === PACKAGE_PATH), 'Source inventory lacks Desktop package metadata');
  return { sourceSha256: fingerprint(entries), files: entries };
}

async function freshOutput(output) {
  check(isAbsolute(output), 'Absolute fresh output directory required');
  await mkdir(output, { mode: 0o700 });
  return realpath(output);
}
export async function evidenceWriter(output, report) {
  return async (name, data) => {
    check(typeof name === 'string' && basename(name) === name, 'Unsafe evidence filename');
    await writeFile(join(output, name), data, { flag: 'wx', mode: 0o600 });
    report.evidence.push({ path: name, ...await fileIdentity(join(output, name)) });
  };
}

export async function prepareBaseline(spec, output) {
  validateSpec(spec, 'prepare-baseline');
  await requireHostedRunner();
  check(process.platform === spec.runner.nativeMachine.split('-')[0] && process.arch === spec.runner.nativeMachine.split('-')[1], 'Native CI platform/Node architecture mismatch');
  check(process.env.RUNNER_TEMP && within(await realpath(process.env.RUNNER_TEMP), await realpath(dirname(output))), 'Baseline packaging only under native CI RUNNER_TEMP');
  const checkout = await realpath(spec.baselineSource.checkout);
  separate(checkout, join(await realpath(dirname(output)), basename(output)));
  output = await freshOutput(output);
  const report = { schemaVersion: 1, kind: 'controlled-version-only-derivative', releaseEligible: false, historicalBaseline: false,
    result: 'failed', version: BASELINE_VERSION, sourceSha256: spec.expected.sourceSha256, target: spec.expected.target,
    parentArtifactSha256: spec.expected.artifactSha256, configSha256: spec.expected.configSha256,
    boundaries: BOUNDARIES, evidence: [], createdAt: new Date().toISOString() };
  const evidence = await evidenceWriter(output, report);
  try {
    const inputs = await bindInputs(spec), source = await verifySource(checkout);
    check(source.sourceSha256 === spec.expected.sourceSha256 && source.upstreamGitHead === spec.expected.upstreamGitHead, 'Frozen source does not match final installer');
    const head = await command('git', ['rev-parse', 'HEAD'], { cwd: checkout, env: buildEnvironment(process.env, {}) });
    check(head.code === 0 && head.stdout.trim() === spec.expected.checkoutHead, 'Frozen checkout commit mismatch');
    const root = join(checkout, 'desktop-workbench');
    const compiledPath = spec.baselineSource.compiledReceiptPath, compiledIdentity = await fileIdentity(compiledPath);
    check(compiledIdentity.sha256 === spec.baselineSource.compiledReceiptSha256, 'Compiled receipt changed');
    const compiled = await json(compiledPath), packaged = spec.baselineSource.mode === 'final-installer-copy';
    check(compiled.planSha256 === fingerprint(inputs.receipt.plan) && SHA.test(compiled.outputsSha256), 'Compiled receipt differs from final build plan');
    let outputs;
    if (!packaged) {
      outputs = await outputsFingerprint(root);
      check(compiled.outputsSha256 === outputs, 'Compiled outputs differ from final build');
      check(fingerprint(await dependencies(checkout)) === fingerprint(inputs.receipt.plan.dependencies), 'Final build dependency resolution/Node mismatch');
    }
    await evidence('parent-build-receipt.json', await readFile(spec.buildReceiptPath));
    await evidence('parent-system-signature.json', await readFile(spec.systemSignatureReportPath));
    await evidence('parent-source-provenance.json', await readFile(join(checkout, 'osir-source.json')));
    await evidence('compiled-receipt.json', await readFile(compiledPath));
    const copy = join(output, 'baseline-source'); await mkdir(copy);
    for (const file of source.files) await copyIndependent(join(checkout, file.path), join(copy, file.path), checkout, copy);
    const copiedRoot = join(copy, 'desktop-workbench');
    const env = { ...buildEnvironment(process.env, {}), CSC_IDENTITY_AUTO_DISCOVERY: 'false' };
    const hardware = await observeUpgradeHardware({ env, work: output, evidence });
    assertNativeMachine(spec.runner.nativeMachine, process.platform, process.arch, hardware.arch, hardware.translated);
    await evidence('native-gui.json', bytes(await nativeGuiProvenance(env)));
    let extracted;
    if (packaged) {
      const nativeSignature = await inspectSystemSignature(process.platform, spec.finalInstallerPath, inputs.artifact.sha256, env);
      check(nativeSignature.systemSignature === inputs.receipt.artifact.systemSignature, 'Original final signature differs from receipt');
      await evidence('extraction-final-system-signature.json', bytes(nativeSignature));
      const { extractPackagedOutputs } = await import('./osir-native-upgrade-acceptance.extract.mjs');
      extracted = await extractPackagedOutputs({ spec, inputs, root: copiedRoot, output, env, evidence });
      outputs = await outputsFingerprint(copiedRoot);
      await evidence('resolved-yarn.lock', await readFile(spec.baselineSource.dependencyLockPath));
    } else {
      // Original mutable dependency/build trees are copied, never shared.
      for (const name of ['dist', 'renderer/out', 'build/uv', 'build/python', 'node_modules', 'yarn.lock']) await copyIndependent(join(root, name), join(copiedRoot, name), checkout, copy);
      try { await copyIndependent(join(root, 'renderer/node_modules'), join(copiedRoot, 'renderer/node_modules'), checkout, copy); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    check(await outputsFingerprint(copiedRoot) === outputs, 'Copied compiled outputs changed');
    const rendererSha256 = await fingerprintTree(join(copiedRoot, 'renderer/out'));
    const original = await readFile(join(copy, PACKAGE_PATH));
    const derivative = versionOnlyDerivative(original); await writeFile(join(copy, PACKAGE_PATH), derivative.changed);
    report.metadataDiff = derivative.metadataDiff;
    await evidence('original-package.json', original);
    await evidence('derivative-package.json', derivative.changed);
    const inventory = await derivativeInventory(source, copy, derivative.metadataDiff);
    report.derivedSourceSha256 = inventory.sourceSha256;
    report.sourceExecutableModeVerified = process.platform !== 'win32';
    await evidence('derivative-source-inventory.json', bytes(inventory));
    await evidence('metadata-diff.json', bytes(derivative.metadataDiff));
    report.reusedOutputs = { mode: packaged ? 'final-installer-copy' : 'compiled-checkout', compiledReceiptSha256: compiledIdentity.sha256,
      parentCompiledOutputsSha256: compiled.outputsSha256, wholeCompiledTreeVerified: !packaged,
      outputsSha256: outputs, rendererSha256, rebuilt: false, ...(extracted ? { extracted } : {}) };
    const config = createDesktopPackageConfig((await json(join(copiedRoot, 'package.json'))).build, {
      platform: process.platform === 'darwin' ? 'mac' : 'win', arch: spec.expected.target.split('-')[1], runtimePackagePaths: desktopRuntimePackagePaths(copiedRoot), unsignedMac: process.platform === 'darwin',
    });
    config.directories = { ...config.directories, output: join(output, 'package') };
    // The exact Electron ABI and runtime modules already came from the final
    // build. Rebuilding/reinstalling them would invalidate the reuse claim.
    config.npmRebuild = false; config.nodeGypRebuild = false;
    if (extracted) config.electronVersion = extracted.electronVersion;
    config.artifactName = `TEST-ONLY-osir-anywhere-${BASELINE_VERSION}-${spec.expected.target}.\${ext}`;
    // This derivative is never signed with a production identity/key.
    if (process.platform === 'darwin') { config.mac.identity = '-'; config.mac.notarize = false; }
    if (config.win) { delete config.win.certificateFile; delete config.win.certificatePassword; delete config.win.sign; }
    const configPath = join(output, 'baseline-package-config.json'); await evidence(basename(configPath), bytes(config));
    // The reviewed acceptance harness supplies packaging tools in artifact-copy
    // mode. They do not become source or runtime dependencies of the product.
    const require = createRequire(packaged ? import.meta.url : join(copiedRoot, 'package.json'));
    let packaging;
    try {
      packaging = await command(process.execPath, [require.resolve('electron-builder/cli.js'), '--config', configPath,
        process.platform === 'darwin' ? '--mac' : '--win', process.platform === 'darwin' ? 'dmg' : 'nsis', `--${spec.expected.target.split('-')[1]}`, '--publish', 'never'],
      { cwd: copiedRoot, env, timeout: 30 * 60000 });
    } catch (error) { if (error.commandResult) await evidence('baseline-packaging-failure.json', bytes(error.commandResult)); throw error; }
    await evidence('baseline-packaging.json', bytes(packaging)); check(packaging.code === 0, 'Baseline native packaging failed');
    const installers = (await readdir(config.directories.output)).filter(name => name.endsWith(process.platform === 'darwin' ? '.dmg' : '.exe'));
    check(installers.length === 1 && installers[0].startsWith('TEST-ONLY-'), 'Expected one clearly test-only installer');
    const filename = installers[0], artifactPath = join(output, filename);
    await copyFile(join(config.directories.output, filename), artifactPath, constants.COPYFILE_EXCL);
    report.artifact = { filename, ...await fileIdentity(artifactPath) }; report.artifactSha256 = report.artifact.sha256;
    const signature = await inspectSystemSignature(process.platform, artifactPath, report.artifact.sha256, env);
    check(signature.systemSignature === 'unsigned', 'Test-only baseline unexpectedly acquired a publisher signature');
    report.artifact.systemSignature = signature.systemSignature;
    await evidence('baseline-system-signature.json', bytes(signature));
    report.systemSignatureReportSha256 = (await fileIdentity(join(output, 'baseline-system-signature.json'))).sha256;
    check((await derivativeInventory(source, copy, derivative.metadataDiff)).sourceSha256 === inventory.sourceSha256 && await outputsFingerprint(copiedRoot) === outputs && await fingerprintTree(join(copiedRoot, 'renderer/out')) === rendererSha256, 'Packaging changed source or compiled outputs');
    if (extracted) for (const subset of extracted.subsets) check(await fingerprintTree(join(copiedRoot, subset.path)) === subset.sha256, `Packaging changed extracted runtime subset: ${subset.path}`);
    check((await verifySource(checkout)).sourceSha256 === source.sourceSha256 && (packaged || await outputsFingerprint(root) === outputs), 'Original frozen checkout/outputs changed');
    check((await fileIdentity(spec.finalInstallerPath)).sha256 === inputs.artifact.sha256, 'Final installer changed');
    report.harness = [];
    for (const name of ['osir-native-upgrade-acceptance.mjs', 'osir-native-upgrade-acceptance.runtime.mjs', 'osir-native-upgrade-acceptance.extract.mjs']) report.harness.push({ path: name, ...await fileIdentity(new URL(name, import.meta.url)) });
    report.networkPolicy = 'unrestricted-no-product-credentials';
    report.packagingDifferences = ['test-only installer container rebuilt', 'app version resources generated for 2.1.0', ...(process.platform === 'darwin' ? ['valid ad-hoc signatures generated after packaging; classification remains unsigned'] : ['NSIS and PE version resources generated without Authenticode'])];
    report.result = 'prepared';
  } catch (error) { report.failure = String(error.message).slice(0, 600); }
  await writeFile(join(output, 'baseline-receipt.json'), bytes(report), { flag: 'wx', mode: 0o600 });
  return report;
}

export async function bindBaseline(spec) {
  check((await fileIdentity(spec.baselineReceiptPath)).sha256 === spec.baselineReceiptSha256, 'Baseline receipt digest mismatch');
  const baseline = await json(spec.baselineReceiptPath), root = await realpath(dirname(spec.baselineReceiptPath));
  check(baseline.schemaVersion === 1 && baseline.kind === 'controlled-version-only-derivative' && baseline.result === 'prepared' && baseline.version === BASELINE_VERSION && baseline.releaseEligible === false && baseline.historicalBaseline === false, 'Not a prepared controlled baseline');
  for (const key of ['sourceSha256', 'target', 'configSha256']) check(baseline[key] === spec.expected[key], `Baseline ${key} mismatch`);
  check(baseline.parentArtifactSha256 === spec.expected.artifactSha256 && SHA.test(baseline.derivedSourceSha256) && baseline.reusedOutputs?.rebuilt === false, 'Baseline derived from different final build');
  const diff = baseline.metadataDiff;
  check(Array.isArray(diff) && diff.length === 1 && diff[0].path === PACKAGE_PATH && diff[0].pointer === '/version' && diff[0].before === FINAL_VERSION && diff[0].after === BASELINE_VERSION && SHA.test(diff[0].beforeSha256) && SHA.test(diff[0].afterSha256), 'Baseline must have exactly one version-only metadata difference');
  check(baseline.artifact && basename(baseline.artifact.filename) === baseline.artifact.filename && baseline.artifact.filename.startsWith('TEST-ONLY-') && baseline.artifact.systemSignature === 'unsigned', 'Invalid test-only baseline artifact');
  const artifactPath = join(root, baseline.artifact.filename), artifact = await fileIdentity(artifactPath);
  check(artifact.sha256 === baseline.artifact.sha256 && artifact.sha256 === baseline.artifactSha256 && artifact.size === baseline.artifact.size, 'Baseline installer bytes mismatch');
  check(Array.isArray(baseline.evidence) && baseline.evidence.length > 0, 'Missing baseline derivation evidence');
  for (const name of ['original-package.json', 'derivative-package.json', 'parent-source-provenance.json', 'parent-build-receipt.json', 'compiled-receipt.json', 'derivative-source-inventory.json', 'metadata-diff.json', 'baseline-system-signature.json']) check(baseline.evidence.some(item => item.path === name), `Missing baseline raw evidence: ${name}`);
  for (const item of baseline.evidence) {
    check(basename(item.path) === item.path && SHA.test(item.sha256), 'Unsafe baseline evidence');
    const actual = await fileIdentity(join(root, item.path));
    check(within(root, await realpath(join(root, item.path))) && actual.sha256 === item.sha256 && actual.size === item.size, 'Baseline evidence changed');
  }
  const source = await json(join(root, 'parent-source-provenance.json'));
  const original = await readFile(join(root, 'original-package.json'));
  const derived = versionOnlyDerivative(original);
  check(derived.changed.equals(await readFile(join(root, 'derivative-package.json'))) && fingerprint(derived.metadataDiff) === fingerprint(diff), 'Raw baseline package metadata differs beyond the single version token');
  const inventory = await json(join(root, 'derivative-source-inventory.json'));
  check(source.sourceSha256 === spec.expected.sourceSha256 && fingerprint(source.files) === source.sourceSha256 && fingerprint(inventory.files) === baseline.derivedSourceSha256, 'Baseline source provenance mismatch');
  check(source.files.length === inventory.files.length && fingerprint(diff) === fingerprint(await json(join(root, 'metadata-diff.json'))), 'Baseline metadata evidence mismatch');
  for (const [i, before] of source.files.entries()) {
    const after = inventory.files[i];
    check(fingerprint(after) === fingerprint(before.path === PACKAGE_PATH ? { ...before, sha256: diff[0].afterSha256, size: diff[0].afterSize } : before), 'Baseline inventory includes a non-version change');
    if (before.path === PACKAGE_PATH) check(before.sha256 === diff[0].beforeSha256 && before.size === diff[0].beforeSize, 'Baseline original metadata binding mismatch');
  }
  const parent = await json(join(root, 'parent-build-receipt.json'));
  const compiled = await json(join(root, 'compiled-receipt.json'));
  check(parent.artifact.sha256 === spec.expected.artifactSha256 && fingerprint(parent.plan) === compiled.planSha256 && compiled.outputsSha256 === baseline.reusedOutputs.parentCompiledOutputsSha256 &&
    (baseline.reusedOutputs.mode === 'final-installer-copy' || compiled.outputsSha256 === baseline.reusedOutputs.outputsSha256), 'Baseline compiled-output provenance mismatch');
  check((await fileIdentity(join(root, 'compiled-receipt.json'))).sha256 === baseline.reusedOutputs.compiledReceiptSha256, 'Baseline compiled receipt digest mismatch');
  if (baseline.reusedOutputs.mode === 'final-installer-copy') {
    const extracted = await json(join(root, 'extracted-runtime-subsets.json'));
    check(fingerprint(extracted) === fingerprint(baseline.reusedOutputs.extracted) && extracted.finalArtifactSha256 === spec.expected.artifactSha256 && extracted.scope === 'final-packaged-runtime-subset' && extracted.rendererRebuilt === false && baseline.reusedOutputs.wholeCompiledTreeVerified === false, 'Packaged runtime extraction evidence mismatch');
    check((await fileIdentity(join(root, 'resolved-yarn.lock'))).sha256 === parent.plan.dependencies.lockSha256, 'Extracted runtime dependency lock mismatch');
  }
  const signaturePath = join(root, 'baseline-system-signature.json');
  const signature = await json(signaturePath);
  check((await fileIdentity(signaturePath)).sha256 === baseline.systemSignatureReportSha256 && signature.artifactSha256 === artifact.sha256 && signature.systemSignature === 'unsigned', 'Baseline signature report mismatch');
  return { baseline, artifactPath, root };
}

export async function runAcceptance(spec, output, { adapterFactory, isolationVerifier } = {}) {
  output = await freshOutput(output);
  const synthetic = Boolean(adapterFactory || isolationVerifier);
  const report = { ...(spec?.expected ?? {}), schemaVersion: 1, scope: 'native-upgrade-acceptance', evidenceMode: synthetic ? 'synthetic' : 'native',
    result: 'failed', nativeMachines: [], checks: { upgradeDataPreserved: false, updateDiscovery: false }, evidence: [], boundaries: BOUNDARIES,
    execution: { baselineInstallAttempted: false, finalInstallAttempted: false }, startedAt: new Date().toISOString() };
  const evidence = await evidenceWriter(output, report);
  try {
    validateSpec(spec);
    await evidence('upgrade-spec.json', bytes(spec));
    const inputs = await bindInputs(spec), controlled = await bindBaseline(spec);
    await evidence('build-receipt.json', await readFile(spec.buildReceiptPath));
    await evidence('reviewed-system-signature.json', await readFile(spec.systemSignatureReportPath));
    await evidence('baseline-receipt.json', await readFile(spec.baselineReceiptPath));
    for (const item of controlled.baseline.evidence) await evidence(`baseline-${item.path}`, await readFile(join(controlled.root, item.path)));
    report.baseline = { ...controlled.baseline, evidence: controlled.baseline.evidence.map(item => ({ ...item, path: `baseline-${item.path}` })) };
    report.scriptSha256 = (await fileIdentity(SELF)).sha256;
    const runtime = await import('./osir-native-upgrade-acceptance.runtime.mjs');
    const isolation = await (isolationVerifier ?? runtime.verifyUpgradeIsolation)(spec, { output, evidence });
    report.networkPolicy = isolation.networkPolicy;
    report.publicNetworkMayBeReachable = isolation.publicNetworkMayBeReachable;
    report.networkIsolationClaimed = false;
    report.offline = false;
    await evidence('runner-isolation.json', bytes(isolation));
    if (isolation.rawEvidence) for (const item of isolation.rawEvidence) await evidence(item.name, await readFile(item.path));
    const context = { spec, inputs, controlled, output, evidence, accountHome: isolation.home };
    const adapter = adapterFactory ? adapterFactory(context) : await runtime.createUpgradeAdapter(context);
    await adapter.hardware();
    report.nativeMachines = [spec.runner.nativeMachine];
    report.execution.baselineInstallAttempted = true;
    const baseline = await adapter.installBaseline();
    const seed = await adapter.seedBaseline(baseline);
    const before = await adapter.snapshot(seed);
    await evidence('data-before-upgrade.json', bytes(before));
    report.execution.finalInstallAttempted = true;
    const final = await adapter.installFinal();
    const installed = await adapter.snapshot(seed);
    check(fingerprint(before) === fingerprint(installed), 'Installer changed seeded data before final launch');
    await evidence('data-after-install.json', bytes(installed));
    const verified = await adapter.verifyFinal(final, seed);
    check(verified.dataPreserved === true && verified.baselineVersion === BASELINE_VERSION && verified.finalVersion === FINAL_VERSION && verified.sameInstallPath === true && verified.sameUserData === true && verified.rendererStoragePreserved === true, 'Native cross-version data preservation incomplete');
    const after = await adapter.snapshot(seed);
    check(fingerprint(before) === fingerprint(after), 'Final app changed seeded settings/data');
    await evidence('data-after-final-exit.json', bytes(after));
    await evidence('upgrade-observations.json', bytes(verified));
    report.checks.upgradeDataPreserved = true;
    report.discovery = await adapter.discovery();
    validateDiscovery(report.discovery);
    await evidence('desktop-discovery.json', bytes(report.discovery));
    report.checks.updateDiscovery = true;
    check((await fileIdentity(spec.finalInstallerPath)).sha256 === inputs.artifact.sha256 && (await fileIdentity(controlled.artifactPath)).sha256 === controlled.baseline.artifactSha256, 'Installer bytes changed during acceptance');
    if (synthetic) { report.simulatedChecks = { ...report.checks }; report.result = 'simulated'; }
    else report.result = 'passed';
  } catch (error) { report.failure = String(error.message).slice(0, 600); }
  finally {
    if (synthetic) { report.simulatedChecks ??= { ...report.checks }; report.checks = { upgradeDataPreserved: false, updateDiscovery: false }; }
    report.completedAt = new Date().toISOString();
    await writeFile(join(output, 'native-upgrade-acceptance.json'), bytes(report), { flag: 'wx', mode: 0o600 });
  }
  return report;
}

export function validateDiscovery(value) {
  check(value?.kind === 'packaged-native-service-integration' && value.syntheticManifest === true && value.temporaryTestKey === true && value.serverVersionUnchanged === true, 'Discovery scope/key/feed mismatch');
  check(fingerprint(value.actualVersions) === fingerprint({ desktop: FINAL_VERSION, manifestBaseline: FINAL_VERSION, manifestPatch: PATCH_VERSION, serverBefore: FINAL_VERSION, serverAfter: FINAL_VERSION }), 'Discovery version observations mismatch');
  check(value.baseline?.available === false && value.patch?.available === true && value.patch.latestVersion === PATCH_VERSION && value.patch.error === null && value.invalidSignature?.error === 'checkFailed', 'Desktop PATCH / negative signature controls failed');
  check(value.packageVersion === FINAL_VERSION && value.packaged === true && typeof value.electron === 'string' && SHA.test(value.serviceSha256) && /app\.asar[\\/]dist[\\/]electron[\\/]desktop-updates\.js$/.test(value.servicePath), 'Discovery did not execute the final ASAR service');
  check(Array.isArray(value.requests) && value.requests.length === 6 && value.requests.every(r => r.transport === 'synthetic-fetcher' && r.method === 'GET'), 'Discovery request evidence incomplete');
  check(value.requests.map(r => r.kind).join(',') === 'control-health,manifest,manifest,health,manifest,control-health' && value.requests.filter(r => r.kind.endsWith('health')).every(r => r.version === FINAL_VERSION) && value.installerCalls === 0, 'Discovery used an unexpected request/installer path');
  return value;
}

export function parseArguments(args) {
  const [action, ...rest] = args;
  check(['prepare-baseline', 'run'].includes(action), 'Use --help for exact CLI');
  const allowed = ['spec', 'output'];
  check(rest.length === allowed.length * 2, 'Unknown/missing CLI arguments');
  const options = { action };
  for (let i = 0; i < rest.length; i += 2) {
    const key = rest[i].slice(2);
    check(rest[i].startsWith('--') && allowed.includes(key) && options[key] === undefined && isAbsolute(rest[i + 1] ?? ''), 'Unknown/duplicate/non-absolute CLI argument');
    options[key] = rest[i + 1];
  }
  return options;
}

async function main() {
  if (process.argv.slice(2).join(' ') === '--help') {
    console.log('prepare-baseline --spec ABS --output NEW_ABS\nrun --spec ABS --output NEW_ABS\nRemote GitHub-hosted clean native GUI CI only. prepare reuses frozen compiled outputs or extracts them from the final installer, then packages test-only 2.1.0. run installs baseline and original final bytes. Network policy: unrestricted-no-product-credentials; public network may be reachable, never an offline claim. No production source writes or publish. See osir-native-upgrade-acceptance.md.'); return;
  }
  const options = parseArguments(process.argv.slice(2)), spec = await json(options.spec);
  let result;
  if (options.action === 'prepare-baseline') result = await prepareBaseline(spec, options.output);
  else {
    const runtime = await import('./osir-native-upgrade-acceptance.runtime.mjs');
    result = await runtime.provisionUpgrade(spec, options);
  }
  console.log(JSON.stringify({ result: result.result, failure: result.failure, output: options.output }));
  if (!['prepared', 'passed'].includes(result.result)) process.exitCode = 1;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main().catch(error => { console.error(`OSIR upgrade acceptance: ${String(error.message).slice(0, 600)}`); process.exitCode = 1; });
