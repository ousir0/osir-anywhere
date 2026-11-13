import { spawnSync } from 'node:child_process';
import { copyFile, lstat, mkdir, readFile, readdir, readlink, realpath, rm, writeFile } from 'node:fs/promises';
import { join, resolve, isAbsolute } from 'node:path';
import { RELEASE_SECRET_VARIABLES, readMacReleaseCredentials, readWindowsReleaseCredentials } from './release-credentials.mjs';
import { resolveDesktopBuildConfig } from './desktop-build-config.mjs';
import { sourcePath, verifySource } from './osir-anywhere-source.mjs';
import { inspectSystemSignature } from './osir-anywhere-system-signature.mjs';
import { SHA, bytes, check, cli, digest, fingerprint, immutableFile, inspect, isMain, json, matches, safe, within } from './osir-anywhere-release-common.mjs';

export const CONFIG_KEYS = ['OSIR_IDENTITY_API_ORIGIN', 'OSIR_IDENTITY_WEB_ORIGIN', 'OSIR_ANYWHERE_API_ORIGIN', 'OSIR_ANYWHERE_OAUTH_WEB_ORIGIN', 'OSIR_ANYWHERE_OAUTH_CONTRACT_VERIFIED'];
const BUILD_KEYS = ['PATH', 'HOME', 'USERPROFILE', 'SystemRoot', 'SYSTEMROOT', 'COMSPEC', 'PATHEXT', 'TEMP', 'TMP', 'TMPDIR', 'LANG', 'LC_ALL', 'CI', 'GITHUB_ACTIONS', 'RUNNER_TEMP', 'ELECTRON_CACHE', 'ELECTRON_BUILDER_CACHE', 'YARN_CACHE_FOLDER', 'YARN_GLOBAL_FOLDER'];
export function buildEnvironment(env, config) {
  check(Object.keys(config).every(k => CONFIG_KEYS.includes(k)), 'Unknown build configuration variable');
  return { ...Object.fromEntries(BUILD_KEYS.filter(k => env[k] !== undefined).map(k => [k, env[k]])), ...config,
    YARN_ENABLE_IMMUTABLE_INSTALLS: 'false', YARN_ENABLE_SCRIPTS: 'false' };
}
export function run(command, args, cwd, env) {
  const result = spawnSync(command, args, { cwd, env, stdio: 'inherit', shell: process.platform === 'win32' && command.endsWith('.cmd') });
  check(!result.error && result.status === 0, `Build subprocess failed: ${command}`);
}
export async function outputsFingerprint(root) {
  const files = [];
  async function walk(name) {
    const path = join(root, name), stat = await lstat(path);
    if (stat.isSymbolicLink()) {
      check(within(root, await realpath(path)), 'Build output link escapes checkout');
      files.push({ path: name, symlink: await readlink(path) });
    } else if (stat.isDirectory()) {
      for (const entry of (await readdir(path)).sort()) await walk(`${name}/${entry}`);
    } else {
      check(stat.isFile(), 'Unsupported build output');
      files.push({ path: name, size: stat.size, sha256: digest(await readFile(path)) });
    }
  }
  for (const name of ['dist', 'renderer/out', 'build/uv', 'build/python']) await walk(name);
  return fingerprint(files);
}
export async function dependencies(checkout) {
  const root = join(checkout, 'desktop-workbench');
  // Lockfiles are exported evidence, never committed back to the source repo.
  const lock = await readFile(join(root, 'yarn.lock'));
  check(lock.length > 0, 'Install dependencies first; resolved yarn.lock is required');
  const state = await readFile(join(root, 'node_modules/.yarn-state.yml'));
  return { lockSha256: digest(lock), installStateSha256: digest(state), node: process.version };
}
export async function verifyWindowsArm64Evidence(checkout, source, evidence) {
  check(evidence && typeof evidence.reportPath === 'string' && SHA.test(evidence.reportSha256), 'Windows ARM64 requires a reviewed native runner/dependency report and SHA-256; boolean flags are insufficient');
  sourcePath(evidence.reportPath);
  check(source.files.some(f => f.path === evidence.reportPath && f.sha256 === evidence.reportSha256), 'ARM64 report must be a reviewed source input');
  const reportBytes = await readFile(join(checkout, evidence.reportPath));
  check(digest(reportBytes) === evidence.reportSha256, 'ARM64 dependency report changed');
  const report = JSON.parse(reportBytes);
  check(report.schemaVersion === 1 && report.result === 'passed' && report.runner?.label === 'windows-11-arm' && report.runner.platform === 'win32' &&
    report.runner.arch === 'arm64' && report.runner.runId && report.runner.runAttempt &&
    ['electron', 'python', 'uv', 'nativeDependencies'].every(k => report.checks?.[k] === true), 'Windows ARM64 native dependency evidence is incomplete');
  const required = ['desktop-workbench/package.json', 'desktop-workbench/renderer/package.json', 'connector/pyproject.toml', 'desktop-workbench/scripts/prepare-uv.mjs', 'desktop-workbench/scripts/prepare-python.mjs'];
  check(Array.isArray(report.inputs) && required.every(path => report.inputs.some(input => input.path === path && source.files.some(f => f.path === path && f.sha256 === input.sha256))), 'ARM64 preflight dependency inputs differ from this source');
  return evidence.reportSha256;
}
export async function buildPlan(spec, target) {
  check(['darwin-universal', 'win32-x64', 'win32-arm64'].includes(target), 'Unsupported build target');
  if (target === 'win32-arm64') {
    check(spec.windowsArm64Evidence?.reportPath && SHA.test(spec.windowsArm64Evidence.reportSha256), 'Windows ARM64 requires a reviewed native runner/dependency report and SHA-256');
  }
  check(isAbsolute(spec.checkout) && isAbsolute(spec.stateDirectory) && !within(spec.checkout, spec.stateDirectory) && !within(spec.stateDirectory, spec.checkout), 'Build state must be outside isolated checkout');
  const source = await verifySource(spec.checkout);
  check(source.sourceSha256 === spec.sourceSha256, 'Reviewed source fingerprint mismatch');
  const windowsArm64EvidenceSha256 = target === 'win32-arm64' ? await verifyWindowsArm64Evidence(spec.checkout, source, spec.windowsArm64Evidence) : undefined;
  safe(spec.releaseId); safe(spec.version);
  const root = join(spec.checkout, 'desktop-workbench');
  check((await json(join(root, 'package.json'))).version === spec.version, 'Build version mismatch');
  const config = resolveDesktopBuildConfig(await json(join(root, 'config.json')), spec.config ?? {});
  const environment = buildEnvironment({}, spec.config ?? {});
  check(environment.OSIR_ANYWHERE_OAUTH_CONTRACT_VERIFIED === '1', 'Production OAuth acceptance flag required');
  const deps = await dependencies(spec.checkout);
  check(spec.dependencyLockSha256 === deps.lockSha256, 'All targets require the same reviewed externally resolved dependency lock');
  const checkoutHead = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: spec.checkout, encoding: 'utf8' }).stdout?.trim();
  check(checkoutHead === spec.checkoutHead, 'Dedicated checkout SHA mismatch');
  return { schemaVersion: 1, releaseId: spec.releaseId, version: spec.version, target, sourceSha256: source.sourceSha256,
    upstreamGitHead: source.upstreamGitHead, checkoutHead, recipeSha256: spec.recipeSha256 ?? null, windowsArm64EvidenceSha256, configSha256: fingerprint(config), configEnvironmentSha256: fingerprint(spec.config ?? {}), dependencies: deps };
}
export async function assertCompiledBuild(root, target, environment) {
  const path = environment.OSIR_ANYWHERE_BUILD_SPEC;
  check(typeof path === 'string' && isAbsolute(path), '--skip-build requires OSIR_ANYWHERE_BUILD_SPEC from the isolated build tool');
  const spec = await json(path);
  check(await realpath(root) === await realpath(join(spec.checkout, 'desktop-workbench')), '--skip-build checkout mismatch');
  const plan = await buildPlan(spec, target);
  const compiled = await json(join(spec.stateDirectory, target, 'compiled.json'));
  check(compiled.planSha256 === fingerprint(plan) && compiled.outputsSha256 === await outputsFingerprint(root), '--skip-build source/config/dependency/output fingerprint mismatch');
}
export async function buildPrepare(spec, target, skipBuild = false) {
  const started = performance.now(), timings = {};
  const plan = await buildPlan(spec, target);
  const platform = target.startsWith('darwin') ? 'darwin' : 'win32';
  check(process.platform === platform && (target !== 'win32-arm64' || process.arch === 'arm64'), 'Build must run on native platform/architecture');
  const root = join(spec.checkout, 'desktop-workbench'), out = join(spec.stateDirectory, target);
  await mkdir(out, { recursive: true, mode: 0o700 });
  // Lock the checkout itself, not merely output. Build directories are shared by
  // upstream scripts; a target marker prevents sequential cross-target reuse too.
  const gitDirResult = spawnSync('git', ['rev-parse', '--absolute-git-dir'], { cwd: spec.checkout, encoding: 'utf8' });
  check(gitDirResult.status === 0, 'Cannot find isolated checkout Git directory');
  const gitDir = gitDirResult.stdout.trim(), lock = join(gitDir, 'osir-build.lock');
  await immutableFile(join(gitDir, 'osir-build-target.json'), bytes({ target, stateDirectory: await realpath(spec.stateDirectory) }));
  await mkdir(lock);
  try {
    const specPath = join(out, 'build-spec.json');
    await immutableFile(specPath, bytes(spec));
    const receiptPath = join(out, 'build-receipt.json');
    let receipt;
    try { receipt = await json(receiptPath); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (receipt) {
      check(fingerprint(receipt.plan) === fingerprint(plan), 'Successful package belongs to another source/config/dependency resolution');
      await matches(join(out, receipt.artifact.filename), receipt.artifact);
      return receipt;
    }
    const clean = buildEnvironment(process.env, spec.config ?? {});
    const compiledPath = join(out, 'compiled.json');
    const compileStarted = performance.now();
    if (skipBuild) {
      const compiled = await json(compiledPath);
      check(compiled.planSha256 === fingerprint(plan) && compiled.outputsSha256 === await outputsFingerprint(root), '--skip-build source/config/dependency/output fingerprint mismatch');
    } else {
      const targets = platform === 'darwin' ? 'darwin-arm64,darwin-x64' : target;
      const yarn = process.platform === 'win32' ? 'yarn.cmd' : 'yarn';
      run(yarn, ['bundle:uv'], root, { ...clean, UV_BUNDLE_TARGETS: targets });
      run(yarn, ['bundle:python'], root, { ...clean, PYTHON_BUNDLE_TARGETS: targets });
      run(yarn, ['build'], root, clean);
      await verifySource(spec.checkout);
      await immutableFile(compiledPath, bytes({ planSha256: fingerprint(plan), outputsSha256: await outputsFingerprint(root) }));
    }
    timings.compileAndRuntimeBundlesMs = Math.round(performance.now() - compileStarted);
    const signingEnv = { ...clean, ...Object.fromEntries([...RELEASE_SECRET_VARIABLES, 'CSC_IDENTITY_AUTO_DISCOVERY'].filter(k => process.env[k] !== undefined).map(k => [k, process.env[k]])) };
    const credentials = platform === 'darwin' ? readMacReleaseCredentials(signingEnv) : readWindowsReleaseCredentials(signingEnv);
    const signing = { status: credentials.signing.source === 'p12' || credentials.signing.identity ? 'signed' : 'unsigned', notarized: false };
    // Auto-discovery is disabled unless an explicit identity was supplied, so
    // a receipt never guesses whether a discovered certificate was used.
    if (signing.status === 'unsigned') signingEnv.CSC_IDENTITY_AUTO_DISCOVERY = 'false';
    signing.notarized = platform === 'darwin' && signing.status === 'signed' && credentials.notarization !== 'none';
    const attempt = await import('node:fs/promises').then(fs => fs.mkdtemp(join(out, 'package-')));
    const packageStarted = performance.now();
    run(process.execPath, ['scripts/dist-desktop.mjs', platform === 'darwin' ? 'mac' : 'win', `--${target.split('-')[1]}`, '--skip-build'], root,
      { ...signingEnv, OSIR_ANYWHERE_POC_OUTPUT_DIR: attempt, OSIR_ANYWHERE_BUILD_SPEC: specPath });
    await verifySource(spec.checkout);
    const installers = (await readdir(attempt)).filter(f => f.endsWith(platform === 'darwin' ? '.dmg' : '.exe'));
    check(installers.length === 1, 'Expected exactly one final platform installer');
    timings.packageSignNotarizeVerifyMs = Math.round(performance.now() - packageStarted);
    const filename = safe(`osir-anywhere-${spec.version}-${target}${platform === 'darwin' ? '.dmg' : '.exe'}`);
    const final = join(out, filename);
    await copyFile(join(attempt, installers[0]), final, (await import('node:fs')).constants.COPYFILE_EXCL);
    const artifact = { filename, ...await inspect(final) };
    const signatureReport = await inspectSystemSignature(platform, final, artifact.sha256, clean);
    artifact.systemSignature = signatureReport.systemSignature;
    check((signing.status === 'unsigned') === (artifact.systemSignature === 'unsigned'), 'Actual system signature differs from requested signing mode');
    signing.notarized = artifact.systemSignature === 'developer-id-notarized';
    await immutableFile(join(out, 'system-signature.json'), bytes(signatureReport));
    const sourceProvenance = await readFile(join(spec.checkout, 'osir-source.json'));
    await immutableFile(join(out, 'source-provenance.json'), sourceProvenance);
    await immutableFile(join(out, 'resolved-yarn.lock'), await readFile(join(root, 'yarn.lock')));
    timings.totalMs = Math.round(performance.now() - started);
    const result = { schemaVersion: 1, plan, artifact, signing, sourceProvenanceSha256: digest(sourceProvenance), systemSignatureReportSha256: digest(bytes(signatureReport)), timings, builtAt: new Date().toISOString(),
      runner: { os: process.platform, arch: process.arch, image: process.env.ImageOS ?? null, runId: process.env.GITHUB_RUN_ID ?? null } };
    await immutableFile(receiptPath, bytes(result));
    return result;
  } finally { await rm(lock, { recursive: true }); }
}
if (isMain(import.meta.url)) await cli(async () => {
  const [command, path, target, flag] = process.argv.slice(2);
  check(['plan', 'prepare'].includes(command) && isAbsolute(path ?? '') && (!flag || flag === '--skip-build'), 'Usage: osir-anywhere-build.mjs <plan|prepare> /absolute/build-spec.json <darwin-universal|win32-x64|win32-arm64> [--skip-build]');
  console.log(JSON.stringify(await (command === 'plan' ? buildPlan(await json(path), target) : buildPrepare(await json(path), target, flag === '--skip-build')), null, 2));
});
