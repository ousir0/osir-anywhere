#!/usr/bin/env node
// Glue for the independent, reviewed upgrade workflow. No product ref changes.
import { execFileSync } from 'node:child_process';
import { constants } from 'node:fs';
import { appendFile, copyFile, lstat, mkdir, readFile, readdir, realpath, symlink } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { HARNESS_FILES, acceptanceMatrix, reviewedBindings, verifyHarness, verifyHarnessFiles } from './osir-artifact-acceptance-ci.mjs';
import { bindInputs } from './osir-native-smoke.mjs';
import { bindBaseline, validateSpec } from './osir-native-upgrade-acceptance.mjs';
import { SHA, bytes, check, fingerprint, immutableFile, inspect, json, matches, within } from './osir-anywhere-release-common.mjs';

export const TOOL_VERSIONS = { 'electron-builder': '26.18.1', '@electron/asar': '3.4.1', typescript: '6.0.3' };
export const UPGRADE_FILES = [
  '.github/workflows/osir-anywhere-upgrade-acceptance.yml',
  ...['mjs', 'runtime.mjs', 'extract.mjs', 'test.mjs', 'ci.mjs', 'ci.test.mjs', 'md'].map(suffix => `desktop-workbench/scripts/osir-native-upgrade-acceptance.${suffix}`),
];
// Include transitive local imports; all bytes must match the dispatched Git SHA.
export const REVIEW_FILES = [...new Set([...HARNESS_FILES, ...UPGRADE_FILES,
  ...['osir-anywhere-build.mjs', 'osir-anywhere-source.mjs', 'desktop-package-config.mjs', 'desktop-runtime-packages.mjs',
    'release-credentials.mjs', 'desktop-build-config.mjs', 'osir-native-acceptance-aggregate.mjs'].map(name => `desktop-workbench/scripts/${name}`),
])];

function safeName(value) {
  check(typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$/.test(value) && !value.includes('..'), 'Unsafe transfer filename');
  return value;
}
async function regular(path, limit = Infinity) {
  const s = await lstat(path);
  check(s.isFile() && !s.isSymbolicLink() && s.nlink === 1 && s.size > 0 && s.size <= limit, 'Transfer input must be a nonempty regular file');
}
async function preserve(source, destination, identity, limit = 32 * 1024 * 1024) {
  await regular(source, limit);
  if (identity) await matches(source, identity);
  await copyFile(source, destination, constants.COPYFILE_EXCL);
  const actual = await inspect(destination);
  if (identity) check(actual.sha256 === identity.sha256 && actual.size === identity.size, 'Transferred bytes changed');
  return actual;
}

export async function linkTools(checkout, tools) {
  check(isAbsolute(checkout) && isAbsolute(tools) && !within(checkout, tools) && !within(tools, checkout), 'Packaging tools must be independent of product/harness source');
  const modules = join(await realpath(tools), 'node_modules');
  for (const [name, version] of Object.entries(TOOL_VERSIONS)) check((await json(join(modules, name, 'package.json'))).version === version, 'Independent tool version mismatch');
  const destination = join(checkout, 'desktop-workbench/node_modules');
  try { await lstat(destination); throw Error('Harness node_modules already exists; refusing replacement'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  await symlink(modules, destination, process.platform === 'win32' ? 'junction' : 'dir');
}

export async function prepareSpec(base, checkout, original) {
  // Checkout is the immutable product commit, never the independent harness.
  checkout = await realpath(checkout);
  const provenance = join(original, 'source-provenance.json'), destination = join(checkout, 'osir-source.json');
  try { await matches(destination, await inspect(provenance)); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    await preserve(provenance, destination, await inspect(provenance));
  }
  const spec = { ...base, runner: { ...base.runner, mode: 'disposable-clean-runner' }, baselineSource: {
    mode: 'final-installer-copy', checkout, compiledReceiptPath: join(original, 'compiled.json'),
    compiledReceiptSha256: (await inspect(join(original, 'compiled.json'))).sha256, dependencyLockPath: join(original, 'resolved-yarn.lock'),
  } };
  validateSpec(spec, 'prepare-baseline'); return spec;
}

export async function sealBaseline(spec, directory, output, harness) {
  const receiptPath = join(directory, 'baseline-receipt.json'), receiptIdentity = await inspect(receiptPath);
  const runSpec = { ...spec, baselineReceiptPath: receiptPath, baselineReceiptSha256: receiptIdentity.sha256 };
  const { baseline } = await bindBaseline(runSpec);
  await mkdir(output, { mode: 0o700 });
  const files = [{ path: 'baseline-receipt.json', ...receiptIdentity },
    { path: baseline.artifact.filename, size: baseline.artifact.size, sha256: baseline.artifact.sha256 }, ...baseline.evidence];
  const seen = new Set(['baseline-transfer.json']);
  for (const item of files) {
    safeName(item.path); check(!seen.has(item.path), 'Duplicate baseline transfer file'); seen.add(item.path);
    await preserve(join(directory, item.path), join(output, item.path), item, item.path === baseline.artifact.filename ? 8 * 1024 ** 3 : undefined);
  }
  const transfer = { schemaVersion: 1, scope: 'controlled-baseline-transfer', harness,
    nativeMachine: spec.runner.nativeMachine, expected: spec.expected, baselineReceiptSha256: receiptIdentity.sha256, files };
  await immutableFile(join(output, 'baseline-transfer.json'), bytes(transfer)); return transfer;
}

export async function runSpec(base, bundle, harness) {
  const transfer = await json(join(bundle, 'baseline-transfer.json'));
  check(transfer.schemaVersion === 1 && transfer.scope === 'controlled-baseline-transfer' && fingerprint(transfer.harness) === fingerprint(harness), 'Baseline came from a different harness/run/attempt');
  check(fingerprint(transfer.expected) === fingerprint(base.expected) && transfer.nativeMachine === base.runner.nativeMachine && SHA.test(transfer.baselineReceiptSha256), 'Baseline transfer product/machine mismatch');
  check(Array.isArray(transfer.files) && transfer.files.length > 2, 'Baseline transfer lacks raw evidence');
  const names = new Set(['baseline-transfer.json']);
  for (const item of transfer.files) {
    safeName(item.path); check(!names.has(item.path), 'Duplicate baseline transfer input'); names.add(item.path);
    await regular(join(bundle, item.path)); await matches(join(bundle, item.path), item);
  }
  check(JSON.stringify((await readdir(bundle)).sort()) === JSON.stringify([...names].sort()), 'Unexpected baseline transfer content');
  const spec = { ...base, runner: { ...base.runner, mode: 'disposable-clean-runner' },
    baselineReceiptPath: join(bundle, 'baseline-receipt.json'), baselineReceiptSha256: transfer.baselineReceiptSha256 };
  validateSpec(spec); await bindBaseline(spec); return spec;
}

export async function collectRaw(base, directory, output, harness, phase) {
  check(['prepare', 'run'].includes(phase), 'Unknown upgrade phase');
  await mkdir(output, { mode: 0o700 });
  const evidence = [], failures = [];
  try { await bindInputs(base); } catch { failures.push('Original final installer binding failed'); }
  let report;
  const reportName = phase === 'prepare' ? 'baseline-receipt.json' : 'native-upgrade-acceptance.json';
  try {
    report = await json(join(directory, reportName));
    for (const name of (await readdir(directory)).sort()) {
      safeName(name); const s = await lstat(join(directory, name)); if (s.isDirectory()) continue;
      if (!/\.(json|lock|png|txt|log)$/.test(name)) continue;
      const identity = await preserve(join(directory, name), join(output, name)); evidence.push({ path: name, ...identity });
    }
    check(Array.isArray(report.evidence), 'Missing raw evidence inventory');
    for (const item of report.evidence) { safeName(item.path); await matches(join(output, item.path), item); }
    if (phase === 'prepare') check(report.result === 'prepared', 'Controlled baseline preparation did not pass');
    else {
      check(report.schemaVersion === 1 && report.scope === 'native-upgrade-acceptance' && report.evidenceMode === 'native' && report.result === 'passed', 'Native upgrade was not actually passed');
      check(Object.keys(base.expected).every(k => report[k] === base.expected[k]) && fingerprint(report.nativeMachines) === fingerprint([base.runner.nativeMachine]), 'Native report product/machine mismatch');
      check(report.checks?.upgradeDataPreserved === true && report.checks?.updateDiscovery === true, 'Both native upgrade checks must execute');
    }
  } catch (error) { failures.push(String(error.message).split(/[\r\n]/)[0].slice(0, 240)); }
  const result = { schemaVersion: 1, scope: 'native-upgrade-ci-evidence', phase, result: failures.length ? 'failed' : 'passed',
    harness, expected: base.expected, nativeMachine: base.runner.nativeMachine, failures, evidence };
  await immutableFile(join(output, 'evidence-index.json'), bytes(result)); return result;
}

async function main() {
  const [mode, machine] = process.argv.slice(2), checkout = process.cwd(), env = process.env;
  check(['plan', 'verify', 'link-tools', 'prepare-spec', 'seal-baseline', 'run-spec', 'collect-prepare', 'collect-run'].includes(mode), 'Use plan|verify|link-tools|prepare-spec|seal-baseline|run-spec|collect-prepare|collect-run MACHINE');
  const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: checkout, encoding: 'utf8' }).trim();
  const harness = verifyHarness(env, head), files = await verifyHarnessFiles(head, checkout, REVIEW_FILES);
  const bindings = reviewedBindings(env.OSIR_ACCEPTANCE_BINDINGS, env.OSIR_ACCEPTANCE_BINDINGS_SHA256);
  const selected = acceptanceMatrix(bindings, env.OSIR_ACCEPTANCE_TARGET ?? 'all');
  check(isAbsolute(env.RUNNER_TEMP ?? ''), 'Absolute runner temp required');
  const root = join(env.RUNNER_TEMP, 'osir-artifact-acceptance'); await mkdir(root, { recursive: true, mode: 0o700 });
  if (mode === 'plan') {
    check(env.GITHUB_OUTPUT, 'Workflow outputs unavailable');
    await appendFile(env.GITHUB_OUTPUT, `source_commit=${bindings.sourceCommit}\n`);
    await immutableFile(join(root, 'upgrade-harness-provenance.json'), bytes({ schemaVersion: 1, harness, files, toolVersions: TOOL_VERSIONS })); return;
  }
  check(selected.some(m => m.machine === machine) && `${process.platform}-${process.arch}` === machine, 'Selected native machine required');
  if (mode === 'verify') return;
  if (mode === 'link-tools') return linkTools(checkout, join(env.RUNNER_TEMP, 'osir-upgrade-tools'));
  const base = await json(join(root, 'base-spec.json'));
  check(base.runner.nativeMachine === machine, 'Base spec machine mismatch'); await bindInputs(base);
  if (mode === 'prepare-spec') {
    const spec = await prepareSpec(base, resolve(checkout, '../frozen-source'), join(root, 'original'));
    await immutableFile(join(root, 'prepare-upgrade-spec.json'), bytes(spec)); return;
  }
  if (mode === 'seal-baseline') return sealBaseline(base, join(root, 'baseline'), join(root, 'baseline-bundle'), harness);
  if (mode === 'run-spec') {
    const spec = await runSpec(base, join(root, 'baseline-bundle'), harness);
    await immutableFile(join(root, 'run-upgrade-spec.json'), bytes(spec)); return;
  }
  const phase = mode === 'collect-prepare' ? 'prepare' : 'run';
  const result = await collectRaw(base, join(root, phase === 'prepare' ? 'baseline' : 'upgrade'), join(root, `${phase}-upgrade-evidence`), harness, phase);
  console.log(JSON.stringify({ scope: result.scope, result: result.result, failures: result.failures }));
  if (result.result !== 'passed') process.exitCode = 1;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main().catch(error => {
  console.error(`OSIR upgrade CI: ${String(error.message).split(/[\r\n]/)[0].slice(0, 300)}`); process.exitCode = 1;
});
