#!/usr/bin/env node
// Independent CI harness: consume immutable build artifacts; never rebuild,
// repackage, re-sign, publish, or synthesize native acceptance.
import { execFileSync, spawn } from 'node:child_process';
import { copyFile, lstat, mkdir, readFile, readdir, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { SHA, bytes, check, digest, fingerprint, immutableFile, inspect, matches, within } from './osir-anywhere-release-common.mjs';
import { bindInputs, fingerprintTree, validateSpec } from './osir-native-smoke.mjs';
import { systemSignature } from './osir-anywhere-system-signature.mjs';

export const REPOSITORY = 'ousir0/osir-anywhere';
const COMMIT = /^[a-f0-9]{40}$/;
const WORKFLOW = '.github/workflows/osir-anywhere-native-build.yml';
const TARGETS = ['darwin-universal', 'win32-x64', 'win32-arm64'];
export const HARNESS_FILES = [
  '.github/workflows/osir-anywhere-artifact-acceptance.yml',
  ...['osir-artifact-acceptance-ci.mjs', 'osir-artifact-acceptance-ci.test.mjs', 'osir-native-smoke.mjs', 'osir-native-smoke-provision.mjs',
    'osir-anywhere-system-signature.mjs', 'osir-anywhere-release-common.mjs'].map(name => `desktop-workbench/scripts/${name}`),
];
const MACHINES = [
  { machine: 'darwin-arm64', target: 'darwin-universal', runner: 'macos-15', nodeArch: 'arm64' },
  { machine: 'darwin-x64', target: 'darwin-universal', runner: 'macos-15-intel', nodeArch: 'x64' },
  { machine: 'win32-x64', target: 'win32-x64', runner: 'windows-2022', nodeArch: 'x64' },
  { machine: 'win32-arm64', target: 'win32-arm64', runner: 'windows-11-arm', nodeArch: 'arm64' },
];
const json = async path => parseJson(await readFile(path));
const positive = value => Number.isSafeInteger(value) && value > 0;
function parseJson(raw) { try { return JSON.parse(raw); } catch { throw Error('Invalid acceptance JSON'); } }
function exact(value, keys, message) {
  check(value && !Array.isArray(value) && Object.keys(value).sort().join(',') === keys.sort().join(','), message);
}
function safeName(name) {
  check(typeof name === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$/.test(name) && !name.includes('..'), 'Unsafe evidence filename');
  return name;
}

export function reviewedBindings(raw, sha256) {
  check(SHA.test(sha256 ?? '') && digest(raw) === sha256, 'Reviewed bindings raw-byte SHA-256 mismatch');
  const value = parseJson(raw);
  exact(value, ['schemaVersion', 'repository', 'sourceCommit', 'sourceSha256', 'recipeSha256', 'configSha256', 'dependencyLockSha256', 'version', 'artifacts'], 'Unknown/missing artifact binding fields');
  check(value.schemaVersion === 1 && value.repository === REPOSITORY && COMMIT.test(value.sourceCommit), 'Only the reviewed dedicated repository/product commit is permitted');
  for (const key of ['sourceSha256', 'recipeSha256', 'configSha256', 'dependencyLockSha256']) check(SHA.test(value[key]), 'Invalid reviewed product fingerprint');
  check(/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/.test(value.version), 'Invalid reviewed product version');
  check(Array.isArray(value.artifacts) && value.artifacts.length > 0 && value.artifacts.length <= TARGETS.length, 'Reviewed artifact IDs required');
  const targets = new Set(), ids = new Set();
  for (const a of value.artifacts) {
    const keys = ['target', 'runId', 'runAttempt', 'artifactId', 'archiveSha256', 'receiptSha256', 'artifactSha256', 'artifactSize', 'systemSignatureReportSha256'];
    if (a.target === 'win32-arm64') keys.push('windowsArm64EvidenceSha256');
    exact(a, keys, 'Unknown/missing target artifact bindings');
    check(TARGETS.includes(a.target) && !targets.has(a.target) && !ids.has(a.artifactId), 'Duplicate/unknown target or artifact ID');
    targets.add(a.target); ids.add(a.artifactId);
    for (const key of ['runId', 'runAttempt', 'artifactId', 'artifactSize']) check(positive(a[key]), 'Positive artifact/run/size identity required');
    for (const key of ['archiveSha256', 'receiptSha256', 'artifactSha256', 'systemSignatureReportSha256', ...(a.target === 'win32-arm64' ? ['windowsArm64EvidenceSha256'] : [])]) check(SHA.test(a[key]), 'Explicit artifact/receipt/evidence digest required');
  }
  return value;
}

export function acceptanceMatrix(bindings, target = 'all') {
  check(target === 'all' || TARGETS.includes(target), 'Unknown acceptance target');
  const targets = target === 'all' ? ['darwin-universal', 'win32-x64'] : [target];
  for (const name of targets) check(bindings.artifacts.some(a => a.target === name), 'Selected target has no reviewed original artifact');
  return MACHINES.filter(m => targets.includes(m.target)).map(m => {
    const a = bindings.artifacts.find(a => a.target === m.target);
    return { ...m, artifactId: a.artifactId, runId: a.runId, runAttempt: a.runAttempt };
  });
}

export function verifyHarness(env, head) {
  check(env.GITHUB_ACTIONS === 'true' && env.RUNNER_ENVIRONMENT === 'github-hosted' && env.GITHUB_REPOSITORY === REPOSITORY, 'Disposable dedicated-repository CI harness required');
  check(COMMIT.test(env.OSIR_HARNESS_COMMIT ?? '') && head === env.OSIR_HARNESS_COMMIT && env.GITHUB_WORKFLOW_SHA === head, 'Dispatch workflow ref and checkout must equal the reviewed harness SHA');
  check(/^\d+$/.test(env.GITHUB_RUN_ID ?? '') && /^\d+$/.test(env.GITHUB_RUN_ATTEMPT ?? ''), 'Harness run identity required');
  // Harness SHA intentionally differs from the original product sourceCommit.
  return { repository: REPOSITORY, commit: head, runId: Number(env.GITHUB_RUN_ID), runAttempt: Number(env.GITHUB_RUN_ATTEMPT) };
}

export async function verifyHarnessFiles(head, checkout = process.cwd(), files = HARNESS_FILES) {
  check(COMMIT.test(head), 'Exact harness commit required');
  const inventory = [];
  for (const path of files) {
    const identity = await inspect(join(checkout, path));
    let raw;
    try { raw = execFileSync('git', ['cat-file', 'blob', `${head}:${path}`], { cwd: checkout, stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 4 * 1024 * 1024 }); }
    catch { throw Error('Reviewed harness input is absent from its commit'); }
    check(digest(raw) === identity.sha256, 'Harness raw bytes differ from reviewed Git blob (including line-ending conversion)');
    inventory.push({ path, ...identity });
  }
  return inventory;
}

// Fixed API origin/path; no remote response body, headers, token, or transport
// exception is copied to diagnostics/evidence. Bounded metadata only.
export async function githubMetadata(path, token, fetcher = fetch) {
  check(/^\/repos\/ousir0\/osir-anywhere\/actions\/[A-Za-z0-9/?=&_-]+$/.test(path) && typeof token === 'string' && token.length > 0, 'Fixed repository API path and ephemeral token required');
  let response;
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 30000);
  try {
    try {
      response = await fetcher(`https://api.github.com${path}`, { signal: controller.signal, redirect: 'error', headers: {
        Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
      } });
    } catch { throw Error('GitHub metadata transport failed or timed out'); }
    check(response.status === 200, `GitHub metadata request failed (HTTP ${Number(response.status)})`);
    const chunks = []; let size = 0;
    try {
      for await (const chunk of response.body) {
        size += chunk.length; check(size <= 4 * 1024 * 1024, 'GitHub metadata response exceeds limit'); chunks.push(Buffer.from(chunk));
      }
    } catch { controller.abort(); throw Error('GitHub metadata read failed or exceeded limit'); }
    return parseJson(Buffer.concat(chunks));
  } finally { clearTimeout(timer); }
}

export function verifyProducer(bindings, artifact, run, remote, jobs) {
  check(run.id === artifact.runId && run.run_attempt === artifact.runAttempt && run.head_sha === bindings.sourceCommit && run.event === 'workflow_dispatch' && run.path === WORKFLOW && ['in_progress', 'completed'].includes(run.status), 'Producer run/attempt/workflow/commit mismatch');
  check(run.repository?.full_name === REPOSITORY && run.repository.private === true && run.head_repository?.full_name === REPOSITORY, 'Producer must be the reviewed private repository');
  check(remote.id === artifact.artifactId && remote.expired === false && remote.name === `osir-anywhere-${artifact.target}-${bindings.sourceCommit}-${artifact.runAttempt}` && positive(remote.size_in_bytes), 'Artifact ID/name/attempt invalid, empty or expired');
  check(remote.digest === `sha256:${artifact.archiveSha256}` && remote.workflow_run?.id === artifact.runId && remote.workflow_run.head_sha === bindings.sourceCommit && remote.workflow_run.repository_id === run.repository.id && remote.workflow_run.head_repository_id === run.repository.id, 'Archive digest or artifact producer identity mismatch');
  const label = artifact.target === 'darwin-universal' ? 'macos-15' : artifact.target === 'win32-x64' ? 'windows-2022' : 'windows-11-arm';
  const name = `build (${artifact.target}, ${label})`;
  check(jobs.some(j => j.name === name && j.status === 'completed' && j.conclusion === 'success' && j.head_sha === bindings.sourceCommit && j.run_id === artifact.runId && j.run_attempt === artifact.runAttempt && j.labels?.includes(label)), 'Exact native producer job did not succeed');
  // A different target may have failed; a successful immutable target remains
  // reusable without rerunning or rewriting its package.
  return { schemaVersion: 1, target: artifact.target, runId: run.id, runAttempt: run.run_attempt, runConclusion: run.conclusion,
    sourceCommit: run.head_sha, workflow: run.path, runStatus: run.status, artifactId: remote.id, artifactName: remote.name, archiveSha256: artifact.archiveSha256,
    nativeJob: { name, label, conclusion: 'success' } };
}

export async function verifyRemoteArtifacts(bindings, matrix, token, get = githubMetadata) {
  const evidence = [];
  for (const target of [...new Set(matrix.map(m => m.target))]) {
    const a = bindings.artifacts.find(a => a.target === target), base = `/repos/${REPOSITORY}/actions`;
    const [run, remote] = await Promise.all([
      get(`${base}/runs/${a.runId}/attempts/${a.runAttempt}`, token), get(`${base}/artifacts/${a.artifactId}`, token),
    ]);
    const jobs = [];
    for (let page = 1; ; page++) {
      check(page <= 10, 'Producer job metadata pagination exceeds limit');
      const response = await get(`${base}/runs/${a.runId}/attempts/${a.runAttempt}/jobs?per_page=100&page=${page}`, token);
      check(Array.isArray(response.jobs) && Number.isSafeInteger(response.total_count), 'Invalid producer jobs metadata');
      jobs.push(...response.jobs); if (jobs.length >= response.total_count) break;
      check(response.jobs.length > 0, 'Truncated producer jobs metadata');
    }
    evidence.push(verifyProducer(bindings, a, run, remote, jobs));
  }
  return evidence;
}

export async function unpackProductArchive(bindings, machine, download, output) {
  const identity = MACHINES.find(m => m.machine === machine), a = bindings.artifacts.find(a => a.target === identity?.target);
  check(a && isAbsolute(download) && isAbsolute(output) && !within(download, output) && !within(output, download), 'Original archive requires independent download/extraction paths');
  const names = await readdir(download); check(names.length === 1, 'Exactly one original artifact archive required'); safeName(names[0]);
  const archive = join(download, names[0]), actual = await inspect(archive);
  check(actual.sha256 === a.archiveSha256, 'Full original artifact archive digest mismatch');
  const filename = `osir-anywhere-${bindings.version}-${a.target}.${a.target.startsWith('darwin') ? 'dmg' : 'exe'}`;
  const allowed = ['build-receipt.json', 'compiled.json', 'source-provenance.json', 'system-signature.json', 'resolved-yarn.lock', filename];
  await mkdir(output, { mode: 0o700 });
  const python = `import json,pathlib,stat,sys,zipfile\na=pathlib.Path(sys.argv[1]);d=pathlib.Path(sys.argv[2]);allowed=set(json.loads(sys.argv[3]))\nwith zipfile.ZipFile(a) as z:\n m=z.infolist()\n if len(m)!=len(allowed) or {x.filename for x in m}!=allowed or sum(x.file_size for x in m)>8*1024**3: raise ValueError('unexpected product archive inputs')\n for x in m:\n  if x.is_dir() or stat.S_ISLNK(x.external_attr>>16) or x.file_size<=0 or x.flag_bits&1: raise ValueError('unsafe product archive member')\n z.extractall(d)\n`;
  try { execFileSync(process.platform === 'win32' ? 'python' : 'python3', ['-I', '-c', python, archive, output, JSON.stringify(allowed)], { stdio: 'ignore', timeout: 300000 }); }
  catch { throw Error('Original artifact archive extraction failed'); }
  return actual;
}

export async function bindDownloadedArtifact(bindings, machine, directory, output) {
  const identity = MACHINES.find(m => m.machine === machine);
  check(identity && isAbsolute(directory) && isAbsolute(output) && !within(directory, output), 'Native machine, original download and independent output required');
  const a = bindings.artifacts.find(a => a.target === identity.target); check(a, 'Machine has no reviewed build artifact');
  const receiptPath = join(directory, 'build-receipt.json');
  check((await inspect(receiptPath)).sha256 === a.receiptSha256, 'Original build receipt digest mismatch');
  const receipt = await json(receiptPath), p = receipt.plan;
  check(receipt.schemaVersion === 1 && p && receipt.artifact, 'Invalid original build receipt');
  for (const key of ['sourceSha256', 'configSha256', 'recipeSha256', 'version']) check(p[key] === bindings[key], 'Build receipt differs from reviewed product bindings');
  check(p.checkoutHead === bindings.sourceCommit && p.target === a.target && p.dependencies?.lockSha256 === bindings.dependencyLockSha256, 'Build receipt commit/target/shared dependency lock mismatch');
  check(String(receipt.runner?.runId) === String(a.runId) && receipt.runner.os === a.target.split('-')[0] && receipt.runner.arch === (a.target === 'win32-x64' ? 'x64' : 'arm64'), 'Build receipt native producer identity mismatch');
  safeName(receipt.artifact.filename);
  const expectedFiles = ['build-receipt.json', 'compiled.json', 'source-provenance.json', 'system-signature.json', 'resolved-yarn.lock', receipt.artifact.filename].sort();
  const names = (await readdir(directory)).sort();
  check(JSON.stringify(names) === JSON.stringify(expectedFiles), 'Original artifact contains missing or unexpected files');
  for (const name of names) { const s = await lstat(join(directory, name)); check(s.isFile() && !s.isSymbolicLink() && s.nlink === 1, 'Original artifact contains a nonregular/linked file'); }
  const sourcePath = join(directory, 'source-provenance.json');
  check((await inspect(sourcePath)).sha256 === receipt.sourceProvenanceSha256, 'Source provenance bytes differ from receipt');
  const source = await json(sourcePath);
  check(source.schemaVersion === 1 && source.sourceSha256 === bindings.sourceSha256 && fingerprint(source.files) === source.sourceSha256 && source.upstreamGitHead === p.upstreamGitHead && COMMIT.test(p.upstreamGitHead), 'Product source inventory fingerprint mismatch');
  check(source.files.some(f => f.path === 'osir-build-recipe.json' && f.sha256 === bindings.recipeSha256), 'Reviewed recipe not bound by product source inventory');
  if (a.target === 'win32-arm64') check(p.windowsArm64EvidenceSha256 === a.windowsArm64EvidenceSha256 && source.files.some(f => f.sha256 === a.windowsArm64EvidenceSha256), 'Windows ARM64 dependency evidence mismatch');
  check((await inspect(join(directory, 'resolved-yarn.lock'))).sha256 === bindings.dependencyLockSha256, 'Resolved dependency lock bytes mismatch');
  const compiled = await json(join(directory, 'compiled.json'));
  check(compiled.planSha256 === fingerprint(p) && SHA.test(compiled.outputsSha256), 'Compiled receipt belongs to another build plan');
  const signaturePath = join(directory, 'system-signature.json'), report = await json(signaturePath);
  check(systemSignature(report) === receipt.artifact.systemSignature && report.systemSignature === receipt.artifact.systemSignature, 'Signature report cannot derive the claimed original system signature');
  const spec = { schemaVersion: 1, buildReceiptPath: receiptPath, finalInstallerPath: join(directory, receipt.artifact.filename), systemSignatureReportPath: signaturePath,
    expected: { sourceSha256: bindings.sourceSha256, configSha256: bindings.configSha256, checkoutHead: bindings.sourceCommit, upstreamGitHead: p.upstreamGitHead,
      version: bindings.version, target: a.target, artifactSha256: a.artifactSha256, artifactSize: a.artifactSize, systemSignatureReportSha256: a.systemSignatureReportSha256 }, runner: { nativeMachine: machine } };
  validateSpec(spec, { requireIsolation: false }); await bindInputs(spec);
  await immutableFile(output, bytes(spec));
  return spec;
}

function sameExpected(report, spec) {
  check(Object.keys(spec.expected).every(k => report.expected?.[k] === spec.expected[k]) && report.nativeMachine === spec.runner.nativeMachine, 'Warm cache is bound to different final bytes or architecture');
}
async function warmEvidence(spec, prep) {
  const report = await json(join(prep, 'dependency-cache.json'));
  check(report.schemaVersion === 1 && report.scope === 'native-smoke-dependency-cache' && report.result === 'prepared', 'Online dependency preparation did not succeed');
  sameExpected(report, spec);
  check(Array.isArray(report.evidence) && report.evidence.length > 0, 'Warm cache raw evidence missing');
  const names = new Set(['dependency-cache.json']);
  for (const item of report.evidence) {
    safeName(item.path); check(!names.has(item.path) && SHA.test(item.sha256) && positive(item.size), 'Invalid/duplicate warm cache raw evidence');
    names.add(item.path); await matches(join(prep, item.path), item);
  }
  check(names.has('connector-resolved-uv.lock'), 'Warm cache lacks the resolved Python dependency lock');
  return { report, names: [...names] };
}

export const STDERR_LIMIT = 16384;
export function sanitizedStderr(raw, env = process.env) {
  let text = Buffer.from(raw).subarray(0, STDERR_LIMIT).toString('utf8');
  for (const [key, value] of Object.entries(env)) {
    if (/token|password|secret|credential|api.?key/i.test(key) && typeof value === 'string' && value.length >= 8) text = text.split(value).join('[REDACTED]');
  }
  return text.replace(/\b(?:Bearer|Basic)\s+[^\s]+/gi, '[REDACTED authorization]')
    .replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi, '$1[REDACTED]@')
    .replace(/([?&](?:token|key|signature|sig|password|secret)=)[^\s&#]*/gi, '$1[REDACTED]')
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)\b/g, '[REDACTED]')
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '');
}

// Drain stderr without retaining unbounded output. Never serialize an exception
// object or the environment; only sanitized stderr and fixed process metadata.
export async function boundedArchiveCommand(tool, args, { cwd, env = process.env, timeout = 300000 } = {}) {
  return new Promise(resolveResult => {
    let child;
    try { child = spawn(tool, args, { cwd, stdio: ['ignore', 'ignore', 'pipe'], env, windowsHide: true }); }
    catch { resolveResult({ status: null, signal: null, spawnFailed: true, timedOut: false, stderr: '', stderrBytes: 0, stderrTruncated: false }); return; }
    let kept = 0, total = 0, timedOut = false, spawnFailed = false;
    const chunks = [], timer = setTimeout(() => { timedOut = true; child.kill(); }, timeout);
    child.stderr.on('data', chunk => {
      total += chunk.length;
      const part = chunk.subarray(0, Math.max(0, STDERR_LIMIT - kept));
      if (part.length) { chunks.push(part); kept += part.length; }
    });
    child.on('error', () => { spawnFailed = true; });
    child.on('close', (status, signal) => {
      clearTimeout(timer);
      resolveResult({ status, signal, spawnFailed, timedOut, stderr: sanitizedStderr(Buffer.concat(chunks), env), stderrBytes: total, stderrTruncated: total > kept });
    });
  });
}

export function cacheArchiveArguments(prep, names) {
  // A drive-qualified archive (D:\\...) is interpreted as a remote host by
  // Git for Windows GNU tar. The output cwd supplies its location portably.
  return ['-cf', 'offline-cache.tar', '-C', prep, 'cache', ...names];
}

export async function sealCache(spec, prep, output, harness) {
  check(isAbsolute(prep) && isAbsolute(output) && !within(prep, output) && !within(output, prep), 'Cache bundle must be independent of online preparation');
  const { report, names } = await warmEvidence(spec, prep);
  check(report.cache?.sha256 === await fingerprintTree(join(prep, 'cache')), 'Prepared offline cache tree changed');
  await bindInputs(spec); await mkdir(output, { mode: 0o700 });
  const archive = join(output, 'offline-cache.tar');
  // tar preserves uv cache links and executable permissions; upload-artifact's
  // own zip serialization is not used for the cache tree itself.
  const command = await boundedArchiveCommand('tar', cacheArchiveArguments(prep, names), { cwd: output });
  const passed = command.status === 0 && !command.spawnFailed && !command.timedOut;
  await immutableFile(join(prep, 'cache-archive-command.json'), bytes({ schemaVersion: 1, scope: 'native-cache-archive-command',
    harness, nativeMachine: spec.runner.nativeMachine, expected: spec.expected, tool: 'tar', operation: 'create', archivePathMode: 'relative-to-output-cwd',
    result: passed ? 'passed' : 'failed', ...command }));
  check(passed, 'Cache tar creation failed; bounded sanitized stderr preserved in warm/cache-archive-command.json');
  check(report.cache.sha256 === await fingerprintTree(join(prep, 'cache')), 'Cache changed while archiving');
  const transfer = { schemaVersion: 1, scope: 'native-offline-cache-transfer', harness, nativeMachine: spec.runner.nativeMachine, expected: spec.expected,
    originalReceiptSha256: (await inspect(spec.buildReceiptPath)).sha256, archive: await inspect(archive), reportSha256: (await inspect(join(prep, 'dependency-cache.json'))).sha256,
    cacheSha256: report.cache.sha256, evidence: await Promise.all(names.map(async path => ({ path, ...await inspect(join(prep, path)) }))) };
  await immutableFile(join(output, 'cache-transfer.json'), bytes(transfer)); return transfer;
}

export async function unpackCache(spec, bundle, output, harness) {
  check(isAbsolute(bundle) && isAbsolute(output) && !within(bundle, output) && !within(output, bundle), 'Offline cache extraction must use a new independent directory');
  check(JSON.stringify((await readdir(bundle)).sort()) === JSON.stringify(['cache-transfer.json', 'offline-cache.tar']), 'Unexpected cache transfer files');
  const transfer = await json(join(bundle, 'cache-transfer.json'));
  check(transfer.schemaVersion === 1 && transfer.scope === 'native-offline-cache-transfer' && fingerprint(transfer.harness) === fingerprint(harness), 'Cache transfer came from another reviewed harness/run/attempt');
  sameExpected(transfer, spec);
  check(transfer.originalReceiptSha256 === (await inspect(spec.buildReceiptPath)).sha256 && SHA.test(transfer.reportSha256) && SHA.test(transfer.cacheSha256), 'Cache transfer original receipt/report identity mismatch');
  await matches(join(bundle, 'offline-cache.tar'), transfer.archive);
  await mkdir(output, { mode: 0o700 });
  // Python is harness infrastructure only. Product probes use only the Python
  // bundled inside the original installer. filter=data rejects escaping links,
  // special files, traversal, and unsafe archive metadata before extraction.
  const python = `import pathlib,sys,tarfile\na=pathlib.Path(sys.argv[1]);d=pathlib.Path(sys.argv[2])\nwith tarfile.open(a,'r:') as t:\n m=t.getmembers()\n if len(m)>200000 or sum(x.size for x in m)>8*1024**3: raise ValueError('cache archive exceeds limits')\n for x in m:\n  p=pathlib.PurePosixPath(x.name)\n  if p.is_absolute() or '..' in p.parts or '\\\\' in x.name or not (x.isfile() or x.isdir() or x.issym() or x.islnk()): raise ValueError('unsafe cache member')\n t.extractall(d,filter='data')\n`;
  try { execFileSync(process.platform === 'win32' ? 'python' : 'python3', ['-I', '-c', python, join(bundle, 'offline-cache.tar'), output], { stdio: 'ignore', timeout: 300000 }); }
  catch { throw Error('Offline cache archive extraction failed'); }
  check((await inspect(join(output, 'dependency-cache.json'))).sha256 === transfer.reportSha256, 'Extracted cache report differs from pinned upstream report');
  const { report } = await warmEvidence(spec, output);
  check(report.cache?.sha256 === transfer.cacheSha256 && await fingerprintTree(join(output, 'cache')) === transfer.cacheSha256, 'Extracted offline cache tree fingerprint mismatch');
  check(Array.isArray(transfer.evidence), 'Missing transferred warm raw evidence');
  for (const item of transfer.evidence) { safeName(item.path); await matches(join(output, item.path), item); }
  await bindInputs(spec);
  return transfer;
}

export function verifySmokeReport(report, spec) {
  check(report.schemaVersion === 1 && report.scope === 'native-smoke' && report.evidenceMode === 'native' && report.result === 'passed' && report.releaseAcceptance === 'incomplete', 'Only actual passed partial native smoke may be collected');
  check(Object.keys(spec.expected).every(k => report[k] === spec.expected[k]) && JSON.stringify(report.nativeMachines) === JSON.stringify([spec.runner.nativeMachine]), 'Native smoke provenance/machine mismatch');
  check(['installer', 'launch', 'connector', 'python', 'uv'].every(k => report.checks?.[k] === true), 'Native smoke did not execute all five required checks');
  check(report.checks.upgradeDataPreserved === false && report.checks.updateDiscovery === false, 'Smoke cannot synthesize lifecycle acceptance');
  check(report.runnerMode === 'disposable-clean-runner' && report.networkPolicy === 'unrestricted-no-product-credentials' && report.networkIsolationClaimed === false && report.fullSmokeOfflineClaimed === false, 'Clean-runner smoke must accurately disclose reachable network and no isolation/full-offline claim');
  check(Array.isArray(report.evidence) && report.evidence.length > 0, 'Native smoke raw evidence required');
}

// Preserve raw reports/probes/screenshots, not duplicate installed apps, caches,
// or the private runtime work directory. A blocked/failed run stays failed.
export async function collectEvidence(spec, paths, output, harness, phase) {
  check(['warm', 'smoke'].includes(phase), 'Unknown evidence phase');
  await mkdir(output, { mode: 0o700 });
  const evidence = [], failures = [];
  async function preserve(file, name, identity) {
    const stat = await lstat(file); check(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 32 * 1024 * 1024, 'Raw CI evidence must be a bounded regular file');
    const actual = await inspect(file); if (identity) check(actual.sha256 === identity.sha256 && actual.size === identity.size, 'Raw native evidence digest mismatch');
    await mkdir(dirname(join(output, name)), { recursive: true, mode: 0o700 });
    await copyFile(file, join(output, name), (await import('node:fs')).constants.COPYFILE_EXCL);
    await matches(join(output, name), actual); evidence.push({ path: name, ...actual });
  }
  try { await bindInputs(spec); } catch { failures.push('Original installer/receipt/signature changed or failed binding'); }
  for (const [prefix, directory] of Object.entries(paths)) {
    try {
      for (const name of await readdir(directory)) {
        safeName(name); const file = join(directory, name), s = await lstat(file);
        if (s.isDirectory()) continue;
        if (!/\.(json|lock|sb|png|txt|log)$/.test(name)) continue;
        await preserve(file, `${prefix}/${name}`);
      }
    } catch (error) { if (error.code !== 'ENOENT') failures.push(`Could not preserve ${prefix} raw evidence`); }
  }
  try {
    if (phase === 'warm') {
      await warmEvidence(spec, paths.warm);
      const archiveCommand = await json(join(paths.warm, 'cache-archive-command.json'));
      check(archiveCommand.result === 'passed', 'Cache archive creation failed');
    }
    else {
      const report = await json(join(paths.smoke, 'native-smoke.json')); verifySmokeReport(report, spec);
      for (const item of report.evidence) { safeName(item.path); await matches(join(paths.smoke, item.path), item); }
      const provision = await json(join(paths.provision, 'provision-report.json'));
      check(provision.result === 'passed' && provision.runnerMode === 'disposable-clean-runner' && provision.networkPolicy === 'unrestricted-no-product-credentials' && provision.networkIsolationClaimed === false && provision.cleanup?.globalNetworkStateModified === false && provision.cleanup.networkPolicyRestorationRequired === false, 'Actual clean-runner provision did not pass or policy disclosure is incorrect');
    }
  } catch { failures.push(phase === 'warm' ? 'Online dependency preparation failed or lacked valid raw evidence' : 'Native clean-runner provision/smoke failed or lacked valid raw evidence'); }
  const report = { schemaVersion: 1, scope: 'artifact-acceptance-ci-evidence', phase, result: failures.length ? 'failed' : 'passed', releaseAcceptance: 'incomplete',
    harness, nativeMachine: spec.runner.nativeMachine, expected: spec.expected, originalReceiptSha256: (await inspect(spec.buildReceiptPath)).sha256, failures, evidence,
    boundaries: ['Product packages were consumed as original immutable inputs, never rebuilt/repackaged/re-signed.', 'Lifecycle upgrade/data preservation/update discovery and final release aggregation remain separate.', 'This harness does not certify interactive OS confirmation, real-account OAuth, production endpoints or model calls.'] };
  await immutableFile(join(output, 'evidence-index.json'), bytes(report)); return report;
}

async function main() {
  const [mode, machine, phase] = process.argv.slice(2);
  check(['plan', 'unpack-product', 'bind', 'seal-cache', 'unpack-cache', 'collect'].includes(mode), 'Use plan|unpack-product|bind|seal-cache|unpack-cache|collect; paths are isolated under RUNNER_TEMP');
  const env = process.env, head = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  const harness = verifyHarness(env, head), harnessFiles = await verifyHarnessFiles(head), raw = env.OSIR_ACCEPTANCE_BINDINGS;
  const bindings = reviewedBindings(raw, env.OSIR_ACCEPTANCE_BINDINGS_SHA256);
  check(isAbsolute(env.RUNNER_TEMP ?? ''), 'Absolute isolated runner temp required');
  const base = join(env.RUNNER_TEMP, 'osir-artifact-acceptance'); await mkdir(base, { recursive: true, mode: 0o700 });
  if (mode === 'plan') {
    const matrix = acceptanceMatrix(bindings, env.OSIR_ACCEPTANCE_TARGET ?? 'all');
    const producers = await verifyRemoteArtifacts(bindings, matrix, env.GH_TOKEN);
    await immutableFile(join(base, 'reviewed-bindings.json'), raw);
    await immutableFile(join(base, 'producer-evidence.json'), bytes({ schemaVersion: 1, harness, harnessFiles, bindingsSha256: digest(raw), producers }));
    check(env.GITHUB_OUTPUT, 'CI outputs unavailable');
    await import('node:fs/promises').then(fs => fs.appendFile(env.GITHUB_OUTPUT, `matrix=${JSON.stringify({ include: matrix })}\n`));
    console.log(JSON.stringify({ scope: 'artifact-acceptance-plan', machines: matrix.map(m => m.machine), bindingsSha256: digest(raw), productRebuilt: false })); return;
  }
  check(MACHINES.some(m => m.machine === machine) && process.platform === machine.split('-')[0] && process.arch === machine.split('-')[1], 'Native CI hardware/Node identity mismatch');
  acceptanceMatrix(bindings, env.OSIR_ACCEPTANCE_TARGET ?? 'all').find(m => m.machine === machine) || check(false, 'Machine is not selected');
  const specPath = join(base, 'base-spec.json'), original = join(base, 'original');
  if (mode === 'unpack-product') { await unpackProductArchive(bindings, machine, join(base, 'original-archive'), original); return; }
  if (mode === 'bind') {
    const spec = await bindDownloadedArtifact(bindings, machine, original, specPath);
    await immutableFile(join(base, 'harness-provenance.json'), bytes({ schemaVersion: 1, harness, bindingsSha256: digest(raw), machine,
      helperSha256: (await inspect(fileURLToPath(import.meta.url))).sha256, scripts: harnessFiles }));
    console.log(JSON.stringify({ scope: 'original-package-binding', expected: spec.expected, machine })); return;
  }
  const spec = await json(specPath); validateSpec(spec, { requireIsolation: false });
  const prep = join(base, 'warm'), bundle = join(base, 'cache-bundle'), offline = join(base, 'offline');
  if (mode === 'seal-cache') await sealCache(spec, prep, bundle, harness);
  if (mode === 'unpack-cache') {
    const transfer = await unpackCache(spec, bundle, offline, harness);
    check(env.GITHUB_ENV, 'CI environment output unavailable');
    await import('node:fs/promises').then(fs => fs.appendFile(env.GITHUB_ENV, `OSIR_CACHE_REPORT_SHA256=${transfer.reportSha256}\n`));
  }
  if (mode === 'collect') {
    const result = await collectEvidence(spec, { harness: base, warm: phase === 'warm' ? prep : offline, cache: bundle, smoke: join(base, 'smoke'), provision: join(base, 'smoke.provision') }, join(base, `${phase}-evidence`), harness, phase);
    console.log(JSON.stringify({ scope: result.scope, result: result.result, releaseAcceptance: result.releaseAcceptance, failures: result.failures }));
    if (result.result !== 'passed') process.exitCode = 1;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main().catch(error => {
  // Do not dump error objects, request URLs, response bodies or headers.
  console.error(`OSIR artifact acceptance: ${error instanceof SyntaxError ? 'Invalid acceptance JSON' : String(error.message).split(/[\r\n]/)[0].slice(0, 280)}`); process.exitCode = 1;
});
