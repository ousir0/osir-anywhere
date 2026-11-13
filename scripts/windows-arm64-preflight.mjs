import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { spawn } from 'node:child_process';

const repository = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const root = process.env.OSIR_PREFLIGHT_ROOT;
assert.ok(root, 'Isolated preflight directory is required');
assert.equal(process.platform, 'win32');
assert.equal(process.arch, 'arm64');
assert.equal(process.version, 'v22.23.2');
assert.ok(!existsSync(root), 'Preflight directory must be new');
const evidence = join(root, 'evidence');
mkdirSync(evidence, { recursive: true });
const report = {
  schemaVersion: 1, status: 'running', startedAt: new Date().toISOString(),
  commit: process.env.GITHUB_SHA, runId: process.env.GITHUB_RUN_ID, runAttempt: process.env.GITHUB_RUN_ATTEMPT,
  runner: { os: process.env.RUNNER_OS, arch: process.env.RUNNER_ARCH, image: process.env.ImageOS },
  requested: { node: '22.23.2', electron: '39.2.7', uv: '0.11.26', python: '3.12.14+20260929', target: 'aarch64-pc-windows-msvc' },
  stages: [], artifacts: [],
  scope: 'Native dependency preflight only. No release pointer, installed product, account login, Connector application CLI or authenticated session is changed or claimed.',
};
const save = () => writeFileSync(join(evidence, 'report.json'), JSON.stringify(report, null, 2) + '\n');
save();

async function hash(path) {
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(path)) digest.update(chunk);
  return digest.digest('hex');
}

async function command(name, executable, args, { cwd = root, env = process.env, timeout = 300_000, allowFailure = false } = {}) {
  const logPath = join(evidence, `${name}.log`);
  const log = createWriteStream(logPath);
  const child = spawn(executable, args, { cwd, env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  const record = (chunk) => { log.write(chunk); output = (output + chunk.toString()).slice(-200_000); process.stdout.write(chunk); };
  child.stdout.on('data', record);
  child.stderr.on('data', record);
  const timer = setTimeout(() => child.kill(), timeout);
  const exitCode = await new Promise((done, reject) => { child.once('error', reject); child.once('exit', (code) => done(code)); }).finally(() => { clearTimeout(timer); log.end(); });
  if (exitCode !== 0 && !allowFailure) throw new Error(`${name} exited ${exitCode}; see ${basename(logPath)}`);
  return { exitCode, output, log: basename(logPath) };
}

async function stage(name, action) {
  const item = { name, status: 'running', startedAt: new Date().toISOString() };
  report.stages.push(item); save();
  try { item.result = await action(); item.status = 'passed'; return item.result; }
  catch (error) { item.status = 'failed'; item.error = String(error.stack || error); console.error(item.error); return null; }
  finally { item.finishedAt = new Date().toISOString(); save(); }
}

async function download(url, destination) {
  await mkdir(dirname(destination), { recursive: true });
  const response = await fetch(url, { signal: AbortSignal.timeout(180_000) });
  assert.equal(response.status, 200, `Download failed: ${url}`);
  await pipeline(Readable.fromWeb(response.body), createWriteStream(destination));
  return destination;
}

function checksum(text, name) {
  const matches = text.split(/\r?\n/).map((line) => line.trim().match(/^([a-f0-9]{64})\s+\*?(.+)$/i)).filter((match) => match && match[2] === name);
  assert.equal(matches.length, 1, `Official checksum must list exactly ${name}`);
  return matches[0][1].toLowerCase();
}

async function verifiedArchive({ base, name, sums, pinned }) {
  const archive = await download(`${base}/${encodeURIComponent(name)}`, join(root, 'downloads', name));
  const checksumFile = await download(`${base}/${sums}`, join(evidence, `${name}.official-checksums.txt`));
  const text = await readFile(checksumFile, 'utf8');
  const expected = sums.endsWith('.sha256') ? text.match(/^([a-f0-9]{64})(?:\s|$)/i)?.[1].toLowerCase() : checksum(text, name);
  assert.match(expected || '', /^[a-f0-9]{64}$/);
  const actual = await hash(archive);
  assert.equal(actual, expected, `${name} official checksum mismatch`);
  assert.equal(actual, pinned, `${name} pinned release asset digest mismatch`);
  report.artifacts.push({ name, url: `${base}/${encodeURIComponent(name)}`, checksumUrl: `${base}/${sums}`, sha256: actual, expectedSha256: expected }); save();
  return archive;
}

const tar = join(process.env.SystemRoot, 'System32', 'tar.exe');
async function extract(archive, output, name) {
  await mkdir(output, { recursive: true });
  await command(`extract-${name}`, tar, ['-xf', archive, '-C', output]);
}

function machine(path) {
  const data = readFileSync(path);
  assert.equal(data.subarray(0, 2).toString(), 'MZ');
  const offset = data.readUInt32LE(60);
  assert.equal(data.subarray(offset, offset + 4).toString(), 'PE\0\0');
  const value = data.readUInt16LE(offset + 4);
  assert.equal(value, 0xaa64, `${basename(path)} is not native ARM64`);
  return '0xaa64';
}

async function find(rootPath, filename) {
  for (const entry of await readdir(rootPath, { withFileTypes: true })) {
    const candidate = join(rootPath, entry.name);
    if (entry.isFile() && entry.name === filename) return candidate;
    if (entry.isDirectory()) { const found = await find(candidate, filename); if (found) return found; }
  }
  return null;
}

try {
  await stage('native-node', async () => {
    const sums = await download('https://nodejs.org/download/release/v22.23.2/SHASUMS256.txt', join(evidence, 'node-SHASUMS256.txt'));
    const expected = checksum(await readFile(sums, 'utf8'), 'win-arm64/node.exe');
    const actual = await hash(process.execPath);
    assert.equal(actual, expected);
    return { platform: process.platform, arch: process.arch, version: process.version, sha256: actual, peMachine: machine(process.execPath) };
  });
  await stage('native-electron-main-and-renderer', async () => {
    const archive = await verifiedArchive({ base: 'https://github.com/electron/electron/releases/download/v39.2.7', name: 'electron-v39.2.7-win32-arm64.zip', sums: 'SHASUMS256.txt', pinned: '56c6f8d957239b7e8d5a214255f39007d44abc98f701ab61054afa83ad46e80f' });
    const destination = join(root, 'electron');
    await extract(archive, destination, 'electron');
    const executable = join(destination, 'electron.exe');
    machine(executable);
    const env = { ...process.env };
    delete env.ELECTRON_RUN_AS_NODE;
    await command('electron-launch', executable, [join(repository, 'scripts/windows-arm64-electron.cjs')], { env, timeout: 90_000 });
    const result = JSON.parse(await readFile(join(evidence, 'electron-runtime.json'), 'utf8'));
    assert.equal(result.platform, 'win32'); assert.equal(result.arch, 'arm64'); assert.equal(result.versions.electron, '39.2.7');
    return result;
  });
  const uv = await stage('native-uv', async () => {
    const archive = await verifiedArchive({ base: 'https://github.com/astral-sh/uv/releases/download/0.11.26', name: 'uv-aarch64-pc-windows-msvc.zip', sums: 'uv-aarch64-pc-windows-msvc.zip.sha256', pinned: '98246149741f558e25e45ecf2b0b20f34de0634269f2bf0dcb4012d4b6ba289a' });
    const destination = join(root, 'uv'); await extract(archive, destination, 'uv');
    const executable = await find(destination, 'uv.exe'); assert.ok(executable); machine(executable);
    const result = await command('uv-version', executable, ['--version']); assert.match(result.output, /^uv 0\.11\.26\b/m);
    return { executable, sha256: await hash(executable), peMachine: machine(executable), versionOutput: result.output.trim() };
  });
  const python = await stage('native-bundled-python', async () => {
    const archive = await verifiedArchive({ base: 'https://github.com/astral-sh/python-build-standalone/releases/download/20260929', name: 'cpython-3.12.14+20260929-aarch64-pc-windows-msvc-install_only_stripped.tar.gz', sums: 'SHA256SUMS', pinned: '0569fbe45713c68b034e3c1a1372f5cbb802927d3037395fb3cc94e46401704d' });
    const destination = join(root, 'python'); await extract(archive, destination, 'python');
    const executable = join(destination, 'python', 'python.exe'); machine(executable);
    const code = 'import sys,sysconfig,struct,json; assert sys.version_info[:3]==(3,12,14); assert sysconfig.get_platform()=="win-arm64"; assert struct.calcsize("P")==8; print(json.dumps({"version":sys.version,"platform":sysconfig.get_platform(),"executable":sys.executable}))';
    const result = await command('python-identity', executable, ['-I', '-c', code]);
    return { executable, sha256: await hash(executable), peMachine: machine(executable), identity: JSON.parse(result.output.trim()) };
  });
  if (uv && python) {
    const project = join(repository, 'inputs/connector/pyproject.toml');
    const source = JSON.parse(await readFile(join(repository, 'inputs/connector/source.json'), 'utf8'));
    assert.equal(await hash(project), source.sha256); report.connectorInput = source; save();
    const env = { ...process.env, UV_PYTHON_DOWNLOADS: 'never', UV_CACHE_DIR: join(root, 'uv-cache'), UV_NO_PROGRESS: '1' };
    for (const key of Object.keys(env)) if (/^(OSIR_|ANYWHERE_|CONNECTOR_)/.test(key) && key !== 'OSIR_PREFLIGHT_ROOT') delete env[key];
    const venv = join(root, 'connector-dependencies');
    const venvPython = join(venv, 'Scripts', 'python.exe');
    const resolved = join(evidence, 'connector-resolved.txt');
    const installed = await stage('resolve-and-install-exact-connector-dependencies', async () => {
      await command('uv-create-isolated-venv', uv.executable, ['--no-config', 'venv', '--python', python.executable, venv], { env });
      await command('uv-resolve-connector', uv.executable, ['--no-config', 'pip', 'compile', '--python', venvPython, '--default-index', 'https://pypi.org/simple/', '--no-build', '--generate-hashes', '--output-file', resolved, project], { env, timeout: 480_000 });
      await command('uv-install-connector', uv.executable, ['--no-config', 'pip', 'install', '--python', venvPython, '--default-index', 'https://pypi.org/simple/', '--no-build', '--require-hashes', '--requirement', resolved], { env, timeout: 480_000 });
      await command('uv-check-connector', uv.executable, ['--no-config', 'pip', 'check', '--python', venvPython], { env });
      await command('uv-freeze-connector', uv.executable, ['--no-config', 'pip', 'freeze', '--python', venvPython], { env });
      return { python: venvPython, inputSha256: source.sha256, resolvedSha256: await hash(resolved), index: 'https://pypi.org/simple/', sourceBuilds: 'disabled to test redistributable native wheels', config: 'explicit official index; original pyproject remains byte-identical' };
    });
    if (installed) {
      await stage('native-dependency-imports-and-cli', async () => {
        await command('python-dependency-imports-cli', venvPython, ['-I', join(repository, 'scripts/windows-arm64-python-probe.py')], { env, timeout: 300_000 });
        return JSON.parse(await readFile(join(evidence, 'python-native-dependencies.json'), 'utf8'));
      });
    } else {
      await stage('identify-specific-arm64-dependency-blockers', async () => {
        const code = 'import json,tomllib,sys; print(json.dumps(tomllib.load(open(sys.argv[1],"rb"))["project"]["dependencies"]))';
        const parsed = await command('read-exact-dependency-list', python.executable, ['-I', '-c', code, project], { env });
        const dependencies = JSON.parse(parsed.output.trim());
        const outcomes = [];
        for (let i = 0; i < dependencies.length; i++) {
          const input = join(root, `dependency-${i}.in`); await writeFile(input, dependencies[i] + '\n');
          const result = await command(`dependency-${i}`, uv.executable, ['--no-config', 'pip', 'compile', '--python', venvPython, '--default-index', 'https://pypi.org/simple/', '--no-build', input], { env, timeout: 90_000, allowFailure: true });
          outcomes.push({ requirement: dependencies[i], exitCode: result.exitCode, log: result.log, diagnostic: result.exitCode ? result.output : undefined });
        }
        await writeFile(join(evidence, 'dependency-diagnostics.json'), JSON.stringify(outcomes, null, 2));
        return outcomes;
      });
    }
  } else {
    report.stages.push({ name: 'connector-dependencies', status: 'blocked', reason: 'Required bundled uv or CPython failed; no substitute interpreter is allowed' });
  }
} catch (error) {
  report.stages.push({ name: 'preflight-orchestration', status: 'failed', error: String(error.stack || error) });
} finally {
  report.status = report.stages.every(({ status }) => status === 'passed') ? 'passed' : 'failed';
  report.finishedAt = new Date().toISOString(); save();
  console.log(JSON.stringify({ status: report.status, stages: report.stages.map(({ name, status }) => ({ name, status })) }, null, 2));
  process.exitCode = report.status === 'passed' ? 0 : 1;
}
