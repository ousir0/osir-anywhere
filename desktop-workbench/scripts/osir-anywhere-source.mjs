// Explicit file allowlist only. No archive of an operator's entire working tree.
import { execFileSync } from 'node:child_process';
import { chmod, copyFile, lstat, mkdir, readFile, realpath } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { check, cli, digest, fingerprint, immutableFile, isMain, json, bytes, within } from './osir-anywhere-release-common.mjs';

export function sourcePath(name) {
  check(typeof name === 'string' && name !== 'osir-source.json' && !isAbsolute(name) && !/[\\*?\[\]\r\n\0]/.test(name) && name.split('/').every(p => p && p !== '.' && p !== '..') &&
    !/(^|\/)(\.git|\.env[^/]*|node_modules|\.venv|\.config)(\/|$)/i.test(name) &&
    (!/\.(pem|key|p12|pfx)$/i.test(name)) && !/(rains3\.json|manifest-signing|credentials\.json)/i.test(name), 'Source allowlist contains forbidden path');
  return name;
}
export async function sourcePlan(spec) {
  check(isAbsolute(spec.checkout) && Array.isArray(spec.files) && spec.files.length > 0, 'Source needs checkout and explicit files allowlist');
  const root = await realpath(spec.checkout);
  const gitHead = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
  check(spec.gitHead === gitHead, 'Source Git HEAD differs from reviewed commit');
  const files = [];
  for (const name of [...new Set(spec.files)].sort()) {
    sourcePath(name);
    const file = join(root, name), stat = await lstat(file);
    check(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && within(root, await realpath(file)), 'Source must be regular allowlisted file');
    const data = await readFile(file);
    files.push({ path: name, sha256: digest(data), size: data.length, executable: Boolean(stat.mode & 0o111) });
  }
  return { schemaVersion: 1, upstreamGitHead: gitHead, sourceSha256: fingerprint(files), files };
}
export async function verifySource(root) {
  const source = await json(join(root, 'osir-source.json'));
  check(source.schemaVersion === 1 && /^[a-f0-9]{40}$/.test(source.upstreamGitHead) && fingerprint(source.files) === source.sourceSha256, 'Invalid source provenance');
  const seen = new Set();
  for (const file of source.files) {
    sourcePath(file.path); check(!seen.has(file.path), 'Duplicate source entry'); seen.add(file.path);
    const path = join(root, file.path), stat = await lstat(path);
    check(stat.isFile() && !stat.isSymbolicLink() && within(root, await realpath(path)), 'Source path is not contained regular file');
    const data = await readFile(path);
    check(data.length === file.size && digest(data) === file.sha256, `Frozen source changed: ${file.path}`);
  }
  // An extra tracked/untracked source could be imported by a build. Ignore only
  // Git-ignored dependency/build outputs; every visible input must be reviewed.
  const visible = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], { cwd: root }).toString().split('\0').filter(Boolean);
  for (const file of visible) check(file === 'osir-source.json' || seen.has(file), `Unreviewed source file: ${file}`);
  return source;
}
export async function sourcePrepare(spec) {
  const plan = await sourcePlan(spec);
  check(isAbsolute(spec.outputDirectory) && !within(spec.checkout, spec.outputDirectory) && !within(spec.outputDirectory, spec.checkout), 'Snapshot output must be outside checkout');
  await mkdir(spec.outputDirectory, { recursive: false, mode: 0o700 });
  for (const file of plan.files) {
    const dest = join(spec.outputDirectory, file.path);
    await mkdir(resolve(dest, '..'), { recursive: true });
    await copyFile(join(spec.checkout, file.path), dest);
    await chmod(dest, file.executable ? 0o755 : 0o644);
    check(digest(await readFile(dest)) === file.sha256, 'Source changed during snapshot');
  }
  await immutableFile(join(spec.outputDirectory, 'osir-source.json'), bytes(plan));
  return plan;
}
if (isMain(import.meta.url)) await cli(async () => {
  const [command, path] = process.argv.slice(2);
  check(['plan', 'prepare'].includes(command) && isAbsolute(path ?? ''), 'Usage: osir-anywhere-source.mjs <plan|prepare> /absolute/source-spec.json');
  console.log(JSON.stringify(await (command === 'plan' ? sourcePlan : sourcePrepare)(await json(path)), null, 2));
});
