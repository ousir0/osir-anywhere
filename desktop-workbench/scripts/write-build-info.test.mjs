import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, copyFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { buildInfo, writeBuildInfo } from './write-build-info.mjs';

const pyproject = '[project]\nname = "fixture"\nversion = "2.2.1"\n[tool.fixture]\nversion = "99.0.0"\n';

test('build-info binds Desktop version and uses only explicit recipe releaseRevision', () => {
  const info = recipe => buildInfo(pyproject, recipe, '2.2.0');
  assert.deepEqual(info(), { productId: 'osir-anywhere', desktopVersion: '2.2.0', revision: 0, serverVersion: '2.2.1' });
  assert.deepEqual(info({ releaseRevision: 3, config: {} }), { productId: 'osir-anywhere', desktopVersion: '2.2.0', revision: 3, serverVersion: '2.2.1' });
  assert.equal(info({ revision: 999 }).revision, 0, 'No guessing from other fields');
  for (const releaseRevision of [0, 65535]) assert.equal(info({ releaseRevision }).revision, releaseRevision);
  for (const releaseRevision of [-1, 1.5, '1', null, NaN, Infinity, 65536, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => info({ releaseRevision }), /releaseRevision/);
  }
  for (const recipe of [null, [], '3']) assert.throws(() => info(recipe), /releaseRevision/);
  for (const version of [undefined, null, '', 'latest']) assert.throws(() => buildInfo(pyproject, {}, version), /desktop version/);
  assert.throws(() => buildInfo('[tool.fixture]\nversion = "99"\n'), /project/);
});

test('explicit recipe writer rejects bad input without overwriting metadata', async t => {
  const root = await mkdtemp(join(tmpdir(), 'anywhere-build-info-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const recipePath = join(root, 'recipe.json'), pyprojectPath = join(root, 'pyproject.toml'), outputPath = join(root, 'build-info.json'), packagePath = join(root, 'package.json');
  await writeFile(pyprojectPath, pyproject);
  await writeFile(packagePath, '{"version":"2.2.1"}');
  await writeFile(recipePath, JSON.stringify({ releaseRevision: 4 }));
  assert.equal(writeBuildInfo({ recipePath, pyprojectPath, packagePath, outputPath }).revision, 4);
  const original = await readFile(outputPath, 'utf8');
  assert.equal(JSON.parse(original).revision, 4);
  await writeFile(recipePath, '{"releaseRevision":"4"}');
  assert.throws(() => writeBuildInfo({ recipePath, pyprojectPath, packagePath, outputPath }), /releaseRevision/);
  assert.equal(await readFile(outputPath, 'utf8'), original);
  assert.throws(() => writeBuildInfo({ recipePath: join(root, 'missing'), pyprojectPath, packagePath, outputPath }), { code: 'ENOENT' });
});

test('CLI accepts explicit recipe and ignores arbitrary revision environment variables', async t => {
  const root = await mkdtemp(join(tmpdir(), 'anywhere-build-info-cli-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const scripts = join(root, 'desktop-workbench/scripts');
  await mkdir(scripts, { recursive: true }); await mkdir(join(root, 'server')); await mkdir(join(root, 'home'));
  await copyFile(new URL('./write-build-info.mjs', import.meta.url), join(scripts, 'write-build-info.mjs'));
  await writeFile(join(root, 'server/pyproject.toml'), pyproject);
  await writeFile(join(root, 'desktop-workbench/package.json'), '{"version":"2.2.1"}');
  const recipePath = join(root, 'recipe.json'); await writeFile(recipePath, '{"releaseRevision":5}');
  const run = args => spawnSync(process.execPath, [join(scripts, 'write-build-info.mjs'), ...args], {
    cwd: root, env: { PATH: process.env.PATH, HOME: join(root, 'home'), OSIR_RELEASE_REVISION: '999', OSIR_ANYWHERE_RELEASE_REVISION: '999' }, encoding: 'utf8',
  });
  const output = join(root, 'desktop-workbench/build-info.json');
  const packaged = join(root, 'desktop-workbench/dist/build-info.json');
  const revision = async expected => {
    assert.equal(JSON.parse(await readFile(output, 'utf8')).revision, expected);
    assert.equal(await readFile(packaged, 'utf8'), await readFile(output, 'utf8'), 'actual packaged metadata matches the source metadata');
  };
  assert.equal(run([]).status, 0);
  await revision(0);
  assert.equal(run(['--recipe', recipePath]).status, 0);
  await revision(5);
  await writeFile(join(root, 'osir-build-recipe.json'), '{"releaseRevision":6}');
  assert.equal(run([]).status, 0);
  await revision(6);
  assert.equal(run([]).status, 0);
  await revision(6);
  await writeFile(join(root, 'osir-build-recipe.json'), '{"releaseRevision":"bad"}');
  assert.notEqual(run([]).status, 0, 'a malformed reviewed recipe never silently resets revision');
  await revision(6);
  assert.notEqual(run(['--revision', '999']).status, 0);
});
