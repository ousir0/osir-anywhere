/** Record packaged build metadata. Revision comes only from an explicit recipe. */
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export function buildInfo(pyproject, recipe = {}, desktopVersion) {
  const project = /^\[project\]\s*$([\s\S]*?)(?=^\[|(?![\s\S]))/m.exec(pyproject)?.[1] ?? '';
  const serverVersion = /^version\s*=\s*"([^"]+)"\s*$/m.exec(project)?.[1];
  if (!serverVersion) throw new Error('server/pyproject.toml has no [project] version.');
  if (!recipe || typeof recipe !== 'object' || Array.isArray(recipe) ||
      (recipe.releaseRevision !== undefined && (!Number.isSafeInteger(recipe.releaseRevision) || recipe.releaseRevision < 0 || recipe.releaseRevision > 65535))) {
    throw new Error('Recipe releaseRevision must be an integer in 0..65535 when supplied.');
  }
  if (typeof desktopVersion !== 'string' || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(desktopVersion)) {
    throw new Error('desktop-workbench/package.json has no valid desktop version.');
  }
  return { productId: 'osir-anywhere', desktopVersion, revision: recipe.releaseRevision ?? 0, serverVersion };
}

export function writeBuildInfo({ recipePath, pyprojectPath = new URL('../../server/pyproject.toml', import.meta.url),
  packagePath = new URL('../package.json', import.meta.url),
  outputPath } = {}) {
  // yarn build:info has no CLI args. Its one fixed reviewed source recipe must
  // survive every invocation; no environment variable can select the revision.
  let recipe;
  try { recipe = JSON.parse(readFileSync(recipePath ?? new URL('../../osir-build-recipe.json', import.meta.url), 'utf8')); }
  catch (error) { if (recipePath === undefined && error.code === 'ENOENT') recipe = {}; else throw error; }
  const info = buildInfo(readFileSync(pyprojectPath, 'utf8'), recipe, JSON.parse(readFileSync(packagePath, 'utf8')).version);
  const raw = `${JSON.stringify(info, null, 2)}\n`;
  writeFileSync(outputPath ?? new URL('../build-info.json', import.meta.url), raw);
  // Metadata is read natively, so tsc has no JSON import to copy into dist.
  // Every default build:info invocation must refresh the actual packaged file.
  if (outputPath === undefined) {
    mkdirSync(new URL('../dist/', import.meta.url), { recursive: true });
    writeFileSync(new URL('../dist/build-info.json', import.meta.url), raw);
  }
  return info;
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  const args = process.argv.slice(2);
  if (args.length && (args.length !== 2 || args[0] !== '--recipe' || !args[1])) {
    throw new Error('Usage: write-build-info.mjs [--recipe /path/to/reviewed-recipe.json]');
  }
  writeBuildInfo({ recipePath: args[1] });
}
