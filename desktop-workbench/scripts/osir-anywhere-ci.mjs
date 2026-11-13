// Creates machine-local paths only AFTER checkout/source identity verification.
import { execFileSync } from 'node:child_process';
import { join, isAbsolute, resolve } from 'node:path';
import { appendFile, readFile } from 'node:fs/promises';
import { check, cli, digest, immutableFile, bytes, isMain, json, separate, SHA } from './osir-anywhere-release-common.mjs';
import { verifySource } from './osir-anywhere-source.mjs';
import { CONFIG_KEYS } from './osir-anywhere-build.mjs';

export function reviewedRecipe(raw, expectedSha256) {
  check(SHA.test(expectedSha256 ?? '') && digest(raw) === expectedSha256, 'Reviewed recipe raw-byte SHA-256 mismatch');
  const recipe = JSON.parse(raw);
  check(recipe && !Array.isArray(recipe) && Object.keys(recipe).every(k => ['releaseId', 'config', 'windowsArm64Evidence', 'oauthEvidence'].includes(k)), 'Recipe cannot contain sourceSha256/generated paths/unknown fields');
  check(typeof recipe.releaseId === 'string' && recipe.config && !Array.isArray(recipe.config) && Object.keys(recipe.config).every(k => CONFIG_KEYS.includes(k)), 'Recipe contains missing/unknown configuration');
  return recipe;
}
export async function verifyOAuthEvidence(checkout, source, recipe) {
  if (recipe.config.OSIR_ANYWHERE_OAUTH_CONTRACT_VERIFIED !== '1') return;
  const evidence = recipe.oauthEvidence;
  const required = ['docs/OSIR-ANYWHERE-CONNECTION-VERIFICATION-2026-11-13.md', 'docs/OSIR-ANYWHERE-ALIYUN-ROLLOUT-2026-11-13.md'];
  check(evidence?.basis === 'prior-contract-real-desktop-and-browser-verification' && evidence.scope === 'candidate-build-only' &&
    evidence.requiresFinalPackageReverification === true && Array.isArray(evidence.documents) && evidence.documents.length === required.length,
    'OAuth candidate gate requires reviewed real-verification evidence; synthetic AUTH tests are insufficient');
  for (const name of required) {
    const document = evidence.documents.find(d => d.path === name);
    check(document && SHA.test(document.sha256) && source.files.some(f => f.path === name && f.sha256 === document.sha256), 'OAuth evidence must be exact allowlisted source input');
    check(digest(await readFile(join(checkout, name))) === document.sha256, 'OAuth verification evidence bytes changed');
  }
}
export function runnerEnvironment(temp) {
  check(isAbsolute(temp ?? '') && !/[\r\n]/.test(temp), 'CI requires absolute isolated runner temp');
  return { OSIR_BUILD_SPEC: join(temp, 'build-spec.json'), YARN_CACHE_FOLDER: join(temp, 'osir-yarn-downloads'),
    ELECTRON_CACHE: join(temp, 'osir-electron-downloads'), ELECTRON_BUILDER_CACHE: join(temp, 'osir-builder-downloads') };
}
if (isMain(import.meta.url)) await cli(async () => {
  const [mode = 'spec', recipePath = resolve('osir-build-recipe.json'), output = join(process.env.RUNNER_TEMP ?? '', 'build-spec.json')] = process.argv.slice(2);
  check(['spec', 'lock'].includes(mode), 'CI mode must be spec or lock');
  check(isAbsolute(recipePath ?? '') && isAbsolute(output ?? ''), 'Usage: osir-anywhere-ci.mjs /absolute/reviewed-recipe.json /absolute/generated-build-spec.json');
  const checkout = process.cwd(), source = await verifySource(checkout);
  check(resolve(recipePath) === join(checkout, 'osir-build-recipe.json') && source.files.some(f => f.path === 'osir-build-recipe.json'), 'Recipe must be the exact allowlisted source input');
  separate(checkout, output);
  const head = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  check(/^[a-f0-9]{40}$/.test(process.env.OSIR_SOURCE_COMMIT ?? '') && head === process.env.OSIR_SOURCE_COMMIT, 'CI checkout must equal reviewed immutable SHA');
  check(process.env.GITHUB_WORKFLOW_SHA === head, 'Dispatch workflow ref must resolve to the same reviewed source commit');
  check(source.sourceSha256 === process.env.OSIR_SOURCE_SHA256, 'CI source fingerprint mismatch');
  const recipeBytes = await readFile(recipePath), recipe = reviewedRecipe(recipeBytes, process.env.OSIR_RECIPE_SHA256);
  await verifyOAuthEvidence(checkout, source, recipe);
  const pkg = await json(join(checkout, 'desktop-workbench/package.json'));
  const publicKey = await readFile(join(checkout, 'desktop-workbench/build/release-public.pub'));
  check(publicKey.includes('PUBLIC KEY'), 'Packaged manifest public key missing');
  check(process.env.RUNNER_TEMP, 'CI requires isolated runner temp');
  if (mode === 'lock') {
    const lock = await readFile(join(checkout, 'desktop-workbench/yarn.lock'));
    await immutableFile(join(process.env.RUNNER_TEMP, 'resolved-yarn.lock'), lock);
    check(process.env.GITHUB_OUTPUT, 'CI lock export requires job output');
    await appendFile(process.env.GITHUB_OUTPUT, `lock_sha256=${digest(lock)}\n`);
    await appendFile(process.env.GITHUB_OUTPUT, `lock_artifact_name=osir-anywhere-resolved-lock-${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}\n`);
    return;
  }
  await immutableFile(output, bytes({ checkout, checkoutHead: head, sourceSha256: source.sourceSha256, version: pkg.version,
    recipeSha256: digest(recipeBytes), dependencyLockSha256: process.env.OSIR_DEPENDENCY_LOCK_SHA256,
    releaseId: recipe.releaseId, config: recipe.config, windowsArm64Evidence: recipe.windowsArm64Evidence,
    stateDirectory: join(process.env.RUNNER_TEMP, 'osir-anywhere-build') }));
  check(process.env.GITHUB_ENV, 'CI spec requires environment output');
  await appendFile(process.env.GITHUB_ENV, Object.entries(runnerEnvironment(process.env.RUNNER_TEMP)).map(([key, value]) => `${key}=${value}\n`).join(''));
});
