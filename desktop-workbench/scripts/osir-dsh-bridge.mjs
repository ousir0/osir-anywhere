/** Offline host-only packaging; uses only Desktop's lock-bound TypeScript. */
import ts from 'typescript';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gzipSync } from 'node:zlib';

const desktop = resolve(fileURLToPath(new URL('..', import.meta.url)));
const repository = resolve(desktop, '..');
const plugin = join(repository, 'dsh-bridge-next');
const src = join(plugin, 'src');
const slash = p => p.split(sep).join('/');
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const entry = 'host/osir-index.ts';
const runtimeEntry = 'host/dsh-runtime/index.ts';
const service = 'host/dsh-runtime/bridge-service.ts';
const oldSelf = '@agents-anywhere/dsh-bridge-next/package.json';
const newSelf = '@osir/anywhere-dsh-bridge/package.json';
const versionFunction = `function packageVersion(specifier: string): string {
  try { return String(createRequire(import.meta.url)(specifier).version) || 'unknown' }
  catch { return 'unknown' }
}`;

function readInput(path) {
  const rel = relative(repository, path);
  assert.ok(rel && !rel.startsWith('..') && !rel.split(sep).some(p => p === 'node_modules'), 'Input outside product source');
  let current = repository;
  for (const part of rel.split(sep)) {
    current = join(current, part);
    assert.ok(!lstatSync(current).isSymbolicLink(), `Linked source rejected: ${rel}`);
  }
  assert.ok(lstatSync(path).isFile(), `Not a source file: ${rel}`);
  return readFileSync(path);
}

function allowedModule(p) {
  return [entry, 'host/osir-config.ts', 'host/storage/files.ts'].includes(p)
    || /^(?:host\/(?:dsh-runtime|generated)|contracts)\/[\w./-]+\.ts$/.test(p) && !p.split('/').includes('..');
}

/** Reject loaders that cannot be closed statically. Two audited metadata reads are the only exception. */
export function auditLoaders(source, file) {
  const ast = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  let metadataCalls = 0;
  if (file === service) {
    assert.ok(source.includes(versionFunction), 'Metadata loader changed: review its dependency closure');
    assert.equal((source.match(/\bpackageVersion\(/g) ?? []).length, 3, 'Unexpected metadata loader caller');
  }
  function walk(n) {
    if (ts.isIdentifier(n) && ['eval', 'require', 'Function', 'createRequire', 'packageVersion'].includes(n.text)) {
      const parent = n.parent;
      const inMetadataFunction = file === service && n.pos >= source.indexOf(versionFunction)
        && n.end <= source.indexOf(versionFunction) + versionFunction.length;
      const isLoaderImport = file === service && n.text === 'createRequire' && ts.isImportSpecifier(parent)
        && parent.parent.parent.parent.moduleSpecifier.text === 'node:module';
      const isMetadataCall = file === service && n.text === 'packageVersion' && ts.isCallExpression(parent)
        && parent.expression === n && parent.arguments.length === 1 && ts.isStringLiteral(parent.arguments[0])
        && [oldSelf, '@deepseek-ai/dsh-typert-protocol/package.json'].includes(parent.arguments[0].text);
      assert.ok(inMetadataFunction || isLoaderImport || isMetadataCall, `Unreviewed dynamic loader in ${file}: ${n.text}`);
      if (isMetadataCall) metadataCalls++;
    }
    if (ts.isCallExpression(n) && n.expression.kind === ts.SyntaxKind.ImportKeyword) {
      throw new Error(`Dynamic import needs an explicit packaging rule: ${file}`);
    }
    if (ts.isNewExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === 'URL'
      && n.arguments?.some(a => a.getText(ast) === 'import.meta.url')) {
      throw new Error(`File-relative asset needs an explicit packaging rule: ${file}`);
    }
    if (ts.isPropertyAccessExpression(n) && ['require', 'createRequire'].includes(n.name.text)) {
      throw new Error(`Computed module loader rejected: ${file}`);
    }
    ts.forEachChild(n, walk);
  }
  walk(ast);
  if (file === service) assert.equal(metadataCalls, 2, 'Missing audited version reads');
}

export function compileHost() {
  const manifestBytes = readInput(join(plugin, 'osir-package.json'));
  const manifest = JSON.parse(manifestBytes);
  assert.equal(manifest.name, '@osir/anywhere-dsh-bridge');
  assert.equal(manifest.version, '2.2.1');
  assert.equal(manifest.private, true);
  assert.deepEqual(manifest.dsh, { bundle: { patch: './cordis.patch.yml' } });
  assert.equal(manifest.scripts, undefined);
  assert.deepEqual(manifest.dependencies, { meshcall: '0.3.0' });
  const peers = new Set(Object.keys(manifest.peerDependencies));
  const usedPeers = new Set(['@deepseek-ai/dsh-typert-protocol']);
  const modules = new Map();
  const inputs = new Map();
  const input = p => {
    const bytes = readInput(p);
    inputs.set(slash(relative(repository, p)), { size: bytes.length, sha256: digest(bytes) });
    return bytes;
  };
  input(join(plugin, 'osir-package.json'));
  const patch = input(join(plugin, 'osir-cordis.patch.yml'));
  assert.equal(patch.toString(), "- insert:\n    - id: osir-anywhere-dsh-bridge\n      name: '@osir/anywhere-dsh-bridge'\n      config: {}\n");
  const readme = input(join(plugin, 'osir-README.md'));
  input(fileURLToPath(import.meta.url));
  const desktopManifest = JSON.parse(input(join(desktop, 'package.json')));
  assert.equal(desktopManifest.dependencies.meshcall, '0.3.0');
  function visit(file) {
    if (modules.has(file)) return;
    assert.ok(allowedModule(file), `Unexpected host dependency: ${file}`);
    const source = input(join(src, file)).toString();
    auditLoaders(source, file);
    let configRewrites = 0, selfRewrites = 0;
    const result = ts.transpileModule(source, {
      fileName: file,
      reportDiagnostics: true,
      compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext,
        verbatimModuleSyntax: true, isolatedModules: true, newLine: ts.NewLineKind.LineFeed,
        sourceMap: false, declaration: false, importHelpers: false },
      transformers: { before: [context => {
        const transform = node => {
          if (file === runtimeEntry && ts.isImportDeclaration(node) && node.moduleSpecifier.text === '../config.js') {
            configRewrites++;
            return ts.factory.updateImportDeclaration(node, node.modifiers, node.importClause,
              ts.factory.createStringLiteral('../osir-config.js'), node.attributes);
          }
          if (file === service && ts.isStringLiteral(node) && node.text === oldSelf) {
            selfRewrites++;
            return ts.factory.createStringLiteral(newSelf);
          }
          return ts.visitEachChild(node, transform, context);
        };
        return node => ts.visitNode(node, transform);
      }] },
    });
    const errors = (result.diagnostics ?? []).filter(d => d.category === ts.DiagnosticCategory.Error);
    assert.equal(errors.length, 0, errors.map(d => ts.flattenDiagnosticMessageText(d.messageText, '\n')).join('\n'));
    if (file === runtimeEntry) assert.equal(configRewrites, 1, 'Runtime config alias no longer matches');
    if (file === service) assert.equal(selfRewrites, 1, 'Private package version alias no longer matches');
    modules.set(file, result.outputText);
    const emitted = ts.createSourceFile(file, result.outputText, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
    for (const node of emitted.statements) {
      if ((!ts.isImportDeclaration(node) && !ts.isExportDeclaration(node)) || !node.moduleSpecifier) continue;
      assert.ok(ts.isStringLiteral(node.moduleSpecifier), `Nonliteral module: ${file}`);
      const spec = node.moduleSpecifier.text;
      if (spec.startsWith('.')) {
        assert.ok(spec.endsWith('.js'), `Unsupported import: ${file}: ${spec}`);
        visit(slash(relative(src, resolve(src, dirname(file), spec.slice(0, -3) + '.ts'))));
      } else if (spec.startsWith('node:')) continue;
      else if (spec === 'meshcall') continue;
      else {
        assert.ok(peers.has(spec), `Runtime peer missing from private manifest: ${spec}`);
        usedPeers.add(spec);
      }
    }
  }
  visit(entry);
  assert.deepEqual([...peers].sort(), [...usedPeers].sort(), 'Manifest peers must match the audited runtime closure');
  return { manifest, manifestBytes, patch, readme, modules, inputs };
}

/** Minimal deterministic USTAR: regular files only, short ASCII names, no links/PAX. */
export function ustarGzip(files) {
  const chunks = [];
  for (const [name, content] of [...files].sort(([a], [b]) => a.localeCompare(b, 'en'))) {
    assert.ok(/^package\/[A-Za-z0-9_./-]+$/.test(name) && !name.split('/').includes('..')
      && Buffer.byteLength(name) < 100, `USTAR short path required: ${name}`);
    const data = Buffer.isBuffer(content) ? content : Buffer.from(content);
    const header = Buffer.alloc(512);
    const field = (offset, width, value) => { assert.ok(Buffer.byteLength(value) <= width); header.write(value, offset, width, 'ascii'); };
    const octal = (offset, width, value) => field(offset, width, value.toString(8).padStart(width - 1, '0') + '\0');
    field(0, 100, name); octal(100, 8, 0o644); octal(108, 8, 0); octal(116, 8, 0);
    octal(124, 12, data.length); octal(136, 12, 0); header.fill(32, 148, 156);
    field(156, 1, '0'); field(257, 6, 'ustar\0'); field(263, 2, '00');
    const sum = header.reduce((total, byte) => total + byte, 0);
    field(148, 8, sum.toString(8).padStart(6, '0') + '\0 ');
    chunks.push(header, data, Buffer.alloc((512 - data.length % 512) % 512));
  }
  chunks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(chunks), { level: 9 });
}

export function verifyResources(directory) {
  const info = JSON.parse(readFileSync(join(directory, 'package-info.json')));
  const bytes = readFileSync(join(directory, 'osir-dsh-bridge.tgz'));
  assert.deepEqual(info, { schemaVersion: 1, name: '@osir/anywhere-dsh-bridge', version: '2.2.1',
    sha256: digest(bytes), size: bytes.length }, 'Private plugin resource metadata/hash mismatch');
  return info;
}

export function buildHostPackage(output = join(desktop, 'dist/dsh-bridge')) {
  // This helper only writes Desktop generated outputs; release snapshots are never targets.
  output = resolve(output);
  const outputRelative = relative(join(desktop, 'dist'), output);
  assert.ok(outputRelative && outputRelative !== '..' && !outputRelative.startsWith(`..${sep}`),
    'Output must be a child of this Desktop dist directory');
  for (let p = output; p !== desktop; p = dirname(p)) {
    if (existsSync(p)) assert.ok(!lstatSync(p).isSymbolicLink(), 'Linked build output rejected');
  }
  const compiled = compileHost();
  const files = new Map([
    ['package/package.json', compiled.manifestBytes],
    ['package/cordis.patch.yml', compiled.patch],
    ['package/README.md', compiled.readme],
  ]);
  for (const [file, original] of compiled.modules) {
    const target = file === entry ? 'lib/index.js' : `lib/${file.replace(/\.ts$/, '.js')}`;
    // The public entry is one level above host; all other module paths are retained.
    const code = file === entry ? original.replaceAll('"./dsh-runtime/index.js"', '"./host/dsh-runtime/index.js"')
      .replaceAll("'./dsh-runtime/index.js'", "'./host/dsh-runtime/index.js'")
      .replaceAll('"./osir-config.js"', '"./host/osir-config.js"')
      .replaceAll("'./osir-config.js'", "'./host/osir-config.js'") : original;
    files.set(`package/${target}`, Buffer.from(code));
  }
  const bytes = ustarGzip(files);
  const info = { schemaVersion: 1, name: compiled.manifest.name, version: compiled.manifest.version,
    sha256: digest(bytes), size: bytes.length };
  const receipt = { schemaVersion: 1, compiler: { name: 'typescript', version: ts.version },
    node: process.version, archiveFormat: 'ustar+gzip-regular-short-paths', resource: info,
    archiveFiles: [...files.keys()].sort(),
    inputs: [...compiled.inputs].sort(([a], [b]) => a.localeCompare(b)).map(([path, meta]) => ({ path, ...meta })),
    aliases: { [`${runtimeEntry}:../config.js`]: '../osir-config.js', [oldSelf]: newSelf } };
  const lock = join(desktop, 'yarn.lock');
  if (existsSync(lock)) receipt.desktopYarnLockSha256 = digest(readFileSync(lock));
  mkdirSync(output, { recursive: true });
  writeFileSync(join(output, 'osir-dsh-bridge.tgz'), bytes);
  writeFileSync(join(output, 'package-info.json'), JSON.stringify(info, null, 2) + '\n');
  writeFileSync(join(output, 'osir-build-receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
  verifyResources(output);
  return { output, ...info, modules: compiled.modules.size, receipt: join(output, 'osir-build-receipt.json') };
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const args = process.argv.slice(2);
  assert.ok(args.length === 0 || args.length === 2 && args[0] === '--output', 'Usage: osir-dsh-bridge.mjs [--output <Desktop dist child>]');
  console.log(JSON.stringify(buildHostPackage(args[1]), null, 2));
}
