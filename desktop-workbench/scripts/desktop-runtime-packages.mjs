import { existsSync, readFileSync, realpathSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, relative, sep } from "node:path";

/** Follow installed production dependencies, never renderer workspace tooling. */
export function desktopRuntimePackagePaths(projectRoot) {
  const manifest = join(projectRoot, "package.json");
  const root = JSON.parse(readFileSync(manifest, "utf8"));
  const paths = new Set();
  const visit = (name, from, optional = false) => {
    // Python owns the Router executable; Desktop only connects to its endpoint.
    if (name.startsWith("meshcall-router-")) return;
    const resolver = createRequire(from);
    let packageFile;
    for (const modules of resolver.resolve.paths(name) ?? []) {
      const candidate = join(modules, name, "package.json");
      if (existsSync(candidate)) { packageFile = realpathSync(candidate); break; }
    }
    if (!packageFile) {
      if (optional) return;
      throw new Error(`Missing Desktop runtime package: ${name}`);
    }
    const directory = dirname(packageFile);
    const localPath = relative(projectRoot, directory).split(sep).join("/");
    if (!localPath.startsWith("node_modules/") || localPath.includes("../")) {
      throw new Error(`Desktop runtime package is outside the package root: ${name}`);
    }
    if (paths.has(localPath)) return;
    paths.add(localPath);
    const pkg = JSON.parse(readFileSync(packageFile, "utf8"));
    for (const dependency of Object.keys(pkg.dependencies ?? {})) visit(dependency, packageFile);
    for (const dependency of Object.keys(pkg.optionalDependencies ?? {})) visit(dependency, packageFile, true);
    for (const dependency of Object.keys(pkg.peerDependencies ?? {})) {
      visit(dependency, packageFile, Boolean(pkg.peerDependenciesMeta?.[dependency]?.optional));
    }
  };
  for (const name of Object.keys(root.dependencies ?? {})) visit(name, manifest);
  return [...paths].sort();
}
