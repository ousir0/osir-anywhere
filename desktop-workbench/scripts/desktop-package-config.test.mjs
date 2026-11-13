import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createFilter } from "app-builder-lib/out/util/filter.js";
import minimatch from "minimatch";
import { createDesktopPackageConfig } from "./desktop-package-config.mjs";
import { desktopRuntimePackagePaths } from "./desktop-runtime-packages.mjs";
import { fileURLToPath } from "node:url";

const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const baseFiles = packageJson.build.files;
const nativePackageFiles = [
  "@img/sharp-darwin-{arch}/lib/sharp.node",
  "@img/sharp-libvips-darwin-{arch}/lib/libvips.dylib",
  "@next/swc-darwin-{arch}/next-swc.node",
  "@parcel/watcher-darwin-{arch}/watcher.node",
  "@swc/core-darwin-{arch}/swc.node",
  "@tailwindcss/oxide-darwin-{arch}/oxide.node",
  "lightningcss-darwin-{arch}/lightningcss.node",
];

function matches(config, relativePath) {
  const nodeModulePatterns = ["**/*", ...config.files.filter((pattern) => pattern.startsWith("!") || pattern.startsWith("node_modules/"))];
  const patterns = nodeModulePatterns.map((pattern) => new minimatch.Minimatch(pattern, { dot: true }));
  return createFilter(process.cwd(), patterns)(`${process.cwd()}/${relativePath}`, { isDirectory: () => false });
}

test("single-architecture macOS builds filter only the opposite Darwin native packages", () => {
  const arm64 = createDesktopPackageConfig(packageJson.build, { platform: "mac", arch: "arm64" });
  const x64 = createDesktopPackageConfig(packageJson.build, { platform: "mac", arch: "x64" });

  for (const [config, excluded, included] of [
    [arm64, "x64", "arm64"],
    [x64, "arm64", "x64"],
  ]) {
    for (const file of nativePackageFiles) {
      assert.equal(matches(config, `node_modules/${file.replace("{arch}", excluded)}`), false, `${file} ${excluded}`);
      assert.equal(matches(config, `node_modules/${file.replace("{arch}", included)}`), true, `${file} ${included}`);
    }
    assert.equal(matches(config, "node_modules/@tailwindcss/oxide-wasm32-wasi/index.js"), true);
    assert.ok(config.files.includes("renderer/out/**"));
    assert.ok(config.files.includes("dist/electron/**"));
    for (const resource of config.extraResources.filter((item) => ["uv", "python"].includes(item.to))) {
      assert.ok(resource.filter.includes(`!darwin-${excluded}/**`));
      assert.ok(resource.filter.includes("**/*"));
      assert.ok(!resource.filter.includes(`!darwin-${included}/**`));
    }
  }
});

test("universal macOS and Windows configs preserve the complete original file set", () => {
  for (const target of [
    { platform: "mac", arch: "universal" },
    { platform: "win", arch: "x64" },
    { platform: "win", arch: "arm64" },
  ]) {
    const config = createDesktopPackageConfig(packageJson.build, target);
    assert.deepEqual(config.files, baseFiles);
    assert.deepEqual(config.extraResources, packageJson.build.extraResources);
    assert.equal(matches(config, "node_modules/@next/swc-darwin-arm64/next-swc.node"), true);
    assert.equal(matches(config, "node_modules/@next/swc-darwin-x64/next-swc.node"), true);
    assert.ok(config.files.includes("renderer/out/**"));
  }
});

test("production dependency closure preserves MeshCall and excludes exported renderer build tools", () => {
  const runtimePackagePaths = desktopRuntimePackagePaths(fileURLToPath(new URL("..", import.meta.url)));
  assert.ok(runtimePackagePaths.includes("node_modules/meshcall"));
  assert.ok(runtimePackagePaths.includes("node_modules/ws"));
  assert.ok(runtimePackagePaths.includes("node_modules/ajv"));
  for (const target of [{ platform: "mac", arch: "arm64" }, { platform: "mac", arch: "universal" }, { platform: "win", arch: "x64" }]) {
    const config = createDesktopPackageConfig(packageJson.build, { ...target, runtimePackagePaths });
    for (const directory of runtimePackagePaths) {
      assert.equal(matches(config, `${directory}/package.json`), true, directory);
      assert.equal(matches(config, `${directory}/LICENSE`), true, directory);
    }
    for (const directory of ["next", "monaco-editor", "mermaid", "react-dom", "@next/swc-darwin-arm64"]) {
      assert.equal(matches(config, `node_modules/${directory}/package.json`), false, directory);
    }
    assert.ok(config.files.includes("renderer/out/**"));
    assert.ok(config.files.includes("dist/electron/**"));
  }
});
