/**
 * Credential-aware release entry points behind `yarn dist:mac` / `yarn dist:win`.
 *
 * Order of operations, mirroring the DSH desktop release scripts:
 *
 * 1. read and validate the signing/notarization environment (all-or-nothing)
 * 2. run the uv and Python bundles and the app build with every secret stripped
 * 3. hand the secrets to electron-builder only, which is the step that signs
 * 4. verify the produced artifact
 *
 * With no credentials configured the artifact is simply unsigned; a partially
 * configured release fails before anything is packaged.
 */

import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { createDesktopPackageConfig } from "./desktop-package-config.mjs";
import { assertBuiltDesktopConfig, resolveDesktopBuildConfig } from "./desktop-build-config.mjs";
import { desktopRuntimePackagePaths } from "./desktop-runtime-packages.mjs";
import { assertCompiledBuild } from "./osir-anywhere-build.mjs";
import {
  applyKeychainIdentity,
  parseDeveloperIdIdentities,
  readMacReleaseCredentials,
  readWindowsReleaseCredentials,
  withoutReleaseSecrets,
} from "./release-credentials.mjs";

const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const POC_OUTPUT_DIR = process.env.OSIR_ANYWHERE_POC_OUTPUT_DIR?.trim();
const OUTPUT_DIR = POC_OUTPUT_DIR ? resolve(POC_OUTPUT_DIR) : join(PROJECT_ROOT, "release");
// uv and CPython bundles share the `<platform>-<arch>` target keys.
const BUNDLE_TARGETS = {
  "darwin-arm64": "darwin-arm64",
  "darwin-x64": "darwin-x64",
  "win32-x64": "win32-x64",
  "win32-arm64": "win32-arm64",
};
const ARCH_FLAGS = new Set(["--arm64", "--x64", "--universal"]);
const PASSTHROUGH_FLAGS = new Set(["--dir"]);

function log(message) {
  console.log(`[dist] ${message}`);
}

function fail(message) {
  console.error(`[dist] ${message}`);
  process.exit(1);
}

function run(command, args, env) {
  const result = spawnSync(command, args, {
    cwd: PROJECT_ROOT,
    env,
    stdio: "inherit",
    // Only `.cmd` shims such as yarn.cmd need cmd.exe. It joins the command
    // line unquoted, so Node, electron-builder and any path containing a
    // space (C:\Program Files\nodejs\node.exe) must be spawned directly.
    shell: process.platform === "win32" && command.endsWith(".cmd"),
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} ${args.join(" ")} exited with ${result.status ?? "null"}`);
}

function yarn(args, env) {
  run(process.platform === "win32" ? "yarn.cmd" : "yarn", args, env);
}

function electronBuilder(args, env) {
  const require = createRequire(import.meta.url);
  run(process.execPath, [require.resolve("electron-builder/cli.js"), ...args], env);
}

function parseArguments(argv) {
  const explicitPlatform = argv[0] === "mac" || argv[0] === "win";
  const platform = explicitPlatform ? argv[0] : process.platform === "darwin" ? "mac" : process.platform === "win32" ? "win" : null;
  const flags = explicitPlatform ? argv.slice(1) : argv;
  if (platform !== "mac" && platform !== "win") {
    fail("Usage: node scripts/dist-desktop.mjs <mac|win> [--arm64|--x64|--universal] [--dir]");
  }
  const archFlags = flags.filter((value) => ARCH_FLAGS.has(value));
  const passthrough = flags.filter((value) => PASSTHROUGH_FLAGS.has(value));
  const unknown = flags.filter((value) => !ARCH_FLAGS.has(value) && !PASSTHROUGH_FLAGS.has(value) && value !== "--skip-build");
  if (unknown.length > 0) fail(`Unknown argument(s): ${unknown.join(" ")}`);
  if (archFlags.length > 1) fail(`Choose one architecture flag, received ${archFlags.join(" ")}`);
  return { platform, archFlag: archFlags[0] ?? null, passthrough, skipBuild: flags.includes("--skip-build") };
}

function resolveTargets({ platform, archFlag }) {
  if (platform === "win") {
    if (archFlag === "--universal") fail("--universal is macOS only");
    const arch = archFlag === "--arm64" ? "arm64" : "x64";
    return { builderFlags: [`--${arch}`], bundleTargets: [BUNDLE_TARGETS[`win32-${arch}`]] };
  }
  if (archFlag === null || archFlag === "--universal") {
    return { builderFlags: ["--universal"], bundleTargets: [BUNDLE_TARGETS["darwin-arm64"], BUNDLE_TARGETS["darwin-x64"]] };
  }
  const arch = archFlag === "--x64" || archFlag === "--arm64" ? archFlag.slice(2) : process.arch;
  if (arch !== "arm64" && arch !== "x64") fail(`Unsupported macOS architecture: ${arch}`);
  return { builderFlags: [`--${arch}`], bundleTargets: [BUNDLE_TARGETS[`darwin-${arch}`]] };
}

/** The uv and CPython executables `bundle:uv` and `bundle:python` leave for a target. */
function bundledExecutables(target) {
  const windows = target.startsWith("win32");
  return [
    `build/uv/${target}/${windows ? "uv.exe" : "uv"}`,
    `build/python/${target}/${windows ? "python.exe" : "bin/python3"}`,
  ];
}

/** The first Developer ID Application identity in the Keychain, if any. */
function keychainDeveloperIdIdentity() {
  const result = spawnSync("security", ["find-identity", "-v", "-p", "codesigning"], { encoding: "utf8" });
  if (result.status !== 0) return null;
  return parseDeveloperIdIdentities(result.stdout ?? "")[0] ?? null;
}

function describeSigning(credentials, missingLabel) {
  const { source, identity } = credentials.signing;
  if (source === "none") return `none (${credentials.reason ?? missingLabel})`;
  if (source === "keychain" && identity === null) return "keychain (auto-discovered identity)";
  return `${source} (${identity})`;
}

function assertReleaseConfiguration(env) {
  const required = [
    ["OSIR_ANYWHERE_API_ORIGIN", env.OSIR_ANYWHERE_API_ORIGIN],
    ["OSIR_ANYWHERE_OAUTH_WEB_ORIGIN", env.OSIR_ANYWHERE_OAUTH_WEB_ORIGIN],
  ];
  const missing = required.filter(([, value]) => !value?.trim()).map(([name]) => name);
  if (missing.length > 0) fail(`Release blocked: configure ${missing.join(", ")} with OSIR-owned HTTPS endpoints.`);

  for (const [name, value] of required) {
    let url;
    try { url = new URL(value); } catch { fail(`Release blocked: ${name} must be an HTTPS URL.`); }
    if (url.protocol !== "https:" || url.hostname.endsWith(".invalid") || url.hostname.includes("agents-anywhere")) {
      fail(`Release blocked: ${name} must use an OSIR-owned HTTPS endpoint.`);
    }
  }
  // Validate the fixed signed stable manifest through the shared resolver.
  // Legacy per-platform URL variables are intentionally no longer required.
  resolveDesktopBuildConfig(JSON.parse(readFileSync(join(PROJECT_ROOT, "config.json"), "utf8")), env);
  if (env.OSIR_ANYWHERE_OAUTH_CONTRACT_VERIFIED !== "1") {
    fail("Release blocked: real system-browser OAuth and production integration acceptance are not complete; OSIR_ANYWHERE_OAUTH_CONTRACT_VERIFIED=1 is required after verification.");
  }
}

function artifactPaths() {
  if (!existsSync(OUTPUT_DIR)) return [];
  return readdirSync(OUTPUT_DIR, { withFileTypes: true })
    .filter((entry) => entry.isFile() && /\.(dmg|exe|zip|pkg)$/.test(entry.name))
    .map((entry) => join(OUTPUT_DIR, entry.name))
    .sort();
}

function unpackedAppPaths() {
  if (!existsSync(OUTPUT_DIR)) return [];
  return readdirSync(OUTPUT_DIR, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name.startsWith("mac"))
    .flatMap((entry) => {
      const directory = join(OUTPUT_DIR, entry.name);
      return readdirSync(directory, { withFileTypes: true })
        .filter((child) => child.isDirectory() && child.name.endsWith(".app"))
        .map((child) => join(directory, child.name));
    });
}

function verifyMac({ signed, notarized, artifact }) {
  if (!signed) {
    log("Artifact is unsigned; Gatekeeper will ask the user to confirm the first launch.");
    return;
  }
  const app = readdirSync(OUTPUT_DIR, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name.startsWith("mac"))
    .map((entry) => join(OUTPUT_DIR, entry.name, "OSIR Anywhere.app"))
    .find((candidate) => existsSync(candidate));
  if (!app) fail("The packaged application was not found under release/, so it could not be verified.");
  log(`Verifying the code signature of ${app}`);
  run("codesign", ["--verify", "--deep", "--strict", "--verbose=2", app], process.env);
  const described = spawnSync("codesign", ["-dvv", app], { encoding: "utf8" });
  const authority = /Authority=([^\n]+)/.exec(`${described.stderr ?? ""}`)?.[1];
  log(`Signature authority: ${authority ?? "unknown"}`);
  if (notarized && artifact) {
    log(`Verifying the notarization ticket on ${artifact}`);
    run("xcrun", ["stapler", "validate", artifact], process.env);
  }
}

async function main() {
  const { platform, archFlag, passthrough, skipBuild } = parseArguments(process.argv.slice(2));
  if (platform === "mac" && process.platform !== "darwin") {
    fail("dist:mac must run on macOS: signing and notarization need the Keychain and notarytool.");
  }
  if (platform === "win" && process.platform !== "win32") {
    fail("dist:win must run on Windows: the NSIS installer and Authenticode signing are native there.");
  }

  const { builderFlags, bundleTargets } = resolveTargets({ platform, archFlag });
  const targetArch = platform === "win"
    ? archFlag === "--arm64" ? "arm64" : "x64"
    : archFlag === "--arm64" ? "arm64" : archFlag === "--x64" ? "x64" : "universal";
  const directoryOnly = passthrough.includes("--dir");
  const isLocalPoc = directoryOnly && Boolean(POC_OUTPUT_DIR);
  if (!isLocalPoc) assertReleaseConfiguration(process.env);
  let credentials = platform === "mac"
    ? readMacReleaseCredentials(process.env)
    : readWindowsReleaseCredentials(process.env);
  if (platform === "mac" && credentials.signing.source === "keychain" && credentials.signing.identity === null) {
    // Auto-discovery would happily pick an Apple Development certificate.
    credentials = applyKeychainIdentity(credentials, keychainDeveloperIdIdentity());
  }
  const cleanEnvironment = withoutReleaseSecrets(process.env);
  const signed = credentials.signing.source !== "none";
  const notarized = platform === "mac" && credentials.notarization !== "none";

  if (platform === "mac") {
    log(`Signing: ${describeSigning(credentials, "no Developer ID credentials")}`);
    log(`Notarization: ${notarized ? credentials.notarization : "none — the artifact stays unnotarized"}`);
  } else {
    log(`Signing: ${describeSigning(credentials, "no signing certificate")}`);
  }
  log(`uv and Python targets: ${bundleTargets.join(", ")}`);

  if (skipBuild) {
    await assertCompiledBuild(PROJECT_ROOT, `${platform === "mac" ? "darwin" : "win32"}-${targetArch}`, process.env);
    for (const relative of ["dist/electron/main.js", "renderer/out/index.html", ...bundleTargets.flatMap(bundledExecutables)]) {
      if (!existsSync(join(PROJECT_ROOT, relative))) fail(`--skip-build requires ${relative}; run a full dist first.`);
    }
    assertBuiltDesktopConfig(
      JSON.parse(readFileSync(join(PROJECT_ROOT, "dist/config.json"), "utf8")),
      resolveDesktopBuildConfig(JSON.parse(readFileSync(join(PROJECT_ROOT, "config.json"), "utf8")), cleanEnvironment),
    );
    log("Reusing compiled app, uv and Python bundles (--skip-build)");
  } else {
    yarn(["bundle:uv"], { ...cleanEnvironment, UV_BUNDLE_TARGETS: bundleTargets.join(",") });
    yarn(["bundle:python"], { ...cleanEnvironment, PYTHON_BUNDLE_TARGETS: bundleTargets.join(",") });
    yarn(["build"], cleanEnvironment);
  }
  if (POC_OUTPUT_DIR) {
    if (existsSync(OUTPUT_DIR) && readdirSync(OUTPUT_DIR).length > 0) {
      fail(`POC output directory must be empty: ${OUTPUT_DIR}`);
    }
  } else {
    rmSync(OUTPUT_DIR, { recursive: true, force: true });
  }

  const builderEnvironment = { ...credentials.environment };
  const buildConfig = JSON.parse(readFileSync(join(PROJECT_ROOT, "package.json"), "utf8")).build;
  const runtimePackagePaths = desktopRuntimePackagePaths(PROJECT_ROOT);
  const packageConfig = createDesktopPackageConfig(buildConfig, { platform, arch: targetArch, runtimePackagePaths });
  log(`Packaging ${runtimePackagePaths.length} installed runtime dependency directories; renderer build tools are excluded.`);
  const configDirectory = mkdtempSync(join(tmpdir(), "osir-anywhere-builder-"));
  const configPath = join(configDirectory, "electron-builder.json");
  writeFileSync(configPath, `${JSON.stringify(packageConfig, null, 2)}\n`);
  try {
    electronBuilder([
      "--config",
      configPath,
      ...(process.env.WORKBENCH_ELECTRON_DIST ? [`--config.electronDist=${resolve(process.env.WORKBENCH_ELECTRON_DIST)}`] : []),
      `--${platform}`,
      directoryOnly ? "dir" : platform === "mac" ? "dmg" : "nsis",
      ...builderFlags,
      "--publish",
      "never",
      ...(platform === "mac" ? [`--config.mac.notarize=${notarized}`] : []),
      `--config.directories.output=${OUTPUT_DIR}`,
      ...passthrough,
    ], Object.fromEntries(Object.entries(builderEnvironment).filter(([, entry]) => entry !== undefined)));
  } finally {
    rmSync(configDirectory, { recursive: true, force: true });
  }

  const artifacts = directoryOnly ? unpackedAppPaths() : artifactPaths();
  if (artifacts.length === 0) fail(directoryOnly ? "The unpacked application was not found." : "electron-builder finished without producing an installer.");
  for (const artifact of artifacts) log(`${directoryOnly ? "Unpacked app" : "Artifact"}: ${artifact}`);
  if (platform === "mac") {
    const artifact = artifacts.find((path) => path.endsWith(".dmg"));
    if (notarized && artifact) {
      // App notarization does not attach a ticket to the enclosing DMG.
      const require = createRequire(import.meta.url);
      const { notarize } = require("@electron/notarize");
      const env = credentials.environment;
      const options = credentials.notarization === "apple-id"
        ? { appleId: env.APPLE_ID, appleIdPassword: env.APPLE_APP_SPECIFIC_PASSWORD, teamId: env.APPLE_TEAM_ID }
        : credentials.notarization === "api-key"
          ? { appleApiKey: env.APPLE_API_KEY, appleApiKeyId: env.APPLE_API_KEY_ID, appleApiIssuer: env.APPLE_API_ISSUER }
          : { keychainProfile: env.APPLE_KEYCHAIN_PROFILE, ...(env.APPLE_KEYCHAIN ? { keychain: env.APPLE_KEYCHAIN } : {}) };
      log("Submitting the DMG for notarization and stapling its ticket");
      await notarize({ appPath: artifact, ...options });
      // Stapling changes the image bytes, invalidating the pre-staple blockmap.
      rmSync(`${artifact}.blockmap`, { force: true });
    }
    verifyMac({ signed, notarized, artifact });
  }
}

try {
  await main();
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}
