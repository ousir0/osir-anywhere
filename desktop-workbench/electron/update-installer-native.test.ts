import test, { type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { prepareNativeInstaller, InstallerNativeValidationError, type InstallerCommandRunner } from "./update-installer-native";
import { DesktopUpdateService } from "./desktop-updates";
import { RELEASE_MANIFEST_URL } from "./release-manifest";
import type { ReleaseArtifact, DesktopUpdateState } from "../shared/desktop-updates";

const VERSION = "2.2.0";
const ok = (stdout = "") => ({ status: 0, stdout, stderr: "" });
const fail = (stderr = "inspection failed") => ({ status: 1, stdout: "", stderr });
const metadata = {
  CFBundleIdentifier: "com.osir.anywhere.desktop", CFBundleName: "OSIR Anywhere", CFBundleDisplayName: "OSIR Anywhere",
  CFBundleShortVersionString: VERSION, CFBundleExecutable: "OSIR Anywhere", CFBundlePackageType: "APPL",
};
function signedArtifact(bytes: Buffer, platform: ReleaseArtifact["platform"] = "darwin", policy: ReleaseArtifact["systemSignature"] = "unsigned"): ReleaseArtifact {
  const filename = platform === "darwin" ? "OSIR-Anywhere.dmg" : "OSIR-Anywhere.exe";
  return { platform, arch: platform === "darwin" ? "universal" : "x64", filename,
    url: `https://osirvedio.cn-nb1.rains3.com/osir-anywhere/releases/r1/${filename}`,
    size: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex"), systemSignature: policy };
}
async function fixture(t: TestContext, bytes: Buffer = Buffer.from("RSA authenticated installer bytes"), platform: ReleaseArtifact["platform"] = "darwin") {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "osir-native-test-"));
  const artifact = signedArtifact(bytes, platform);
  const file = path.join(directory, artifact.filename);
  await fs.writeFile(file, bytes, { mode: 0o600 });
  const controller = new AbortController();
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  return { directory, file, artifact, controller, request: { file, artifact, version: VERSION, signal: controller.signal } };
}

type Kind = "unsigned" | "adhoc" | "developer" | "broken" | "unknown" | "other";
type MacOptions = {
  disk?: Kind; app?: Kind; badVerify?: "disk" | "app"; imageBad?: boolean;
  plist?: Record<string, unknown>; apps?: string[]; symlinkApp?: boolean; symlinkExecutable?: boolean;
  package?: Record<string, unknown>; badArchive?: boolean; nested?: Kind; badNested?: boolean; escapedLink?: boolean;
  quarantine?: string; markBad?: boolean; listBad?: boolean; readBad?: boolean;
  attachBad?: boolean; detachBad?: boolean; stapleBad?: boolean; gatekeeperBad?: boolean;
  onProbe?: (tool: string, args: string[]) => void | Promise<void>;
};
function appArchive(patch: Record<string, unknown> = {}): Buffer {
  const body = Buffer.from(JSON.stringify({ name: "osir-anywhere-desktop-workbench", productName: "OSIR Anywhere",
    main: "dist/electron/main.js", version: VERSION, ...patch }));
  const header = Buffer.from(JSON.stringify({ files: { "package.json": { offset: "0", size: body.length } } }));
  const headerSize = 8 + Math.ceil(header.length / 4) * 4;
  const archive = Buffer.alloc(8 + headerSize + body.length);
  archive.writeUInt32LE(4, 0); archive.writeUInt32LE(headerSize, 4);
  archive.writeUInt32LE(headerSize - 4, 8); archive.writeUInt32LE(header.length, 12);
  header.copy(archive, 16); body.copy(archive, 8 + headerSize);
  return archive;
}
function macRuntime(t: TestContext, options: MacOptions = {}) {
  const calls: Array<{ tool: string; args: string[]; signal: AbortSignal }> = [];
  const mounts: string[] = [];
  let quarantine = options.quarantine;
  const run: InstallerCommandRunner = async (tool, args, context) => {
    calls.push({ tool, args, signal: context.signal });
    await options.onProbe?.(tool, args);
    if (tool === "/usr/bin/xattr") {
      if (args[0] === "-w") { if (options.markBad) return fail(); quarantine = args[2]; return ok(); }
      if (args[0] === "-p") return options.readBad ? fail() : ok(quarantine ?? "");
      return options.listBad ? fail() : ok(quarantine === undefined ? "" : "com.apple.quarantine\n");
    }
    if (tool === "/usr/bin/hdiutil") {
      if (args[0] === "verify") return options.imageBad ? fail() : ok();
      if (args[0] === "attach") {
        assert.ok(args.includes("-readonly")); assert.ok(args.includes("-noautoopen"));
        const mount = args[args.indexOf("-mountpoint") + 1]; mounts.push(mount);
        for (const name of options.apps ?? ["OSIR Anywhere.app"]) {
          const app = path.join(mount, name);
          if (options.symlinkApp) { await fs.symlink(os.tmpdir(), app); continue; }
          await fs.mkdir(path.join(app, "Contents", "MacOS"), { recursive: true });
          await fs.mkdir(path.join(app, "Contents", "Resources"));
          await fs.writeFile(path.join(app, "Contents", "Info.plist"), "native plist placeholder");
          await fs.writeFile(path.join(app, "Contents", "Resources", "app.asar"), options.badArchive ? Buffer.from("bad") : appArchive(options.package));
          if (options.escapedLink) await fs.symlink(os.tmpdir(), path.join(app, "Contents", "Resources", "escape"));
          const exe = path.join(app, "Contents", "MacOS", "OSIR Anywhere");
          if (options.symlinkExecutable) await fs.symlink(process.execPath, exe);
          else await fs.writeFile(exe, Buffer.from("feedfacf00000000", "hex"), { mode: 0o755 });
        }
        return options.attachBad ? fail() : ok();
      }
      if (args[0] === "detach") {
        assert.equal(context.signal.aborted, false, "cleanup survives user cancellation");
        if (options.detachBad) return fail();
        for (const entry of await fs.readdir(args[1])) await fs.rm(path.join(args[1], entry), { recursive: true, force: true });
        return ok();
      }
    }
    if (tool === "/usr/bin/plutil") return ok(JSON.stringify({ ...metadata, ...options.plist }));
    if (tool === "/usr/bin/codesign") {
      const app = args.at(-1)!.endsWith(".app");
      const nested = !app && args.at(-1)!.includes(`${path.sep}Contents${path.sep}`);
      if (args[0] === "--verify") return options.badVerify === (app ? "app" : "disk") || (nested && options.badNested) ? fail("invalid sealed resource") : ok();
      const kind = (app ? options.app : nested ? options.nested ?? options.app : options.disk) ?? "unsigned";
      if (kind === "unsigned") return fail(`${args.at(-1)}: code object is not signed at all`);
      if (kind === "broken") return fail("code signature invalid (code or signature have been modified)");
      if (kind === "unknown") return fail("operation not permitted");
      return ok(`Identifier=${app ? metadata.CFBundleIdentifier : "disk-image"}\n` +
        (kind === "adhoc" ? "Signature=adhoc\n" : `Authority=${kind === "developer" ? "Developer ID Application: OSIR (TEAM)" : "Apple Development: Test"}\n`));
    }
    if (tool === "/usr/bin/xcrun") return options.stapleBad ? fail() : ok();
    if (tool === "/usr/sbin/spctl") return options.gatekeeperBad ? fail() : ok();
    throw new Error(`Unexpected native command: ${tool}`);
  };
  t.after(async () => { for (const mount of mounts) await fs.rm(mount, { recursive: true, force: true }); });
  return { platform: "darwin", run, calls, mounts, quarantine: () => quarantine };
}

test("Mac accepts explicit unsigned and valid ad hoc, retains original quarantine, and detaches the read-only image", async t => {
  for (const kind of ["unsigned", "adhoc"] as const) await t.test(kind, async t => {
    const f = await fixture(t);
    const value = "00c3;123456;Safari;original-id";
    const runtime = macRuntime(t, { disk: kind, app: kind, quarantine: value });
    await prepareNativeInstaller(f.request, runtime);
    assert.equal(runtime.quarantine(), value);
    assert.equal(runtime.calls.filter(c => c.tool.endsWith("xattr") && c.args[0] === "-w").length, 0);
    const attach = runtime.calls.find(c => c.args[0] === "attach")!;
    assert.equal(attach.args.at(-1), f.file, "inspects the original signed-manifest artifact");
    assert.ok(runtime.calls.some(c => c.args[0] === "detach"));
    assert.equal(runtime.calls.some(c => c.tool.endsWith("spctl")), false, "unsigned never claims Gatekeeper approval");
    if (kind === "adhoc") assert.equal(runtime.calls.filter(c => c.args[0] === "--verify").length, 3);
    for (const mount of runtime.mounts) await assert.rejects(fs.stat(mount), { code: "ENOENT" });
  });
});

test("Mac adds quarantine and confirms it before inspection; protection failures block preparation", async t => {
  const f = await fixture(t); const runtime = macRuntime(t);
  await prepareNativeInstaller(f.request, runtime);
  assert.match(runtime.quarantine()!, /^0083;[0-9a-f]+;OSIR Anywhere;/);
  assert.ok(runtime.calls.findIndex(c => c.args[0] === "-w") < runtime.calls.findIndex(c => c.args[0] === "attach"));
  for (const options of [{ markBad: true }, { listBad: true }, { quarantine: "existing", readBad: true }, { quarantine: "" }]) {
    const r = macRuntime(t, options);
    await assert.rejects(prepareNativeInstaller(f.request, r), InstallerNativeValidationError);
    assert.equal(r.calls.some(c => c.args[0] === "attach"), false);
  }
});

test("Mac rejects damaged/ad hoc-invalid/unexpected signatures and never downgrades them to unsigned", async t => {
  for (const options of [
    { disk: "broken" }, { app: "broken" }, { app: "unknown" }, { app: "other" }, { app: "developer" },
    { disk: "adhoc", badVerify: "disk" }, { app: "adhoc", badVerify: "app" }, { imageBad: true },
  ] satisfies MacOptions[]) await t.test(JSON.stringify(options), async t => {
    const f = await fixture(t); const runtime = macRuntime(t, options);
    await assert.rejects(prepareNativeInstaller(f.request, runtime), InstallerNativeValidationError);
    if (runtime.mounts.length) assert.ok(runtime.calls.some(c => c.args[0] === "detach"));
  });
});

test("strong/default Mac policy requires verified Developer ID, notarization and app Gatekeeper assessment", async t => {
  for (const declaration of ["developer-id-notarized", undefined] as const) {
    const f = await fixture(t); f.artifact.systemSignature = declaration;
    const runtime = macRuntime(t, { disk: "developer", app: "developer" });
    await prepareNativeInstaller(f.request, runtime);
    assert.ok(runtime.calls.some(c => c.args[0] === "stapler" && c.args.at(-1) === f.file));
    assert.equal(runtime.calls.filter(c => c.tool.endsWith("spctl")).length, 1);
    assert.ok(runtime.calls.filter(c => c.args[0] === "--verify").every(c => c.args.includes("--all-architectures")));
    assert.ok(runtime.calls.some(c => c.args.includes("-R") && c.args.some(a => a.includes("anchor apple generic"))));
    for (const options of [{ disk: "unsigned", app: "unsigned" }, { disk: "adhoc", app: "adhoc" },
      { disk: "developer", app: "developer", stapleBad: true }, { disk: "developer", app: "developer", gatekeeperBad: true },
      { disk: "developer", app: "developer", badVerify: "app" }] satisfies MacOptions[]) {
      await assert.rejects(prepareNativeInstaller(f.request, macRuntime(t, options)), InstallerNativeValidationError);
    }
  }
  const f = await fixture(t); f.artifact.systemSignature = "developer-id-notarized";
  await prepareNativeInstaller(f.request, macRuntime(t, { disk: "unsigned", app: "developer" }));
});

test("Mac checks OSIR bundle identity, exact release version and regular executable, with cleanup on every rejection", async t => {
  const variants: MacOptions[] = [
    { plist: { CFBundleIdentifier: "com.attacker.app" } }, { plist: { CFBundleName: "Other" } },
    { plist: { CFBundleShortVersionString: "2.1.9" } }, { plist: { CFBundleDisplayName: "Other" } },
    { plist: { CFBundleExecutable: "../../evil" } }, { plist: { CFBundlePackageType: "BNDL" } },
    { apps: ["Other.app"] }, { apps: ["OSIR Anywhere.app", "Extra.app"] }, { apps: [] },
    { symlinkApp: true }, { symlinkExecutable: true }, { attachBad: true }, { detachBad: true },
    { package: { name: "other-desktop" } }, { package: { version: "2.1.9" } }, { package: { productName: "Other" } },
    { package: { main: "evil.js" } }, { badArchive: true }, { escapedLink: true },
  ];
  for (const options of variants) await t.test(JSON.stringify(options), async t => {
    const f = await fixture(t); const runtime = macRuntime(t, options);
    await assert.rejects(prepareNativeInstaller(f.request, runtime), InstallerNativeValidationError);
    assert.ok(runtime.calls.some(c => c.args[0] === "detach"));
  });
});

test("unsigned Mac root cannot conceal a broken nested signature; valid nested code remains acceptable", async t => {
  for (const options of [{ nested: "broken" }, { nested: "unknown" }, { nested: "adhoc", badNested: true }] satisfies MacOptions[]) {
    const f = await fixture(t);
    await assert.rejects(prepareNativeInstaller(f.request, macRuntime(t, options)), InstallerNativeValidationError);
  }
  const f = await fixture(t);
  await prepareNativeInstaller(f.request, macRuntime(t, { nested: "developer" }));
});

test("cancellation during mounted inspection still detaches and never uses an aborted cleanup signal", async t => {
  const f = await fixture(t);
  const runtime = macRuntime(t, { onProbe: tool => { if (tool.endsWith("plutil")) f.controller.abort("user-cancelled"); } });
  await assert.rejects(prepareNativeInstaller(f.request, runtime));
  assert.ok(runtime.calls.some(c => c.args[0] === "detach" && !c.signal.aborted));
});

function nsis(certificate = false): Buffer {
  const bytes = Buffer.alloc(certificate ? 4112 : 4096);
  bytes.write("MZ"); bytes.writeUInt32LE(128, 60);
  bytes.write("PE\0\0", 128, "binary"); bytes.writeUInt16LE(0x14c, 132); bytes.writeUInt16LE(1, 134);
  bytes.writeUInt16LE(224, 148); bytes.writeUInt16LE(2, 150);
  bytes.writeUInt16LE(0x10b, 152); bytes.writeUInt32LE(16, 152 + 92);
  bytes.writeUInt32LE(512, 376 + 16); bytes.writeUInt32LE(512, 376 + 20);
  Buffer.from("efbeadde4e756c6c736f6674496e7374", "hex").copy(bytes, 1028);
  bytes.writeUInt32LE(128, 1044); bytes.writeUInt32LE(512, 1048);
  if (certificate) {
    bytes.writeUInt32LE(4096, 152 + 128); bytes.writeUInt32LE(16, 152 + 132);
    bytes.writeUInt32LE(16, 4096); bytes.writeUInt16LE(0x200, 4100); bytes.writeUInt16LE(2, 4102);
  }
  return bytes;
}
function windowsRuntime(patch: Record<string, unknown> = {}, exit = 0) {
  const calls: Array<{ tool: string; args: string[]; env?: NodeJS.ProcessEnv }> = [];
  const run: InstallerCommandRunner = async (tool, args, options) => {
    calls.push({ tool, args, env: options.env });
    assert.match(tool, /System32\\WindowsPowerShell\\v1.0\\powershell.exe$/);
    assert.ok(args.includes("-NoProfile"));
    assert.match(args.at(-1)!, /Get-AuthenticodeSignature -LiteralPath \$env:OSIR_UPDATE_INSTALLER/);
    assert.doesNotMatch(args.join(" "), /Unblock-File|ExecutionPolicy|Start-Process|Remove-Item/);
    return { status: exit, stdout: JSON.stringify({ status: "NotSigned", product: "OSIR Anywhere", version: VERSION, fileVersion: `${VERSION}.0`, ...patch }), stderr: "" };
  };
  return { platform: "win32", run, calls };
}

test("Windows accepts actual unsigned NSIS/product/version and adds Internet-zone origin without embedding the path in PowerShell", async t => {
  const f = await fixture(t, nsis(), "win32"); const runtime = windowsRuntime();
  await prepareNativeInstaller(f.request, runtime);
  const origin = await fs.readFile(`${f.file}:Zone.Identifier`, "utf8");
  assert.match(origin, /\[ZoneTransfer\]\r\nZoneId=3\r\n/);
  assert.ok(origin.includes(`HostUrl=${f.artifact.url}`));
  assert.ok(origin.includes(`ReferrerUrl=${RELEASE_MANIFEST_URL}`));
  assert.equal(runtime.calls[0].env?.OSIR_UPDATE_INSTALLER, f.file);
  assert.equal(runtime.calls[0].args.at(-1)!.includes(f.file), false);
});

test("Windows preserves existing Internet/Restricted origin byte for byte, including UTF-16", async t => {
  for (const bytes of [Buffer.from("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://original.test\r\n"),
    Buffer.from("\uFEFF[ZoneTransfer]\r\nZoneId=4\r\n"),
    Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from("[ZoneTransfer]\r\nZoneId=4\r\n", "utf16le")])]) {
    const f = await fixture(t, nsis(), "win32");
    await fs.writeFile(`${f.file}:Zone.Identifier`, bytes);
    await prepareNativeInstaller(f.request, windowsRuntime());
    assert.deepEqual(await fs.readFile(`${f.file}:Zone.Identifier`), bytes);
  }
});

test("Windows upgrades a local-zone marker but refuses ambiguous or misplaced protection metadata", async t => {
  const f = await fixture(t, nsis(), "win32");
  await fs.writeFile(`${f.file}:Zone.Identifier`, "[ZoneTransfer]\r\nZoneId=2\r\n");
  await prepareNativeInstaller(f.request, windowsRuntime());
  assert.match(await fs.readFile(`${f.file}:Zone.Identifier`, "utf8"), /ZoneId=3/);
  for (const value of ["[ZoneTransfer]\r\nZoneId=4\r\nZoneId=2\r\n", "[ZoneTransfer]\r\n[Other]\r\nZoneId=3\r\n"]) {
    await fs.writeFile(`${f.file}:Zone.Identifier`, value);
    await assert.rejects(prepareNativeInstaller(f.request, windowsRuntime()), InstallerNativeValidationError);
    assert.equal(await fs.readFile(`${f.file}:Zone.Identifier`, "utf8"), value);
  }
});

test("Windows signed/default policy requires Valid plus a certificate table; unsigned rejects every signed/damaged result", async t => {
  for (const declaration of ["authenticode", undefined] as const) {
    const f = await fixture(t, nsis(true), "win32"); f.artifact.systemSignature = declaration;
    await prepareNativeInstaller(f.request, windowsRuntime({ status: "Valid" }));
    for (const status of ["NotSigned", "HashMismatch", "NotTrusted", "UnknownError", "NotSupported"])
      await assert.rejects(prepareNativeInstaller(f.request, windowsRuntime({ status })), InstallerNativeValidationError);
  }
  for (const [cert, status] of [[false, "Valid"], [false, "HashMismatch"], [true, "NotSigned"], [true, "Valid"]] as const) {
    const f = await fixture(t, nsis(cert), "win32");
    await assert.rejects(prepareNativeInstaller(f.request, windowsRuntime({ status })), InstallerNativeValidationError);
  }
  const f = await fixture(t, nsis(), "win32"); f.artifact.systemSignature = "authenticode";
  await assert.rejects(prepareNativeInstaller(f.request, windowsRuntime({ status: "Valid" })), InstallerNativeValidationError);
});

test("Windows rejects foreign product/version, signature tool errors and non-NSIS/malformed PE/certificate boundaries", async t => {
  for (const patch of [{ product: "Other" }, { version: "2.1.9" }, { fileVersion: "2.1.9.0" }]) {
    const f = await fixture(t, nsis(), "win32");
    await assert.rejects(prepareNativeInstaller(f.request, windowsRuntime(patch)), InstallerNativeValidationError);
  }
  const f = await fixture(t, nsis(), "win32");
  await assert.rejects(prepareNativeInstaller(f.request, windowsRuntime({}, 1)), InstallerNativeValidationError);
  const mutations = [
    (b: Buffer) => b.write("XX", 0), (b: Buffer) => b.writeUInt32LE(999999, 60),
    (b: Buffer) => b.writeUInt32LE(0, 1028), (b: Buffer) => b.writeUInt32LE(1, 1024),
    (b: Buffer) => b.writeUInt32LE(999999, 1048), (b: Buffer) => b.writeUInt32LE(999999, 396),
    (b: Buffer) => b.writeUInt32LE(1, 152 + 128), (b: Buffer) => b.writeUInt32LE(16, 152 + 132),
    (b: Buffer) => { b.writeUInt32LE(4096, 152 + 128); b.writeUInt32LE(100, 152 + 132); },
    (b: Buffer) => b.writeUInt32LE(1000, 152 + 92),
  ];
  for (const mutate of mutations) {
    const bytes = nsis(); mutate(bytes);
    const f = await fixture(t, bytes, "win32"); const runtime = windowsRuntime();
    await assert.rejects(prepareNativeInstaller(f.request, runtime), InstallerNativeValidationError);
    assert.equal(runtime.calls.length, 0, "bad structure is rejected before asking Authenticode");
  }
});

test("Windows origin write failure cannot be ignored", async t => {
  const f = await fixture(t, nsis(), "win32");
  await fs.mkdir(`${f.file}:Zone.Identifier`);
  const runtime = windowsRuntime();
  await assert.rejects(prepareNativeInstaller(f.request, runtime), InstallerNativeValidationError);
  assert.equal(runtime.calls.length, 0);
});

test("hash/size, native platform and file identity are mandatory, including rechecks after native inspection", async t => {
  const f = await fixture(t); const runtime = macRuntime(t);
  f.artifact.sha256 = "0".repeat(64);
  await assert.rejects(prepareNativeInstaller(f.request, runtime), InstallerNativeValidationError);
  assert.equal(runtime.calls.length, 0);
  f.artifact.sha256 = createHash("sha256").update(await fs.readFile(f.file)).digest("hex");
  await assert.rejects(prepareNativeInstaller(f.request, { ...runtime, platform: "linux" }), InstallerNativeValidationError);
  const link = path.join(f.directory, "symlink.dmg"); await fs.symlink(f.file, link);
  await assert.rejects(prepareNativeInstaller({ ...f.request, file: link }, runtime), InstallerNativeValidationError);
  const hardlink = path.join(f.directory, "hardlink.dmg"); await fs.link(f.file, hardlink);
  await assert.rejects(prepareNativeInstaller(f.request, runtime), InstallerNativeValidationError);
  await fs.unlink(hardlink);
  const mutate = macRuntime(t, { onProbe: async tool => {
    if (tool.endsWith("plutil")) await fs.writeFile(f.file, Buffer.alloc(f.artifact.size, "x"));
  } });
  await assert.rejects(prepareNativeInstaller(f.request, mutate), InstallerNativeValidationError);
  assert.ok(mutate.calls.some(c => c.args[0] === "detach"));
});

const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const server = { serverUrl: "https://server.test", apiNamespace: "/api/v2", oauthWebOrigin: "https://server.test" };
async function serviceFixture(t: TestContext, options: MacOptions = {}) {
  const f = await fixture(t); const runtime = macRuntime(t, options);
  const states: DesktopUpdateState[] = []; const opened: string[] = [];
  const payload = Buffer.from(JSON.stringify({ schemaVersion: 1, productId: "osir-anywhere", channel: "stable", releaseId: "r1",
    version: VERSION, publishedAt: "2026-11-14T00:00:00Z", artifacts: [f.artifact] }));
  const bytes = await fs.readFile(f.file);
  const service = new DesktopUpdateService({ directory: f.directory, currentVersion: "2.1.0", manifestUrl: RELEASE_MANIFEST_URL,
    publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }).toString(), platform: "darwin", arch: "arm64",
    fetcher: async input => String(input) === RELEASE_MANIFEST_URL
      ? Response.json({ payload: payload.toString("base64"), signature: sign("RSA-SHA256", payload, keys.privateKey).toString("base64") }) : new Response(bytes),
    prepareInstaller: request => prepareNativeInstaller(request, runtime), onState: state => states.push(state),
    openInstaller: async file => { opened.push(file); },
  });
  t.after(() => service.dispose());
  return { ...f, runtime, service, states, opened };
}

test("service completes RSA/hash/native/origin checks before opening; a cached retry repeats native checks", async t => {
  const h = await serviceFixture(t);
  await h.service.check(server);
  assert.equal((await h.service.download()).phase, "downloaded");
  assert.equal(h.opened.length, 1);
  assert.equal(h.service.getState().currentVersion, "2.1.0", "OS handoff is never an installed version claim");
  assert.equal((await h.service.download()).phase, "downloaded");
  assert.equal(h.runtime.calls.filter(c => c.args[0] === "attach").length, 2);
});

test("service never opens/claims downloaded when native checks or origin marking fail", async t => {
  for (const options of [{ app: "broken" }, { plist: { CFBundleIdentifier: "com.other.app" } }, { markBad: true }] satisfies MacOptions[]) {
    const h = await serviceFixture(t, options); await h.service.check(server);
    const state = await h.service.download();
    assert.equal(h.opened.length, 0); assert.equal(state.phase, "idle"); assert.equal(state.error, "downloadFailed");
    assert.match(state.errorDetail!, /系统身份、签名或下载来源/);
    assert.equal(h.states.some(s => s.phase === "opening" || s.phase === "downloaded"), false);
  }
});

test("cancellation/sign-out while native checks are active prevents opening and cleans the mount", async t => {
  for (const action of ["cancel", "signout"] as const) {
    let enter!: () => void, resume!: () => void;
    const entered = new Promise<void>(r => { enter = r; }); const gate = new Promise<void>(r => { resume = r; });
    const h = await serviceFixture(t, { onProbe: async tool => { if (tool.endsWith("plutil")) { enter(); await gate; } } });
    await h.service.check(server); const pending = h.service.download(); await entered;
    if (action === "cancel") void h.service.cancelDownload(); else await h.service.check(null);
    resume(); await pending;
    assert.equal(h.opened.length, 0); assert.equal(h.service.getState().error, null);
    assert.ok(h.runtime.calls.some(c => c.args[0] === "detach"));
  }
});

test("default service boundary cannot open a mere hash-valid text file without native validation", async t => {
  const h = await serviceFixture(t);
  // A separate production-configured service deliberately has no injected runner.
  const payload = Buffer.from(JSON.stringify({ schemaVersion: 1, productId: "osir-anywhere", channel: "stable", releaseId: "r1",
    version: VERSION, publishedAt: "2026-11-14T00:00:00Z", artifacts: [h.artifact] }));
  let opened = false;
  const service = new DesktopUpdateService({ directory: h.directory, currentVersion: "2.1.0", manifestUrl: RELEASE_MANIFEST_URL,
    publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }).toString(), platform: "darwin", arch: "arm64",
    fetcher: async input => String(input) === RELEASE_MANIFEST_URL ? Response.json({ payload: payload.toString("base64"),
      signature: sign("RSA-SHA256", payload, keys.privateKey).toString("base64") }) : new Response(await fs.readFile(h.file)),
    openInstaller: async () => { opened = true; }, onState: () => undefined,
  });
  t.after(() => service.dispose());
  await service.check(server); const state = await service.download();
  assert.equal(opened, false); assert.equal(state.error, "downloadFailed");
});
