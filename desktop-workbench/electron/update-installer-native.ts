import { execFile } from "node:child_process";
import { constants } from "node:fs";
import fs, { type FileHandle } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { RELEASE_MANIFEST_URL, resolveReleaseSystemSignature } from "./release-manifest";
import { verifyDownloadedInstaller } from "./update-download";
import type { ReleaseArtifact } from "../shared/desktop-updates";

type CommandResult = { status: number; stdout: string; stderr: string };
export type InstallerCommandRunner = (tool: string, args: string[], options: {
  signal: AbortSignal; env?: NodeJS.ProcessEnv;
}) => Promise<CommandResult>;
type InstallerRequest = { file: string; artifact: ReleaseArtifact; version: string; signal: AbortSignal };
export type InstallerNativeRuntime = { run?: InstallerCommandRunner; platform?: string };

export class InstallerNativeValidationError extends Error {
  constructor(cause: unknown) {
    super("安装包系统身份、签名或下载来源校验失败，已阻止打开。", { cause });
    this.name = "InstallerNativeValidationError";
  }
}

const APP_ID = "com.osir.anywhere.desktop";
const PRODUCT = "OSIR Anywhere";
const QUARANTINE = "com.apple.quarantine";
const runNative: InstallerCommandRunner = (tool, args, options) => new Promise((resolve, reject) => {
  execFile(tool, args, { encoding: "utf8", windowsHide: true, timeout: 120_000,
    maxBuffer: 256 * 1024, signal: options.signal,
    env: { ...process.env, ...options.env, LC_ALL: "C" } }, (error, stdout, stderr) => {
    // Numeric exit codes are inspection results. Spawn, timeout, output-limit
    // and cancellation errors must never be interpreted as "not signed".
    if (error && (typeof error.code !== "number" || error.killed)) reject(error);
    else resolve({ status: error ? Number(error.code) : 0, stdout, stderr });
  });
});
function requireCheck(ok: unknown, message: string): asserts ok {
  if (!ok) throw new Error(message);
}
function successful(result: CommandResult, message: string): CommandResult {
  requireCheck(result.status === 0, message);
  return result;
}

/** Preserve OS download protection; this module never launches an installer. */
async function markOrigin(request: InstallerRequest, run: InstallerCommandRunner): Promise<void> {
  const { file, artifact, signal } = request;
  if (artifact.platform === "darwin") {
    const listing = successful(await run("/usr/bin/xattr", [file], { signal }), "Cannot inspect quarantine.");
    if (listing.stdout.split(/\r?\n/).includes(QUARANTINE)) {
      const existing = successful(await run("/usr/bin/xattr", ["-p", QUARANTINE, file], { signal }), "Cannot read quarantine.");
      requireCheck(existing.stdout.trim(), "Empty quarantine attribute.");
      return;
    }
    const value = `0083;${Math.floor(Date.now() / 1000).toString(16)};${PRODUCT};${randomUUID()}`;
    successful(await run("/usr/bin/xattr", ["-w", QUARANTINE, value, file], { signal }), "Cannot add quarantine.");
    const marked = successful(await run("/usr/bin/xattr", ["-p", QUARANTINE, file], { signal }), "Cannot confirm quarantine.");
    requireCheck(marked.stdout.trim() === value, "Quarantine was not retained.");
  } else {
    const stream = `${file}:Zone.Identifier`;
    let existing = "";
    try {
      const handle = await fs.open(stream, "r");
      try {
        requireCheck((await handle.stat()).size <= 8192, "Invalid origin stream.");
        const bytes = await handle.readFile();
        existing = bytes[0] === 0xff && bytes[1] === 0xfe ? bytes.subarray(2).toString("utf16le") : bytes.toString("utf8");
      } finally { await handle.close(); }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    const zone = originZone(existing);
    if (zone === 3 || zone === 4) return;
    requireCheck(!existing.trim() || (zone !== null && zone >= 0 && zone <= 2), "Ambiguous origin protection stream.");
    requireCheck(!/[\r\n]/.test(artifact.url) && new URL(artifact.url).protocol === "https:", "Invalid download origin.");
    await fs.writeFile(stream, `[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=${RELEASE_MANIFEST_URL}\r\nHostUrl=${artifact.url}\r\n`, { mode: 0o600 });
    signal.throwIfAborted();
    requireCheck(originZone(await fs.readFile(stream, "utf8")) === 3, "Origin stream was not retained.");
  }
}
function originZone(value: string): number | null {
  let transfer = false, sections = 0;
  const zones: number[] = [];
  for (const raw of value.replace(/^\uFEFF/, "").split(/\r?\n/)) {
    const line = raw.trim();
    const section = /^\[(.+)\]$/.exec(line);
    if (section) { transfer = section[1].toLowerCase() === "zonetransfer"; if (transfer) ++sections; }
    else if (transfer && /^ZoneId\s*=/i.test(line)) {
      const match = /^ZoneId\s*=\s*(\d+)$/i.exec(line);
      if (!match) return null;
      zones.push(Number(match[1]));
    }
  }
  return sections === 1 && zones.length === 1 ? zones[0] : null;
}

type MacSignature = "unsigned" | "adhoc" | "developer" | "other";
async function macSignature(file: string, deep: boolean, signal: AbortSignal, run: InstallerCommandRunner): Promise<MacSignature> {
  const identity = await run("/usr/bin/codesign", ["-dv", "--verbose=4", file], { signal });
  const text = `${identity.stdout}\n${identity.stderr}`;
  if (identity.status !== 0) {
    // Only the native tool's specific unsigned result qualifies. Other failures,
    // including malformed signature data, are a hard failure under every policy.
    requireCheck(/: code object is not signed at all\s*$/.test(text.trim()), "Missing or damaged system signature.");
    return "unsigned";
  }
  const adhoc = /^Signature=adhoc\s*$/m.test(text);
  const developer = /^Authority=Developer ID Application:/m.test(text);
  if (deep) requireCheck(text.split(/\r?\n/).includes(`Identifier=${APP_ID}`), "Signed bundle identity mismatch.");
  successful(await run("/usr/bin/codesign", ["--verify", ...(deep ? ["--deep"] : []), "--strict", "--all-architectures",
    ...(developer ? ["-R", `anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists${deep ? ` and identifier "${APP_ID}"` : ""}`] : []), file], { signal }), "Damaged or untrusted system signature.");
  return adhoc ? "adhoc" : developer ? "developer" : "other";
}

async function verifyMacPackage(app: string, version: string): Promise<void> {
  requireCheck((await fs.lstat(path.join(app, "Contents", "Resources"))).isDirectory(), "Missing or linked app resources.");
  const asar = path.join(app, "Contents", "Resources", "app.asar");
  requireCheck((await fs.lstat(asar)).isFile(), "Missing or linked app package.");
  const file = await fs.open(asar, "r");
  try {
    const size = (await file.stat()).size;
    const prefix = await readAt(file, 0, 16);
    const headerSize = prefix.readUInt32LE(4), jsonSize = prefix.readUInt32LE(12);
    requireCheck(prefix.readUInt32LE(0) === 4 && headerSize >= 8 && headerSize <= 8 * 1024 * 1024 &&
      jsonSize <= headerSize - 8 && headerSize + 8 <= size, "Invalid app archive header.");
    const header = JSON.parse((await readAt(file, 16, jsonSize)).toString("utf8"));
    const entry = header?.files?.["package.json"];
    requireCheck(entry && !Object.hasOwn(entry, "link") && !entry.unpacked && typeof entry.offset === "string" && /^\d+$/.test(entry.offset) &&
      Number.isSafeInteger(entry.size) && entry.size >= 2 && entry.size <= 256 * 1024, "Invalid packaged product metadata.");
    const offset = 8 + headerSize + Number(entry.offset);
    requireCheck(Number.isSafeInteger(offset) && offset >= 8 + headerSize && offset + entry.size <= size, "App package exceeds archive bounds.");
    const info = JSON.parse((await readAt(file, offset, entry.size)).toString("utf8"));
    requireCheck(info?.name === "osir-anywhere-desktop-workbench" && info?.productName === PRODUCT &&
      info?.main === "dist/electron/main.js" && info?.version === version, "Packaged OSIR product/version mismatch.");
  } finally { await file.close(); }
}

async function verifyMacNested(app: string, signal: AbortSignal, run: InstallerCommandRunner): Promise<void> {
  // An unsigned root has no resource seal. Check nested bundles and every Mach-O
  // independently so damaged inner signatures cannot hide behind an unsigned app.
  const root = await fs.realpath(app);
  const queue = [app];
  const started = Date.now();
  let count = 0;
  while (queue.length) {
    signal.throwIfAborted();
    requireCheck(++count <= 100_000 && Date.now() - started <= 180_000, "Application inspection exceeds safety bounds.");
    const file = queue.pop()!;
    const stat = await fs.lstat(file);
    if (stat.isSymbolicLink()) {
      const target = await fs.realpath(file);
      requireCheck(target === root || target.startsWith(`${root}${path.sep}`), "Application symlink escapes bundle.");
    } else if (stat.isDirectory()) {
      if (file !== app && /\.(app|framework|xpc|appex|bundle)$/.test(file)) await macSignature(file, false, signal, run);
      for (const name of await fs.readdir(file)) {
        requireCheck(queue.length + count < 100_000, "Application contains too many entries.");
        queue.push(path.join(file, name));
      }
    } else if (stat.isFile()) {
      if (stat.size < 4) continue;
      const handle = await fs.open(file, "r");
      let magic: number;
      try { magic = (await readAt(handle, 0, 4)).readUInt32BE(0); } finally { await handle.close(); }
      if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca].includes(magic))
        await macSignature(file, false, signal, run);
    } else throw new Error("Unsupported application file type.");
  }
}

async function verifyMac(request: InstallerRequest, run: InstallerCommandRunner): Promise<void> {
  const { file, version, artifact, signal } = request;
  const policy = resolveReleaseSystemSignature(artifact);
  successful(await run("/usr/bin/hdiutil", ["verify", file], { signal }), "Invalid original disk image.");
  // Electron's DMG container may be unsigned even when the contained app has a
  // valid Developer ID/notarization. Still reject any damaged container signature.
  await macSignature(file, false, signal, run);
  const mount = await fs.mkdtemp(path.join(os.tmpdir(), "osir-update-mount-"));
  let attempted = false;
  let attached = false;
  try {
    attempted = true;
    successful(await run("/usr/bin/hdiutil", ["attach", "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", mount, file], { signal }), "Cannot mount original image read-only.");
    attached = true;
    signal.throwIfAborted();
    const apps = (await fs.readdir(mount)).filter(name => name.endsWith(".app"));
    requireCheck(apps.length === 1 && apps[0] === `${PRODUCT}.app`, "Unexpected installer application.");
    const app = path.join(mount, apps[0]);
    for (const dir of [app, path.join(app, "Contents"), path.join(app, "Contents", "MacOS")]) {
      requireCheck((await fs.lstat(dir)).isDirectory(), "Bundle directory is missing or a symlink.");
    }
    const plist = path.join(app, "Contents", "Info.plist");
    requireCheck((await fs.lstat(plist)).isFile(), "Bundle metadata is missing or a symlink.");
    const metadata: unknown = JSON.parse(successful(await run("/usr/bin/plutil", ["-convert", "json", "-o", "-", "--", plist], { signal }), "Cannot read bundle metadata.").stdout);
    requireCheck(metadata && typeof metadata === "object" && !Array.isArray(metadata), "Invalid bundle metadata.");
    const info = metadata as Record<string, unknown>;
    requireCheck(info.CFBundleIdentifier === APP_ID && info.CFBundleName === PRODUCT &&
      info.CFBundleDisplayName === PRODUCT && info.CFBundleExecutable === PRODUCT &&
      info.CFBundleShortVersionString === version && info.CFBundlePackageType === "APPL", "OSIR bundle identity/version mismatch.");
    const executable = await fs.lstat(path.join(app, "Contents", "MacOS", PRODUCT));
    requireCheck(executable.isFile() && (executable.mode & 0o111) !== 0, "Bundle executable is missing or a symlink.");
    await verifyMacPackage(app, version);
    const actual = await macSignature(app, true, signal, run);
    requireCheck(policy === "unsigned" ? actual === "unsigned" || actual === "adhoc" :
      policy === "developer-id-notarized" && actual === "developer", "Application signature differs from release policy.");
    await verifyMacNested(app, signal, run);
    if (policy === "developer-id-notarized") {
      successful(await run("/usr/bin/xcrun", ["stapler", "validate", file], { signal }), "Original image is not notarized.");
      successful(await run("/usr/sbin/spctl", ["--assess", "--type", "execute", "--verbose=4", app], { signal }), "Gatekeeper rejected the app.");
    }
  } finally {
    // Cleanup must survive cancellation; never recursively remove mounted data.
    if (attempted) {
      const result = await run("/usr/bin/hdiutil", ["detach", mount], { signal: new AbortController().signal });
      requireCheck(!attached || result.status === 0, "Temporary installer mount could not be detached.");
    }
    await fs.rmdir(mount);
  }
}

async function readAt(file: FileHandle, position: number, size: number): Promise<Buffer> {
  const bytes = Buffer.alloc(size);
  const result = await file.read(bytes, 0, size, position);
  requireCheck(result.bytesRead === size, "Truncated PE/NSIS installer.");
  return bytes;
}
async function nsisCertificate(file: FileHandle, size: number, signal: AbortSignal): Promise<boolean> {
  const dos = await readAt(file, 0, 64);
  const pe = dos.readUInt32LE(60);
  requireCheck(dos.toString("ascii", 0, 2) === "MZ" && pe >= 64 && pe + 24 <= size, "Invalid PE header.");
  const header = await readAt(file, pe, 24);
  const sections = header.readUInt16LE(6), optionalSize = header.readUInt16LE(20);
  requireCheck(header.readUInt32LE(0) === 0x4550 && [0x14c, 0x8664, 0xaa64].includes(header.readUInt16LE(4)) &&
    (header.readUInt16LE(22) & 2) !== 0 && sections > 0 && sections <= 96 && optionalSize >= 96 && optionalSize <= 4096, "Invalid PE structure.");
  const optional = await readAt(file, pe + 24, optionalSize);
  const magic = optional.readUInt16LE(0);
  requireCheck(magic === 0x10b || magic === 0x20b, "Invalid PE optional header.");
  const table = magic === 0x10b ? 96 : 112;
  requireCheck(optional.length >= table, "Truncated PE directories.");
  const count = optional.readUInt32LE(table - 4);
  requireCheck(count <= (optional.length - table) / 8, "Truncated PE directories.");
  const certOffset = count > 4 ? optional.readUInt32LE(table + 32) : 0;
  const certSize = count > 4 ? optional.readUInt32LE(table + 36) : 0;
  const certificate = certOffset !== 0 || certSize !== 0;
  requireCheck(!certificate || (certOffset !== 0 && certOffset % 8 === 0 && certSize >= 8 && certOffset + certSize <= size), "Damaged PE certificate directory.");
  let overlay = pe + 24 + optionalSize + sections * 40;
  for (let i = 0; i < sections; ++i) {
    const section = await readAt(file, pe + 24 + optionalSize + i * 40, 40);
    const end = section.readUInt32LE(20) + section.readUInt32LE(16);
    requireCheck(end <= size, "PE section exceeds installer.");
    overlay = Math.max(overlay, end);
  }
  const dataEnd = certificate ? certOffset : size;
  requireCheck(overlay <= dataEnd && overlay <= 64 * 1024 * 1024, "Invalid NSIS overlay.");
  const first = Math.ceil(overlay / 512) * 512;
  for (let at = first; at + 28 <= Math.min(dataEnd, first + 64 * 1024); at += 512) {
    signal.throwIfAborted();
    const nsis = await readAt(file, at, 28);
    if (!nsis.subarray(4, 20).equals(Buffer.from("efbeadde4e756c6c736f6674496e7374", "hex"))) continue;
    const flags = nsis.readUInt32LE(0), headerSize = nsis.readUInt32LE(20), allSize = nsis.readUInt32LE(24);
    requireCheck((flags & ~15) === 0 && (flags & 1) === 0 && headerSize > 0 && allSize >= 28 && at + allSize <= dataEnd, "Invalid NSIS installation payload.");
    return certificate;
  }
  throw new Error("Not an NSIS installer.");
}

async function verifyWindows(request: InstallerRequest, file: FileHandle, run: InstallerCommandRunner): Promise<void> {
  const { artifact, signal, version } = request;
  const certificate = await nsisCertificate(file, artifact.size, signal);
  const script = `$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);\n` +
    `$sig=Get-AuthenticodeSignature -LiteralPath $env:OSIR_UPDATE_INSTALLER;\n` +
    `$v=(Get-Item -LiteralPath $env:OSIR_UPDATE_INSTALLER -ErrorAction Stop).VersionInfo;\n` +
    `@{status=[string]$sig.Status;product=[string]$v.ProductName;version=[string]$v.ProductVersion;fileVersion=[string]$v.FileVersion} | ConvertTo-Json -Compress`;
  const powershell = path.win32.join(process.env.SystemRoot ?? "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const result = successful(await run(powershell, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
    { signal, env: { OSIR_UPDATE_INSTALLER: request.file } }), "Authenticode inspection failed.");
  const report: unknown = JSON.parse(result.stdout.replace(/^\uFEFF/, ""));
  requireCheck(report && typeof report === "object" && !Array.isArray(report), "Invalid Authenticode report.");
  const info = report as Record<string, unknown>;
  const core = version.split(/[-+]/)[0];
  requireCheck(info.product === PRODUCT && info.version === version &&
    (info.fileVersion === core || info.fileVersion === `${core}.0`), "OSIR installer product/version mismatch.");
  const policy = resolveReleaseSystemSignature(artifact);
  requireCheck(policy === "unsigned" ? info.status === "NotSigned" && !certificate :
    policy === "authenticode" && info.status === "Valid" && certificate, "Invalid system signature or release policy mismatch.");
}

/** Input is authenticated by the RSA release manifest before reaching here.
 * Hash/size are checked again around native inspection, including cached files.
 * Runtime injection is a trusted main-process test boundary, never IPC input. */
export async function prepareNativeInstaller(request: InstallerRequest, runtime: InstallerNativeRuntime = {}): Promise<void> {
  const { file, artifact, signal } = request;
  const run = runtime.run ?? runNative;
  let handle: FileHandle | undefined;
  try {
    signal.throwIfAborted();
    requireCheck(path.isAbsolute(file) && artifact.platform === (runtime.platform ?? process.platform), "Installer platform/path mismatch.");
    const before = await fs.lstat(file);
    requireCheck(before.isFile() && before.nlink === 1 && (process.platform === "win32" ||
      (before.uid === process.getuid?.() && (before.mode & 0o022) === 0)), "Installer is not a private regular file.");
    handle = await fs.open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const pinned = await handle.stat();
    requireCheck(pinned.ino === before.ino && pinned.dev === before.dev, "Installer was replaced.");
    await verifyDownloadedInstaller(file, artifact, signal);
    await markOrigin(request, run);
    // NTFS timestamps belong to the whole file, including its origin stream.
    const inspected = await handle.stat();
    signal.throwIfAborted();
    if (artifact.platform === "darwin") await verifyMac(request, run);
    else if (artifact.platform === "win32") await verifyWindows(request, handle, run);
    else throw new Error("Unsupported installer platform.");
    signal.throwIfAborted();
    await verifyDownloadedInstaller(file, artifact, signal);
    const after = await fs.lstat(file);
    requireCheck(after.isFile() && after.ino === pinned.ino && after.dev === pinned.dev && after.nlink === 1 &&
      after.size === pinned.size && after.mtimeMs === inspected.mtimeMs && after.uid === pinned.uid && after.mode === pinned.mode,
      "Installer changed during native inspection.");
  } catch (error) {
    if (signal.aborted) throw error;
    throw new InstallerNativeValidationError(error);
  } finally { await handle?.close(); }
}
