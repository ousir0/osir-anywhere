/** Exact published builds authenticate unsigned first-party installations.
 * This supplements, and never disables, the operating system's launch policy.
 */
import { constants, createHash, createPublicKey, verify } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, readdir, readlink, realpath } from "node:fs/promises";
import path from "node:path";

export const HANDOFF_TRUST_URL = "https://osirvedio.cn-nb1.rains3.com/osir-anywhere/releases/handoff-trust.json";
export type HandoffBuild = {
  productId: "osir-client" | "osir-anywhere";
  version: string;
  releaseId: string;
  platform: "darwin";
  treeSha256: string;
};
export type HandoffTrust = { schemaVersion: 1; productId: "osir-desktop-handoff-trust";
  publishedAt: string; validUntil: string; builds: HandoffBuild[] };

function record(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
function exact(value: Record<string, unknown>, fields: string[]): boolean {
  return Object.keys(value).sort().join(",") === fields.sort().join(",");
}
function decoded(value: unknown): Buffer {
  if (typeof value !== "string" || value.length > 180_000 || !value.length) throw new Error("无法验证已安装的客户端。");
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) throw new Error("无法验证已安装的客户端。");
  return bytes;
}

function timestamp(value: unknown): number {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) return NaN;
  // Date.parse normalizes e.g. February 30 instead of rejecting it.
  const date = new Date(`${value.slice(0, 10)}T00:00:00Z`);
  if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0, 10) !== value.slice(0, 10) ||
      Number(value.slice(11, 13)) > 23) return NaN;
  return Date.parse(value);
}

export function verifyHandoffTrust(envelope: unknown, publicKeyPem: string, now = Date.now()): HandoffTrust {
  if (!record(envelope) || !exact(envelope, ["payload", "signature"])) throw new Error("无法验证已安装的客户端。");
  const bytes = decoded(envelope.payload), signature = decoded(envelope.signature);
  const key = createPublicKey(publicKeyPem);
  const bits = key.asymmetricKeyDetails?.modulusLength ?? 0;
  if (!publicKeyPem.startsWith("-----BEGIN PUBLIC KEY-----") || key.asymmetricKeyType !== "rsa" || bits < 2048 || bits > 8192 ||
      !verify("RSA-SHA256", bytes, { key, padding: constants.RSA_PKCS1_PADDING }, signature)) throw new Error("客户端验证失败。");
  const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  return validateHandoffTrust(value, now);
}

/** Shared by the offline feed builder; this validates metadata, not authenticity. */
export function validateHandoffTrust(value: unknown, now = Date.now()): HandoffTrust {
  const published = record(value) ? timestamp(value.publishedAt) : NaN;
  const expires = record(value) ? timestamp(value.validUntil) : NaN;
  if (!Number.isFinite(now) || !record(value) || !exact(value, ["schemaVersion", "productId", "publishedAt", "validUntil", "builds"]) ||
      value.schemaVersion !== 1 || value.productId !== "osir-desktop-handoff-trust" ||
      !Number.isFinite(published) || !Number.isFinite(expires) || expires <= published ||
      published > now + 300_000 || expires <= now || expires - published > 366 * 86400_000 ||
      !Array.isArray(value.builds) || !value.builds.length || value.builds.length > 128) throw new Error("客户端验证信息已过期或不可用。");
  const seen = new Set<string>();
  for (const build of value.builds) {
    if (!record(build) || !exact(build, ["productId", "version", "releaseId", "platform", "treeSha256"]) ||
        typeof build.productId !== "string" || !["osir-client", "osir-anywhere"].includes(build.productId) || build.platform !== "darwin" ||
        typeof build.version !== "string" || build.version.length > 40 ||
        !/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\+[1-9][0-9]{0,4})?$/.test(build.version) ||
        (build.version.includes("+") && Number(build.version.split("+")[1]) > 65535) ||
        typeof build.releaseId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(build.releaseId) || build.releaseId.includes("..") ||
        typeof build.treeSha256 !== "string" || !/^[a-f0-9]{64}$/.test(build.treeSha256) ||
        seen.has(`${build.productId}:${build.treeSha256}`)) throw new Error("客户端验证信息无效。");
    seen.add(`${build.productId}:${build.treeSha256}`);
  }
  return value as HandoffTrust;
}

export async function fetchHandoffTrust(fetcher: typeof fetch, key: string, signal?: AbortSignal): Promise<HandoffTrust> {
  const response = await fetcher(HANDOFF_TRUST_URL, { signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(10_000)]) : AbortSignal.timeout(10_000),
    credentials: "omit", redirect: "error", cache: "no-store", headers: { accept: "application/json" } });
  if (response.status !== 200 || response.redirected || (response.url && response.url !== HANDOFF_TRUST_URL)) throw new Error("暂时无法验证客户端，请稍后重试。");
  if (!response.body) throw new Error("暂时无法验证客户端，请稍后重试。");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = []; let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 256 * 1024) throw new Error("客户端验证信息过大。");
      chunks.push(value);
    }
  } finally { await reader.cancel().catch(() => {}); }
  return verifyHandoffTrust(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks))), key);
}

function inside(root: string, child: string): boolean {
  const relative = path.relative(root, child);
  return relative === "" || (!path.isAbsolute(relative) && relative !== ".." && !relative.startsWith(`..${path.sep}`));
}

/** Same byte algorithm as release native-smoke fingerprintTree: sorted DFS,
 * compact JSON [{path,size,sha256}|{path,link}], SHA256 over UTF-8 JSON.
 */
export async function handoffBundleFingerprint(root: string): Promise<string> {
  const base = await realpath(root);
  const rootStat = await lstat(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || base !== path.resolve(root)) throw new Error("客户端安装路径无效。");
  const entries: ({ path: string; link: string } | { path: string; size: number; sha256: string })[] = [];
  let total = 0;
  let visited = 0;
  async function walk(file: string, name: string): Promise<void> {
    if (++visited > 100_000) throw new Error("客户端安装文件过多。");
    const before = await lstat(file);
    if (before.isSymbolicLink()) {
      if (!inside(base, await realpath(file))) throw new Error("客户端安装路径无效。");
      const link = await readlink(file);
      const after = await lstat(file);
      if (before.ino !== after.ino || before.ctimeMs !== after.ctimeMs || link !== await readlink(file)) throw new Error("客户端文件已变化，请重试。");
      entries.push({ path: name, link });
    } else if (before.isDirectory()) {
      for (const child of (await readdir(file)).sort()) await walk(path.join(file, child), name ? `${name}/${child}` : child);
      const after = await lstat(file);
      if (before.ino !== after.ino || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw new Error("客户端文件已变化，请重试。");
    } else {
      if (!before.isFile() || before.nlink !== 1) throw new Error("客户端安装文件无效。");
      total += before.size;
      if (total > 16 * 1024 ** 3) throw new Error("客户端安装文件过大。");
      const hash = createHash("sha256");
      const handle = await open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
      try {
        const opened = await handle.stat();
        if (!opened.isFile() || opened.ino !== before.ino || opened.dev !== before.dev || opened.nlink !== 1) throw new Error("客户端文件已变化，请重试。");
        for await (const chunk of handle.createReadStream({ autoClose: false })) hash.update(chunk);
      } finally { await handle.close(); }
      const after = await lstat(file);
      if (before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw new Error("客户端文件已变化，请重试。");
      entries.push({ path: name, size: after.size, sha256: hash.digest("hex") });
    }
  }
  await walk(root, "");
  if (!entries.length) throw new Error("客户端安装文件缺失。");
  return createHash("sha256").update(JSON.stringify(entries)).digest("hex");
}

export async function verifyHandoffBundle(root: string, product: HandoffBuild["productId"], trust: HandoffTrust): Promise<HandoffBuild> {
  const hash = await handoffBundleFingerprint(root);
  const build = trust.builds.find(item => item.productId === product && item.platform === "darwin" && item.treeSha256 === hash);
  if (!build) throw new Error("客户端版本无法验证，请从 OSIR 客户端重新安装。");
  return build;
}
