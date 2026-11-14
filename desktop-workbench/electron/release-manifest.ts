import fs from "node:fs";
import path from "node:path";
import { constants, createPublicKey, verify } from "node:crypto";
import type { DesktopReleaseManifest, ReleaseArtifact, ReleaseSystemSignature } from "../shared/desktop-updates";

export const RELEASE_MANIFEST_URL = "https://osirvedio.cn-nb1.rains3.com/osir-anywhere/releases/stable.json";
const RELEASE_ROOT = "https://osirvedio.cn-nb1.rains3.com/osir-anywhere/releases/";
const MAX_MANIFEST_BYTES = 256 * 1024;

/** A missing resource disables updates, rather than preventing Desktop startup. */
export function readReleasePublicKey(resourceRoot: string): string {
  try { return fs.readFileSync(path.join(resourceRoot, "build", "release-public.pub"), "utf8").trim(); }
  catch { return ""; }
}

export function assertManifestUrl(url: string): void {
  if (url !== RELEASE_MANIFEST_URL) throw new Error("更新清单地址不受信任，已停止检查更新。");
}

function record(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function version(value: unknown): value is string {
  return typeof value === "string" && value.length <= 128 &&
    /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.test(value);
}

export function validateReleaseArtifact(value: unknown, releaseId: string): ReleaseArtifact {
  if (!record(value) || typeof value.platform !== "string" || !["darwin", "win32"].includes(value.platform) ||
      typeof value.arch !== "string" || !["arm64", "x64", ...(value.platform === "darwin" ? ["universal"] : [])].includes(value.arch) ||
      (value.systemSignature !== undefined && value.systemSignature !== "unsigned" && value.systemSignature !== (value.platform === "darwin" ? "developer-id-notarized" : "authenticode")) ||
      typeof value.filename !== "string" || value.filename.length > 200 ||
      !/^[A-Za-z0-9][A-Za-z0-9._ -]*$/.test(value.filename) || value.filename.includes("..") ||
      !value.filename.endsWith(value.platform === "darwin" ? ".dmg" : ".exe") ||
      !Number.isSafeInteger(value.size) || (value.size as number) <= 0 ||
      typeof value.sha256 !== "string" || !/^[0-9a-fA-F]{64}$/.test(value.sha256) ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(releaseId) || releaseId.includes("..")) {
    throw new Error("发行清单的安装包信息无效。");
  }
  // One immutable object, in this product's release directory. No redirects,
  // signed query URLs, alternate buckets, encoded slashes or prefix matching.
  const expected = `${RELEASE_ROOT}${encodeURIComponent(releaseId)}/${encodeURIComponent(value.filename)}`;
  if (value.url !== expected) throw new Error("安装包地址与受信任的发行对象路径不匹配。");
  return { platform: value.platform as ReleaseArtifact["platform"], arch: value.arch as ReleaseArtifact["arch"],
    url: expected, size: value.size as number, sha256: value.sha256.toLowerCase(), filename: value.filename,
    ...(value.systemSignature !== undefined ? { systemSignature: value.systemSignature as ReleaseSystemSignature } : {}) };
}

export function resolveReleaseSystemSignature(artifact: ReleaseArtifact): ReleaseSystemSignature {
  return artifact.systemSignature ?? (artifact.platform === "darwin" ? "developer-id-notarized" : "authenticode");
}

function base64(value: unknown): Buffer {
  if (typeof value !== "string" || !value.length || value.length > MAX_MANIFEST_BYTES ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error("发行清单封套格式无效。");
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) throw new Error("发行清单封套格式无效。");
  return decoded;
}

export function verifyReleaseManifest(envelope: unknown, publicKeyPem: string): DesktopReleaseManifest {
  if (!record(envelope)) throw new Error("发行清单封套格式无效。");
  let key;
  try {
    if (!/^-----BEGIN (?:RSA )?PUBLIC KEY-----/.test(publicKeyPem.trim())) throw new Error();
    key = createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== "rsa" || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new Error();
  } catch { throw new Error("缺少有效的发行公钥，暂时无法安全检查更新。"); }
  const payload = base64(envelope.payload);
  const signature = base64(envelope.signature);
  if (!verify("RSA-SHA256", payload, { key, padding: constants.RSA_PKCS1_PADDING }, signature)) {
    throw new Error("发行清单签名校验失败，已阻止更新。");
  }
  const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payload));
  if (!record(value) || value.schemaVersion !== 1 || value.productId !== "osir-anywhere" || value.channel !== "stable" ||
      typeof value.releaseId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value.releaseId) || value.releaseId.includes("..") ||
      !version(value.version) || typeof value.publishedAt !== "string" ||
      (value.revision !== undefined && (!Number.isSafeInteger(value.revision) || (value.revision as number) < 0 || (value.revision as number) > 65535)) ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value.publishedAt) || !Number.isFinite(Date.parse(value.publishedAt)) ||
      (value.minimumClientVersion !== undefined && !version(value.minimumClientVersion)) ||
      (value.minimumServerVersion !== undefined && !version(value.minimumServerVersion)) ||
      !Array.isArray(value.artifacts) || value.artifacts.length > 16) {
    throw new Error("发行清单内容无效或不兼容。");
  }
  const artifacts = value.artifacts.map((artifact) => validateReleaseArtifact(artifact, value.releaseId as string));
  const targets = artifacts.map((artifact) => `${artifact.platform}/${artifact.arch}`);
  if (new Set(targets).size !== targets.length) throw new Error("发行清单包含重复的平台安装包。");
  return { schemaVersion: 1, productId: "osir-anywhere", channel: "stable", releaseId: value.releaseId,
    version: value.version, publishedAt: value.publishedAt,
    ...(value.revision !== undefined ? { revision: value.revision as number } : {}),
    ...(value.minimumClientVersion !== undefined ? { minimumClientVersion: value.minimumClientVersion as string } : {}),
    ...(value.minimumServerVersion !== undefined ? { minimumServerVersion: value.minimumServerVersion as string } : {}), artifacts };
}

export function selectReleaseArtifact(manifest: DesktopReleaseManifest, platform: string, arch: string): ReleaseArtifact | null {
  if (!["darwin", "win32"].includes(platform) || !["arm64", "x64"].includes(arch)) return null;
  const artifacts = manifest.artifacts.filter((artifact) => artifact.platform === platform);
  return artifacts.find((artifact) => artifact.arch === arch) ??
    (platform === "darwin" ? artifacts.find((artifact) => artifact.arch === "universal") : null) ?? null;
}

/** Limit bytes while streaming, including a body stalled after response headers. */
export async function readReleaseJson(response: Response, signal: AbortSignal): Promise<unknown> {
  if (!response.body) throw new Error("发行清单响应为空。");
  const reader = response.body.getReader();
  const cancel = () => { void reader.cancel().catch(() => undefined); };
  signal.addEventListener("abort", cancel, { once: true });
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      signal.throwIfAborted();
      const { done, value } = await reader.read();
      signal.throwIfAborted();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_MANIFEST_BYTES) throw new Error("发行清单响应过大。");
      chunks.push(value);
    }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)));
  } finally {
    signal.removeEventListener("abort", cancel);
    await reader.cancel().catch(() => undefined);
  }
}
