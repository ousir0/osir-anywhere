import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { assertManifestUrl, readReleaseJson, readReleasePublicKey, RELEASE_MANIFEST_URL, resolveReleaseSystemSignature, selectReleaseArtifact, verifyReleaseManifest } from "./release-manifest";
import type { DesktopReleaseManifest, ReleaseArtifact } from "../shared/desktop-updates";

const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
const body = Buffer.from("synthetic installer");
function artifact(platform: "darwin" | "win32" = "darwin", arch: ReleaseArtifact["arch"] = "universal"): ReleaseArtifact {
  const filename = `OSIR-Anywhere-${arch}.${platform === "darwin" ? "dmg" : "exe"}`;
  return { platform, arch, filename, url: `https://osirvedio.cn-nb1.rains3.com/osir-anywhere/releases/r1/${filename}`,
    size: body.length, sha256: createHash("sha256").update(body).digest("hex"), systemSignature: "unsigned" };
}
function manifest(patch: Record<string, unknown> = {}) {
  return { schemaVersion: 1, productId: "osir-anywhere", channel: "stable", releaseId: "r1", version: "2.1.1",
    publishedAt: "2026-11-14T00:00:00Z", artifacts: [artifact()], ...patch };
}
function envelope(value: unknown) {
  const payload = Buffer.from(JSON.stringify(value));
  return { payload: payload.toString("base64"), signature: sign("RSA-SHA256", payload, privateKey).toString("base64") };
}

test("RSA-SHA256 verifies the exact signed bytes and preserves compatibility metadata", () => {
  const value = manifest({ minimumClientVersion: "0.1.10", minimumServerVersion: "2.0.9" });
  assert.deepEqual(verifyReleaseManifest(envelope(value), pem), value);
  const original = envelope(value);
  assert.throws(() => verifyReleaseManifest({ ...original, payload: Buffer.from(JSON.stringify(manifest({ version: "99.0.0" }))).toString("base64") }, pem), /签名/);
  const other = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ type: "spki", format: "pem" }).toString();
  assert.throws(() => verifyReleaseManifest(original, other), /签名/);
});

test("optional revision is a signed bounded integer; omission preserves legacy manifests", () => {
  assert.equal(Object.hasOwn(verifyReleaseManifest(envelope(manifest()), pem), "revision"), false);
  for (const revision of [0, 1, 2, 65535]) {
    assert.equal(verifyReleaseManifest(envelope(manifest({ revision })), pem).revision, revision);
  }
  for (const revision of [-1, 0.5, null, "1", true, {}, [], 65536, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => verifyReleaseManifest(envelope(manifest({ revision })), pem));
  }
  const original = envelope(manifest({ revision: 1 }));
  assert.throws(() => verifyReleaseManifest({ ...original,
    payload: Buffer.from(JSON.stringify(manifest({ revision: 2 }))).toString("base64") }, pem), /签名/);
});

test("missing, weak, private and non-RSA keys fail closed", () => {
  const weak = generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey;
  const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey;
  for (const key of ["", "invalid", privateKey.export({ type: "pkcs8", format: "pem" }).toString(), ...[weak, ec].map(k => k.export({ type: "spki", format: "pem" }).toString())]) {
    assert.throws(() => verifyReleaseManifest(envelope(manifest()), key), /公钥/);
  }
});

test("malformed envelopes and noncanonical base64 cannot bypass verification", () => {
  const original = envelope(manifest());
  for (const value of [null, [], {}, { ...original, payload: original.payload + "\n" }, { ...original, signature: "!!!" },
    { ...original, payload: "AB==" }, { ...original, payload: "a".repeat(262148) }]) {
    assert.throws(() => verifyReleaseManifest(value, pem));
  }
  const invalid = Buffer.from("not json");
  assert.throws(() => verifyReleaseManifest({ payload: invalid.toString("base64"), signature: sign("RSA-SHA256", invalid, privateKey).toString("base64") }, pem));
});

test("signed payloads still require the v1 product, channel and valid release fields", () => {
  for (const patch of [{ schemaVersion: 2 }, { productId: "osir-client" }, { channel: "beta" }, { version: "latest" },
    { version: "2.1" }, { releaseId: "../other" }, { releaseId: ".." }, { releaseId: "" }, { publishedAt: "yesterday" },
    { publishedAt: "2026-99-14T00:00:00Z" }, { minimumClientVersion: "latest" }, { minimumServerVersion: null },
    { artifacts: null }, { artifacts: new Array(17).fill(artifact()) }, { artifacts: [artifact(), artifact()] }]) {
    assert.throws(() => verifyReleaseManifest(envelope(manifest(patch)), pem), JSON.stringify(patch));
  }
});

test("artifact URLs bind exactly to HTTPS origin, product, release ID and filename", () => {
  const good = artifact();
  for (const url of [
    good.url.replace("https:", "http:"), good.url.replace("osirvedio.", "evil.osirvedio."),
    good.url.replace(".com/", ".com.evil.test/"), good.url.replace("https://", "https://user:password@"),
    good.url.replace("osir-anywhere/", "osir-client/"), good.url.replace("/r1/", "/r2/"),
    good.url.replace("/r1/", "/r1/../r1/"), good.url.replace("/r1/", "/r1%2f/"),
    good.url + "?download=1", good.url + "#fragment", good.url.replace(".dmg", ".exe"),
    good.url.replace(".com/", ".com:443/"), good.url.replace("/releases/", "/releases-evil/"),
  ]) assert.throws(() => verifyReleaseManifest(envelope(manifest({ artifacts: [{ ...good, url }] })), pem), /地址/);
  const filename = "OSIR Anywhere universal.dmg";
  assert.equal(verifyReleaseManifest(envelope(manifest({ artifacts: [{ ...good, filename,
    url: `https://osirvedio.cn-nb1.rains3.com/osir-anywhere/releases/r1/${encodeURIComponent(filename)}` }] })), pem).artifacts[0].filename, filename);
});

test("artifact validation rejects wrong types, traversal, unsupported targets, sizes and hashes", () => {
  for (const patch of [{ platform: "linux" }, { platform: ["darwin"] }, { arch: ["arm64"] }, { arch: "ia32" }, { platform: "win32", arch: "universal" },
    { filename: "../test.dmg" }, { filename: "test.exe" }, { filename: "test\\name.dmg" }, { size: 0 }, { size: -1 },
    { size: 1.5 }, { size: "19" }, { size: Number.MAX_SAFE_INTEGER + 1 }, { sha256: "0".repeat(63) }, { sha256: "x".repeat(64) }]) {
    assert.throws(() => verifyReleaseManifest(envelope(manifest({ artifacts: [{ ...artifact(), ...patch }] })), pem), JSON.stringify(patch));
  }
});

test("target selection prefers native split packages, permits Mac Universal, never guesses Windows ARM or unknown targets", () => {
  const value = verifyReleaseManifest(envelope(manifest({ artifacts: [artifact(), artifact("darwin", "arm64"), artifact("win32", "x64")] })), pem);
  assert.equal(selectReleaseArtifact(value, "darwin", "arm64")?.arch, "arm64");
  assert.equal(selectReleaseArtifact(value, "darwin", "x64")?.arch, "universal");
  assert.equal(selectReleaseArtifact(value, "win32", "x64")?.arch, "x64");
  for (const [platform, arch] of [["win32", "arm64"], ["linux", "x64"], ["darwin", "ia32"], ["darwin", "universal"], ["unknown", "arm64"]]) {
    assert.equal(selectReleaseArtifact(value, platform, arch), null);
  }
  const split = { ...value, artifacts: [artifact("darwin", "arm64")] } satisfies DesktopReleaseManifest;
  assert.equal(selectReleaseArtifact(split, "darwin", "x64"), null);
});

test("manifest endpoint is pinned; public key loading uses only the resource build directory", (t) => {
  assert.doesNotThrow(() => assertManifestUrl(RELEASE_MANIFEST_URL));
  for (const value of [RELEASE_MANIFEST_URL + "?x=1", RELEASE_MANIFEST_URL.replace("https:", "http:"), "https://untrusted.test/stable.json"]) {
    assert.throws(() => assertManifestUrl(value));
  }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "aa-release-resource-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  assert.equal(readReleasePublicKey(root), "");
  fs.mkdirSync(path.join(root, "build"));
  fs.writeFileSync(path.join(root, "build", "release-public.pub"), pem);
  assert.equal(readReleasePublicKey(root), pem.trim());
});

test("streamed manifest bodies enforce a byte bound and cancellation after headers", async () => {
  let cancelled = false;
  await assert.rejects(readReleaseJson(new Response(new ReadableStream({
    start(c) { c.enqueue(new Uint8Array(262145)); }, cancel() { cancelled = true; },
  })), new AbortController().signal), /过大/);
  assert.equal(cancelled, true);
  const controller = new AbortController();
  cancelled = false;
  const response = new Response(new ReadableStream({ cancel() { cancelled = true; } }));
  const pending = readReleaseJson(response, controller.signal);
  controller.abort();
  await assert.rejects(pending);
  assert.equal(cancelled, true);
});

test("system signature declarations are optional, platform-specific and protected by the RSA signature", () => {
  for (const [platform, signature] of [["darwin", "unsigned"], ["darwin", "developer-id-notarized"], ["win32", "unsigned"], ["win32", "authenticode"]] as const) {
    const item = { ...artifact(platform, platform === "darwin" ? "universal" : "x64"), systemSignature: signature };
    assert.equal(verifyReleaseManifest(envelope(manifest({ artifacts: [item] })), pem).artifacts[0].systemSignature, signature);
  }
  for (const signature of [null, "signed", "authenticode", ["unsigned"]]) {
    assert.throws(() => verifyReleaseManifest(envelope(manifest({ artifacts: [{ ...artifact(), systemSignature: signature }] })), pem));
  }
  assert.throws(() => verifyReleaseManifest(envelope(manifest({ artifacts: [{ ...artifact("win32", "x64"), systemSignature: "developer-id-notarized" }] })), pem));
  const original = envelope(manifest());
  const forged = manifest({ artifacts: [{ ...artifact(), systemSignature: "developer-id-notarized" }] });
  assert.throws(() => verifyReleaseManifest({ ...original, payload: Buffer.from(JSON.stringify(forged)).toString("base64") }, pem), /签名/);
});

test("omitted system signature preserves absence and applies strong platform defaults, never unsigned", () => {
  for (const platform of ["darwin", "win32"] as const) {
    const { systemSignature: _signature, ...legacy } = artifact(platform, platform === "darwin" ? "universal" : "x64");
    const parsed = verifyReleaseManifest(envelope(manifest({ artifacts: [legacy] })), pem).artifacts[0];
    assert.equal(Object.hasOwn(parsed, "systemSignature"), false);
    assert.equal(resolveReleaseSystemSignature(parsed), platform === "darwin" ? "developer-id-notarized" : "authenticode");
    assert.equal(resolveReleaseSystemSignature({ ...parsed, systemSignature: "unsigned" }), "unsigned");
  }
});
