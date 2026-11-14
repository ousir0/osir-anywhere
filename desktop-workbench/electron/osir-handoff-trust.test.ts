import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { fetchHandoffTrust, HANDOFF_TRUST_URL, validateHandoffTrust, verifyHandoffTrust } from "./osir-handoff-trust";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
const now = Date.parse("2026-11-15T00:00:00Z");
const build = { productId: "osir-client", version: "0.1.11+10", releaseId: "prod-0.1.11.build.10",
  platform: "darwin", treeSha256: "a".repeat(64) };
const payload = (patch = {}) => ({ schemaVersion: 1, productId: "osir-desktop-handoff-trust",
  publishedAt: "2026-11-15T00:00:00Z", validUntil: "2026-12-15T00:00:00Z", builds: [build], ...patch });
function envelope(value: unknown) {
  const data = Buffer.isBuffer(value) ? value : Buffer.from(JSON.stringify(value));
  return { payload: data.toString("base64"), signature: sign("RSA-SHA256", data, privateKey).toString("base64") };
}

test("trust authenticates exact payload bytes and rejects malformed envelopes, signatures and keys", () => {
  const valid = envelope(payload());
  assert.deepEqual(verifyHandoffTrust(valid, pem, now), payload());
  for (const candidate of [null, [], {}, { ...valid, extra: true }, { ...valid, signature: "" },
    { ...valid, payload: valid.payload + "\n" }, { ...valid, signature: "AB==" },
    { ...valid, payload: "a".repeat(180004) }, { ...valid, payload: envelope(payload({ builds: [] })).payload },
    envelope(Buffer.from([0xff])), envelope(Buffer.from("not-json"))]) {
    assert.throws(() => verifyHandoffTrust(candidate, pem, now));
  }
  const other = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey;
  const weak = generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey;
  const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey;
  for (const key of ["", "invalid", privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    ...[other, weak, ec].map(k => k.export({ type: "spki", format: "pem" }).toString())]) {
    assert.throws(() => verifyHandoffTrust(valid, key, now));
  }
});

test("validity is finite, ordered, bounded and RFC3339; schema and build identities are strict", () => {
  for (const patch of [
    { publishedAt: "2026-11-15T00:05:01Z" }, { validUntil: "2026-11-15T00:00:00Z" },
    { publishedAt: "2026-11-15T00:05:00Z", validUntil: "2026-11-15T00:04:00Z" },
    { validUntil: "2027-11-17T00:00:00Z" }, { publishedAt: "November 15, 2026" },
    { publishedAt: "2026-02-30T00:00:00Z" }, { publishedAt: "2026-11-14T24:00:00Z" },
    { validUntil: "2026-12-15" }, { schemaVersion: 2 }, { productId: "other" }, { extra: true },
    { builds: [] }, { builds: Array(129).fill(build) }, { builds: [build, build] },
  ]) assert.throws(() => verifyHandoffTrust(envelope(payload(patch)), pem, now), JSON.stringify(patch));
  assert.throws(() => validateHandoffTrust(payload(), NaN));
  for (const patch of [
    { version: "00.1.11" }, { version: "0.1.11+0" }, { version: "0.1.11+01" },
    { version: "0.1.11+65536" }, { version: "0.1.11-beta" }, { version: "1".repeat(41) },
    { releaseId: "../r1" }, { releaseId: "r+1" }, { treeSha256: "A".repeat(64) },
    { platform: "win32" }, { productId: "codex" }, { productId: ["osir-client"] }, { extra: true },
  ]) assert.throws(() => verifyHandoffTrust(envelope(payload({ builds: [{ ...build, ...patch }] })), pem, now));
  for (const version of ["0.1.11", "0.1.11+1", "0.1.11+65535", "2.2.1"]) {
    assert.equal(verifyHandoffTrust(envelope(payload({ builds: [{ ...build, version }] })), pem, now).builds[0].version, version);
  }
});

test("fetch uses the fixed trust root, forbids credentials/redirects and preserves caller cancellation plus timeout", async () => {
  // Use current time only for the network wrapper, which validates against Date.now().
  const live = envelope(payload({ publishedAt: new Date().toISOString(), validUntil: new Date(Date.now() + 86400000).toISOString() }));
  const controller = new AbortController();
  let combined: AbortSignal | undefined;
  const fetcher: typeof fetch = async (url, options) => {
    assert.equal(url, HANDOFF_TRUST_URL);
    assert.equal(options?.credentials, "omit"); assert.equal(options?.redirect, "error");
    assert.equal(options?.cache, "no-store");
    combined = options?.signal ?? undefined;
    assert.ok(combined && combined !== controller.signal);
    return new Response(JSON.stringify(live));
  };
  assert.equal((await fetchHandoffTrust(fetcher, pem, controller.signal)).builds[0].version, "0.1.11+10");
  controller.abort(); assert.equal(combined?.aborted, true);
});

test("fetch rejects redirected, oversized, malformed UTF-8 and unsuccessful responses", async () => {
  for (const response of [new Response("{}", { status: 302 }), new Response(null),
    new Response("x".repeat(256 * 1024 + 1)), new Response(Uint8Array.from([255])),
    Object.assign(new Response("{}"), {}),
  ]) await assert.rejects(fetchHandoffTrust(async () => response, pem));
  for (const patch of [{ redirected: true }, { url: HANDOFF_TRUST_URL + "?other=1" }]) {
    const response = new Response("{}");
    for (const [key, value] of Object.entries(patch)) Object.defineProperty(response, key, { value });
    await assert.rejects(fetchHandoffTrust(async () => response, pem));
  }
});
