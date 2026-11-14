import test, { type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { DesktopUpdateService } from "./desktop-updates";
import { InstallerNativeValidationError } from "./update-installer-native";
import { RELEASE_MANIFEST_URL } from "./release-manifest";
import { compareUpdateVersions } from "./update-version";
import type { DesktopUpdateState, ReleaseArtifact } from "../shared/desktop-updates";

const server = { serverUrl: "https://server.test", apiNamespace: "/api/v2", oauthWebOrigin: "https://server.test" };
const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const installer = Buffer.from("installer");
function artifact(platform: ReleaseArtifact["platform"] = "darwin", arch: ReleaseArtifact["arch"] = "universal"): ReleaseArtifact {
  const filename = `OSIR-Anywhere-${arch}.${platform === "darwin" ? "dmg" : "exe"}`;
  return { platform, arch, filename, url: `https://osirvedio.cn-nb1.rains3.com/osir-anywhere/releases/r1/${filename}`,
    size: installer.length, sha256: createHash("sha256").update(installer).digest("hex"), systemSignature: "unsigned" };
}
function signed(patch: Record<string, unknown> = {}) {
  const payload = Buffer.from(JSON.stringify({ schemaVersion: 1, productId: "osir-anywhere", channel: "stable", releaseId: "r1",
    version: "2.1.1", publishedAt: "2026-11-14T00:00:00Z", artifacts: [artifact(), artifact("win32", "x64")], ...patch }));
  return Response.json({ payload: payload.toString("base64"), signature: sign("RSA-SHA256", payload, privateKey).toString("base64") });
}
function binary(body: BodyInit = installer, headers: HeadersInit = {}) {
  return new Response(body, { headers: { "content-type": "application/octet-stream", ...headers } });
}
function harness(t: TestContext, overrides: Partial<ConstructorParameters<typeof DesktopUpdateService>[0]> = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aa-update-"));
  const states: DesktopUpdateState[] = [];
  const opened: string[] = [];
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  let manifestPatch: Record<string, unknown> = {};
  const options: ConstructorParameters<typeof DesktopUpdateService>[0] = {
    directory, currentVersion: "2.1.0", manifestUrl: RELEASE_MANIFEST_URL, publicKeyPem, platform: "darwin", arch: "arm64",
    fetcher: async (input, init) => {
      requests.push({ url: String(input), init });
      return String(input) === RELEASE_MANIFEST_URL ? signed(manifestPatch) : binary();
    },
    openInstaller: async (file) => { opened.push(file); },
    // Text fixtures exercise download/state orchestration; native validation has
    // its own platform fixtures in update-installer-native.test.ts.
    prepareInstaller: async () => {},
    onState: (state) => states.push(state), ...overrides,
  };
  const services: DesktopUpdateService[] = [];
  const make = (patch: Partial<typeof options> = {}) => { const s = new DesktopUpdateService({ ...options, ...patch }); services.push(s); return s; };
  t.after(() => { services.forEach(s => s.dispose()); fs.rmSync(directory, { recursive: true, force: true }); });
  return { service: make(), make, directory, states, opened, requests, setManifest: (patch: Record<string, unknown>) => { manifestPatch = patch; } };
}

test("version comparison handles numeric releases and prereleases", () => {
  for (const [left, right, expected] of [["2.1.10", "2.1.9", 1], ["0.1.7.2", "0.1.7", 1], ["v1.2.0+build", "1.2", 0],
    ["1.0.0-rc.2", "1.0.0-rc.10", -1], ["1.0.0-rc.1", "1.0.0", -1], ["invalid", "2.1.0", null]] as const) {
    assert.equal(compareUpdateVersions(left, right), expected);
  }
});

test("Desktop-only PATCH is discovered without any Server health or version request", async t => {
  const h = harness(t);
  const state = await h.service.check(server);
  assert.equal(state.available, true);
  assert.equal(state.latestVersion, "2.1.1");
  assert.equal(state.currentVersion, "2.1.0");
  assert.equal(state.dialogOpen, true);
  assert.deepEqual(state.artifact, { platform: "darwin", arch: "universal", systemSignature: "unsigned", systemSignatureDeclared: true });
  assert.deepEqual(h.requests.map(r => r.url), [RELEASE_MANIFEST_URL]);
  assert.equal(h.requests[0].init?.redirect, "error");
  assert.equal(h.requests[0].init?.credentials, "omit");
});

test("the installed Desktop version controls availability and prevents downgrade", async t => {
  const h = harness(t);
  for (const [currentVersion, available] of [["2.1.0", true], ["2.1.1", false], ["2.1.2", false], ["2.2.0", false]] as const) {
    const s = h.make({ currentVersion });
    assert.equal((await s.check(server)).available, available);
    if (!available) { await s.download(); assert.equal(h.opened.length, 0); }
  }
});

test("signed revisions break only equal public-version ties; missing revisions are legacy zero", async t => {
  const h = harness(t, { currentVersion: "2.2.1", currentRevision: 2 });
  for (const [version, revision, available] of [
    ["2.2.1", undefined, false], ["2.2.1", 1, false], ["2.2.1", 2, false], ["2.2.1", 3, true],
    ["2.2.0", 999, false], ["2.2.2", undefined, true], ["2.2.1+new-build", 3, true],
  ] as const) {
    h.setManifest({ version, revision });
    const state = await h.service.check(server);
    assert.equal(state.available, available, `${version} revision ${revision}`);
    assert.equal(state.dialogOpen, available);
    assert.equal(state.release?.revision, revision);
    if (!available) { await h.service.download(); assert.equal(h.opened.length, 0); }
  }
  h.setManifest({ version: "2.2.1", revision: 1 });
  assert.equal((await h.make({ currentRevision: undefined }).check(server)).available, true);
});

test("installed revision must be a trusted nonnegative safe integer", t => {
  const h = harness(t);
  for (const currentRevision of [-1, 0.5, NaN, Infinity, 65536, Number.MAX_SAFE_INTEGER + 1, "1", null]) {
    assert.throws(() => h.make({ currentRevision: currentRevision as number }), /currentRevision/);
  }
});

test("ignore persists the exact version/revision and never suppresses a later revision", async t => {
  const h = harness(t, { currentVersion: "2.2.1", currentRevision: 1 });
  h.setManifest({ version: "2.2.1", revision: 2 });
  await h.service.check(server);
  h.service.ignoreVersion();
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(h.directory, "state.json"), "utf8")).ignoredVersions[RELEASE_MANIFEST_URL],
    { version: "2.2.1", revision: 2 });
  assert.equal((await h.make().check({ ...server, serverUrl: "https://other.test" })).ignored, true);
  h.setManifest({ version: "2.2.1", revision: 3 });
  const next = await h.make().check(server);
  assert.equal(next.ignored, false);
  assert.equal(next.dialogOpen, true);
});

test("legacy and malformed ignores cannot hide new revisions", async t => {
  const h = harness(t, { currentVersion: "2.2.0" });
  for (const ignored of ["2.2.1", { version: "2.2.1", revision: 0 }, { version: "2.2.1" },
    { version: "2.2.1", revision: "1" }, { version: "2.2.1", revision: -1 }, null, []]) {
    fs.writeFileSync(path.join(h.directory, "state.json"), JSON.stringify({ ignoredVersions: { [RELEASE_MANIFEST_URL]: ignored } }));
    h.setManifest({ version: "2.2.1", revision: 1 });
    assert.equal((await h.make().check(server)).ignored, false);
  }
  fs.writeFileSync(path.join(h.directory, "state.json"), JSON.stringify({ ignoredVersions: { [RELEASE_MANIFEST_URL]: "2.2.1" } }));
  h.setManifest({ version: "2.2.1" });
  assert.equal((await h.make().check(server)).ignored, true, "legacy ignore applies only to legacy revision zero");
});

test("ignore is product/channel scoped, survives restart/server change, and newer releases prompt", async t => {
  const h = harness(t);
  await h.service.check(server);
  h.service.ignoreVersion();
  assert.equal(h.service.getState().available, true);
  assert.equal(h.service.getState().dialogOpen, false);
  const restarted = h.make();
  assert.equal((await restarted.check({ ...server, serverUrl: "https://other.test" })).ignored, true);
  assert.equal(restarted.showPrompt().dialogOpen, true);
  h.setManifest({ version: "2.1.2" });
  assert.equal((await h.make().check(server)).dialogOpen, true);
});

test("unavailable/untrusted manifests report a reason and never offer an unverified download", async t => {
  for (const fetcher of [async () => new Response("missing", { status: 404 }), async () => { throw new Error("network"); },
    async () => Response.json({ status: "ok", version: "99.0.0", downloadUrl: artifact().url }),
    async () => Response.json({ payload: "e30=", signature: "eA==" }), async () => new Response("invalid json")]) {
    const h = harness(t, { fetcher });
    const state = await h.service.check(server);
    assert.equal(state.available, false);
    assert.equal(state.error, "checkFailed");
    assert.ok(state.errorDetail);
    await h.service.download();
    assert.equal(h.opened.length, 0);
  }
  const h = harness(t);
  for (const patch of [{ publicKeyPem: "" }, { manifestUrl: "https://example.invalid/stable.json" }]) {
    assert.equal((await h.make(patch).check(server)).error, "checkFailed");
  }
  assert.equal(h.requests.length, 0);
});

test("only a size/hash verified package opens; duplicate download/check/ignore preserve the download lock", async t => {
  const h = harness(t);
  await h.service.check(server);
  const pending = h.service.download();
  assert.equal(h.service.download(), pending);
  assert.equal((await h.service.check(server)).phase, "downloading");
  assert.equal(h.service.ignoreVersion().dialogOpen, true);
  const state = await pending;
  assert.equal(state.phase, "downloaded");
  assert.equal(state.currentVersion, "2.1.0", "opening the installer never claims an installed upgrade");
  assert.equal(state.available, true);
  assert.equal(h.opened.length, 1);
  assert.deepEqual(fs.readFileSync(h.opened[0]), installer);
  assert.equal(path.extname(h.opened[0]), ".dmg");
  assert.equal(h.requests[1].url, artifact().url);
  assert.equal(h.requests[1].init?.redirect, "error");
  assert.equal(h.requests[1].init?.credentials, "omit");
  assert.ok(h.states.some(s => s.downloadedBytes === installer.length && s.totalBytes === installer.length));
  assert.ok(h.states.every((s, i) => !i || s.revision > h.states[i - 1].revision));
});

test("native preparation blocks opening until it succeeds and revalidates cached files on retry", async t => {
  let finish!: () => void;
  let started!: () => void;
  const ready = new Promise<void>(resolve => { started = resolve; });
  const validation = new Promise<void>(resolve => { finish = resolve; });
  const prepared: string[] = [];
  const h = harness(t, { prepareInstaller: async request => {
    assert.deepEqual(fs.readFileSync(request.file), installer);
    assert.deepEqual(request.artifact, artifact());
    assert.equal(request.version, "2.1.1");
    assert.equal(request.signal.aborted, false);
    prepared.push(request.file);
    started();
    await validation;
  }, openInstaller: async file => {
    assert.equal(prepared.at(-1), file);
    throw new Error("no handler");
  } });
  await h.service.check(server);
  const pending = h.service.download();
  await ready;
  assert.equal(h.service.getState().phase, "downloading");
  assert.ok(h.states.every(state => state.phase !== "opening"));
  finish();
  assert.equal((await pending).error, "openFailed");
  assert.equal((await h.service.download()).error, "openFailed");
  assert.equal(prepared.length, 2, "cached bytes still require native preparation before every open");
  assert.equal(h.requests.length, 2, "retry reuses the hash-verified download");
});

test("native validation failure remains visible and never opens an installer", async t => {
  const failure = new InstallerNativeValidationError(new Error("bad system signature"));
  let validations = 0;
  const h = harness(t, { prepareInstaller: async () => { validations++; throw failure; } });
  await h.service.check(server);
  for (let attempt = 0; attempt < 2; attempt++) {
    const state = await h.service.download();
    assert.equal(state.phase, "idle");
    assert.equal(state.error, "downloadFailed");
    assert.equal(state.errorDetail, failure.message);
    assert.equal(state.dialogOpen, true);
  }
  assert.equal(validations, 2);
  assert.equal(h.opened.length, 0);
  assert.ok(h.states.every(state => state.phase !== "opening" && state.phase !== "downloaded"));
});

test("Mac split packages and Windows x64/ARM64 select only their matching signed artifacts", async t => {
  for (const [platform, arch] of [["darwin", "arm64"], ["darwin", "x64"], ["win32", "arm64"], ["win32", "x64"]] as const) {
    const h = harness(t, { platform, arch });
    h.setManifest({ artifacts: [artifact(), artifact("darwin", "arm64"), artifact("darwin", "x64"), artifact("win32", "x64"), artifact("win32", "arm64")] });
    await h.service.check(server);
    assert.equal((await h.service.download()).phase, "downloaded");
    assert.equal(h.requests[1].url, artifact(platform, arch).url);
    assert.equal(path.extname(h.opened[0]), platform === "darwin" ? ".dmg" : ".exe");
  }
});

test("missing architecture, unknown system and empty releases are explicitly blocked", async t => {
  for (const patch of [{ platform: "linux" }, { platform: "win32", arch: "arm64" }, { arch: "ia32" }]) {
    const h = harness(t, patch);
    const state = await h.service.check(server);
    assert.equal(state.available, true);
    assert.equal(state.error, "downloadNotConfigured");
    assert.match(state.errorDetail!, /系统和架构/);
    await h.service.download();
    assert.equal(h.requests.length, 1);
    assert.equal(h.opened.length, 0);
  }
  const h = harness(t); h.setManifest({ artifacts: [] });
  assert.equal((await h.service.check(server)).error, "downloadNotConfigured");
});

test("minimum Server is checked only when declared; Server payload URLs never control downloads", async t => {
  for (const [serverVersion, allowed] of [["2.1.0", false], ["2.1.1", true], ["99.0.0", true], ["invalid", false]] as const) {
    const requests: string[] = [];
    const h = harness(t, { fetcher: async input => {
      const url = String(input); requests.push(url);
      if (url === RELEASE_MANIFEST_URL) return signed({ minimumServerVersion: "2.1.1", minimumClientVersion: "99.0.0" });
      if (url.endsWith("/health")) return Response.json({ status: "ok", version: serverVersion, downloadUrl: "https://untrusted.test/installer" });
      return binary();
    } });
    const state = await h.service.check(server);
    assert.equal(state.latestVersion, "2.1.1");
    assert.equal(state.available, true);
    assert.equal(state.release?.minimumClientVersion, "99.0.0", "OSIR Client metadata is not compared against Desktop");
    const downloaded = await h.service.download();
    assert.equal(downloaded.error, allowed ? null : "downloadNotConfigured");
    assert.equal(h.opened.length, allowed ? 1 : 0);
    assert.deepEqual(requests, [RELEASE_MANIFEST_URL, "https://server.test/api/v2/health", ...(allowed ? [artifact().url] : [])]);
  }
});

test("partial/corrupt packages are removed and retry succeeds", async t => {
  let fail = true;
  const h = harness(t, { fetcher: async input => String(input) === RELEASE_MANIFEST_URL ? signed() : binary(fail ? "bad" : installer) });
  await h.service.check(server);
  assert.equal((await h.service.download()).error, "downloadFailed");
  assert.equal(h.service.getState().dialogOpen, true);
  assert.deepEqual(fs.readdirSync(path.join(h.directory, "downloads")), []);
  assert.equal(h.opened.length, 0);
  fail = false;
  assert.equal((await h.service.download()).phase, "downloaded");
});

test("failed opens reuse a verified file; changed cached files are verified and downloaded again", async t => {
  let calls = 0;
  let cached = "";
  const h = harness(t, { openInstaller: async file => { cached = file; if (++calls < 3) throw new Error("no handler"); } });
  await h.service.check(server);
  assert.equal((await h.service.download()).error, "openFailed");
  assert.equal((await h.service.download()).error, "openFailed");
  assert.equal(h.requests.length, 2);
  fs.writeFileSync(cached, "corrupted"); // Same size as the original.
  assert.equal((await h.service.download()).phase, "downloaded");
  assert.equal(h.requests.length, 3);
  assert.deepEqual(fs.readFileSync(cached), installer);
});

test("overlapping checks share a promise; a late previous-server response cannot overwrite active state", async t => {
  let finish!: (response: Response) => void;
  let started!: () => void;
  const ready = new Promise<void>(r => { started = r; });
  let calls = 0;
  const h = harness(t, { fetcher: async () => ++calls === 1 ? new Promise<Response>(resolve => { finish = resolve; started(); }) : signed({ version: "2.1.0" }) });
  const old = h.service.check(server);
  assert.equal(h.service.check(server), old);
  await ready;
  await h.service.check({ ...server, serverUrl: "https://other.test" });
  finish(signed({ version: "99.0.0" }));
  await old;
  assert.equal(h.service.getState().latestVersion, "2.1.0");
  assert.equal(h.service.getState().available, false);
});

test("cancel/sign-out/quit cancel a stalled package body, clean partial files and do not open", async t => {
  for (const action of ["cancel", "signout", "quit"]) {
    let cancelled = false;
    let started!: () => void;
    const ready = new Promise<void>(r => { started = r; });
    const h = harness(t, {
      fetcher: async input => String(input) === RELEASE_MANIFEST_URL ? signed() : new Response(new ReadableStream({
        start(c) { c.enqueue(new Uint8Array([1])); }, cancel() { cancelled = true; },
      })), onState: s => { if (s.downloadedBytes) started(); },
    });
    await h.service.check(server);
    const pending = h.service.download();
    await ready;
    if (action === "cancel") h.service.cancelDownload();
    else if (action === "signout") await h.service.check(null);
    else h.service.dispose();
    await pending;
    assert.equal(cancelled, true);
    assert.equal(h.opened.length, 0);
    assert.deepEqual(fs.readdirSync(path.join(h.directory, "downloads")), []);
    if (action === "cancel") {
      assert.equal(h.service.getState().phase, "idle");
      assert.equal(h.service.getState().error, null);
    }
  }
});

test("stalled manifest and installer streams time out without holding their locks", async t => {
  let manifestCancelled = false;
  const h = harness(t, { checkTimeoutMs: 10, fetcher: async () => new Response(new ReadableStream({ cancel() { manifestCancelled = true; } })) });
  assert.equal((await h.service.check(server)).error, "checkFailed");
  assert.equal(manifestCancelled, true);
  let downloadCancelled = false;
  const d = harness(t, { downloadTimeoutMs: 10, fetcher: async input => String(input) === RELEASE_MANIFEST_URL ? signed() : new Response(new ReadableStream({ cancel() { downloadCancelled = true; } })) });
  await d.service.check(server);
  assert.equal((await d.service.download()).error, "downloadFailed");
  assert.equal(downloadCancelled, true);
  assert.equal(d.opened.length, 0);
});

test("failed rechecks invalidate old artifacts, and missing sessions preserve ignore preference", async t => {
  const h = harness(t);
  assert.equal((await h.service.check(null)).available, false);
  assert.equal(h.requests.length, 0);
  await h.service.check(server);
  h.service.ignoreVersion();
  await h.service.check(null);
  assert.equal((await h.service.check(server)).ignored, true);
  h.setManifest({ version: "invalid" });
  assert.equal((await h.service.check(server)).error, "checkFailed");
  assert.equal(h.service.getState().available, false);
  await h.service.download();
  assert.equal(h.opened.length, 0);
});

test("signing out aborts an in-flight manifest check and late responses cannot reopen the prompt", async t => {
  let finish!: (response: Response) => void;
  let started!: () => void;
  const ready = new Promise<void>(r => { started = r; });
  let signal: AbortSignal | null | undefined;
  const h = harness(t, { fetcher: (_input, init) => {
    signal = init?.signal;
    return new Promise(resolve => { finish = resolve; started(); });
  } });
  const pending = h.service.check(server);
  await ready;
  await h.service.check(null);
  assert.equal(signal?.aborted, true);
  finish(signed()); await pending;
  assert.equal(h.service.getState().dialogOpen, false);
  assert.equal(h.service.getState().available, false);
  assert.equal(h.service.getState().error, null);
});

test("failed preference writes preserve the prompt", async t => {
  const h = harness(t);
  await h.service.check(server);
  fs.mkdirSync(path.join(h.directory, "state.json"));
  assert.equal(h.service.ignoreVersion().error, "ignoreFailed");
  assert.equal(h.service.getState().dialogOpen, true);
});

test("manifest redirects and an unreachable minimum Server cannot enable an installer", async t => {
  const redirected = signed();
  Object.defineProperty(redirected, "url", { value: "https://untrusted.test/stable.json" });
  const h = harness(t, { fetcher: async () => redirected });
  assert.equal((await h.service.check(server)).error, "checkFailed");
  assert.equal(h.service.getState().available, false);
  const d = harness(t, { fetcher: async input => {
    if (String(input) === RELEASE_MANIFEST_URL) return signed({ minimumServerVersion: "2.1.0" });
    throw new Error("offline Server");
  } });
  const state = await d.service.check(server);
  assert.equal(state.latestVersion, "2.1.1");
  assert.equal(state.available, true);
  assert.equal(state.error, "downloadNotConfigured");
  assert.match(state.errorDetail!, /最低版本 2.1.0/);
  await d.service.download();
  assert.equal(d.opened.length, 0);
});

test("switching Servers during a download cancels the old stream and preserves the new release", async t => {
  let started!: () => void;
  const ready = new Promise<void>(r => { started = r; });
  let downloads = 0;
  let cancelled = false;
  const h = harness(t, {
    fetcher: async input => String(input) === RELEASE_MANIFEST_URL ? signed() : ++downloads === 1
      ? new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array([1])); }, cancel() { cancelled = true; } }))
      : binary(),
    onState: state => { if (state.downloadedBytes) started(); },
  });
  await h.service.check(server);
  const old = h.service.download();
  await ready;
  await h.service.check({ ...server, serverUrl: "https://new-server.test" });
  await old;
  assert.equal(cancelled, true);
  assert.equal(h.service.getState().available, true);
  assert.equal((await h.service.download()).phase, "downloaded");
  assert.equal(h.opened.length, 1);
  assert.equal(downloads, 2);
});

test("user cancellation releases the download lock for a verified retry", async t => {
  let started!: () => void;
  const ready = new Promise<void>(r => { started = r; });
  let downloads = 0;
  const h = harness(t, {
    fetcher: async input => String(input) === RELEASE_MANIFEST_URL ? signed() : ++downloads === 1
      ? new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array([1])); } })) : binary(),
    onState: state => { if (state.downloadedBytes) started(); },
  });
  await h.service.check(server);
  const old = h.service.download();
  await ready;
  const cancellation = h.service.cancelDownload();
  assert.equal(cancellation, old, "cancellation waits for the active download and file cleanup");
  assert.equal((await cancellation).phase, "idle");
  assert.deepEqual(fs.readdirSync(path.join(h.directory, "downloads")), []);
  assert.equal((await h.service.download()).phase, "downloaded");
  assert.equal(h.opened.length, 1);
});

test("legacy manifest artifacts publish a strong default policy without inventing a signature declaration", async t => {
  for (const platform of ["darwin", "win32"] as const) {
    const h = harness(t, { platform });
    const { systemSignature: _signature, ...legacy } = artifact(platform, platform === "darwin" ? "universal" : "arm64");
    h.setManifest({ artifacts: [legacy] });
    const state = await h.service.check(server);
    assert.equal(state.available, true);
    assert.equal(state.error, null);
    assert.deepEqual(state.artifact, {
      platform, arch: legacy.arch, systemSignature: platform === "darwin" ? "developer-id-notarized" : "authenticode", systemSignatureDeclared: false,
    });
  }
});
