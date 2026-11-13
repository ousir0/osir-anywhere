import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { downloadDesktopInstaller, verifyDownloadedInstaller } from "./update-download";
import type { ReleaseArtifact } from "../shared/desktop-updates";

const bytes = Buffer.from("synthetic installer bytes");
const artifact: ReleaseArtifact = {
  platform: "darwin", arch: "universal", filename: "OSIR-Anywhere.dmg",
  url: "https://osirvedio.cn-nb1.rains3.com/osir-anywhere/releases/r1/OSIR-Anywhere.dmg",
  size: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex"),
  systemSignature: "unsigned",
};

test("streamed size and SHA-256 are verified even without Content-Length", async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aa-download-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const progress: number[][] = [];
  const signal = new AbortController().signal;
  const target = await downloadDesktopInstaller({ artifact, releaseId: "r1", directory, signal,
    onProgress: (received, total) => { progress.push([received, total]); },
    fetcher: async () => new Response(new ReadableStream({ start(c) {
      c.enqueue(bytes.subarray(0, 3)); c.enqueue(bytes.subarray(3)); c.close();
    } })),
  });
  assert.deepEqual(fs.readFileSync(target), bytes);
  assert.ok(progress.every(p => p[1] === bytes.length));
  await verifyDownloadedInstaller(target, artifact, signal);
});

test("short, oversize, same-size corrupt, HTML, redirected, encoded and partial HTTP responses fail closed", async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aa-download-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const redirected = new Response(bytes);
  Object.defineProperty(redirected, "url", { value: "https://untrusted.test/installer.dmg" });
  const responses = [
    new Response(bytes.subarray(1)), new Response(Buffer.concat([bytes, bytes])), new Response(Buffer.alloc(bytes.length)),
    new Response(bytes, { headers: { "content-length": "999" } }), new Response(bytes, { headers: { "content-length": "1.5" } }),
    new Response(bytes, { headers: { "content-type": "text/html" } }),
    new Response(bytes, { headers: { "content-encoding": "gzip" } }), new Response(bytes, { status: 206 }),
    new Response(null, { status: 302, headers: { location: artifact.url } }), redirected,
  ];
  for (const response of responses) {
    await assert.rejects(downloadDesktopInstaller({ artifact, releaseId: "r1", directory,
      signal: new AbortController().signal, onProgress: () => {}, fetcher: async () => response }));
    assert.deepEqual(fs.readdirSync(directory), []);
  }
});

test("invalid object paths are rejected before fetching, aborted downloads do not fetch", async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aa-download-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  let fetched = false;
  const options = { artifact, releaseId: "r1", directory, signal: new AbortController().signal,
    onProgress: () => {}, fetcher: async () => { fetched = true; return new Response(bytes); } };
  await assert.rejects(downloadDesktopInstaller({ ...options, artifact: { ...artifact, url: artifact.url + "?x=1" } }));
  const controller = new AbortController(); controller.abort();
  await assert.rejects(downloadDesktopInstaller({ ...options, signal: controller.signal }));
  assert.equal(fetched, false);
});

test("cached installers reject changed bytes, wrong sizes and symbolic links", async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aa-download-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const target = path.join(directory, artifact.filename);
  const signal = new AbortController().signal;
  fs.writeFileSync(target, Buffer.alloc(bytes.length));
  await assert.rejects(verifyDownloadedInstaller(target, artifact, signal), /SHA-256/);
  fs.writeFileSync(target, "short");
  await assert.rejects(verifyDownloadedInstaller(target, artifact, signal), /size/);
  fs.writeFileSync(target, bytes);
  fs.symlinkSync(target, path.join(directory, "link.dmg"));
  await assert.rejects(verifyDownloadedInstaller(path.join(directory, "link.dmg"), artifact, signal), /size/);
});
