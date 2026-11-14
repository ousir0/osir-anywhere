import test, { type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { readPackagedRevision } from "./release-build-info";

function fixture(t: TestContext) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "anywhere-packaged-info-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, "dist"));
  return { root, file: path.join(root, "dist/build-info.json") };
}
const info = { productId: "osir-anywhere", desktopVersion: "2.2.1", revision: 2, serverVersion: "2.2.0" };
test("packaged revision uses only the trusted dist path and binds the Desktop version", t => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.root, "build-info.json"), JSON.stringify({ ...info, revision: 999 }));
  assert.equal(readPackagedRevision(f.root, "2.2.1"), 0);
  for (const revision of [0, 2, 65535]) {
    fs.writeFileSync(f.file, JSON.stringify({ ...info, revision }));
    assert.equal(readPackagedRevision(f.root, "2.2.1"), revision);
  }
  assert.throws(() => readPackagedRevision(f.root, "2.2.0"), /build information/);
});
test("missing and exact legacy Server-only metadata return legacy zero", t => {
  const f = fixture(t);
  assert.equal(readPackagedRevision(f.root, "2.2.1"), 0);
  fs.writeFileSync(f.file, JSON.stringify({ serverVersion: "2.1.0" }));
  assert.equal(readPackagedRevision(f.root, "2.2.1"), 0);
});
test("malformed or mismatched metadata fails closed without leaking file/body details", t => {
  const f = fixture(t);
  for (const value of [null, [], {}, { ...info, productId: "other" }, { ...info, desktopVersion: "2.2.0" },
    { ...info, revision: -1 }, { ...info, revision: 0.5 }, { ...info, revision: 65536 }, { ...info, revision: "2" },
    { ...info, revision: null }, { ...info, revision: undefined }, { ...info, releaseRevision: 2 },
    { serverVersion: "2.2.1", releaseRevision: 2 }]) {
    fs.writeFileSync(f.file, JSON.stringify(value));
    assert.throws(() => readPackagedRevision(f.root, "2.2.1"), /^Error: Packaged Desktop build information is invalid\.$/);
  }
  for (const body of ["{secret", " ".repeat(4097), Buffer.from([0xff])]) {
    fs.writeFileSync(f.file, body); assert.throws(() => readPackagedRevision(f.root, "2.2.1"), /build information/);
  }
  assert.throws(() => readPackagedRevision("relative", "2.2.1"), /build information/);
});
test("metadata file must be regular and cannot be redirected through a symlink", t => {
  const f = fixture(t);
  fs.mkdirSync(f.file); assert.throws(() => readPackagedRevision(f.root, "2.2.1"), /build information/);
  fs.rmdirSync(f.file);
  if (process.platform === "win32") return;
  const target = path.join(f.root, "untrusted.json"); fs.writeFileSync(target, JSON.stringify(info));
  fs.symlinkSync(target, f.file); assert.throws(() => readPackagedRevision(f.root, "2.2.1"), /build information/);
});
