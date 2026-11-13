import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { assertBuiltDesktopConfig, resolveDesktopBuildConfig } from "./desktop-build-config.mjs";

const source = JSON.parse(readFileSync(new URL("../config.json", import.meta.url), "utf8"));

test("cloud defaults and explicit development endpoints use the same compiled configuration", () => {
  const cloud = resolveDesktopBuildConfig(source);
  assert.equal(cloud.cloud.serverUrl, "https://anywhere.osirclaw.com");
  const local = resolveDesktopBuildConfig(source, {
    OSIR_ANYWHERE_API_ORIGIN: "http://127.0.0.1:8000/",
    OSIR_ANYWHERE_OAUTH_WEB_ORIGIN: "http://localhost:5174",
  });
  assert.equal(local.cloud.serverUrl, "http://127.0.0.1:8000");
  assert.equal(local.cloud.oauthWebOrigin, "http://localhost:5174");
  assert.equal(source.cloud.serverUrl, cloud.cloud.serverUrl);
});

test("packaging retry rejects a stale local build instead of shipping it as cloud", () => {
  const expected = resolveDesktopBuildConfig(source);
  const stale = resolveDesktopBuildConfig(source, { OSIR_ANYWHERE_API_ORIGIN: "http://127.0.0.1:8000" });
  assert.throws(() => assertBuiltDesktopConfig(stale, expected), /settings are stale/);
  assert.doesNotThrow(() => assertBuiltDesktopConfig(structuredClone(expected), expected));
});

test("build endpoints reject credentials, page paths and nonlocal cleartext without echoing them", () => {
  for (const value of ["https://user:synthetic-secret@example.test", "https://example.test/page", "https://example.test?token=synthetic-secret", "http://example.test", "file:///tmp/test"]) {
    assert.throws(() => resolveDesktopBuildConfig(source, { OSIR_ANYWHERE_API_ORIGIN: value }), error =>
      error instanceof Error && !error.message.includes("synthetic-secret") && error.message.startsWith("Invalid OSIR_ANYWHERE_API_ORIGIN"));
  }
});

test("Desktop update configuration pins the signed stable manifest and rejects legacy direct URL overrides", () => {
  const url = "https://osirvedio.cn-nb1.rains3.com/osir-anywhere/releases/stable.json";
  assert.deepEqual(resolveDesktopBuildConfig(source).updates, { manifestUrl: url });
  for (const updates of [{ manifestUrl: "https://example.invalid/latest" }, { manifestUrl: url + "?token=x" },
    { manifestUrl: url.replace("https:", "http:") }, { manifestUrl: url, downloadUrls: { darwin: "https://example.test/installer" } }]) {
    assert.throws(() => resolveDesktopBuildConfig({ ...source, updates }), /fixed signed stable manifest/);
  }
  for (const variable of ["OSIR_ANYWHERE_MAC_UPDATE_URL", "OSIR_ANYWHERE_WIN_UPDATE_URL", "OSIR_ANYWHERE_RELEASE_MANIFEST_URL"]) {
    assert.throws(() => resolveDesktopBuildConfig(source, { [variable]: url }), /fixed signed stable manifest/);
  }
});
