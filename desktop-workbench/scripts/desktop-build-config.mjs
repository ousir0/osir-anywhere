import { isDeepStrictEqual } from "node:util";

/** Shared by compilation and packaging, including retries that reuse a build. */
export function resolveDesktopBuildConfig(source, env = {}) {
  const config = structuredClone(source);
  for (const [section, field, variable] of [
    ["identity", "apiOrigin", "OSIR_IDENTITY_API_ORIGIN"],
    ["identity", "webOrigin", "OSIR_IDENTITY_WEB_ORIGIN"],
    ["cloud", "serverUrl", "OSIR_ANYWHERE_API_ORIGIN"],
    ["cloud", "oauthWebOrigin", "OSIR_ANYWHERE_OAUTH_WEB_ORIGIN"],
  ]) {
    const value = env[variable]?.trim() || config[section][field];
    let url;
    try { url = new URL(value); } catch { throw new Error(`Invalid ${variable}: an origin is required.`); }
    const localHttp = url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname);
    if ((!localHttp && url.protocol !== "https:") || url.username || url.password ||
      url.pathname !== "/" || url.search || url.hash) {
      throw new Error(`Invalid ${variable}: use an HTTPS origin, or loopback HTTP for development.`);
    }
    config[section][field] = url.origin;
  }
  const manifestUrl = "https://osirvedio.cn-nb1.rains3.com/osir-anywhere/releases/stable.json";
  if (config.updates?.manifestUrl !== manifestUrl || config.updates.downloadUrls !== undefined ||
      env.OSIR_ANYWHERE_MAC_UPDATE_URL?.trim() || env.OSIR_ANYWHERE_WIN_UPDATE_URL?.trim() ||
      env.OSIR_ANYWHERE_RELEASE_MANIFEST_URL?.trim()) {
    throw new Error("Desktop updates require the fixed signed stable manifest; direct installer URL overrides are unsupported.");
  }
  return config;
}

export function assertBuiltDesktopConfig(built, expected) {
  if (!isDeepStrictEqual(built, expected)) {
    throw new Error("Packaged connection settings are stale. Rebuild the app with the selected OSIR endpoints before retrying packaging.");
  }
}
