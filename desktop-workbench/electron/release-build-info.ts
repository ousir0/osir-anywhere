import fs from "node:fs";
import path from "node:path";

const INVALID = "Packaged Desktop build information is invalid.";
/** Pure native accessor. root is trusted app.getAppPath() (including app.asar),
 * never an IPC/manifest/env-selected directory. Failure disables update checks;
 * it must not be silently downgraded to installed revision zero by the caller.
 */
export function readPackagedRevision(root: string, currentVersion: string): number {
  if (!path.isAbsolute(root) || typeof currentVersion !== "string" || !currentVersion) throw new Error(INVALID);
  const file = path.join(root, "dist", "build-info.json");
  let raw: Buffer;
  try {
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 1 || stat.size > 4096) throw new Error(INVALID);
    raw = fs.readFileSync(file);
    if (raw.length !== stat.size || raw.length > 4096) throw new Error(INVALID);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return 0;
    throw new Error(INVALID);
  }
  try {
    const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
    const info = value as Record<string, unknown>;
    const keys = Object.keys(info).sort().join(",");
    if (keys === "serverVersion" && typeof info.serverVersion === "string" && info.serverVersion.length > 0 && info.serverVersion.length <= 128) return 0;
    if (keys !== "desktopVersion,productId,revision,serverVersion" || info.productId !== "osir-anywhere" || info.desktopVersion !== currentVersion
      || typeof info.serverVersion !== "string" || !info.serverVersion || info.serverVersion.length > 128
      || !Number.isSafeInteger(info.revision) || (info.revision as number) < 0 || (info.revision as number) > 65535) throw new Error();
    return info.revision as number;
  } catch { throw new Error(INVALID); }
}
