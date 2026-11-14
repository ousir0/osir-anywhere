import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolveDesktopBuildConfig } from "./desktop-build-config.mjs";

const sourcePath = new URL("../config.json", import.meta.url);
const outputPath = new URL("../dist/config.json", import.meta.url);
const config = resolveDesktopBuildConfig(JSON.parse(await readFile(sourcePath, "utf8")), process.env);

await writeFile(fileURLToPath(outputPath), `${JSON.stringify(config, null, 2)}\n`, "utf8");
// tsc emits TypeScript only. This native peer inspector must travel with Main
// in both development and the final app.asar; never depend on a source checkout.
await mkdir(new URL("../dist/electron/", import.meta.url), { recursive: true });
await copyFile(new URL("../electron/osir-client-handoff-peer.py", import.meta.url),
  new URL("../dist/electron/osir-client-handoff-peer.py", import.meta.url));
