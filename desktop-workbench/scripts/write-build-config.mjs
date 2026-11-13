import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolveDesktopBuildConfig } from "./desktop-build-config.mjs";

const sourcePath = new URL("../config.json", import.meta.url);
const outputPath = new URL("../dist/config.json", import.meta.url);
const config = resolveDesktopBuildConfig(JSON.parse(await readFile(sourcePath, "utf8")), process.env);

await writeFile(fileURLToPath(outputPath), `${JSON.stringify(config, null, 2)}\n`, "utf8");
