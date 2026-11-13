import { readdir, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

const root = resolve(process.argv[2] ?? "renderer/out");
const files = [];

async function walk(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await walk(path);
    else if (entry.isFile()) files.push({ path, size: (await stat(path)).size });
  }
}

try {
  await walk(root);
} catch (error) {
  console.error(`Cannot measure ${root}: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}

const total = files.reduce((sum, file) => sum + file.size, 0);
const byDirectory = new Map();
for (const file of files) {
  const relative = file.path.slice(root.length + 1);
  const directory = dirname(relative).split("/")[0] || ".";
  byDirectory.set(directory, (byDirectory.get(directory) ?? 0) + file.size);
}

console.log(`Root: ${root}`);
console.log(`Files: ${files.length}`);
console.log(`Total: ${total} bytes (${(total / 1024 / 1024).toFixed(2)} MiB)`);
console.log("Largest files:");
for (const file of files.sort((left, right) => right.size - left.size).slice(0, 20)) {
  console.log(`${String(file.size).padStart(12)}  ${file.path.slice(root.length + 1)}`);
}
console.log("Top-level totals:");
for (const [directory, size] of [...byDirectory].sort((left, right) => right[1] - left[1])) {
  console.log(`${String(size).padStart(12)}  ${directory}`);
}
