import fs from "node:fs/promises";
import { createReadStream } from "node:fs";
import path from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { validateReleaseArtifact } from "./release-manifest";
import type { ReleaseArtifact } from "../shared/desktop-updates";

export async function verifyDownloadedInstaller(file: string, artifact: ReleaseArtifact, signal: AbortSignal): Promise<void> {
  signal.throwIfAborted();
  const stat = await fs.lstat(file);
  if (!stat.isFile() || stat.size !== artifact.size) throw new Error("Installer size mismatch.");
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file, { signal })) hash.update(chunk);
  signal.throwIfAborted();
  if (hash.digest("hex") !== artifact.sha256.toLowerCase()) throw new Error("Installer SHA-256 mismatch.");
}

export async function downloadDesktopInstaller(options: {
  artifact: ReleaseArtifact;
  releaseId: string;
  directory: string;
  fetcher: typeof fetch;
  signal: AbortSignal;
  onProgress: (downloadedBytes: number, totalBytes: number) => void;
}): Promise<string> {
  const artifact = validateReleaseArtifact(options.artifact, options.releaseId);
  options.signal.throwIfAborted();
  const response = await options.fetcher(artifact.url, {
    credentials: "omit", cache: "no-store", redirect: "error", signal: options.signal,
  });
  const lengthHeader = response.headers.get("content-length");
  const encoding = response.headers.get("content-encoding");
  if (response.status !== 200 || !response.body || (response.url && response.url !== artifact.url) ||
      /text\/|json|xml/i.test(response.headers.get("content-type") ?? "") ||
      (encoding !== null && encoding.toLowerCase() !== "identity") ||
      (lengthHeader !== null && (!/^\d+$/.test(lengthHeader) || Number(lengthHeader) !== artifact.size))) {
    await response.body?.cancel();
    throw new Error("Installer response does not match the signed release.");
  }
  const reader = response.body.getReader();
  // Electron's fetch body needs explicit cancellation after headers have arrived.
  const cancel = () => { void reader.cancel().catch(() => undefined); };
  options.signal.addEventListener("abort", cancel, { once: true });
  let partial: string | undefined;
  let output: Awaited<ReturnType<typeof fs.open>> | undefined;
  let completed: string | undefined;
  try {
    options.signal.throwIfAborted();
    await fs.mkdir(options.directory, { recursive: true, mode: 0o700 });
    const target = path.join(options.directory, `${randomUUID()}-${artifact.filename}`);
    partial = `${target}.part`;
    output = await fs.open(partial, "wx", 0o600);
    const hash = createHash("sha256");
    let received = 0;
    let lastPublished = 0;
    options.onProgress(0, artifact.size);
    while (true) {
      options.signal.throwIfAborted();
      const { done, value } = await reader.read();
      options.signal.throwIfAborted();
      if (done) break;
      received += value.byteLength;
      if (received > artifact.size) throw new Error("Installer exceeds signed size.");
      hash.update(value);
      await output.writeFile(value);
      if (Date.now() - lastPublished >= 100 || received === artifact.size) {
        options.onProgress(received, artifact.size);
        lastPublished = Date.now();
      }
    }
    if (received !== artifact.size || hash.digest("hex") !== artifact.sha256) throw new Error("Installer size or SHA-256 mismatch.");
    await output.sync();
    await output.close();
    output = undefined;
    options.signal.throwIfAborted();
    await fs.rename(partial, target);
    partial = undefined;
    completed = target;
    options.signal.throwIfAborted();
    options.onProgress(received, artifact.size);
    completed = undefined;
    return target;
  } finally {
    options.signal.removeEventListener("abort", cancel);
    await reader.cancel().catch(() => undefined);
    await output?.close();
    if (partial) await fs.rm(partial, { force: true });
    if (completed) await fs.rm(completed, { force: true });
  }
}
