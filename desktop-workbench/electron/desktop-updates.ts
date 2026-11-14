import fs from "node:fs";
import path from "node:path";
import type { DesktopServerConnection } from "./desktop-server";
import { readJsonFile, writeJsonFile } from "./json-store";
import { compareUpdateVersions } from "./update-version";
import { downloadDesktopInstaller, verifyDownloadedInstaller } from "./update-download";
import { InstallerNativeValidationError, prepareNativeInstaller } from "./update-installer-native";
import { assertManifestUrl, readReleaseJson, resolveReleaseSystemSignature, selectReleaseArtifact, verifyReleaseManifest } from "./release-manifest";
import type { DesktopUpdateState, ReleaseArtifact } from "../shared/desktop-updates";

type Options = {
  directory: string;
  currentVersion: string;
  /** Trusted packaged build-info only; omitted for legacy revision zero. Never from IPC/Server/env. */
  currentRevision?: number;
  /** Trusted build/runtime configuration only; never populated from Server data. */
  manifestUrl: string;
  publicKeyPem: string;
  platform: string;
  arch: string;
  fetcher: typeof fetch;
  openInstaller: (filePath: string) => Promise<void>;
  /** Trusted main-process dependency; never populated from IPC or Server data. */
  prepareInstaller?: typeof prepareNativeInstaller;
  onState: (state: DesktopUpdateState) => void;
  checkTimeoutMs?: number;
  downloadTimeoutMs?: number;
};

export class DesktopUpdateService {
  private state: DesktopUpdateState;
  private serverKey = "";
  private generation = 0;
  private checkPromise: Promise<DesktopUpdateState> | null = null;
  private downloadPromise: Promise<DesktopUpdateState> | null = null;
  private checkAbort: AbortController | null = null;
  private downloadAbort: AbortController | null = null;
  private installerPath: string | null = null;
  private artifact: ReleaseArtifact | null = null;

  constructor(private readonly options: Options) {
    if (options.currentRevision !== undefined && (!Number.isSafeInteger(options.currentRevision) || options.currentRevision < 0 || options.currentRevision > 65535)) {
      throw new Error("currentRevision must be an integer in 0..65535 from trusted build-info.");
    }
    this.state = this.initialState();
  }

  getState(): DesktopUpdateState {
    return { ...this.state, release: this.state.release ? { ...this.state.release } : null,
      artifact: this.state.artifact ? { ...this.state.artifact } : null };
  }

  check(server: DesktopServerConnection | null): Promise<DesktopUpdateState> {
    if (!server?.serverUrl.trim()) {
      this.dispose();
      this.serverKey = "";
      this.publish(this.initialState());
      return Promise.resolve(this.getState());
    }
    const key = `${server.serverUrl}${server.apiNamespace}`;
    if (key === this.serverKey) {
      if (this.checkPromise) return this.checkPromise;
      if (this.downloadPromise) return Promise.resolve(this.getState());
    }
    this.dispose();
    const generation = this.generation;
    this.serverKey = key;
    const controller = new AbortController();
    this.checkAbort = controller;
    const timeout = setTimeout(() => controller.abort(), this.options.checkTimeoutMs ?? 10_000);
    const promise = Promise.resolve().then(async () => {
      try {
        assertManifestUrl(this.options.manifestUrl);
        if (!this.options.publicKeyPem.trim()) throw new Error("缺少有效的发行公钥，暂时无法安全检查更新。");
        const response = await this.options.fetcher(this.options.manifestUrl, {
          headers: { accept: "application/json" }, credentials: "omit", cache: "no-store",
          redirect: "error", signal: controller.signal,
        });
        if (response.status !== 200 || (response.url && response.url !== this.options.manifestUrl)) {
          await response.body?.cancel();
          throw new Error("更新清单暂不可用，请稍后重试。");
        }
        const manifest = verifyReleaseManifest(await readReleaseJson(response, controller.signal), this.options.publicKeyPem);
        const comparison = compareUpdateVersions(manifest.version, this.options.currentVersion);
        if (comparison === null) throw new Error("更新清单无法与当前桌面版本比较。");
        controller.signal.throwIfAborted();
        if (generation !== this.generation) return this.getState();
        const releaseRevision = manifest.revision ?? 0;
        const available = comparison > 0 || (comparison === 0 && releaseRevision > (this.options.currentRevision ?? 0));
        let artifact = selectReleaseArtifact(manifest, this.options.platform, this.options.arch);
        let errorDetail: string | null = available && !artifact ? "此发行版没有适用于当前系统和架构的安装包。" : null;
        // Health is consulted only for an explicit minimum Server requirement.
        // It is never the source of the latest Desktop version or download URL.
        if (available && artifact && manifest.minimumServerVersion) {
          const compatible = await this.serverCompatible(key, manifest.minimumServerVersion, controller.signal);
          if (!compatible) {
            artifact = null;
            errorDetail = `无法确认当前 Server 满足最低版本 ${manifest.minimumServerVersion}，请先升级或检查服务后重试。`;
          }
        }
        controller.signal.throwIfAborted();
        if (generation !== this.generation) return this.getState();
        this.artifact = available ? artifact : null;
        const preference = this.readIgnored()[this.options.manifestUrl];
        // Old string preferences apply only to the old, unrevisioned release.
        const ignoredRelease = typeof preference === "string" ? { version: preference, revision: 0 } :
          preference && typeof preference === "object" && !Array.isArray(preference) ? preference as { version?: unknown; revision?: unknown } : null;
        const ignored = available && !!ignoredRelease && typeof ignoredRelease.version === "string" &&
          ignoredRelease.revision === releaseRevision && compareUpdateVersions(ignoredRelease.version, manifest.version) === 0;
        const { artifacts: _artifacts, ...release } = manifest;
        this.publish({ checking: false, latestVersion: manifest.version, available, ignored, release,
          artifact: this.artifact ? { platform: this.artifact.platform, arch: this.artifact.arch,
            systemSignature: resolveReleaseSystemSignature(this.artifact), systemSignatureDeclared: this.artifact.systemSignature !== undefined } : null,
          dialogOpen: available && !ignored, error: errorDetail ? "downloadNotConfigured" : null, errorDetail });
      } catch (error) {
        if (generation === this.generation) this.publish({ checking: false, error: "checkFailed",
          errorDetail: error instanceof Error && /^(发行清单|安装包地址|缺少有效|更新清单)/.test(error.message)
            ? error.message : "更新清单暂不可用或格式无效，请稍后重试。" });
      } finally {
        clearTimeout(timeout);
        if (this.checkAbort === controller) { this.checkPromise = null; this.checkAbort = null; }
      }
      return this.getState();
    });
    this.checkPromise = promise;
    this.publish({ ...this.initialState(), checking: true });
    return promise;
  }

  showPrompt(): DesktopUpdateState {
    if (this.state.available) this.publish({ dialogOpen: true });
    return this.getState();
  }

  ignoreVersion(): DesktopUpdateState {
    if (!this.state.available || !this.state.latestVersion || this.downloadPromise) return this.getState();
    try {
      writeJsonFile(path.join(this.options.directory, "state.json"), {
        ignoredVersions: { ...this.readIgnored(), [this.options.manifestUrl]: {
          version: this.state.latestVersion, revision: this.state.release?.revision ?? 0,
        } },
      });
      this.publish({ ignored: true, dialogOpen: false });
    } catch {
      this.publish({ error: "ignoreFailed", errorDetail: "无法保存忽略记录，请重试。" });
    }
    return this.getState();
  }

  download(): Promise<DesktopUpdateState> {
    if (this.downloadPromise) return this.downloadPromise;
    if (!this.state.available) return Promise.resolve(this.getState());
    const artifact = this.artifact;
    const releaseId = this.state.release?.releaseId;
    const releaseVersion = this.state.release?.version;
    if (!artifact || !releaseId || !releaseVersion) {
      this.publish({ dialogOpen: true, error: "downloadNotConfigured",
        errorDetail: this.state.errorDetail ?? "没有经过验证且适用于本机的安装包。" });
      return Promise.resolve(this.getState());
    }
    const generation = this.generation;
    const controller = new AbortController();
    this.downloadAbort = controller;
    const timeout = setTimeout(() => controller.abort(), this.options.downloadTimeoutMs ?? 30 * 60_000);
    const promise = Promise.resolve().then(async () => {
      try {
        // A previously verified file may have changed after an unsuccessful launch.
        let installerPath = this.installerPath;
        if (installerPath) {
          try { await verifyDownloadedInstaller(installerPath, artifact, controller.signal); }
          catch {
            controller.signal.throwIfAborted();
            if (generation !== this.generation) return this.getState();
            fs.rmSync(installerPath, { force: true });
            this.installerPath = null;
            installerPath = null;
          }
        }
        controller.signal.throwIfAborted();
        if (generation !== this.generation) return this.getState();
        if (!installerPath) {
          const downloadedPath = await downloadDesktopInstaller({
            artifact, releaseId, directory: path.join(this.options.directory, "downloads"),
            fetcher: this.options.fetcher, signal: controller.signal,
            onProgress: (downloadedBytes, totalBytes) => {
              if (generation === this.generation) this.publish({ downloadedBytes, totalBytes });
            },
          });
          if (generation !== this.generation || controller.signal.aborted) {
            fs.rmSync(downloadedPath, { force: true });
            return this.getState();
          }
          this.installerPath = downloadedPath;
          installerPath = downloadedPath;
        }
        controller.signal.throwIfAborted();
        if (generation !== this.generation) return this.getState();
        await (this.options.prepareInstaller ?? prepareNativeInstaller)({
          file: installerPath, artifact, version: releaseVersion, signal: controller.signal,
        });
        controller.signal.throwIfAborted();
        if (generation !== this.generation) return this.getState();
        this.publish({ phase: "opening", downloadedBytes: artifact.size, totalBytes: artifact.size });
        controller.signal.throwIfAborted();
        if (generation !== this.generation) return this.getState();
        await this.options.openInstaller(installerPath);
        // Opening DMG/NSIS is a handoff to the OS, not proof of installation.
        if (generation === this.generation) this.publish({ phase: "downloaded", dialogOpen: false });
      } catch (error) {
        if (generation === this.generation) {
          const opening = this.state.phase === "opening";
          const cancelled = controller.signal.reason === "user-cancelled";
          this.publish({ phase: "idle", error: cancelled ? null : opening ? "openFailed" : "downloadFailed",
            errorDetail: cancelled ? null : error instanceof InstallerNativeValidationError ? error.message :
              opening ? "无法打开安装包，请重试。" : "安装包下载或大小、SHA-256 校验失败，请重试。" });
        }
      } finally {
        clearTimeout(timeout);
        if (this.downloadAbort === controller) { this.downloadPromise = null; this.downloadAbort = null; }
      }
      return this.getState();
    });
    this.downloadPromise = promise;
    this.publish({ dialogOpen: true, phase: "downloading", error: null, errorDetail: null, downloadedBytes: 0, totalBytes: artifact.size });
    return promise;
  }

  cancelDownload(): Promise<DesktopUpdateState> {
    this.downloadAbort?.abort("user-cancelled");
    return this.downloadPromise ?? Promise.resolve(this.getState());
  }

  dispose(): void {
    ++this.generation;
    this.checkAbort?.abort();
    this.downloadAbort?.abort();
    this.checkAbort = null;
    this.downloadAbort = null;
    this.checkPromise = null;
    this.downloadPromise = null;
    this.installerPath = null;
    this.artifact = null;
  }

  private async serverCompatible(key: string, minimum: string, signal: AbortSignal): Promise<boolean> {
    try {
      const response = await this.options.fetcher(`${key}/health`, {
        headers: { accept: "application/json" }, credentials: "omit", cache: "no-store", redirect: "error", signal,
      });
      if (response.status !== 200 || (response.url && response.url !== `${key}/health`)) {
        await response.body?.cancel();
        return false;
      }
      const value = await readReleaseJson(response, signal);
      if (!value || typeof value !== "object") return false;
      const health = value as { status?: unknown; version?: unknown };
      if (health.status !== "ok" || typeof health.version !== "string") return false;
      const comparison = compareUpdateVersions(health.version, minimum);
      return comparison !== null && comparison >= 0;
    } catch { return false; }
  }

  private readIgnored(): Record<string, unknown> {
    const value = readJsonFile<{ ignoredVersions?: unknown } | null>(path.join(this.options.directory, "state.json"), null)?.ignoredVersions;
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
  }

  private initialState(): DesktopUpdateState {
    return {
      revision: 0, currentVersion: this.options.currentVersion, latestVersion: null,
      checking: false, available: false, ignored: false, dialogOpen: false,
      phase: "idle", downloadedBytes: 0, totalBytes: null, error: null, errorDetail: null, release: null, artifact: null,
    };
  }

  private publish(patch: Partial<DesktopUpdateState>): void {
    this.state = { ...this.state, ...patch, revision: this.state.revision + 1 };
    this.options.onState(this.getState());
  }
}
