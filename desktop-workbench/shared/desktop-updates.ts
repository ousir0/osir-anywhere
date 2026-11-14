export type DesktopUpdateError = "checkFailed" | "downloadNotConfigured" | "downloadFailed" | "openFailed" | "ignoreFailed";

export type ReleaseSystemSignature = "unsigned" | "developer-id-notarized" | "authenticode";

export type ReleaseArtifact = {
  platform: "darwin" | "win32";
  arch: "universal" | "arm64" | "x64";
  url: string;
  size: number;
  sha256: string;
  filename: string;
  /** Signed publisher declaration; omission requires the platform's strong signature policy. */
  systemSignature?: ReleaseSystemSignature;
};

export type DesktopReleaseManifest = {
  schemaVersion: 1;
  productId: "osir-anywhere";
  channel: "stable";
  releaseId: string;
  version: string;
  /** Signed build revision (0..65535). Omission denotes the legacy revision zero. */
  revision?: number;
  publishedAt: string;
  /** OSIR Client compatibility metadata; this is not the Desktop version. */
  minimumClientVersion?: string;
  minimumServerVersion?: string;
  artifacts: ReleaseArtifact[];
};

export type DesktopUpdateState = {
  /** State event counter, unrelated to the signed release revision. */
  revision: number;
  currentVersion: string;
  latestVersion: string | null;
  checking: boolean;
  available: boolean;
  ignored: boolean;
  dialogOpen: boolean;
  phase: "idle" | "downloading" | "opening" | "downloaded";
  downloadedBytes: number;
  totalBytes: number | null;
  error: DesktopUpdateError | null;
  /** Human-readable reason for unavailable manifests, targets or compatibility. */
  errorDetail: string | null;
  release: Omit<DesktopReleaseManifest, "artifacts"> | null;
  artifact: (Pick<ReleaseArtifact, "platform" | "arch"> & {
    /** Effective policy, including the strong platform default for legacy manifests. */
    systemSignature: ReleaseSystemSignature;
    systemSignatureDeclared: boolean;
  }) | null;
};
