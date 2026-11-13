export function createDesktopPackageConfig(buildConfig, { platform, arch, runtimePackagePaths, unsignedMac = false }) {
  const config = structuredClone(buildConfig);
  const files = config.files ?? [];

  if (platform === "mac" && unsignedMac) {
    // Universal merging and app metadata edits invalidate Electron's original
    // signature. Seal the completed app, including nested code, before DMG
    // creation. Ad-hoc is still published as unsigned, never Developer ID.
    config.mac = { ...config.mac, identity: "-", notarize: false };
  }

  if (runtimePackagePaths) {
    // The static renderer already contains browser dependencies. Yarn workspace
    // discovery otherwise adds its complete build tree to the native app.
    config.files = [
      ...files,
      "!node_modules/**",
      ...runtimePackagePaths.map((directory) => `${directory}/**`),
    ];
  }

  if (platform === "mac" && (arch === "arm64" || arch === "x64")) {
    const excludedArch = arch === "arm64" ? "x64" : "arm64";
    config.files = [
      ...(config.files ?? files),
      `!node_modules/**/*-darwin-${excludedArch}/**`,
      `!node_modules/**/*-darwin-${excludedArch}`,
    ];
    // Caches may contain runtimes from a previous build for the other CPU.
    // Exclude those resources too, without removing shared license files.
    config.extraResources = (config.extraResources ?? []).map((resource) =>
      typeof resource === "object" && ["uv", "python"].includes(resource.to)
        ? { ...resource, filter: [...(Array.isArray(resource.filter) ? resource.filter : [resource.filter ?? "**/*"]), `!darwin-${excludedArch}/**`, `!darwin-${excludedArch}`] }
        : resource,
    );
  }

  return config;
}
