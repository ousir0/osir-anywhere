/** Launch metadata contains only a public flow identifier. The authenticated
 * local transport still verifies the Client and owns all authorization. */
const FLAG = "--osir-client-handoff-flow";
const valid = (value: unknown): value is string => typeof value === "string"
  && /^[A-Za-z0-9_-]{32,128}$/.test(value);

export function clientHandoffFlowFromArgv(argv: readonly string[]): string | null {
  const entries = argv.flatMap((value, index) => value === FLAG
    ? [argv[index + 1]] : value.startsWith(`${FLAG}=`) ? [value.slice(FLAG.length + 1)] : []);
  return entries.length === 1 && valid(entries[0]) ? entries[0] : null;
}

export function clientHandoffLockData(flowId: string | null): Record<string, unknown> {
  return valid(flowId) ? { osirClientHandoff: { version: 1, flowId } } : {};
}

export function clientHandoffFlowFromSecondInstance(argv: readonly string[], data: unknown): string | null {
  // Chromium may insert its own switches between a flag and its value in the
  // forwarded argv. Capture argv in the secondary process before requesting
  // the lock, then pass its validated value through Electron's additionalData.
  if (data && typeof data === "object" && Object.hasOwn(data, "osirClientHandoff")) {
    const value = (data as Record<string, unknown>).osirClientHandoff;
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const row = value as Record<string, unknown>;
    return Object.keys(row).sort().join(",") === "flowId,version" && row.version === 1 && valid(row.flowId)
      ? row.flowId : null;
  }
  // Compatibility for a sender without additionalData; never guess a value
  // from unrelated positional arguments or scan the discovery directory.
  return clientHandoffFlowFromArgv(argv);
}
