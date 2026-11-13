import { dashboardApi } from "@/features/dashboard/api"

export const WORKSPACE_INVENTORY_TIMEOUT_MS = 10_000

/** Bound the whole read, including response bodies and transports that ignore abort. */
export async function readWorkspaceInventory<T>(
  read: (signal: AbortSignal) => Promise<T>,
  options: { signal?: AbortSignal; timeoutMs?: number } = {},
): Promise<T> {
  const controller = new AbortController()
  const cancel = () => controller.abort(options.signal?.reason)
  options.signal?.addEventListener("abort", cancel, { once: true })
  if (options.signal?.aborted) cancel()
  let onAbort: () => void = () => {}
  const aborted = new Promise<never>((_resolve, reject) => {
    onAbort = () => reject(controller.signal.reason)
    controller.signal.addEventListener("abort", onAbort, { once: true })
    if (controller.signal.aborted) onAbort()
  })
  const timer = setTimeout(() => controller.abort(new Error("Workspace inventory request timed out")),
    options.timeoutMs ?? WORKSPACE_INVENTORY_TIMEOUT_MS)
  try {
    return await Promise.race([
      aborted,
      (async () => { controller.signal.throwIfAborted(); return read(controller.signal) })(),
    ])
  } finally {
    clearTimeout(timer)
    options.signal?.removeEventListener("abort", cancel)
    controller.signal.removeEventListener("abort", onAbort)
    controller.abort()
  }
}

export function loadWorkspaceInventory(token: string, options: { signal?: AbortSignal; timeoutMs?: number } = {}) {
  return readWorkspaceInventory(signal => Promise.all([
    dashboardApi.listConnectors(token, { signal }),
    dashboardApi.listProjects(token, { signal }),
    dashboardApi.listSessionInventory(token, { signal }),
  ]), options)
}
