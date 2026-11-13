import { isApiError } from "@/lib/api/errors"
import { isTransientHttpStatus, retryWithDelays, waitFor } from "@/lib/retry"

import { dashboardApi } from "@/features/dashboard/api"
import { mergeRuntimeTypes } from "@/features/dashboard/runtime-instances"
import type { DeviceRuntimeView, RuntimeTypeView } from "@/features/dashboard/types"

const DEFAULT_RETRY_DELAYS_MS = [500, 1000, 2000] as const

export type ConnectorRuntimeOverview = {
  runtimes: DeviceRuntimeView[]
  runtimeTypes: RuntimeTypeView[]
}

/** Read persisted inventory only; opening a device must not trigger discovery. */
export async function loadConnectorRuntimeOverview(
  token: string,
  connectorId: string,
  options: { signal?: AbortSignal; timeoutMs?: number } = {},
): Promise<ConnectorRuntimeOverview> {
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
  const timer = setTimeout(() => {
    controller.abort(new Error("Runtime inventory request timed out"))
  }, options.timeoutMs ?? 10_000)
  try {
    return await Promise.race([
      aborted,
      (async () => {
        controller.signal.throwIfAborted()
        const requestOptions = { signal: controller.signal }
        const [runtimeResponse, typeResponse] = await Promise.all([
          dashboardApi.getConnectorRuntimes(token, connectorId, requestOptions),
          dashboardApi.getConnectorRuntimeTypes(token, connectorId, requestOptions),
        ])
        return {
          runtimes: runtimeResponse.runtimes,
          runtimeTypes: mergeRuntimeTypes(typeResponse.runtimeTypes, runtimeResponse.runtimes),
        }
      })(),
    ])
  } finally {
    clearTimeout(timer)
    options.signal?.removeEventListener("abort", cancel)
    controller.signal.removeEventListener("abort", onAbort)
    controller.abort() // Cancel the other read if one failed.
  }
}

export async function discoverConnectorRuntimeOverview(
  token: string,
  connectorId: string,
  options: {
    initialDelayMs?: number
    retryDelaysMs?: readonly number[]
  } = {},
): Promise<ConnectorRuntimeOverview> {
  if (options.initialDelayMs) await waitFor(options.initialDelayMs)
  return retryWithDelays(
    async () => {
      const typeResponse = await dashboardApi.discoverConnectorRuntimeTypes(token, connectorId)
      const runtimeResponse = await dashboardApi.getConnectorRuntimes(token, connectorId)
      return {
        runtimes: runtimeResponse.runtimes,
        runtimeTypes: mergeRuntimeTypes(typeResponse.runtimeTypes, runtimeResponse.runtimes),
      }
    },
    options.retryDelaysMs ?? DEFAULT_RETRY_DELAYS_MS,
    isRetryableRuntimeDiscoveryError,
  )
}

function isRetryableRuntimeDiscoveryError(error: unknown): boolean {
  return isApiError(error) && isTransientHttpStatus(error.status)
}
