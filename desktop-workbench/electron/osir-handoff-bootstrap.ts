/** Main-only adapter after an authenticated Client handoff. */
import { setTimeout as pause } from "node:timers/promises";
import type { DesktopBackendClient } from "./backend-client";
import type { ConnectorState, PublicLocalDesktopBinding } from "./connector-types";
import type { DesktopSessionPayload } from "./desktop-session";
import { OsirRuntimeBootstrap, type OsirBootstrapTool, type OsirRuntimeBootstrapApi, type OsirRuntimeBootstrapResult } from "./osir-runtime-bootstrap";

const ORIGIN = "https://anywhere.osirclaw.com";
type Options = {
  backend: Pick<DesktopBackendClient, "request">;
  fetcher: typeof fetch;
  session: DesktopSessionPayload;
  configuredToolTypes: readonly OsirBootstrapTool[];
  signal: AbortSignal;
};

export async function bootstrapClientHandoff(options: Options): Promise<OsirRuntimeBootstrapResult[]> {
  const { backend, session, signal } = options;
  const live = () => { if (signal.aborted) throw new Error("Anywhere 连接已取消。"); };
  live();
  const previous = await backend.request<PublicLocalDesktopBinding | null>("/device/binding", { signal });
  live();
  if (previous && (previous.serverUrl !== ORIGIN || previous.ownerUserId !== session.identity.userId)) {
    throw new Error("Anywhere 当前设备属于其他账号，请先退出原账号。");
  }
  const state = previous ? await backend.request<ConnectorState>("/state", { signal }) : null;
  live();
  if (state && (state.connectorId !== previous!.connectorId || state.serverUrl !== ORIGIN)) {
    throw new Error("Anywhere 本机设备信息已改变，请重新打开。");
  }
  const input = { userId: session.identity.userId, userToken: session.accessToken, serverUrl: ORIGIN };
  const route = previous && (previous.manualDisconnected || !previous.hasCredential || state?.authFailed) ? "/device/reconnect" : "/device/create";
  // One provisioning mutation. An uncertain response is recovered from saved
  // binding on the next explicit click, never retried in a loop.
  const binding = await backend.request<PublicLocalDesktopBinding>(route,
    { method: "POST", body: JSON.stringify(input), signal });
  live();
  if (!binding || binding.ownerUserId !== input.userId || binding.serverUrl !== ORIGIN ||
      !binding.connectorId || binding.manualDisconnected || !binding.hasCredential) {
    throw new Error("Anywhere 本机设备尚未连接。");
  }
  if (!options.configuredToolTypes.length) return [];

  const request = async <T>(suffix: string, method = "GET", body?: object): Promise<T> => {
    live();
    const url = `${ORIGIN}/api/v2/connectors/${encodeURIComponent(binding.connectorId)}${suffix}`;
    const response = await options.fetcher(url, {
      method, body: body === undefined ? undefined : JSON.stringify(body),
      headers: { authorization: `Bearer ${session.accessToken}`, accept: "application/json", "content-type": "application/json" },
      credentials: "omit", redirect: "error", cache: "no-store", signal: AbortSignal.any([signal, AbortSignal.timeout(15_000)]),
    });
    if (!response.ok || response.redirected || response.url && response.url !== url) throw new Error("Anywhere 实例同步暂未完成。");
    const reader = response.body?.getReader(); if (!reader) throw new Error("Anywhere 实例响应无效。");
    let size = 0; const chunks: Uint8Array[] = [];
    try {
      for (;;) { const { done, value } = await reader.read(); if (done) break;
        size += value.length; if (size > 1024 * 1024) throw new Error("Anywhere 实例响应过大。"); chunks.push(value); }
    } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
    live(); return JSON.parse(Buffer.concat(chunks).toString("utf8")) as T;
  };
  const api: OsirRuntimeBootstrapApi = {
    getRuntimes: () => request("/runtimes"),
    getRuntimeTypes: () => request("/runtime-types"),
    createRuntime: (_id, body) => request("/runtimes", "POST", body),
    setActive: (_id, runtimeId) => request(`/runtimes/${encodeURIComponent(runtimeId)}/active`, "PUT", { active: true }),
    // Client authenticated selection includes DSH only after the official CLI
    // has prepared the pinned local bridge and started the Desktop application.
    configureDSH: async () => ({ status: "ready" }),
  };
  const deadline = Date.now() + 45_000;
  // Connector startup publishes its supported runtime types asynchronously.
  // Poll only reads; never create duplicate instances while waiting for it.
  for (;;) {
    live(); const types = await api.getRuntimeTypes(binding.connectorId);
    if (types.connectorId !== binding.connectorId || !Array.isArray(types.runtimeTypes)) throw new Error("Anywhere 实例响应无效。");
    if (options.configuredToolTypes.every(tool => types.runtimeTypes.some(row => row.runtimeType === tool))) break;
    if (Date.now() >= deadline) throw new Error("Anywhere 本机实例发现超时，请重新打开。");
    await pause(750, undefined, { signal });
  }
  const results = await new OsirRuntimeBootstrap(api).run({ connId: binding.connectorId,
    selectedAvailableToolTypes: options.configuredToolTypes });
  while (results.some(row => row.status === "blocked" && row.code === "runtime_starting") && Date.now() < deadline) {
    await pause(750, undefined, { signal }); live();
    const inventory = await api.getRuntimes(binding.connectorId);
    if (inventory.connectorId !== binding.connectorId || !Array.isArray(inventory.runtimes)) throw new Error("Anywhere 实例响应无效。");
    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      if (result.status !== "blocked" || result.code !== "runtime_starting") continue;
      const runtime = inventory.runtimes.find(row => row.connectorId === binding.connectorId && row.runtimeId === result.runtimeId && row.runtimeType === result.tool);
      if (runtime?.active && runtime.status === "running") results[i] = { tool: result.tool, runtimeId: result.runtimeId, status: "ready", code: "runtime_ready" };
      else if (runtime?.status === "error") results[i] = { tool: result.tool, runtimeId: result.runtimeId, status: "error", code: "runtime_start_failed" };
    }
  }
  return results;
}
