import assert from "node:assert/strict"
import test from "node:test"
import { readFileSync } from "node:fs"
import { registerHooks } from "node:module"
import { JSDOM } from "jsdom"
import { registerSource } from "./helpers/onboarding-source.mjs"

const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://fixture.example/", pretendToBeVisual: true })
for (const name of ["window", "document", "navigator", "HTMLElement", "HTMLInputElement", "HTMLButtonElement", "HTMLFormElement", "Element", "Node", "NodeFilter", "Event", "CustomEvent", "MutationObserver", "getComputedStyle", "requestAnimationFrame", "cancelAnimationFrame", "DocumentFragment"]) {
  Object.defineProperty(globalThis, name, { configurable: true, value: dom.window[name] })
}
window.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} })
globalThis.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} }
globalThis.IS_REACT_ACT_ENVIRONMENT = true
const { createElement: h, act } = await import("react")
const { createRoot } = await import("react-dom/client")
const { NextIntlClientProvider } = await import("next-intl")
const sourceHooks = registerSource()
const contextHooks = registerHooks({ load(url, context, nextLoad) {
  if (url.endsWith("/components/auth/auth-context.tsx")) return { format: "module", shortCircuit: true, source: "export const useAuth = () => ({session: {accessToken: 'fixture-token'}})" }
  if (url.endsWith("/components/workspace-context.tsx")) return { format: "module", shortCircuit: true, source: "export const useWorkspace = () => globalThis.deviceWorkspace" }
  if (url.endsWith("/features/desktop/desktop-connector-context.tsx")) return { format: "module", shortCircuit: true, source: "export const useDesktopConnector = () => ({isLocalConnector: () => false})" }
  if (url.endsWith("/components/dashboard-sidebar-toggle.tsx")) return { format: "module", shortCircuit: true, source: "export const DashboardSidebarToggle = () => null" }
  if (url.endsWith("/components/pair-device-dialog.tsx")) return { format: "module", shortCircuit: true, source: "export const PairDeviceDialog = () => null" }
  return nextLoad(url, context)
} })
const { DevicePage } = await import("../src/components/pages/device-page.tsx")
const { dashboardApi, DashboardApi } = await import("../src/features/dashboard/api.ts")
const { loadConnectorRuntimeOverview } = await import("../src/features/dashboard/runtime-discovery.ts")
contextHooks.deregister()
sourceHooks.deregister()

function deferred() {
  let resolve
  const promise = new Promise((done) => { resolve = done })
  return { promise, resolve }
}
function runtime(id = "rti_saved", connectorId = "conn_a") {
  return { runtimeId: id, connectorId, runtimeType: "codex", name: "Saved Codex", displayName: "Codex", implementationType: "cli", configured: true, active: false, present: true, available: true, status: "stopped", config: {}, schema: {}, capabilities: {}, metadata: {} }
}
async function render(t, { status = "offline", locale = "zh-CN" } = {}) {
  globalThis.deviceWorkspace = {
    activeConnectorId: "conn_a", connectors: [{ id: "conn_a", name: "Test Mac", status }],
    projects: [], sessions: [], runtimes: [], refreshData() {},
  }
  t.mock.method(dashboardApi, "discoverConnectorRuntimeTypes", async () => { throw new Error("Opening a device must not discover or start local runtimes") })
  const container = document.createElement("div")
  document.body.append(container)
  const root = createRoot(container)
  const messages = JSON.parse(readFileSync(new URL(`../messages/${locale}.json`, import.meta.url), "utf8"))
  const rerender = async () => act(async () => root.render(h(NextIntlClientProvider, { locale, messages, timeZone: "UTC" }, h(DevicePage))))
  t.after(async () => { await act(async () => root.unmount()); container.remove() })
  await rerender()
  return { container, rerender }
}

test("offline empty device settles to registered/offline and local connection guidance in both languages", async (t) => {
  for (const locale of ["zh-CN", "en"]) {
    t.mock.method(dashboardApi, "getConnectorRuntimes", async () => ({ runtimes: [] }))
    t.mock.method(dashboardApi, "getConnectorRuntimeTypes", async () => ({ runtimeTypes: [] }))
    const view = await render(t, { locale })
    const messages = JSON.parse(readFileSync(new URL(`../messages/${locale}.json`, import.meta.url), "utf8"))
    assert.ok(view.container.textContent.includes(messages.dashboard.device.registeredOffline))
    assert.ok(view.container.textContent.includes(messages.dashboard.device.noConfiguredRuntimes))
    assert.ok(view.container.textContent.includes(messages.dashboard.device.noSessionsOffline))
    assert.ok(view.container.textContent.includes(messages.dashboard.device.registeredOfflineHint))
    assert.equal(view.container.querySelector('[data-slot="spinner"]'), null)
    assert.equal(dashboardApi.discoverConnectorRuntimeTypes.mock.callCount(), 0)
  }
})

test("offline cached runtime types remain addable and configured runtimes remain visible", async (t) => {
  t.mock.method(dashboardApi, "getConnectorRuntimes", async () => ({ runtimes: [runtime()] }))
  t.mock.method(dashboardApi, "getConnectorRuntimeTypes", async () => ({ runtimeTypes: [{
    connectorId: "conn_a", runtimeType: "claude", displayName: "Claude Code", implementationType: "cli",
    available: true, present: true, instancePolicy: "single", maxInstances: 1,
    schema: { type: "object", properties: {} }, defaults: {}, capabilities: {}, metadata: {},
  }] }))
  const { container } = await render(t)
  assert.match(container.textContent, /Saved Codex/)
  assert.match(container.textContent, /Claude Code/)
  const add = [...container.querySelectorAll("button")].find((button) => button.textContent.trim() === "添加")
  assert.ok(add)
  assert.equal(add.disabled, false)
  assert.equal(dashboardApi.discoverConnectorRuntimeTypes.mock.callCount(), 0)
})

test("a failed refresh after disconnect retains saved runtimes and stays reentrant", async (t) => {
  let fail = false
  t.mock.method(dashboardApi, "getConnectorRuntimes", async () => {
    if (fail) throw new Error("network unavailable")
    return { runtimes: [runtime()] }
  })
  t.mock.method(dashboardApi, "getConnectorRuntimeTypes", async () => ({ runtimeTypes: [] }))
  const view = await render(t, { status: "online" })
  assert.match(view.container.textContent, /Saved Codex/)
  fail = true
  globalThis.deviceWorkspace = { ...globalThis.deviceWorkspace, connectors: [{ id: "conn_a", name: "Test Mac", status: "offline" }] }
  await view.rerender()
  assert.match(view.container.textContent, /Saved Codex/)
  assert.match(view.container.querySelector('[role="alert"]').textContent, /无法加载 Runtime/)
  fail = false
  const refresh = [...view.container.querySelectorAll("button")].find((button) => button.textContent.trim() === "刷新")
  assert.equal(refresh.disabled, false)
  await act(async () => refresh.click())
  assert.equal(view.container.querySelector('[role="alert"]'), null)
  assert.match(view.container.textContent, /Saved Codex/)
  assert.equal(dashboardApi.discoverConnectorRuntimeTypes.mock.callCount(), 0)
})

test("offline pending read never shows a spinner or claims inventory is empty", async (t) => {
  const pending = deferred()
  t.mock.method(dashboardApi, "getConnectorRuntimes", () => pending.promise)
  t.mock.method(dashboardApi, "getConnectorRuntimeTypes", async () => ({ runtimeTypes: [] }))
  const { container } = await render(t)
  assert.match(container.textContent, /正在读取已保存的 Runtime 信息/)
  assert.doesNotMatch(container.textContent, /还没有配置 Runtime/)
  assert.equal(container.querySelector('[data-slot="spinner"]'), null)
  await act(async () => pending.resolve({ runtimes: [] }))
  assert.match(container.textContent, /还没有配置 Runtime/)
})

test("read failure is visible and retry reads saved inventory without discovery", async (t) => {
  t.mock.method(dashboardApi, "getConnectorRuntimes", async () => { throw new Error("HTTP 403") })
  t.mock.method(dashboardApi, "getConnectorRuntimeTypes", async () => ({ runtimeTypes: [] }))
  const { container } = await render(t)
  assert.match(container.querySelector('[role="alert"]').textContent, /无法加载 Runtime/)
  assert.match(container.textContent, /暂时无法确认 Runtime 信息/)
  assert.doesNotMatch(container.textContent, /还没有配置 Runtime/)
  t.mock.method(dashboardApi, "getConnectorRuntimes", async () => ({ runtimes: [runtime()] }))
  const retry = [...container.querySelectorAll("button")].find((button) => button.textContent === "重试读取")
  await act(async () => retry.click())
  assert.equal(container.querySelector('[role="alert"]'), null)
  assert.match(container.textContent, /Saved Codex/)
  assert.equal(dashboardApi.discoverConnectorRuntimeTypes.mock.callCount(), 0)
})

test("reconnect reloads inventory once without refetching on each dashboard snapshot", async (t) => {
  t.mock.method(dashboardApi, "getConnectorRuntimes", async () => ({ runtimes: [] }))
  t.mock.method(dashboardApi, "getConnectorRuntimeTypes", async () => ({ runtimeTypes: [] }))
  const view = await render(t)
  assert.equal(dashboardApi.getConnectorRuntimes.mock.callCount(), 1)
  globalThis.deviceWorkspace = { ...globalThis.deviceWorkspace, connectors: [{ id: "conn_a", name: "Test Mac", status: "online" }] }
  await view.rerender()
  assert.equal(dashboardApi.getConnectorRuntimes.mock.callCount(), 2)
  globalThis.deviceWorkspace = { ...globalThis.deviceWorkspace, connectors: [...globalThis.deviceWorkspace.connectors] }
  await view.rerender()
  assert.equal(dashboardApi.getConnectorRuntimes.mock.callCount(), 2)
})

test("switching devices aborts old reads and ignores their late response", async (t) => {
  const old = deferred()
  const signals = []
  t.mock.method(dashboardApi, "getConnectorRuntimes", (_token, id, options) => {
    signals.push(options.signal)
    return id === "conn_a" ? old.promise : Promise.resolve({ runtimes: [] })
  })
  t.mock.method(dashboardApi, "getConnectorRuntimeTypes", async () => ({ runtimeTypes: [] }))
  const view = await render(t)
  globalThis.deviceWorkspace = { ...globalThis.deviceWorkspace, activeConnectorId: "conn_b", connectors: [{ id: "conn_b", name: "Other Mac", status: "offline" }] }
  await view.rerender()
  assert.equal(signals[0].aborted, true)
  await act(async () => old.resolve({ runtimes: [runtime()] }))
  assert.match(view.container.textContent, /Other Mac/)
  assert.doesNotMatch(view.container.textContent, /Saved Codex/)
})

test("late explicit discovery from the previous device cannot overwrite the current inventory", async (t) => {
  const discovery = deferred()
  t.mock.method(dashboardApi, "getConnectorRuntimes", async (_token, id) => ({ runtimes: id === "conn_b" ? [runtime("rti_b", "conn_b")] : [] }))
  t.mock.method(dashboardApi, "getConnectorRuntimeTypes", async () => ({ runtimeTypes: [] }))
  const view = await render(t, { status: "online" })
  t.mock.method(dashboardApi, "discoverConnectorRuntimeTypes", () => discovery.promise)
  const refresh = [...view.container.querySelectorAll("button")].find((button) => button.textContent.trim() === "刷新")
  await act(async () => refresh.click())
  assert.match(view.container.textContent, /正在发现/)
  globalThis.deviceWorkspace = { ...globalThis.deviceWorkspace, activeConnectorId: "conn_b", connectors: [{ id: "conn_b", name: "Other Mac", status: "offline" }] }
  await view.rerender()
  await act(async () => discovery.resolve({ runtimeTypes: [] }))
  assert.match(view.container.textContent, /Other Mac/)
  assert.match(view.container.textContent, /Saved Codex/)
  assert.doesNotMatch(view.container.textContent, /正在发现/)
})

test("a hanging inventory read times out and cancels both HTTP reads", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] })
  const signals = []
  for (const method of ["getConnectorRuntimes", "getConnectorRuntimeTypes"]) {
    t.mock.method(dashboardApi, method, (_token, _id, options) => { signals.push(options.signal); return new Promise(() => {}) })
  }
  const pending = loadConnectorRuntimeOverview("fixture-token", "conn_a", { timeoutMs: 100 })
  const rejected = assert.rejects(pending, /timed out/)
  t.mock.timers.tick(100)
  await rejected
  assert.equal(signals.length, 2)
  assert.ok(signals.every((signal) => signal.aborted))
})

test("runtime query methods pass cancellation to the HTTP client and retain existing routes", async () => {
  const calls = []
  const api = new DashboardApi({ get: async (path, options) => { calls.push({ path, options }); return {} } })
  const controller = new AbortController()
  await api.getConnectorRuntimes("fixture-token", "conn/a", { signal: controller.signal })
  await api.getConnectorRuntimeTypes("fixture-token", "conn/a", { signal: controller.signal })
  assert.deepEqual(calls.map((call) => call.path), ["/connectors/conn%2Fa/runtimes", "/connectors/conn%2Fa/runtime-types"])
  assert.ok(calls.every((call) => call.options.signal === controller.signal && call.options.token === "fixture-token"))
})
