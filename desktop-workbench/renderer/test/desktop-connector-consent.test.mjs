import assert from "node:assert/strict"
import test from "node:test"
import { registerHooks } from "node:module"
import { readFileSync } from "node:fs"
import { JSDOM } from "jsdom"
import { registerSource } from "./helpers/onboarding-source.mjs"

const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://fixture.example/", pretendToBeVisual: true })
for (const name of ["window", "document", "navigator", "HTMLElement", "HTMLInputElement", "HTMLButtonElement", "HTMLFormElement", "Element", "Node", "NodeFilter", "Event", "CustomEvent", "MutationObserver", "getComputedStyle", "requestAnimationFrame", "cancelAnimationFrame", "DocumentFragment"]) {
  Object.defineProperty(globalThis, name, { configurable: true, value: dom.window[name] })
}
globalThis.IS_REACT_ACT_ENVIRONMENT = true
const { createElement: h, act } = await import("react")
const { createRoot } = await import("react-dom/client")
const { NextIntlClientProvider } = await import("next-intl")
const source = registerSource()
const mocks = registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "@/components/auth/auth-context") return { shortCircuit: true, url: "data:text/javascript,export function useAuth(){return {session:globalThis.testNativeAccount}}" }
    if (specifier === "@/components/workspace-context") return { shortCircuit: true, url: "data:text/javascript,export function useWorkspace(){return {refreshData:globalThis.testRefreshData}}" }
    return nextResolve(specifier, context)
  },
})
const { DesktopConnectorProvider, useDesktopConnector } = await import("../src/features/desktop/desktop-connector-context.tsx")
const { dashboardApi } = await import("../src/features/dashboard/api.ts")
mocks.deregister(); source.deregister()
const messages = JSON.parse(readFileSync(new URL("../messages/en.json", import.meta.url), "utf8"))

test("fresh login, restored binding and access renewal read metadata without provisioning or reconnecting", async () => {
  const calls = []
  let local = null
  let latest
  globalThis.testNativeAccount = { userId: "synthetic-user", accessToken: "synthetic-access" }
  globalThis.testRefreshData = () => {}
  const state = { status: "stopped", hasCredential: true, authFailed: false }
  window.desktopWorkbench = {
    device: {
      getLocalBinding: async () => local,
      createAndConnect: async () => { calls.push("create"); return local },
      reconnectAndConnect: async () => { calls.push("reconnect"); return local },
    },
    connector: { getState: async () => state, onState: () => () => {} },
  }
  function Probe() { latest = useDesktopConnector(); return null }
  const host = document.createElement("div"); document.body.append(host)
  const root = createRoot(host)
  const render = () => root.render(h(NextIntlClientProvider, { locale: "en", messages, timeZone: "UTC" }, h(DesktopConnectorProvider, null, h(Probe))))
  try {
    await act(async () => render())
    assert.deepEqual(calls, [])
    local = { connectorId: "saved-device", serverUrl: "https://anywhere.example", ownerUserId: "synthetic-user" }
    await act(async () => latest.refresh())
    globalThis.testNativeAccount = { userId: "synthetic-user", accessToken: "synthetic-renewed" }
    await act(async () => render())
    assert.equal(latest.binding.connectorId, "saved-device")
    assert.deepEqual(calls, [])
  } finally {
    await act(async () => root.unmount()); host.remove(); delete window.desktopWorkbench
    delete globalThis.testNativeAccount; delete globalThis.testRefreshData
  }
})

async function connectionFixture(t, { saved = true, failFirst = false, pending = false } = {}) {
  const calls = []
  let local = saved ? { connectorId: "saved-device", serverUrl: "https://fixture.example", ownerUserId: "synthetic-user" } : null
  let latest
  let release
  const gate = pending ? new Promise(resolve => { release = resolve }) : Promise.resolve()
  globalThis.testNativeAccount = { userId: "synthetic-user", accessToken: "synthetic-access" }
  globalThis.testRefreshData = () => {}
  const connect = async (kind, input) => {
    calls.push({ kind, input })
    await gate
    local ??= { connectorId: "created-device", serverUrl: "https://fixture.example", ownerUserId: "synthetic-user" }
    if (failFirst && calls.length === 1) throw new Error("Synthetic startup failed after saving binding")
    return local
  }
  window.desktopWorkbench = {
    device: {
      getLocalBinding: async () => local,
      createAndConnect: input => connect("create", input),
      reconnectAndConnect: input => connect("reconnect", input),
    },
    connector: {
      getState: async () => ({ status: "stopped", running: false, hasCredential: Boolean(local), connectorId: local?.connectorId }),
      onState: () => () => {},
      start: async () => { calls.push({ kind: "raw-start" }); throw new Error("Consent required") },
    },
  }
  t.mock.method(dashboardApi, "getConnector", async () => ({ connector: { id: local.connectorId, status: "online" } }))
  function Probe() { latest = useDesktopConnector(); return null }
  const host = document.createElement("div"); document.body.append(host)
  const root = createRoot(host)
  t.after(async () => {
    await act(async () => root.unmount()); host.remove(); delete window.desktopWorkbench
    delete globalThis.testNativeAccount; delete globalThis.testRefreshData
  })
  await act(async () => root.render(h(NextIntlClientProvider, { locale: "en", messages, timeZone: "UTC" }, h(DesktopConnectorProvider, null, h(Probe)))))
  return { calls, get latest() { return latest }, release }
}

for (const action of ["start", "restart", "reconnect", "retryProvision"]) {
  for (const saved of [true, false]) {
    test(`${action}: explicit click ${saved ? "reconnects saved device" : "creates unbound device"} without raw start`, async t => {
      const f = await connectionFixture(t, { saved })
      assert.deepEqual(f.calls, [])
      await act(async () => { await f.latest[action]() })
      assert.deepEqual(f.calls.map(c => c.kind), [saved ? "reconnect" : "create"])
      assert.equal(f.latest.binding.connectorId, saved ? "saved-device" : "created-device")
      assert.equal(f.latest.connectionStatus, "online")
      if (saved) assert.equal(f.calls[0].input.connectorId, "saved-device")
      assert.equal(f.latest.busy, false)
    })
  }
}

for (const saved of [true, false]) {
  test(`rapid connect and retry clicks send one ${saved ? "reconnect" : "create"} request`, async t => {
    const f = await connectionFixture(t, { saved, pending: true })
    await act(async () => {
      const first = f.latest.start()
      const second = f.latest.reconnect()
      const third = f.latest.restart()
      const fourth = f.latest.retryProvision()
      assert.equal(first, second)
      assert.equal(first, third)
      assert.equal(first, fourth)
      await new Promise(resolve => setImmediate(resolve))
      assert.deepEqual(f.calls.map(c => c.kind), [saved ? "reconnect" : "create"])
      f.release()
      await Promise.all([first, second, third, fourth])
    })
    assert.equal(f.latest.busy, false)
    assert.equal(f.latest.connectionStatus, "online")
  })
}

test("retry after partial creation re-reads saved binding and reconnects without duplicate creation", async t => {
  const f = await connectionFixture(t, { saved: false, failFirst: true })
  await act(async () => { await f.latest.start() })
  assert.equal(f.latest.busy, false)
  await act(async () => { await f.latest.retryProvision() })
  assert.deepEqual(f.calls.map(c => c.kind), ["create", "reconnect"])
  assert.equal(f.calls[1].input.connectorId, "created-device")
  assert.equal(f.latest.connectionStatus, "online")
})
