import assert from "node:assert/strict"
import test from "node:test"
import { registerHooks } from "node:module"
import { readFileSync } from "node:fs"
import { JSDOM } from "jsdom"
import { registerSource } from "./helpers/onboarding-source.mjs"

const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://fixture.example/", pretendToBeVisual: true })
for (const name of ["window", "document", "navigator", "HTMLElement", "Element", "Node", "Event", "MutationObserver"]) {
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
