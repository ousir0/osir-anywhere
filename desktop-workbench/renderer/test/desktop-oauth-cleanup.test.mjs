import assert from "node:assert/strict"
import test from "node:test"
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
const hooks = registerSource()
const { AuthProvider } = await import("../src/components/auth/auth-context.tsx")
const { authApi } = await import("../src/features/auth/api.ts")
hooks.deregister()
const messages = JSON.parse(readFileSync(new URL("../messages/en.json", import.meta.url), "utf8"))

test("owning AuthContext cancels Main OAuth on unmount; preview windows never cancel its attempt", async t => {
  t.mock.method(authApi, "config", async () => ({ needsBootstrap: false, registrationOpen: true }))
  for (const preview of [false, true]) {
    window.localStorage.clear()
    window.history.replaceState({}, "", preview ? "/#/preview?path=x" : "/#/login")
    let cancellations = 0
    window.desktopWorkbench = { auth: {
      getServer: async () => ({ serverUrl: "https://anywhere.example", apiNamespace: "/api/v2", oauthWebOrigin: "https://anywhere.example" }),
      consumeOAuthResult: async () => null,
      onOAuthResult: () => () => {},
      cancelOAuth: async () => { cancellations += 1 },
    } }
    const host = document.createElement("div")
    document.body.append(host)
    const root = createRoot(host)
    try {
      await act(async () => root.render(h(NextIntlClientProvider, { locale: "en", messages, timeZone: "UTC" }, h(AuthProvider))))
      assert.equal(cancellations, 0)
    } finally {
      await act(async () => root.unmount())
      host.remove()
      delete window.desktopWorkbench
    }
    assert.equal(cancellations, preview ? 0 : 1)
  }
})
