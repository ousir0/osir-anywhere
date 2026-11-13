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
const source = registerSource()
const { AuthProvider, useAuth } = await import("../src/components/auth/auth-context.tsx")
const { authApi } = await import("../src/features/auth/api.ts")
const { clearStoredSession, loadStoredSession } = await import("../src/features/auth/session.ts")
source.deregister()
const messages = JSON.parse(readFileSync(new URL("../messages/en.json", import.meta.url), "utf8"))
const server = { serverUrl: "https://anywhere.example", apiNamespace: "/api/v2", oauthWebOrigin: "https://anywhere.example" }

async function render(t, overrides = {}) {
  window.history.replaceState({}, "", "/#/")
  clearStoredSession()
  window.localStorage.setItem("aa.session.v1", JSON.stringify({ accessToken: "synthetic-stale", userId: "old", role: "member" }))
  const timers = []
  t.mock.method(window, "setTimeout", (callback, milliseconds) => { timers.push({ callback, milliseconds }); return timers.length })
  t.mock.method(window, "clearTimeout", () => {})
  window.desktopWorkbench = { auth: {
    getServer: async () => server,
    refreshSession: async () => ({ accessToken: "synthetic-restored", expiresIn: 300, server }),
    logout: async () => ({ pending: false, connectorStopped: true }),
    consumeOAuthResult: async () => null,
    onOAuthResult: () => () => {},
    cancelOAuth: async () => {},
    ...overrides,
  } }
  t.mock.method(authApi, "me", async () => ({ userId: "synthetic-user", role: "member", displayName: "Synthetic" }))
  let latest
  function Probe() { latest = useAuth(); return null }
  const host = document.createElement("div"); document.body.append(host)
  const root = createRoot(host)
  await act(async () => root.render(h(NextIntlClientProvider, { locale: "en", messages, timeZone: "UTC" }, h(AuthProvider, null, h(Probe)))))
  t.after(async () => { await act(async () => root.unmount()); host.remove(); clearStoredSession(); delete window.desktopWorkbench })
  return { current: () => latest, timers }
}

test("Main restores native login and renderer keeps only memory access, never localStorage credentials", async t => {
  const f = await render(t)
  assert.equal(f.current().isAuthenticated, true)
  assert.equal(f.current().session.accessToken, "synthetic-restored")
  assert.equal(window.localStorage.getItem("aa.session.v1"), null)
  assert.equal(loadStoredSession().accessToken, "synthetic-restored")
  assert.ok(f.timers.some(timer => timer.milliseconds === 240000))
})

test("logout during access renewal cannot restore authentication and pending revocation is visible", async t => {
  let calls = 0
  let release
  const blocked = new Promise(resolve => { release = resolve })
  const f = await render(t, {
    refreshSession: async () => ++calls === 1 ? { accessToken: "synthetic-restored", expiresIn: 300, server } : blocked,
    logout: async () => ({ pending: true, connectorStopped: true }),
  })
  await act(async () => { f.timers.find(timer => timer.milliseconds === 240000).callback() })
  await act(async () => f.current().signOut())
  await act(async () => release({ accessToken: "synthetic-late-access", expiresIn: 300, server }))
  assert.equal(f.current().session, null)
  assert.equal(loadStoredSession(), null)
  assert.match(f.current().error, /revocation is pending/)
})

test("refresh transport errors are redacted and do not revive stale localStorage sessions", async t => {
  const f = await render(t, { refreshSession: async () => { throw new Error("synthetic-refresh-secret-in-server-body") } })
  assert.equal(f.current().session, null)
  assert.equal(f.current().screen, "login")
  assert.equal(f.current().error.includes("synthetic"), false)
  assert.equal(window.localStorage.getItem("aa.session.v1"), null)
})
