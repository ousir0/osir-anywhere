import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import vm from "node:vm"
import test from "node:test"
import ts from "typescript"
import { SessionRecoveryGuard } from "../src/components/session/session-recovery-guard.ts"
import { createSessionEventBuffer } from "../src/components/session/session-event-buffer.ts"
import * as eventState from "../src/components/session/session-event-state.ts"

// Execute the actual component's recovery effect with fake transports. No React,
// browser, login, server, or copied recovery implementation participates.
const source = readFileSync(new URL("../src/components/session-detail.tsx", import.meta.url), "utf8")
const tree = ts.createSourceFile("session-detail.tsx", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
let effect
function visit(node) {
  if (ts.isCallExpression(node) && node.expression.getText(tree) === "React.useEffect"
      && node.arguments[0]?.getText(tree).includes("new SessionRecoveryGuard()")) effect = node.arguments[0]
  ts.forEachChild(node, visit)
}
visit(tree)
assert.ok(effect)
const script = ts.transpileModule(`globalThis.cleanup = (${effect.getText(tree)})()`, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText
const flush = async () => { for (let i = 0; i < 40; i++) await Promise.resolve() }
function snapshot(seq = 10, items = [{ id: "initial" }]) {
  return { session: { id: "synthetic" }, nextSeq: seq, eventCursor: `seq:${seq}`, items, timelineResetVersion: 0 }
}
function wire(seq, id = `item-${seq}`, type = "timeline.item_created") {
  return { sessionId: "synthetic", eventId: `${type}-${id}`, type, sequence: seq, payload: { item: { id } } }
}
function deferred() {
  let resolve, reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
async function harness(t, snapshots = []) {
  t.mock.timers.enable({ apis: ["setTimeout"] })
  const sockets = [], signals = [], errors = []
  let state = null, snapshotReads = 0
  const cursor = new eventState.SessionEventSequenceCursor("synthetic")
  const connected = { current: false }
  class Socket {
    constructor() { sockets.push(this) }
    close(code = 1000) {
      assert.ok(code === 1000 || (code >= 3000 && code <= 4999), "browser close code must be valid")
      if (!this.closed) { this.closed = true; queueMicrotask(() => this.onclose?.()) }
    }
    event(event) { this.onmessage?.({ data: JSON.stringify(event) }) }
    subscribed() { this.event(wire(1000, "sub", "session.subscribed")) }
    disconnect() { this.closed = true; this.onclose?.() }
  }
  const context = {
    ...eventState, SessionRecoveryGuard, createSessionEventBuffer,
    isLocalOptimisticSession: false, sessionId: "synthetic", token: "synthetic-only",
    WebSocket: Socket, window: globalThis, console,
    createClientId: () => "synthetic-client", parseProtocolEvent: JSON.parse,
    createRecoveredSubscriptionTracker: () => ({ observed() {}, recovered() {} }),
    eventSequenceCursor: cursor, streamConnectedRef: connected,
    applyOptimisticItemsRef: { current: value => value },
    clearResolvedOptimisticMessagesRef: { current() {} }, onSessionUpdatedRef: { current() {} },
    tSessionRef: { current: () => "failed" },
    setState: change => { state = typeof change === "function" ? change(state) : change },
    setError: error => errors.push(error), setLoading() {}, setCatalogRecoveryGeneration() {},
    cursorSequence: value => Number(value.split(":")[1]),
    nextTimelineResetVersion: current => current + 1,
    mergeSessionSnapshot: (_current, incoming) => incoming,
    sessionEventCanUpdateState: () => true,
    readPayloadValue: value => value,
    mergeRuntimeState: (current, incoming) => incoming ?? current,
    mergeSessionEvent: (current, event) => ({ ...current, nextSeq: event.sequence, items: [...current.items, event.payload.item] }),
    dashboardApi: {
      createWsTicket: async () => ({ ticket: "synthetic-ticket" }),
      sessionWebSocketUrl: () => "wss://synthetic.invalid/no-network",
      getSessionEvents: async () => ({ events: [], nextCursor: `seq:${cursor.current("synthetic")}`, snapshotRequired: false }),
      getSessionRuntimeState: async () => null, getSessionRuntimeCapabilities: async () => null,
    },
    loadInitialSessionState: async (_token, _session, { signal }) => {
      signals.push(signal)
      const next = snapshots[snapshotReads++]
      return typeof next === "function" ? next(signal) : next ?? snapshot()
    },
  }
  vm.runInNewContext(script, context)
  t.after(() => context.cleanup())
  await flush()
  sockets[0].subscribed()
  await flush()
  return { sockets, signals, errors, cursor, connected, context,
    state: () => state, reads: () => snapshotReads,
    async reconnect() { t.mock.timers.tick(1200); await flush(); sockets.at(-1).subscribed(); await flush() },
  }
}

test("300 distinct items and terminal state recover through an authoritative snapshot, then live resumes", async t => {
  const all = Array.from({ length: 300 }, (_, i) => ({ id: `item-${i}` }))
  const h = await harness(t, [snapshot(), { ...snapshot(310, all), state: { status: "idle" } }])
  h.sockets[0].disconnect()
  assert.equal(h.connected.current, false)
  assert.equal(h.reads(), 1)
  await h.reconnect()
  assert.equal(h.reads(), 2)
  assert.deepEqual(h.state().items, all)
  assert.equal(h.state().state.status, "idle")
  h.sockets.at(-1).event(wire(311))
  t.mock.timers.tick(34)
  assert.equal(h.cursor.current("synthetic"), 311)
  assert.equal(h.state().items.at(-1).id, "item-311")
})

test("failed snapshot remains invalid; high tail is not consumed before a successful retry", async t => {
  const failure = deferred()
  const h = await harness(t, [snapshot(), () => failure.promise, snapshot(10, [{ id: "missed-at-same-sequence" }])])
  h.sockets[0].event(wire(0, "overflow", "session.refetch_required"))
  await flush()
  await h.reconnect()
  h.sockets.at(-1).event(wire(9000))
  failure.reject(new Error("synthetic snapshot failure"))
  await flush()
  assert.equal(h.cursor.current("synthetic"), 10)
  assert.equal(h.connected.current, false)
  assert.equal(h.sockets.at(-1).closed, true)
  await h.reconnect()
  assert.equal(h.cursor.current("synthetic"), 10)
  assert.equal(h.state().items[0].id, "missed-at-same-sequence")
  assert.equal(h.connected.current, true)
})

test("deadline aborts a non-settling snapshot and a late response cannot replace newer state", async t => {
  const stuck = deferred()
  const h = await harness(t, [snapshot(), () => stuck.promise, snapshot(4)])
  h.sockets[0].disconnect()
  await h.reconnect()
  t.mock.timers.tick(15_000)
  await flush()
  assert.equal(h.signals[1].aborted, true)
  assert.equal(h.cursor.current("synthetic"), 10)
  assert.equal(h.connected.current, false)
  await h.reconnect()
  assert.equal(h.cursor.current("synthetic"), 4)
  stuck.resolve(snapshot(9999))
  await flush()
  assert.equal(h.cursor.current("synthetic"), 4)
})

for (const budget of ["count", "bytes"]) {
  test(`recovery ${budget} budget closes and keeps the old cursor`, async t => {
    const pending = deferred()
    const h = await harness(t, [snapshot(), () => pending.promise, snapshot(20)])
    h.sockets[0].disconnect()
    await h.reconnect()
    const socket = h.sockets.at(-1)
    if (budget === "count") {
      for (let i = 0; i < 257; i++) socket.event(wire(100 + i))
    } else {
      socket.event(wire(100, "中".repeat(1_500_000)))
    }
    await flush()
    assert.equal(socket.closed, true)
    assert.equal(h.signals[1].aborted, true)
    assert.equal(h.cursor.current("synthetic"), 10)
    pending.resolve(snapshot(9999))
    await flush()
    await h.reconnect()
    assert.equal(h.cursor.current("synthetic"), 20)
  })
}

test("live state reads share the recovery deadline and cannot hold the buffer indefinitely", async t => {
  const h = await harness(t)
  h.context.dashboardApi.getSessionRuntimeState = () => new Promise(() => {})
  h.sockets[0].subscribed()
  await flush()
  h.sockets[0].event(wire(99))
  t.mock.timers.tick(15_000)
  await flush()
  assert.equal(h.sockets[0].closed, true)
  assert.equal(h.cursor.current("synthetic"), 10)
  assert.equal(h.connected.current, false)
})

test("unmount aborts pending recovery and late data cannot change the previous session", async t => {
  const stuck = deferred()
  const h = await harness(t, [snapshot(), () => stuck.promise])
  h.sockets[0].disconnect()
  await h.reconnect()
  h.context.cleanup()
  stuck.resolve(snapshot(10000))
  await flush()
  assert.equal(h.signals[1].aborted, true)
  assert.equal(h.cursor.current("synthetic"), 10)
})
