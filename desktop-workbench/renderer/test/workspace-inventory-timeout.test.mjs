import assert from 'node:assert/strict'
import test from 'node:test'
import { registerSource } from './helpers/onboarding-source.mjs'

const hooks = registerSource()
const { loadWorkspaceInventory, readWorkspaceInventory } = await import('../src/features/dashboard/workspace-inventory.ts')
hooks.deregister()

test('inventory GETs receive cancellation signals and timeout covers a stalled response body', async t => {
  const requests = []
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    requests.push({ url, signal: options.signal })
    if (String(url).endsWith('/sessions/list')) {
      return { status: 200, ok: true, headers: new Headers(), text: () => new Promise(() => {}) }
    }
    return Response.json(String(url).endsWith('/projects') ? { projects: [] } : { connectors: [] })
  })
  await assert.rejects(loadWorkspaceInventory('synthetic-access', { timeoutMs: 20 }), /timed out/)
  assert.deepEqual(requests.map(request => request.url).sort(), ['/api/v2/connectors', '/api/v2/projects', '/api/v2/sessions/list'])
  assert.equal(requests.length, 3)
  assert.ok(requests.every(request => request.signal.aborted))
})

test('explicit cancellation settles even when the read ignores abort', async () => {
  const controller = new AbortController()
  let signal
  const pending = readWorkspaceInventory(value => { signal = value; return new Promise(() => {}) }, { signal: controller.signal })
  controller.abort(new Error('synthetic cancellation'))
  await assert.rejects(pending, /synthetic cancellation/)
  assert.equal(signal.aborted, true)
})

test('already cancelled reads never enter the transport', async () => {
  const controller = new AbortController()
  controller.abort(new Error('already cancelled'))
  let calls = 0
  await assert.rejects(readWorkspaceInventory(async () => { calls++; return [] }, { signal: controller.signal }), /already cancelled/)
  assert.equal(calls, 0)
})

test('one failed inventory GET cancels its pending siblings', async t => {
  const signals = []
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    signals.push(options.signal)
    if (String(url).endsWith('/projects')) return Response.json({ detail: 'synthetic unavailable' }, { status: 503 })
    return new Promise(() => {})
  })
  await assert.rejects(loadWorkspaceInventory('synthetic-access'), error => error.status === 503)
  assert.equal(signals.length, 3)
  assert.ok(signals.every(signal => signal.aborted))
})
