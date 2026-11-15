import assert from "node:assert/strict";
import test from "node:test";
import { bootstrapClientHandoff } from "./osir-handoff-bootstrap";
import type { DesktopSessionPayload } from "./desktop-session";

const origin = "https://anywhere.osirclaw.com";
const session: DesktopSessionPayload = { accessToken: "synthetic-access", tokenType: "Bearer", expiresIn: 300,
  refreshToken: "a".repeat(43), refreshExpiresIn: 600,
  identity: { issuer: "https://osirclaw.com", subject: "123", userId: "synthetic-user" } };
const binding = { connectorId: "conn_synthetic", serverUrl: origin, ownerUserId: session.identity.userId,
  name: "Synthetic Mac", manualDisconnected: false, hasCredential: true };
const runtime = { connectorId: binding.connectorId, runtimeId: "rti_synthetic", runtimeType: "codex",
  present: true, available: true, configured: true, active: false, status: "stopped" };

test("fresh handoff creates one local device and only the Client-selected runtime with empty cloud config", async () => {
  const local: { route: string; body: unknown }[] = [];
  const remote: { route: string; method: string; body: unknown }[] = [];
  let created = false;
  const results = await bootstrapClientHandoff({ session, configuredToolTypes: ["codex"], signal: new AbortController().signal,
    backend: { request: async <T>(route: string, init?: RequestInit) => {
      local.push({ route, body: init?.body ? JSON.parse(String(init.body)) : null });
      return (route === "/device/binding" ? null : binding) as T;
    } },
    fetcher: async (input, init) => {
      const route = new URL(String(input)).pathname;
      remote.push({ route, method: init?.method ?? "GET", body: init?.body ? JSON.parse(String(init.body)) : null });
      let data: unknown;
      if (route.endsWith("/runtime-types")) data = { connectorId: binding.connectorId,
        runtimeTypes: [{ connectorId: binding.connectorId, runtimeType: "codex", present: true, available: true, schema: {} }] };
      else if (route.endsWith("/active")) data = { ...runtime, active: true, status: "running" };
      else if (init?.method === "POST") { created = true; data = runtime; }
      else data = { connectorId: binding.connectorId, runtimes: created ? [runtime] : [] };
      return new Response(JSON.stringify(data), { status: init?.method === "POST" ? 201 : 200 });
    },
  });
  assert.deepEqual(results, [{ tool: "codex", runtimeId: runtime.runtimeId, status: "ready", code: "runtime_ready" }]);
  assert.deepEqual(local.map(row => row.route), ["/device/binding", "/device/create"]);
  const writes = remote.filter(row => row.method !== "GET");
  assert.equal(writes.length, 2);
  assert.deepEqual(writes[0].body, { runtimeType: "codex", name: "Codex", config: {}, active: false });
  assert.deepEqual(writes[1].body, { active: true });
  assert.ok(!JSON.stringify(remote).includes("synthetic-access"));
});

test("existing device owned by another account is rejected before any mutation or model discovery", async () => {
  let calls = 0;
  await assert.rejects(bootstrapClientHandoff({ session, configuredToolTypes: ["claude"], signal: new AbortController().signal,
    backend: { request: async <T>() => { calls++; return { ...binding, ownerUserId: "another-user" } as T; } },
    fetcher: async () => { throw new Error("must not fetch"); },
  }), /其他账号/);
  assert.equal(calls, 1);
});

test("explicit Client open reconnects the same disconnected device without creating another device", async () => {
  const routes: string[] = [];
  const result = await bootstrapClientHandoff({ session, configuredToolTypes: [], signal: new AbortController().signal,
    backend: { request: async <T>(route: string) => {
      routes.push(route); return (route === "/device/binding" ? { ...binding, manualDisconnected: true } :
        route === "/state" ? { connectorId: binding.connectorId, serverUrl: origin, authFailed: false } : binding) as T;
    } }, fetcher: async () => { throw new Error("no configured tools"); },
  });
  assert.deepEqual(routes, ["/device/binding", "/state", "/device/reconnect"]);
  assert.deepEqual(result, []);
});

test("expired device credentials are renewed on the same device after explicit Client handoff", async () => {
  const routes: string[] = [];
  await bootstrapClientHandoff({ session, configuredToolTypes: [], signal: new AbortController().signal,
    backend: { request: async <T>(route: string) => {
      routes.push(route); return (route === "/state"
        ? { connectorId: binding.connectorId, serverUrl: origin, authFailed: true } : binding) as T;
    } }, fetcher: async () => { throw new Error("no configured tools"); },
  });
  assert.deepEqual(routes, ["/device/binding", "/state", "/device/reconnect"]);
});

test("device replacement while reading state prevents provisioning", async () => {
  const routes: string[] = [];
  await assert.rejects(bootstrapClientHandoff({ session, configuredToolTypes: [], signal: new AbortController().signal,
    backend: { request: async <T>(route: string) => {
      routes.push(route); return (route === "/device/binding" ? binding :
        { connectorId: "different-device", serverUrl: origin, authFailed: false }) as T;
    } }, fetcher: async () => { throw new Error("must not fetch"); },
  }), /信息已改变/);
  assert.deepEqual(routes, ["/device/binding", "/state"]);
});

test("cancelled handoff performs no connection or model requests", async () => {
  const abort = new AbortController(); abort.abort();
  await assert.rejects(bootstrapClientHandoff({ session, configuredToolTypes: ["dsh"], signal: abort.signal,
    backend: { request: async () => { throw new Error("must not connect"); } },
    fetcher: async () => { throw new Error("must not fetch"); },
  }), /已取消/);
});

for (const savedActive of [false, true]) {
  test(`first-install unavailable Codex is rediscovered before ${savedActive ? "reusing a saved active instance" : "creating one runtime"}`, async () => {
    const routes: string[] = [];
    let discovered = false;
    let created = savedActive;
    const results = await bootstrapClientHandoff({ session, configuredToolTypes: ["codex"], signal: new AbortController().signal,
      backend: { request: async <T>(route: string) => (route === "/device/binding" ? null : binding) as T },
      fetcher: async (input, init) => {
        const route = new URL(String(input)).pathname;
        routes.push(`${init?.method ?? "GET"} ${route.split(binding.connectorId)[1]}`);
        let data: unknown;
        if (route.endsWith("/runtime-types/discover")) {
          assert.equal(init?.method, "POST");
          assert.equal(init?.body, undefined);
          discovered = true;
        }
        if (route.includes("/runtime-types")) data = { connectorId: binding.connectorId,
          runtimeTypes: [{ connectorId: binding.connectorId, runtimeType: "codex", present: true, available: discovered, schema: {} }] };
        else if (route.endsWith("/active")) data = { ...runtime, active: true, status: "running" };
        else if (init?.method === "POST") {
          assert.ok(discovered, "must not create while binding is unavailable");
          assert.ok(!created, "must not duplicate a saved runtime");
          created = true; data = runtime;
        } else data = { connectorId: binding.connectorId, runtimes: created
          ? [{ ...runtime, active: savedActive, status: savedActive ? "running" : "stopped" }] : [] };
        return new Response(JSON.stringify(data));
      },
    });
    assert.deepEqual(results, [{ tool: "codex", runtimeId: runtime.runtimeId, status: "ready", code: "runtime_ready" }]);
    assert.equal(routes.filter(route => route === "POST /runtime-types/discover").length, 1);
    assert.equal(routes.filter(route => route === "POST /runtimes").length, savedActive ? 0 : 1);
    assert.equal(routes.filter(route => route.endsWith("/active")).length, savedActive ? 0 : 1);
  });
}

test("binding wait is cancelled without runtime creation or rediscovery", async () => {
  const abort = new AbortController();
  let writes = 0;
  const pending = bootstrapClientHandoff({ session, configuredToolTypes: ["codex"], signal: abort.signal,
    backend: { request: async <T>(route: string) => (route === "/device/binding" ? null : binding) as T },
    fetcher: async (_input, init) => {
      if (init?.method !== "GET") writes++;
      queueMicrotask(() => abort.abort());
      return new Response(JSON.stringify({ connectorId: binding.connectorId,
        runtimeTypes: [{ connectorId: binding.connectorId, runtimeType: "codex", present: true, available: false, schema: {} }] }));
    },
  });
  await assert.rejects(pending);
  assert.equal(writes, 0);
});

test("binding wait ends at the deadline with fixed unavailable result and no runtime writes", async t => {
  t.mock.timers.enable({ apis: ["Date"] });
  let writes = 0;
  const results = await bootstrapClientHandoff({ session, configuredToolTypes: ["codex"], signal: new AbortController().signal,
    backend: { request: async <T>(route: string) => (route === "/device/binding" ? null : binding) as T },
    fetcher: async (input, init) => {
      const route = new URL(String(input)).pathname;
      if (init?.method !== "GET") writes++;
      t.mock.timers.setTime(Date.now() + 46_000);
      return new Response(JSON.stringify(route.endsWith("/runtimes") ? { connectorId: binding.connectorId, runtimes: [] }
        : { connectorId: binding.connectorId, runtimeTypes: [{ connectorId: binding.connectorId,
          runtimeType: "codex", present: true, available: false, schema: {} }] }));
    },
  });
  assert.deepEqual(results, [{ tool: "codex", status: "blocked", code: "runtime_type_unavailable" }]);
  assert.equal(writes, 0);
});
