import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import { execFileSync, spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { OsirClientHandoffTransport, HandoffTransportError, HANDOFF_DISCOVERY_RELATIVE,
  encodeHandoffFrame, parseHandoffJson, inspectHandoffPeer } from "./osir-client-handoff-transport";
import type { HandoffTransportOptions, HandoffPeerIdentity, HandoffTokenRequest } from "./osir-client-handoff-transport";

const mac = process.platform === "darwin";
// Test runtime only. Production Main MUST supply its pinned bundled Python.
const python = mac ? execFileSync("/usr/bin/which", ["python3"], { encoding: "utf8" }).trim() : "";
// Supports both narrow temporary compilation and regular dist/electron tests.
const helper = path.resolve(process.cwd(), "electron/osir-client-handoff-peer.py");
const flowId = Buffer.alloc(32, 7).toString("base64url");
const code = Buffer.alloc(32, 8).toString("base64url");
const base = { skip: !mac };
const safeError = (reason: string) => (error: unknown) => error instanceof HandoffTransportError && error.message === reason;
type Handshake = { flowId: string; state: string; receiverInstanceId: string; codeChallenge: string; [key: string]: unknown };

async function fixture(respond?: (handshake: Handshake, socket: net.Socket) => void) {
  const home = fs.mkdtempSync("/private/tmp/oh-home-");
  const root = path.join(home, HANDOFF_DISCOVERY_RELATIVE);
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const temp = fs.mkdtempSync("/private/tmp/oh-socket-");
  const socketPath = path.join(temp, "s");
  const sockets = new Set<net.Socket>();
  const holders = new Set<ChildProcess>();
  let handshake: Handshake | undefined;
  const server = net.createServer({ allowHalfOpen: true }, socket => {
    sockets.add(socket); socket.on("error", () => {}); socket.on("close", () => sockets.delete(socket));
    // Emulate Rust's retained server FD after SHUT_WR. Node would otherwise
    // auto-close both directions before the receiver's second kernel lookup.
    const holder = spawn(python, ["-I", "-S", "-B", "-c", "import sys,socket; s=socket.socket(fileno=3); sys.stdin.buffer.readline(); s.shutdown(socket.SHUT_WR); sys.stdin.buffer.read()"],
      { stdio: ["pipe", "ignore", "ignore", socket] });
    holder.on("error", () => {}); holder.stdin!.on("error", () => {}); holders.add(holder);
    socket.once("finish", () => holder.stdin!.write("shutdown\n"));
    let bytes = Buffer.alloc(0);
    socket.on("data", chunk => { bytes = Buffer.concat([bytes, chunk]); });
    socket.on("end", () => {
      if (bytes.length < 4) return;
      assert.equal(bytes.readUInt32BE(0), bytes.length - 4);
      handshake = parseHandoffJson(bytes.subarray(4)) as Handshake;
      if (respond) respond(handshake, socket);
      else socket.end(encodeHandoffFrame({ flowId, state: handshake.state, code, expiresIn: 60, configuredToolTypes: ["claude", "codex"] }));
    });
    // spawn's inherited Stream pauses the accepted socket; restore fixture IO.
    socket.resume();
  });
  await new Promise<void>(resolve => server.listen(socketPath, resolve)); fs.chmodSync(socketPath, 0o600);
  const manifest = path.join(root, `${flowId}.json`);
  fs.writeFileSync(manifest, JSON.stringify({ version: 1, flowId, socketPath, clientPid: process.pid }), { mode: 0o600 });
  const seen: HandoffPeerIdentity[] = [];
  const options: HandoffTransportOptions = { home, pythonExecutable: python, helperPath: helper,
    verifyPeer: async peer => {
      // Synthetic identity policy only, deliberately local to tests.
      assert.equal(peer.pid, process.pid); assert.equal(peer.uid, process.geteuid!());
      assert.ok(path.isAbsolute(peer.executablePath)); assert.ok(peer.parentPid > 0);
      assert.ok(path.isAbsolute(peer.parentExecutablePath)); seen.push(peer);
    } };
  return { home, root, temp, socketPath, manifest, options, seen,
    get handshake() { return handshake; },
    async close() {
      for (const socket of sockets) socket.destroy();
      for (const holder of holders) { holder.stdin!.destroy(); holder.kill(); }
      await Promise.all([...holders].map(holder => new Promise<void>(resolve => {
        if (holder.exitCode !== null || holder.signalCode !== null) resolve(); else holder.once("exit", () => resolve());
      })));
      await new Promise<void>(resolve => server.close(() => resolve()));
      fs.rmSync(home, { recursive: true, force: true }); fs.rmSync(temp, { recursive: true, force: true });
    } };
}

test("strict parser rejects duplicates including escaped keys, bad integers, trailing JSON and UTF8", () => {
  for (const text of ['{"state":"a","state":"b"}', '{"state":"a","\\u0073tate":"b"}',
    '{"expiresIn":1.0}', '{"expiresIn":1e1}', '{"expiresIn":01}', '{"expiresIn":-0}',
    '{"v":9007199254740993}', '{}{}', '{"a":}', '{"a":1,}', '[1,]', '{"__proto__":{}}']) {
    assert.throws(() => parseHandoffJson(Buffer.from(text)), safeError("invalid_handoff"));
  }
  assert.throws(() => parseHandoffJson(Buffer.from([0xff])), safeError("invalid_handoff"));
  assert.throws(() => parseHandoffJson(Buffer.alloc(4097, 32)), safeError("invalid_handoff"));
  assert.equal((parseHandoffJson(Buffer.from('{"n":60,"a":["identity"]}')) as { n: number }).n, 60);
  assert.throws(() => encodeHandoffFrame({ value: "x".repeat(4096) }), safeError("invalid_handoff"));
});

test("verifier is mandatory and cannot default to accept", () => {
  assert.throws(() => new OsirClientHandoffTransport({} as HandoffTransportOptions), safeError("peer_untrusted"));
});

test("Main generates private PKCE, only challenge crosses socket, peer is Main not Python", base, async () => {
  const f = await fixture(); let requestCopy: HandoffTokenRequest | undefined; let held: HandoffTokenRequest | undefined;
  try {
    const transport = new OsirClientHandoffTransport(f.options);
    const result = await transport.run(flowId, async (request, context, signal) => {
      requestCopy = { ...request }; held = request;
      assert.equal(context.flowId, flowId); assert.equal(signal.aborted, false);
      assert.equal(context.state, request.state); assert.equal(context.receiverInstanceId, request.receiver_instance_id);
      assert.deepEqual(context.configuredToolTypes, ["claude", "codex"]);
      assert.equal(Object.isFrozen(context.configuredToolTypes), true);
      assert.equal(request.code, code); assert.equal(request.target_origin, "https://anywhere.osirclaw.com");
      assert.equal(request.code_verifier.length, 64); assert.equal(request.state.length, 43);
      assert.equal(f.handshake!.codeChallenge, createHash("sha256").update(request.code_verifier, "ascii").digest("base64url"));
      return "consumed-once";
    });
    assert.equal(result, "consumed-once"); assert.equal(f.seen.length, 2);
    assert.equal(Object.keys(f.handshake!).length, 9);
    assert.deepEqual(f.handshake!.actions, ["identity", "connect-local", "bootstrap-configured-tools"]);
    assert.equal(Object.hasOwn(f.handshake!, "codeVerifier"), false);
    assert.equal(Object.hasOwn(f.handshake!, "code"), false);
    assert.equal(JSON.stringify(f.handshake).includes(requestCopy!.code_verifier), false);
    assert.equal(held!.code, ""); assert.equal(held!.code_verifier, "");
    await assert.rejects(transport.run(flowId, async () => assert.fail("replay")), safeError("flow_pending"));
  } finally { await f.close(); }
});

test("peer trust rejection before handshake and after delivery never consumes", base, async () => {
  for (const failAt of [1, 2]) {
    const f = await fixture(); let calls = 0;
    try {
      const transport = new OsirClientHandoffTransport({ ...f.options, verifyPeer: async () => {
        calls++; if (calls === failAt) throw new HandoffTransportError("peer_untrusted");
      } });
      await assert.rejects(transport.run(flowId, async () => assert.fail("must not consume")), safeError("peer_untrusted"));
      assert.equal(calls, failAt); if (failAt === 1) assert.equal(f.handshake, undefined);
    } finally { await f.close(); }
  }
});

test("untrusted exception text is sanitized and no consume retry occurs", base, async () => {
  const f = await fixture(); let calls = 0;
  try {
    const transport = new OsirClientHandoffTransport(f.options);
    await assert.rejects(transport.run(flowId, async () => { calls++; throw new Error("synthetic-secret-never-log"); }), safeError("consume_failed"));
    assert.equal(calls, 1);
    await assert.rejects(transport.run(flowId, async () => assert.fail()), safeError("flow_pending"));
  } finally { await f.close(); }
});

test("malformed code delivery rejects extra/duplicate fields, wrong binding, noncanonical code and lifetime", base, async () => {
  const mutations: Array<(v: Record<string, unknown>) => string> = [
    v => JSON.stringify({ ...v, accessToken: "never" }),
    v => JSON.stringify({ ...v, flowId: "z".repeat(43) }),
    v => JSON.stringify({ ...v, state: "z".repeat(43) }),
    v => JSON.stringify({ ...v, code: "z".repeat(43) }),
    v => JSON.stringify({ ...v, expiresIn: 0 }), v => JSON.stringify({ ...v, expiresIn: 61 }),
    v => JSON.stringify({ ...v, configuredToolTypes: ["opencode"] }),
    v => JSON.stringify({ ...v, configuredToolTypes: ["codex", "claude"] }),
    v => JSON.stringify({ ...v, configuredToolTypes: ["dsh", "dsh"] }),
    v => JSON.stringify({ ...v, configuredToolTypes: "codex" }),
    v => { const { configuredToolTypes: _, ...old } = v; return JSON.stringify(old); },
    v => JSON.stringify(v).replace('"expiresIn":60', '"expiresIn":60.0'),
    v => '{"state":"duplicate",' + JSON.stringify(v).slice(1),
    v => JSON.stringify(v) + '{}',
  ];
  for (const mutate of mutations) {
    const f = await fixture((h, socket) => {
      const bytes = Buffer.from(mutate({ flowId, state: h.state, code, expiresIn: 60, configuredToolTypes: ["claude", "codex"] }));
      const prefix = Buffer.alloc(4); prefix.writeUInt32BE(bytes.length); socket.end(Buffer.concat([prefix, bytes]));
    });
    try { await assert.rejects(new OsirClientHandoffTransport(f.options).run(flowId, async () => assert.fail()), safeError("invalid_handoff")); }
    finally { await f.close(); }
  }
});

test("oversize, truncated and multiple frames fail without consuming", base, async () => {
  for (const respond of [
    (_: Handshake, socket: net.Socket) => socket.end(Buffer.from([0, 0, 16, 0])),
    (_: Handshake, socket: net.Socket) => socket.end(Buffer.from([0, 0, 0, 4, 123])),
    (h: Handshake, socket: net.Socket) => { const frame = encodeHandoffFrame({ flowId, state: h.state, code, expiresIn: 60, configuredToolTypes: [] }); socket.end(Buffer.concat([frame, frame])); },
  ]) {
    const f = await fixture(respond);
    try { await assert.rejects(new OsirClientHandoffTransport(f.options).run(flowId, async () => assert.fail()), safeError("invalid_handoff")); }
    finally { await f.close(); }
  }
});

test("in-flight duplicate and cancellation reject late verifier without handshake", base, async () => {
  const f = await fixture(); let release!: () => void; let entered!: () => void;
  const ready = new Promise<void>(resolve => { entered = resolve; });
  const wait = new Promise<void>(resolve => { release = resolve; });
  const controller = new AbortController();
  const transport = new OsirClientHandoffTransport({ ...f.options, verifyPeer: async () => { entered(); await wait; } });
  try {
    const running = transport.run(flowId, async () => assert.fail("late consume"), controller.signal);
    await ready;
    await assert.rejects(transport.run(flowId, async () => assert.fail()), safeError("flow_pending"));
    controller.abort(); await assert.rejects(running, safeError("cancelled")); release();
    await new Promise<void>(resolve => setImmediate(resolve)); assert.equal(f.handshake, undefined);
  } finally { release(); await f.close(); }
});

test("manifest and socket permissions, symlinks, extra fields and forged PID are rejected", base, async () => {
  for (const variant of ["file-mode", "root-mode", "symlink", "socket-mode", "parent-mode", "pid", "extra", "duplicate"]) {
    const f = await fixture();
    try {
      const manifest = JSON.parse(fs.readFileSync(f.manifest, "utf8"));
      switch (variant) {
        case "file-mode": fs.chmodSync(f.manifest, 0o644); break;
        case "root-mode": fs.chmodSync(f.root, 0o755); break;
        case "socket-mode": fs.chmodSync(f.socketPath, 0o666); break;
        case "parent-mode": fs.chmodSync(f.temp, 0o755); break;
        case "symlink": { const other = path.join(f.home, "manifest"); fs.renameSync(f.manifest, other); fs.symlinkSync(other, f.manifest); break; }
        case "pid": fs.writeFileSync(f.manifest, JSON.stringify({ ...manifest, clientPid: process.pid + 100000 })); break;
        case "extra": fs.writeFileSync(f.manifest, JSON.stringify({ ...manifest, code: "never" })); break;
        case "duplicate": fs.writeFileSync(f.manifest, '{"version":1,' + JSON.stringify(manifest).slice(1)); break;
      }
      await assert.rejects(new OsirClientHandoffTransport(f.options).run(flowId, async () => assert.fail()));
      assert.equal(f.handshake, undefined);
    } finally { await f.close(); }
  }
});

test("peer helper without socket emits fixed failure with no stderr or secrets", base, () => {
  try { execFileSync(python, ["-I", "-S", "-B", helper], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }); assert.fail(); }
  catch (error) {
    const result = error as { stdout: string; stderr: string };
    assert.equal(result.stdout, '{"error":"peer_untrusted"}\n'); assert.equal(result.stderr, "");
  }
});

test("peer helper reports actual server and parent, and missing helper fails closed", base, async () => {
  const f = await fixture(); const socket = net.createConnection(f.socketPath); socket.on("error", () => {});
  try {
    await new Promise<void>(resolve => socket.once("connect", resolve));
    const peer = await inspectHandoffPeer(socket, f.options, new AbortController().signal);
    assert.equal(peer.pid, process.pid); assert.equal(peer.parentPid, process.ppid);
    assert.ok(peer.startedAt[0] > 0); assert.ok(path.isAbsolute(peer.executablePath));
    await assert.rejects(inspectHandoffPeer(socket, { ...f.options, helperPath: path.join(f.home, "missing.py") }, new AbortController().signal), safeError("peer_untrusted"));
  } finally { socket.destroy(); await f.close(); }
});

test("empty configured selection remains empty; never infer installed SDKs", base, async () => {
  const f = await fixture((h, socket) => socket.end(encodeHandoffFrame({ flowId, state: h.state, code, expiresIn: 60, configuredToolTypes: [] })));
  try {
    await new OsirClientHandoffTransport(f.options).run(flowId, async (_, context) => {
      assert.deepEqual(context.configuredToolTypes, []);
    });
  } finally { await f.close(); }
});

test("second live identity mismatch fails before second build verification", base, async () => {
  const f = await fixture(); let verifies = 0;
  const fake = path.join(f.home, "synthetic-peer.py");
  fs.writeFileSync(fake, `import os,json,sys\np={"uid":os.geteuid(),"pid":os.getppid(),"executablePath":"/synthetic/main","parentPid":1,"parentExecutablePath":"/synthetic/parent","startedAt":[1,0]}\nprint(json.dumps(p),flush=True)\nsys.stdin.readline()\np["startedAt"][1]=1\nprint(json.dumps(p),flush=True)\n`);
  try {
    const transport = new OsirClientHandoffTransport({ ...f.options, helperPath: fake, verifyPeer: async () => { verifies++; } });
    await assert.rejects(transport.run(flowId, async () => assert.fail("mismatched process")), safeError("peer_untrusted"));
    assert.equal(verifies, 1);
  } finally { await f.close(); }
});
