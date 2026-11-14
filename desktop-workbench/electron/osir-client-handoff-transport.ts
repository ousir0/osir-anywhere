/** Native Main only. No Electron imports, API calls, logging or app launch.
 * Discovery: <trusted home>/Library/Application Support/OSIR/handoff/v1/<flowId>.json
 * Wire: uint32 BE length + UTF-8 JSON; TOTAL frame <=4096; exactly one frame
 * per direction. Main half-closes after handshake. Secrets never enter argv.
 * verifyPeer MUST pin kernel peer + running build to release-signed full bundle
 * tree trust. The callback is required and is repeated before consuming code.
 */
import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import { spawn } from "node:child_process";
import { randomBytes, createHash, timingSafeEqual } from "node:crypto";
import { performance } from "node:perf_hooks";

export const HANDOFF_DISCOVERY_RELATIVE = "Library/Application Support/OSIR/handoff/v1";
export const HANDOFF_MAX_FRAME_BYTES = 4096;
const MAX_WAIT_MS = 300_000;
const IO_WAIT_MS = 5_000;
const ACTIONS = ["identity", "connect-local", "bootstrap-configured-tools"] as const;
const ORIGIN = "https://anywhere.osirclaw.com";
const RECIPIENT = "osir-anywhere-desktop";

export type HandoffFailure = "invalid_handoff" | "unsafe_path" | "peer_untrusted" | "timeout" | "cancelled" | "flow_pending" | "unavailable" | "consume_failed";
export class HandoffTransportError extends Error {
  constructor(readonly reason: HandoffFailure) { super(reason); this.name = "HandoffTransportError"; }
}
function fail(reason: HandoffFailure): never { throw new HandoffTransportError(reason); }
export interface HandoffPeerIdentity {
  readonly uid: number;
  readonly pid: number;
  readonly executablePath: string;
  readonly parentPid: number;
  readonly parentExecutablePath: string;
  readonly startedAt: readonly [number, number];
}
export interface HandoffTokenRequest {
  grant_type: "urn:osir:params:grant-type:anywhere-handoff";
  client_id: "osir-anywhere-desktop";
  code: string;
  code_verifier: string;
  state: string;
  receiver_instance_id: string;
  target_origin: "https://anywhere.osirclaw.com";
}
export interface HandoffContext {
  readonly flowId: string;
  readonly state: string;
  readonly receiverInstanceId: string;
  readonly targetOrigin: "https://anywhere.osirclaw.com";
  readonly configuredToolTypes: readonly ("claude" | "codex" | "dsh")[];
  /** Monotonic deadline; consumption must still enforce the server expiry. */
  readonly codeDeadline: number;
}
export interface HandoffTransportOptions {
  /** All configuration is supplied by trusted Main, never renderer/launch args. */
  home: string;
  pythonExecutable: string;
  helperPath: string;
  /** Must verify BOTH running process identity and the release-pinned full tree.
   * No default, same-UID shortcut, unsigned bypass, or caller supplied trust URL.
   * It must honor cancellation; throws/rejects on any inability to prove trust.
   */
  verifyPeer(peer: HandoffPeerIdentity, signal: AbortSignal): Promise<void>;
}

function opaque(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{32,128}$/.test(value);
}
function canonical32(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value)
    && Buffer.from(value, "base64url").toString("base64url") === value;
}
function equal(a: string, b: string): boolean {
  const aa = Buffer.from(a); const bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
function samePeer(a: HandoffPeerIdentity, b: HandoffPeerIdentity): boolean {
  return a.uid === b.uid && a.pid === b.pid && a.executablePath === b.executablePath
    && a.parentPid === b.parentPid && a.parentExecutablePath === b.parentExecutablePath
    && a.startedAt[0] === b.startedAt[0] && a.startedAt[1] === b.startedAt[1];
}
function object(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("invalid_handoff");
  const result = value as Record<string, unknown>;
  if (Object.keys(result).length !== keys.length || keys.some(k => !Object.hasOwn(result, k))) fail("invalid_handoff");
  return result;
}

/** Bounded JSON with duplicate-key rejection BEFORE object construction. JSON's
 * native parser silently overwrites duplicates. Reject float/exponent numbers,
 * trailing JSON, invalid UTF-8, excessive nesting and prototype keys as well.
 */
export function parseHandoffJson(bytes: Buffer, maximum = HANDOFF_MAX_FRAME_BYTES): unknown {
  if (bytes.length === 0 || bytes.length > maximum) fail("invalid_handoff");
  let text: string;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { fail("invalid_handoff"); }
  let index = 0;
  const whitespace = () => { while (/[\x20\t\r\n]/.test(text[index] ?? "x")) index++; };
  const string = (): string => {
    const re = /"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/y;
    re.lastIndex = index; const match = re.exec(text);
    if (!match) fail("invalid_handoff"); index = re.lastIndex;
    return JSON.parse(match[0]) as string;
  };
  const value = (depth: number): unknown => {
    if (depth > 8) fail("invalid_handoff"); whitespace();
    if (text[index] === '"') return string();
    if (text[index] === "{") {
      index++; whitespace(); const result: Record<string, unknown> = Object.create(null); const seen = new Set<string>();
      if (text[index] === "}") { index++; return result; }
      for (;;) {
        whitespace(); const key = string();
        if (seen.has(key) || ["__proto__", "constructor", "prototype"].includes(key)) fail("invalid_handoff");
        seen.add(key); whitespace(); if (text[index++] !== ":") fail("invalid_handoff");
        result[key] = value(depth + 1); whitespace();
        if (text[index] === "}") { index++; return result; }
        if (text[index++] !== ",") fail("invalid_handoff");
      }
    }
    if (text[index] === "[") {
      index++; whitespace(); const result: unknown[] = [];
      if (text[index] === "]") { index++; return result; }
      for (;;) {
        result.push(value(depth + 1)); whitespace();
        if (text[index] === "]") { index++; return result; }
        if (text[index++] !== ",") fail("invalid_handoff");
      }
    }
    for (const [literal, result] of [["true", true], ["false", false], ["null", null]] as const) {
      if (text.startsWith(literal, index)) { index += literal.length; return result; }
    }
    const re = /-?(?:0|[1-9][0-9]*)/y; re.lastIndex = index; const match = re.exec(text);
    if (!match || /[.eE0-9]/.test(text[re.lastIndex] ?? "x")) fail("invalid_handoff");
    index = re.lastIndex; const result = Number(match[0]);
    if (!Number.isSafeInteger(result) || Object.is(result, -0)) fail("invalid_handoff");
    return result;
  };
  const result = value(0); whitespace(); if (index !== text.length) fail("invalid_handoff"); return result;
}

export function encodeHandoffFrame(value: unknown): Buffer {
  const bytes = Buffer.from(JSON.stringify(value));
  if (!bytes.length || bytes.length + 4 > HANDOFF_MAX_FRAME_BYTES) fail("invalid_handoff");
  const length = Buffer.alloc(4); length.writeUInt32BE(bytes.length); return Buffer.concat([length, bytes]);
}

function sameInode(a: fs.Stats, b: fs.Stats): boolean { return a.dev === b.dev && a.ino === b.ino; }
function privatePath(value: string, kind: "directory" | "file" | "socket", mode: number): fs.Stats {
  if (!path.isAbsolute(value) || path.normalize(value) !== value || fs.realpathSync(value) !== value) fail("unsafe_path");
  const info = fs.lstatSync(value);
  if (info.isSymbolicLink() || info.uid !== process.geteuid?.() || (info.mode & 0o777) !== mode
    || !(kind === "directory" ? info.isDirectory() : kind === "socket" ? info.isSocket() : info.isFile())) fail("unsafe_path");
  return info;
}
function discovery(home: string, flowId: string): { socketPath: string; clientPid: number; assertUnchanged(): void } {
  if (!opaque(flowId)) fail("invalid_handoff");
  if (!path.isAbsolute(home) || fs.realpathSync(home) !== home || path.normalize(home) !== home) fail("unsafe_path");
  const root = path.join(home, HANDOFF_DISCOVERY_RELATIVE);
  const rootInfo = privatePath(root, "directory", 0o700);
  // Reject every symlink/foreign-writable ancestor below the trusted home.
  let ancestor = root;
  while (ancestor !== home) {
    const info = fs.lstatSync(ancestor);
    if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.geteuid?.() || info.mode & 0o022) fail("unsafe_path");
    ancestor = path.dirname(ancestor);
  }
  const filename = path.join(root, `${flowId}.json`);
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  let info: fs.Stats; let bytes: Buffer;
  try {
    info = fs.fstatSync(fd);
    if (!info.isFile() || info.uid !== process.geteuid?.() || (info.mode & 0o777) !== 0o600 || info.nlink !== 1 || info.size > 4096) fail("unsafe_path");
    bytes = Buffer.alloc(4097); const count = fs.readSync(fd, bytes, 0, bytes.length, 0); bytes = bytes.subarray(0, count);
    if (bytes.length !== info.size) fail("unsafe_path");
  } finally { fs.closeSync(fd); }
  const manifest = object(parseHandoffJson(bytes), ["version", "flowId", "socketPath", "clientPid"]);
  if (manifest.version !== 1 || manifest.flowId !== flowId || typeof manifest.socketPath !== "string"
    || !Number.isSafeInteger(manifest.clientPid) || Number(manifest.clientPid) <= 0) fail("invalid_handoff");
  const socketPath = manifest.socketPath;
  // Fixed private temporary namespace; discovery never grants arbitrary paths.
  if (!/^\/private\/tmp\/oh-[A-Za-z0-9_-]+\/s$/.test(socketPath) || Buffer.byteLength(socketPath) > 103) fail("unsafe_path");
  const parent = path.dirname(socketPath);
  const parentInfo = privatePath(parent, "directory", 0o700);
  const socketInfo = privatePath(socketPath, "socket", 0o600);
  const assertUnchanged = () => {
    if (!sameInode(rootInfo, privatePath(root, "directory", 0o700))
      || !sameInode(info, privatePath(filename, "file", 0o600))
      || !sameInode(parentInfo, privatePath(parent, "directory", 0o700))
      || !sameInode(socketInfo, privatePath(socketPath, "socket", 0o600))) fail("unsafe_path");
  };
  assertUnchanged(); return { socketPath, clientPid: Number(manifest.clientPid), assertUnchanged };
}

function abortReason(signal: AbortSignal): HandoffTransportError {
  return signal.reason instanceof HandoffTransportError ? signal.reason : new HandoffTransportError("cancelled");
}
function abortable<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const abort = () => reject(abortReason(signal));
    signal.addEventListener("abort", abort, { once: true });
    work.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
    if (signal.aborted) abort();
  });
}

/** Helper inherits the connected socket as fd 3. stdio supports a Stream with
 * a descriptor; no Node private _handle access and no PID guessing are needed.
 * It emits ONLY peer metadata, never touches socket bytes or outputs secrets.
 */
function peerFromBytes(bytes: Buffer): HandoffPeerIdentity {
  const peer = object(parseHandoffJson(bytes, 12288), ["uid", "pid", "executablePath", "parentPid", "parentExecutablePath", "startedAt"]);
  if (peer.uid !== process.geteuid?.() || !Number.isSafeInteger(peer.pid) || Number(peer.pid) <= 0
    || !Number.isSafeInteger(peer.parentPid) || Number(peer.parentPid) <= 0
    || typeof peer.executablePath !== "string" || !path.isAbsolute(peer.executablePath)
    || typeof peer.parentExecutablePath !== "string" || !path.isAbsolute(peer.parentExecutablePath)
    || !Array.isArray(peer.startedAt) || peer.startedAt.length !== 2
    || peer.startedAt.some(n => !Number.isSafeInteger(n) || n < 0)) fail("peer_untrusted");
  return Object.freeze({ ...peer, startedAt: Object.freeze([...peer.startedAt]) }) as unknown as HandoffPeerIdentity;
}

/** Hold the dup'ed fd across Node's automatic close on EOF. The Python process
 * reads no payload and handles exactly two metadata inspections on this fd.
 */
function openPeerInspector(socket: net.Socket, options: Pick<HandoffTransportOptions, "pythonExecutable" | "helperPath">, signal: AbortSignal) {
  if (process.platform !== "darwin") fail("unavailable");
  if (signal.aborted) throw abortReason(signal);
  if (![options.pythonExecutable, options.helperPath].every(p => path.isAbsolute(p))) fail("peer_untrusted");
  const child = spawn(options.pythonExecutable, ["-I", "-S", "-B", options.helperPath], {
    shell: false, env: { LANG: "en_US.UTF-8" }, stdio: ["pipe", "pipe", "ignore", socket], windowsHide: true,
  });
  let bytes = Buffer.alloc(0); let calls = 0; let stopped: HandoffTransportError | undefined;
  let pending: { resolve(peer: HandoffPeerIdentity): void; reject(error: HandoffTransportError): void; timer: ReturnType<typeof setTimeout> } | undefined;
  const stop = (error = new HandoffTransportError("peer_untrusted")) => {
    if (stopped) return; stopped = error; signal.removeEventListener("abort", abort);
    if (pending) { clearTimeout(pending.timer); pending.reject(error); pending = undefined; }
    child.stdin!.destroy(); child.kill(); bytes = Buffer.alloc(0);
  };
  const abort = () => stop(abortReason(signal));
  signal.addEventListener("abort", abort, { once: true });
  child.on("error", () => stop()); child.stdin!.on("error", () => stop());
  const dispatch = () => {
    const newline = bytes.indexOf(10);
    if (newline < 0 || !pending) return;
    if (newline !== bytes.length - 1) { stop(); return; }
    const waiter = pending;
    try {
      const peer = peerFromBytes(bytes.subarray(0, newline));
      pending = undefined; clearTimeout(waiter.timer); bytes = Buffer.alloc(0); waiter.resolve(peer);
    } catch { stop(); }
  };
  child.stdout!.on("data", (chunk: Buffer) => {
    if (bytes.length + chunk.length > 12288) { stop(); return; }
    bytes = Buffer.concat([bytes, chunk]); dispatch();
  });
  child.on("close", (code, exitSignal) => { if (pending || code !== 0 || exitSignal) stop(); });
  return {
    inspect(): Promise<HandoffPeerIdentity> {
      if (stopped) return Promise.reject(stopped);
      if (pending || calls >= 2) return Promise.reject(new HandoffTransportError("peer_untrusted"));
      return new Promise((resolve, reject) => {
        pending = { resolve, reject, timer: setTimeout(() => stop(new HandoffTransportError("timeout")), IO_WAIT_MS) };
        if (calls++ > 0) child.stdin!.write("inspect\n");
        dispatch();
      });
    },
    close: () => stop(new HandoffTransportError("cancelled")),
  };
}

export async function inspectHandoffPeer(socket: net.Socket, options: Pick<HandoffTransportOptions, "pythonExecutable" | "helperPath">, signal: AbortSignal): Promise<HandoffPeerIdentity> {
  const inspector = openPeerInspector(socket, options, signal);
  try { return await inspector.inspect(); } finally { inspector.close(); }
}

function readDelivery(socket: net.Socket, signal: AbortSignal): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let bytes = Buffer.alloc(0); let done = false;
    const finish = (error?: HandoffTransportError, result?: unknown) => {
      if (done) return; done = true; clearTimeout(timer); signal.removeEventListener("abort", abort);
      socket.removeListener("data", data); socket.removeListener("end", end); socket.removeListener("close", close);
      bytes.fill(0); if (error) reject(error); else resolve(result);
    };
    const abort = () => finish(abortReason(signal));
    const data = (chunk: Buffer) => {
      if (bytes.length + chunk.length > HANDOFF_MAX_FRAME_BYTES) { finish(new HandoffTransportError("invalid_handoff")); return; }
      bytes = Buffer.concat([bytes, chunk]);
      if (bytes.length >= 4) {
        const length = bytes.readUInt32BE(0);
        if (!length || length + 4 > HANDOFF_MAX_FRAME_BYTES || bytes.length > length + 4) finish(new HandoffTransportError("invalid_handoff"));
      }
    };
    const end = () => {
      try {
        if (bytes.length < 4 || bytes.readUInt32BE(0) + 4 !== bytes.length) fail("invalid_handoff");
        finish(undefined, parseHandoffJson(bytes.subarray(4)));
      } catch { finish(new HandoffTransportError("invalid_handoff")); }
    };
    const close = () => { if (!done) finish(new HandoffTransportError("invalid_handoff")); };
    const timer = setTimeout(() => finish(new HandoffTransportError("timeout")), 15_000);
    socket.on("data", data); socket.once("end", end); socket.once("close", close);
    signal.addEventListener("abort", abort, { once: true }); if (signal.aborted) abort();
    socket.resume();
  });
}

export class OsirClientHandoffTransport {
  private readonly pending = new Set<string>();
  private readonly spent = new Map<string, number>();
  private readonly options: Readonly<HandoffTransportOptions>;
  constructor(options: HandoffTransportOptions) {
    if (typeof options.verifyPeer !== "function") fail("peer_untrusted");
    this.options = Object.freeze({ ...options });
  }

  async run<T>(flowId: string, consume: (request: HandoffTokenRequest, context: HandoffContext, signal: AbortSignal) => Promise<T>, signal?: AbortSignal): Promise<T> {
    if (!opaque(flowId) || typeof consume !== "function") fail("invalid_handoff");
    for (const [id, deadline] of this.spent) if (deadline <= performance.now()) this.spent.delete(id);
    if (this.pending.has(flowId) || this.spent.has(flowId)) fail("flow_pending");
    // Register BEFORE generating/sending secrets, including asynchronous verify.
    this.pending.add(flowId);
    const controller = new AbortController();
    const abort = () => controller.abort(new HandoffTransportError("cancelled"));
    signal?.addEventListener("abort", abort, { once: true }); if (signal?.aborted) abort();
    const timer = setTimeout(() => controller.abort(new HandoffTransportError("timeout")), MAX_WAIT_MS);
    let socket: net.Socket | undefined;
    let inspector: ReturnType<typeof openPeerInspector> | undefined;
    let verifier = randomBytes(48); let verifierText = verifier.toString("base64url");
    let state = randomBytes(32).toString("base64url");
    const receiverInstanceId = randomBytes(32).toString("base64url");
    let tokenRequest: HandoffTokenRequest | undefined;
    const connected = async (): Promise<T> => {
      if (controller.signal.aborted) throw abortReason(controller.signal);
      const source = discovery(this.options.home, flowId);
      socket = net.createConnection({ path: source.socketPath, allowHalfOpen: true });
      socket.pause();
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new HandoffTransportError("timeout")), IO_WAIT_MS);
        socket!.once("connect", () => { clearTimeout(timer); resolve(); });
        socket!.on("error", () => { clearTimeout(timer); reject(new HandoffTransportError("unavailable")); });
      });
      inspector = openPeerInspector(socket, this.options, controller.signal);
      const peer = await inspector.inspect();
      if (peer.pid !== source.clientPid) fail("peer_untrusted");
      try { await this.options.verifyPeer(peer, controller.signal); } catch { fail("peer_untrusted"); }
      source.assertUnchanged();
      if (controller.signal.aborted) throw abortReason(controller.signal);
      const handshake = { version: 1, flowId, receiverInstanceId, state,
        codeChallenge: createHash("sha256").update(verifierText, "ascii").digest("base64url"),
        codeChallengeMethod: "S256", recipientClientId: RECIPIENT, targetOrigin: ORIGIN, actions: ACTIONS };
      const delivered = readDelivery(socket, controller.signal);
      socket.end(encodeHandoffFrame(handshake));
      const raw = await delivered;
      const receivedAt = performance.now();
      const delivery = object(raw, ["flowId", "state", "code", "expiresIn", "configuredToolTypes"]);
      if (delivery.flowId !== flowId || typeof delivery.state !== "string" || !equal(delivery.state, state)
        || !canonical32(delivery.code) || !Number.isInteger(delivery.expiresIn)
        || Number(delivery.expiresIn) < 1 || Number(delivery.expiresIn) > 60) fail("invalid_handoff");
      const allowedTools = ["claude", "codex", "dsh"] as const;
      if (!Array.isArray(delivery.configuredToolTypes) || delivery.configuredToolTypes.length > 3) fail("invalid_handoff");
      let previous = -1;
      for (const tool of delivery.configuredToolTypes) {
        const index = allowedTools.indexOf(tool as typeof allowedTools[number]);
        if (index < 0 || index <= previous) fail("invalid_handoff"); previous = index;
      }
      const configuredToolTypes = Object.freeze([...delivery.configuredToolTypes]) as readonly ("claude" | "codex" | "dsh")[];
      // Read the kernel/libproc identity again on this very connection, never
      // trust cached metadata or ask the build verifier to invent a PID lookup.
      const currentPeer = await inspector.inspect();
      if (!samePeer(peer, currentPeer)) fail("peer_untrusted");
      try { await this.options.verifyPeer(currentPeer, controller.signal); } catch { fail("peer_untrusted"); }
      if (controller.signal.aborted) throw abortReason(controller.signal);
      const codeDeadline = receivedAt + Number(delivery.expiresIn) * 1000;
      if (performance.now() >= codeDeadline) fail("timeout");
      tokenRequest = { grant_type: "urn:osir:params:grant-type:anywhere-handoff", client_id: RECIPIENT,
        code: delivery.code, code_verifier: verifierText, state, receiver_instance_id: receiverInstanceId, target_origin: ORIGIN };
      const context = Object.freeze({ flowId, state, receiverInstanceId, targetOrigin: ORIGIN, codeDeadline, configuredToolTypes });
      try { return await consume(tokenRequest, context, controller.signal); } catch { return fail("consume_failed"); }
    };
    try { return await abortable(connected(), controller.signal); }
    catch (error) { if (error instanceof HandoffTransportError) throw error; return fail("unavailable"); }
    finally {
      controller.abort(new HandoffTransportError("cancelled"));
      clearTimeout(timer); signal?.removeEventListener("abort", abort); inspector?.close(); socket?.destroy();
      this.pending.delete(flowId); this.spent.set(flowId, performance.now() + MAX_WAIT_MS);
      verifier.fill(0); verifierText = ""; state = "";
      if (tokenRequest) { tokenRequest.code = ""; tokenRequest.code_verifier = ""; tokenRequest.state = ""; }
    }
  }
}
