/** Main-only consumer of contracts/osir-client-handoff/v1. No startup side effects,
 * logging, credential persistence, local configuration discovery or Runtime APIs.
 * Main must cancel this controller on logout/account change/shutdown, and must
 * construct its transport with release-pinned peer verification.
 */
import { performance } from "node:perf_hooks";
import type { DesktopServerConnection } from "./desktop-server";
import { parseDesktopSession, type DesktopSessionPayload } from "./desktop-session";
import type { LocalDesktopBinding } from "./connector-types";
import { HandoffTransportError, parseHandoffJson, type HandoffContext, type HandoffTokenRequest,
  type OsirClientHandoffTransport } from "./osir-client-handoff-transport";

export const OSIR_HANDOFF_TOKEN_URL = "https://osirclaw.com/api/v1/auth/desktop/anywhere/handoff/token";
export const OSIR_HANDOFF_EXCHANGE_URL = "https://anywhere.osirclaw.com/api/v2/auth/osir/desktop/exchange";
const ORIGIN = "https://anywhere.osirclaw.com";
const SERVER: DesktopServerConnection = Object.freeze({ serverUrl: ORIGIN, apiNamespace: "/api/v2", oauthWebOrigin: ORIGIN });
const TOOLS = ["claude", "codex", "dsh"] as const;
type Tool = typeof TOOLS[number];
type Identity = DesktopSessionPayload["identity"];

export type OsirHandoffAccountContext = {
  /** Trusted Main auth/binding epoch; increment on logout or account/binding changes. */
  generation: number;
  /** Refresh/validate readable stored sessions first. Explicit Client handoff may
   * recover an unreadable session through the Main-only ciphertext backup path.
   * Network/refresh failures must still reject; local binding checks always apply.
   */
  desktopIdentity: Identity | null;
  localBinding: Pick<LocalDesktopBinding, "serverUrl" | "ownerUserId"> | null;
};
export type OsirHandoffFailure = "invalid_request" | "invalid_handoff" | "receiver_untrusted" | "capability_unavailable"
  | "consent_required" | "account_mismatch" | "rate_limited" | "dependency_unavailable"
  | "timeout" | "cancelled" | "flow_pending" | "session_rejected" | "cleanup_failed";
export type OsirHandoffResult = { status: "authenticated" } | { status: "error"; reason: OsirHandoffFailure };
export type OsirClientHandoffOptions = {
  transport: Pick<OsirClientHandoffTransport, "run">;
  fetcher: typeof fetch;
  /** Bind these to the existing DesktopSessionManager.prepareLogin/reject. */
  prepareLogin(): Promise<void>;
  reject(session: DesktopSessionPayload, server: DesktopServerConnection): Promise<void>;
  readAccountContext(signal: AbortSignal): Promise<OsirHandoffAccountContext>;
  /** Accept/persist ONLY here, after the controller's account checks. Main must
   * recheck signal/auth epoch immediately at its actual session accept, including
   * after any await. Return true only after acceptance/delivery succeeds.
   * Selection is verified IPC metadata, never inferred from installed SDKs.
   */
  onAuthenticated(value: { session: DesktopSessionPayload; server: DesktopServerConnection;
    configuredToolTypes: readonly Tool[]; accountGeneration: number }, signal: AbortSignal): boolean | Promise<boolean>;
};

class Failure extends Error {
  constructor(readonly reason: OsirHandoffFailure) { super(reason); }
}
const fail = (reason: OsirHandoffFailure): never => { throw new Failure(reason); };
const errorResult = (reason: OsirHandoffFailure): OsirHandoffResult => ({ status: "error", reason });
function reason(error: unknown): OsirHandoffFailure {
  if (error instanceof Failure) return error.reason;
  if (error instanceof HandoffTransportError) {
    if (error.reason === "peer_untrusted") return "receiver_untrusted";
    if (["timeout", "cancelled", "flow_pending"].includes(error.reason)) return error.reason as OsirHandoffFailure;
  }
  return "invalid_handoff";
}
function object(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("invalid_handoff");
  const row = value as Record<string, unknown>;
  if (Object.keys(row).length !== keys.length || keys.some(key => !Object.hasOwn(row, key))) fail("invalid_handoff");
  return row;
}
const opaque = (value: unknown): value is string => typeof value === "string" && /^[A-Za-z0-9_-]{32,128}$/.test(value);
const canonical32 = (value: unknown): value is string => typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value)
  && Buffer.from(value, "base64url").toString("base64url") === value;
function identity(value: Identity): Identity {
  if (!value || value.issuer !== "https://osirclaw.com" || typeof value.subject !== "string"
    || !/^[1-9][0-9]{0,18}$/.test(value.subject) || BigInt(value.subject) > 9223372036854775807n
    || typeof value.userId !== "string" || !value.userId || value.userId.length > 16384 || /\s/.test(value.userId)) fail("account_mismatch");
  return { issuer: value.issuer, subject: value.subject, userId: value.userId };
}
const sameIdentity = (a: Identity | null, b: Identity | null) => a === null || b === null ? a === b :
  a.issuer === b.issuer && a.subject === b.subject && a.userId === b.userId;
function accountContext(value: OsirHandoffAccountContext): OsirHandoffAccountContext {
  if (!value || !Number.isSafeInteger(value.generation) || value.generation < 0
    || value.desktopIdentity === undefined || value.localBinding === undefined) fail("account_mismatch");
  const desktopIdentity = value.desktopIdentity === null ? null : identity(value.desktopIdentity);
  const localBinding = value.localBinding === null ? null : {
    serverUrl: value.localBinding.serverUrl, ownerUserId: value.localBinding.ownerUserId,
  };
  if (localBinding && (localBinding.serverUrl !== ORIGIN || typeof localBinding.ownerUserId !== "string" || !localBinding.ownerUserId)) fail("account_mismatch");
  return { generation: value.generation, desktopIdentity, localBinding };
}
function matchesAccount(session: DesktopSessionPayload, context: OsirHandoffAccountContext): void {
  const next = identity(session.identity);
  if (context.desktopIdentity && !sameIdentity(next, context.desktopIdentity)
    || context.localBinding && context.localBinding.ownerUserId !== next.userId) fail("account_mismatch");
}
function matchesContext(before: OsirHandoffAccountContext, after: OsirHandoffAccountContext): void {
  if (before.generation !== after.generation || !sameIdentity(before.desktopIdentity, after.desktopIdentity)
    || before.localBinding?.serverUrl !== after.localBinding?.serverUrl
    || before.localBinding?.ownerUserId !== after.localBinding?.ownerUserId) fail("account_mismatch");
}

/** Requests already sent may have issued credentials. Read their bounded response
 * under an independent deadline even if the flow was cancelled, so cleanup can
 * take ownership before accepting anything. No POST is retried.
 */
async function readJson(response: Response): Promise<unknown> {
  if (!response.body) fail("invalid_handoff");
  const reader = response.body!.getReader();
  const chunks: Buffer[] = []; let size = 0; let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; void reader.cancel().catch(() => {}); }, 10_000);
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (timedOut) fail("timeout");
      if (done) break;
      size += value.byteLength; if (size > 16384) fail("invalid_handoff");
      chunks.push(Buffer.from(value));
    }
    return parseHandoffJson(Buffer.concat(chunks), 16384);
  } finally { clearTimeout(timer); await reader.cancel().catch(() => {}); reader.releaseLock(); }
}
async function post(fetcher: typeof fetch, url: string, payload: object, signal: AbortSignal, timeout = 10_000): Promise<unknown> {
  if (signal.aborted) fail("cancelled");
  const controller = new AbortController(); let timedOut = false;
  const abort = () => controller.abort();
  signal.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeout);
  try {
    const response = await fetcher(url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(payload), signal: controller.signal, credentials: "omit", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer" });
    if (response.redirected || response.url && response.url !== url) { await response.body?.cancel(); fail("invalid_handoff"); }
    const data = await readJson(response);
    if (response.status !== 200) {
      const expected: Record<string, number> = { invalid_request: 400, invalid_handoff: 401, capability_unavailable: 403,
        receiver_untrusted: 403, consent_required: 403, account_mismatch: 409, rate_limited: 429, dependency_unavailable: 503 };
      const code = data && typeof data === "object" ? (data as { reason?: unknown }).reason : null;
      if (typeof code === "string" && Object.hasOwn(expected, code) && expected[code] === response.status) fail(code as OsirHandoffFailure);
      fail(response.status === 503 ? "dependency_unavailable" : "invalid_handoff");
    }
    return data;
  } catch (error) {
    if (timedOut) fail("timeout");
    if (error instanceof Failure || error instanceof HandoffTransportError) throw error;
    fail(signal.aborted ? "cancelled" : "dependency_unavailable");
  } finally { clearTimeout(timer); signal.removeEventListener("abort", abort); }
}

function proof(flowId: string, request: HandoffTokenRequest, context: HandoffContext) {
  object(request, ["grant_type", "client_id", "code", "code_verifier", "state", "receiver_instance_id", "target_origin"]);
  if (!context || context.flowId !== flowId || !canonical32(context.state) || !opaque(context.receiverInstanceId)
    || context.targetOrigin !== ORIGIN || request.grant_type !== "urn:osir:params:grant-type:anywhere-handoff"
    || request.client_id !== "osir-anywhere-desktop" || !canonical32(request.code)
    || typeof request.code_verifier !== "string" || !/^[A-Za-z0-9_-]{64}$/.test(request.code_verifier)
    || request.state !== context.state || request.receiver_instance_id !== context.receiverInstanceId || request.target_origin !== ORIGIN) fail("invalid_handoff");
  const selection = context.configuredToolTypes;
  if (!Array.isArray(selection) || selection.length > 3 || selection.some((tool, index) =>
    !TOOLS.includes(tool) || index > 0 && TOOLS.indexOf(selection[index - 1]) >= TOOLS.indexOf(tool))) fail("invalid_handoff");
  if (!Number.isFinite(context.codeDeadline) || context.codeDeadline <= performance.now()) fail("timeout");
  return { handoff: { flowId, state: context.state, receiverInstanceId: context.receiverInstanceId,
    codeVerifier: request.code_verifier, targetOrigin: ORIGIN }, configuredToolTypes: Object.freeze([...selection]) as readonly Tool[] };
}

type Attempt = { flowId: string; controller: AbortController; promise: Promise<OsirHandoffResult> };
export class OsirClientHandoffController {
  private active: Attempt | null = null;
  private stopped = false;
  private spent = new Map<string, number>();
  constructor(private readonly options: OsirClientHandoffOptions) {}

  /** Only a native launch's explicit flowId is accepted; no default/background flow. */
  run(input: { flowId: string }, signal?: AbortSignal): Promise<OsirHandoffResult> {
    if (!input || Object.keys(input).join(",") !== "flowId" || !opaque(input.flowId)) return Promise.resolve(errorResult("invalid_request"));
    if (this.stopped || signal?.aborted) return Promise.resolve(errorResult("cancelled"));
    if (this.active) return this.active.flowId === input.flowId ? this.active.promise : Promise.resolve(errorResult("flow_pending"));
    for (const [flow, expiry] of this.spent) if (expiry <= performance.now()) this.spent.delete(flow);
    if (this.spent.has(input.flowId)) return Promise.resolve(errorResult("flow_pending"));
    const controller = new AbortController();
    const abort = () => controller.abort(new Failure("cancelled"));
    signal?.addEventListener("abort", abort, { once: true });
    const timer = setTimeout(() => controller.abort(new Failure("timeout")), 300_000);
    const attempt: Attempt = { flowId: input.flowId, controller, promise: undefined! };
    attempt.promise = Promise.resolve().then(() => this.execute(attempt)).finally(() => {
      clearTimeout(timer); signal?.removeEventListener("abort", abort);
      if (this.active === attempt) this.active = null;
      this.spent.set(attempt.flowId, performance.now() + 300_000);
    });
    this.active = attempt;
    return attempt.promise;
  }

  cancel(): Promise<OsirHandoffResult> {
    this.active?.controller.abort(new Failure("cancelled"));
    return this.active?.promise ?? Promise.resolve(errorResult("cancelled"));
  }
  dispose(): Promise<OsirHandoffResult> { this.stopped = true; return this.cancel(); }

  private async execute(attempt: Attempt): Promise<OsirHandoffResult> {
    const signal = attempt.controller.signal;
    let issued: DesktopSessionPayload | null = null;
    let consume: Promise<OsirHandoffResult> | null = null;
    let result: OsirHandoffResult = errorResult("invalid_handoff");
    const live = () => { if (signal.aborted) throw signal.reason instanceof Failure ? signal.reason : new Failure("cancelled"); };
    try {
      live();
      await this.options.prepareLogin(); live();
      const before = accountContext(await this.options.readAccountContext(signal)); live();
      result = await this.options.transport.run(attempt.flowId, (request, context, transportSignal) => {
        if (consume) return Promise.resolve(errorResult("flow_pending"));
        const combined = AbortSignal.any([signal, transportSignal]);
        consume = (async (): Promise<OsirHandoffResult> => {
          try {
            live(); if (combined.aborted) fail("cancelled");
            const verified = proof(attempt.flowId, request, context);
            const raw = object(await post(this.options.fetcher, OSIR_HANDOFF_TOKEN_URL, { ...request }, combined,
              Math.max(1, Math.min(10_000, context.codeDeadline - performance.now()))), ["code", "message", "data"]);
            live(); if (combined.aborted) fail("cancelled");
            const token = object(raw.data, ["assertion", "token_type", "expires_in", "audience"]);
            if (raw.code !== 0 || raw.message !== "success" || token.token_type !== "urn:osir:params:token-type:anywhere-handoff"
              || token.expires_in !== 60 || token.audience !== "osir-anywhere-server" || typeof token.assertion !== "string"
              || token.assertion.length < 100 || token.assertion.length > 4096
              || !/^[A-Za-z0-9_-]{1,512}\.[A-Za-z0-9_-]{1,3072}\.[A-Za-z0-9_-]{85}[AQgw]$/.test(token.assertion)) fail("invalid_handoff");
            const parsed = parseDesktopSession(await post(this.options.fetcher, OSIR_HANDOFF_EXCHANGE_URL,
              { assertion: token.assertion, handoff: verified.handoff }, combined));
            const session: DesktopSessionPayload = Object.freeze({ accessToken: parsed.accessToken, tokenType: parsed.tokenType,
              expiresIn: parsed.expiresIn, refreshToken: parsed.refreshToken, refreshExpiresIn: parsed.refreshExpiresIn,
              identity: Object.freeze({ issuer: parsed.identity.issuer, subject: parsed.identity.subject, userId: parsed.identity.userId }) });
            issued = session; // Own cleanup before cancellation/account checks or callbacks.
            live(); if (combined.aborted) fail("cancelled");
            matchesAccount(session, before);
            const current = accountContext(await this.options.readAccountContext(signal)); live();
            matchesContext(before, current); matchesAccount(session, current);
            const accepted = await this.options.onAuthenticated({ session, server: SERVER,
              configuredToolTypes: verified.configuredToolTypes, accountGeneration: current.generation }, combined);
            live(); if (combined.aborted) fail("cancelled");
            if (accepted !== true) fail("session_rejected");
            return { status: "authenticated" };
          } catch (error) { return errorResult(reason(error)); }
        })();
        return consume;
      }, signal);
      if (!consume) fail("invalid_handoff");
      live();
    } catch (error) {
      result = errorResult(reason(error));
    }
    // Transport can cancel while consume is still reading an issued response.
    // Keep the flight locked until it has stopped and cleanup has taken ownership.
    if (consume) await consume;
    if (signal.aborted) result = errorResult(signal.reason instanceof Failure ? signal.reason.reason : "cancelled");
    if (issued && result.status !== "authenticated") {
      try { await this.options.reject(issued, SERVER); }
      catch { result = errorResult("cleanup_failed"); }
    }
    return result;
  }
}
