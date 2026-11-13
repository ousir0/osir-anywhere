import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage } from "node:http";
import config from "../config.json";
import type { DesktopServerConnection } from "./desktop-server";
import { parseDesktopSession, type DesktopSessionPayload } from "./desktop-session";

// This scheme is now onboarding-only. OAuth never consumes a custom-scheme URL.
export const DESKTOP_OAUTH_PROTOCOL = config.oauth.protocol;
export const DESKTOP_OAUTH_CLIENT_ID = "osir-anywhere-desktop";
export const DESKTOP_OAUTH_SCOPE = "identity:read";
export const DESKTOP_OAUTH_CALLBACK_PATH = "/osir/desktop/callback";
const ASSERTION_TYPE = "urn:osir:params:token-type:anywhere-login";
const MAX_RESPONSE_BYTES = 64 * 1024;

export type DesktopOAuthResult =
  | { status: "success"; accessToken: string; server: DesktopServerConnection }
  | { status: "error"; error: string };
export type DesktopOAuthMainResult =
  | { status: "success"; accessToken: string; credentials: DesktopSessionPayload; server: DesktopServerConnection }
  | { status: "error"; error: string };
export type DesktopIdentityOptions = { env?: NodeJS.ProcessEnv; development?: boolean };
export type DesktopIdentity = { apiOrigin: string; webOrigin: string; allowLoopbackHttp: boolean };
export type DesktopOAuthPending = { state: string; verifier: string; redirectUri: string };

// All public errors are local constants: upstream bodies/URLs may contain secrets.
export class DesktopOAuthError extends Error {}
const cancelled = () => new DesktopOAuthError("Desktop sign-in was cancelled. Start sign-in again.");
const expired = () => new DesktopOAuthError("Desktop sign-in timed out. Start sign-in again.");

function secureOrigin(value: string, allowLoopbackHttp: boolean): string {
  try {
    const url = new URL(value);
    const local = ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname);
    if (url.username || url.password || url.pathname !== "/" || url.search || url.hash ||
      !(url.protocol === "https:" || (url.protocol === "http:" && local && allowLoopbackHttp))) throw new Error();
    return url.origin;
  } catch {
    throw new DesktopOAuthError("Sign-in requires an HTTPS origin; loopback HTTP requires explicit development opt-in.");
  }
}

export function resolveDesktopIdentity(options: DesktopIdentityOptions = {}): DesktopIdentity {
  const env = options.env ?? process.env;
  const allowLoopbackHttp = options.development === true && env.OSIR_IDENTITY_ALLOW_LOOPBACK_HTTP === "1";
  return {
    apiOrigin: secureOrigin(env.OSIR_IDENTITY_API_ORIGIN?.trim() || config.identity.apiOrigin, allowLoopbackHttp),
    webOrigin: secureOrigin(env.OSIR_IDENTITY_WEB_ORIGIN?.trim() || config.identity.webOrigin, allowLoopbackHttp),
    allowLoopbackHttp,
  };
}

function validateServer(server: DesktopServerConnection, identity: DesktopIdentity): void {
  secureOrigin(server.serverUrl, identity.allowLoopbackHttp);
  if (server.apiNamespace !== "/api/v2") throw new DesktopOAuthError("OSIR Anywhere sign-in requires the /api/v2 server API.");
}

export function createDesktopOAuthRequest(webOrigin: string, redirectUri: string): {
  authorizeUrl: string; pending: DesktopOAuthPending;
} {
  const callback = new URL(redirectUri);
  if (callback.origin !== `http://127.0.0.1:${callback.port}` || !callback.port ||
    callback.pathname !== DESKTOP_OAUTH_CALLBACK_PATH || callback.search || callback.hash || callback.username || callback.password) {
    throw new DesktopOAuthError("Invalid loopback callback address.");
  }
  const verifier = randomBytes(48).toString("base64url");
  const state = randomBytes(32).toString("base64url");
  const params = new URLSearchParams({
    response_type: "code", client_id: DESKTOP_OAUTH_CLIENT_ID, redirect_uri: redirectUri,
    code_challenge: createHash("sha256").update(verifier, "ascii").digest("base64url"),
    code_challenge_method: "S256", scope: DESKTOP_OAUTH_SCOPE, state,
  });
  return {
    authorizeUrl: `${webOrigin}/auth/desktop/authorize?${params.toString()}`,
    pending: { state, verifier, redirectUri },
  };
}

function secureEqual(left: string, right: string): boolean {
  const a = Buffer.from(left), b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function callbackCode(req: IncomingMessage, redirectUri: string, state: string): string {
  const target = req.url ?? "";
  const hostHeaders = req.rawHeaders.filter((_, i) => i % 2 === 0).filter(name => name.toLowerCase() === "host");
  if (req.method !== "GET" || hostHeaders.length !== 1 || req.headers.host !== new URL(redirectUri).host ||
    target.length > 4096 || target.split("?")[0] !== DESKTOP_OAUTH_CALLBACK_PATH || target.includes("#")) {
    throw new DesktopOAuthError("Invalid callback request.");
  }
  const params = new URL(target, redirectUri).searchParams;
  const allowed = new Set(["state", "code", "error", "error_description"]);
  for (const key of params.keys()) {
    if (!allowed.has(key) || params.getAll(key).length !== 1) throw new DesktopOAuthError("Invalid callback fields.");
  }
  if (!secureEqual(params.get("state") ?? "", state)) throw new DesktopOAuthError("Invalid callback state.");
  if (params.has("error")) {
    if (params.has("code") || !params.get("error")) throw new DesktopOAuthError("Invalid callback fields.");
    // Mark a state-validated denial separately; unauthenticated bad requests do not end a login.
    throw new AuthorizationDenied();
  }
  const code = params.get("code") ?? "";
  if (!/^[A-Za-z0-9_-]{43}$/.test(code) || params.has("error_description")) throw new DesktopOAuthError("Invalid callback code.");
  return code;
}
class AuthorizationDenied extends DesktopOAuthError {
  constructor() { super("OSIR authorization was declined. Start sign-in again."); }
}

export type DesktopOAuthListener = {
  authorizeUrl: string; pending: DesktopOAuthPending; code: Promise<string>; close: () => Promise<void>;
};

/** A fresh IPv4 listener per attempt, never 0.0.0.0, localhost resolution, or a fixed port. */
export async function listenDesktopOAuth(
  webOrigin: string,
  options: { signal?: AbortSignal; timeoutMs?: number } = {},
): Promise<DesktopOAuthListener> {
  let resolveCode!: (code: string) => void, rejectCode!: (error: Error) => void;
  const code = new Promise<string>((resolve, reject) => { resolveCode = resolve; rejectCode = reject; });
  // The caller may still be awaiting listen()/openExternal() when cancellation arrives.
  void code.catch(() => {});
  let pending: DesktopOAuthPending;
  let authorizeUrl = "";
  let settled = false;
  let closed: Promise<void> | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const finish = (error?: Error, value?: string) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", abort);
    if (error) rejectCode(error); else resolveCode(value!);
  };
  const server = createServer({ maxHeaderSize: 8192 }, (req, res) => {
    res.setHeader("content-type", "text/plain; charset=utf-8");
    res.setHeader("cache-control", "no-store");
    res.setHeader("connection", "close");
    res.setHeader("content-security-policy", "default-src 'none'; frame-ancestors 'none'");
    res.setHeader("referrer-policy", "no-referrer");
    if (settled || !pending) { res.writeHead(410).end("Sign-in is no longer active."); return; }
    try {
      const value = callbackCode(req, pending.redirectUri, pending.state);
      finish(undefined, value);
      res.end("OSIR authorization received. You can return to OSIR Anywhere.", () => { void close(); });
    } catch (error) {
      if (error instanceof AuthorizationDenied) {
        finish(error);
        res.writeHead(400).end("OSIR authorization was declined.", () => { void close(); });
      } else {
        res.writeHead(400).end("Invalid sign-in callback.");
      }
    }
  });
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  const close = (): Promise<void> => {
    if (closed) return closed;
    finish(cancelled());
    closed = new Promise<void>((resolve) => { server.close(() => resolve()); server.closeAllConnections(); });
    return closed;
  };
  const abort = () => { finish(options.signal?.reason instanceof DesktopOAuthError ? options.signal.reason : cancelled()); void close(); };
  // Bind first, then attach abort; the post-bind check covers cancellation while listen was pending.
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => { server.removeListener("error", reject); resolve(); });
    });
    server.on("error", () => { finish(new DesktopOAuthError("Desktop sign-in listener failed.")); void close(); });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error();
    const request = createDesktopOAuthRequest(webOrigin, `http://127.0.0.1:${address.port}${DESKTOP_OAUTH_CALLBACK_PATH}`);
    pending = request.pending;
    authorizeUrl = request.authorizeUrl;
    options.signal?.addEventListener("abort", abort, { once: true });
    if (options.signal?.aborted) { abort(); await close(); throw cancelled(); }
    timer = setTimeout(() => { finish(expired()); void close(); }, options.timeoutMs ?? config.oauth.requestTtlMs);
    return { authorizeUrl, pending, code, close };
  } catch {
    await close();
    throw new DesktopOAuthError("Could not start the Desktop sign-in listener.");
  }
}

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}
function token(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 16384 && !/\s/.test(value);
}
async function readJson(response: Response): Promise<Record<string, unknown>> {
  if (!response.body) throw new Error();
  const reader = response.body.getReader();
  let size = 0;
  const chunks: Uint8Array[] = [];
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) throw new Error();
      chunks.push(value);
    }
    return record(JSON.parse(Buffer.concat(chunks).toString("utf8")));
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}
async function postJson(
  fetcher: typeof fetch, url: string, body: object,
  options: { signal?: AbortSignal; accessToken?: string; timeoutMs?: number } = {},
): Promise<Record<string, unknown>> {
  const controller = new AbortController();
  const abort = () => controller.abort();
  options.signal?.addEventListener("abort", abort, { once: true });
  if (options.signal?.aborted) controller.abort();
  const timer = setTimeout(abort, options.timeoutMs ?? config.oauth.tokenTimeoutMs);
  try {
    const response = await fetcher(url, {
      method: "POST", headers: { "content-type": "application/json", accept: "application/json",
        ...(options.accessToken ? { authorization: `Bearer ${options.accessToken}` } : {}) },
      body: JSON.stringify(body), signal: controller.signal, credentials: "omit", redirect: "error", cache: "no-store",
    });
    if (!response.ok || response.redirected) { await response.body?.cancel(); throw new Error(); }
    return await readJson(response);
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", abort);
  }
}
function envelope(payload: Record<string, unknown>): Record<string, unknown> {
  if (payload.code !== 0) throw new Error();
  return record(payload.data);
}

/** OSIR tokens exist only on this Main stack; never stored, returned, logged, or sent to Anywhere. */
export async function exchangeDesktopOAuthCode(
  code: string, pending: DesktopOAuthPending, server: DesktopServerConnection,
  identity: DesktopIdentity, fetcher: typeof fetch,
  onIssued: (session: DesktopSessionPayload) => void, signal?: AbortSignal,
): Promise<DesktopSessionPayload> {
  let refreshToken: string | undefined;
  let accessToken: string | undefined;
  let session: DesktopSessionPayload | undefined;
  try {
    validateServer(server, identity);
    secureOrigin(identity.apiOrigin, identity.allowLoopbackHttp);
    const raw = await postJson(fetcher, `${identity.apiOrigin}/api/v1/auth/desktop/token`, {
      grant_type: "authorization_code", client_id: DESKTOP_OAUTH_CLIENT_ID, code,
      code_verifier: pending.verifier, redirect_uri: pending.redirectUri,
    }, { signal });
    const data = record(raw.data);
    // Capture refresh early so a malformed success response still gets best-effort revocation.
    if (token(data.refresh_token)) refreshToken = data.refresh_token;
    envelope(raw);
    if (!token(data.access_token) || !refreshToken || data.token_type !== "Bearer" ||
      typeof data.expires_in !== "number" || !Number.isInteger(data.expires_in) || data.expires_in <= 0 ||
      data.scope !== DESKTOP_OAUTH_SCOPE) throw new Error();
    accessToken = data.access_token;
    const assertion = envelope(await postJson(fetcher, `${identity.apiOrigin}/api/v1/auth/desktop/anywhere/assertion`, {}, { signal, accessToken }));
    if (!token(assertion.assertion) || assertion.token_type !== ASSERTION_TYPE ||
      assertion.expires_in !== 60 || assertion.audience !== "osir-anywhere-server") throw new Error();
    session = parseDesktopSession(await postJson(fetcher, `${server.serverUrl}/api/v2/auth/osir/desktop/exchange`, { assertion: assertion.assertion }, { signal }));
    // Transfer cleanup ownership before the independent source logout can await/cancel.
    onIssued(session);
    if (signal?.aborted) throw cancelled();
  } catch {
    if (signal?.aborted) throw (signal.reason instanceof DesktopOAuthError ? signal.reason : cancelled());
    throw new DesktopOAuthError("OSIR sign-in exchange failed. Check the identity service and Anywhere server, then retry.");
  } finally {
    if (refreshToken) {
      // Independent bounded signal: cancellation must not skip revoking the temporary OSIR grant.
      try { await postJson(fetcher, `${identity.apiOrigin}/api/v1/auth/logout`, { refresh_token: refreshToken }); } catch { /* best effort, no token/error output */ }
    }
    refreshToken = undefined;
    accessToken = undefined;
  }
  if (signal?.aborted) throw (signal.reason instanceof DesktopOAuthError ? signal.reason : cancelled());
  return session!;
}

type Attempt = { controller: AbortController; listener?: DesktopOAuthListener; done?: Promise<void>; timer: ReturnType<typeof setTimeout> };

/** Main-only coordinator shared by development and packaged builds. */
export class DesktopOAuthFlow {
  private active: Attempt | null = null;
  private stopped = false;
  constructor(private readonly options: DesktopIdentityOptions & {
    fetcher: typeof fetch;
    openExternal: (url: string) => Promise<unknown>;
    onResult: (result: DesktopOAuthMainResult, signal: AbortSignal) => boolean | void | Promise<boolean | void>;
    onDiscard: (session: DesktopSessionPayload, server: DesktopServerConnection) => Promise<void>;
    timeoutMs?: number;
  }) {}

  async start(server: DesktopServerConnection): Promise<{ authorizeUrl: string }> {
    if (this.stopped) throw cancelled();
    await this.cancel();
    if (this.stopped) throw cancelled();
    const controller = new AbortController();
    const attempt: Attempt = {
      controller,
      timer: setTimeout(() => controller.abort(expired()), this.options.timeoutMs ?? config.oauth.requestTtlMs),
    };
    this.active = attempt;
    try {
      const identity = resolveDesktopIdentity(this.options);
      validateServer(server, identity);
      attempt.listener = await listenDesktopOAuth(identity.webOrigin, { signal: controller.signal, timeoutMs: this.options.timeoutMs });
      if (controller.signal.aborted || this.active !== attempt) throw cancelled();
      const listener = attempt.listener;
      attempt.done = (async () => {
        let issued: DesktopSessionPayload | undefined;
        let accepted = false;
        try {
          const code = await listener.code;
          const credentials = await exchangeDesktopOAuthCode(code, listener.pending, server, identity, this.options.fetcher,
            session => { issued = session; }, controller.signal);
          if (this.active === attempt && !controller.signal.aborted) {
            accepted = await this.options.onResult({ status: "success", accessToken: credentials.accessToken, credentials, server }, controller.signal) === true;
          }
        } catch (error) {
          if (this.active === attempt && (!controller.signal.aborted || controller.signal.reason instanceof DesktopOAuthError && controller.signal.reason.message === expired().message)) {
            await this.options.onResult({ status: "error", error: error instanceof DesktopOAuthError ? error.message : "Desktop sign-in failed. Start sign-in again." }, controller.signal);
          }
        } finally {
          clearTimeout(attempt.timer);
          try {
            if (issued && !accepted) await this.options.onDiscard(issued, server);
          } finally {
            await listener.close();
            if (this.active === attempt) this.active = null;
          }
        }
      })();
      // Avoid an unhandled rejection even if a consumer's result callback fails.
      void attempt.done.catch(() => {});
      await this.options.openExternal(listener.authorizeUrl);
      if (controller.signal.aborted) throw cancelled();
      return { authorizeUrl: listener.authorizeUrl };
    } catch {
      controller.abort(cancelled());
      clearTimeout(attempt.timer);
      await attempt.listener?.close();
      await attempt.done?.catch(() => {});
      if (this.active === attempt) this.active = null;
      throw new DesktopOAuthError("Could not open OSIR sign-in. Start sign-in again.");
    }
  }

  async cancel(): Promise<void> {
    const active = this.active;
    this.active = null;
    if (!active) return;
    active.controller.abort(cancelled());
    clearTimeout(active.timer);
    await active.listener?.close();
    await active.done?.catch(() => {});
  }

  async shutdown(): Promise<void> {
    this.stopped = true;
    await this.cancel();
  }
}
