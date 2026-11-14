import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import type { DesktopServerConnection } from "./desktop-server";

export type DesktopSessionPayload = {
  accessToken: string; tokenType: "Bearer"; expiresIn: 300; refreshToken: string;
  refreshExpiresIn: number; identity: { issuer: string; subject: string; userId: string };
};
export type PublicDesktopSession = { accessToken: string; expiresIn: number; server: DesktopServerConnection };
type Stored = { version: 1; server: DesktopServerConnection; refreshToken: string; expiresAt: number; pendingLogout: boolean };
type SecureStorage = {
  isEncryptionAvailable(): boolean; encryptString(value: string): Buffer; decryptString(value: Buffer): string;
  getSelectedStorageBackend?(): string;
};
const SESSION_ERROR = "Desktop session unavailable. Sign in again or check your connection.";
const validToken = (value: unknown): value is string => typeof value === "string" && value.length > 0 && value.length <= 16384 && !/\s/.test(value);
const validRefresh = (value: unknown): value is string => typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
class SessionRejected extends Error {}

export function parseDesktopSession(value: unknown): DesktopSessionPayload {
  const data = value as Partial<DesktopSessionPayload> | null;
  if (!data || !validToken(data.accessToken) || data.tokenType !== "Bearer" || data.expiresIn !== 300 ||
      !validRefresh(data.refreshToken) || !Number.isInteger(data.refreshExpiresIn) ||
      data.refreshExpiresIn! < 1 || data.refreshExpiresIn! > 604800 ||
      !data.identity || data.identity.issuer !== "https://osirclaw.com" ||
      typeof data.identity.subject !== "string" || !/^[0-9]+$/.test(data.identity.subject) || !validToken(data.identity.userId)) throw new Error(SESSION_ERROR);
  return data as DesktopSessionPayload;
}

export class DesktopSessionStore {
  constructor(private readonly file: string, private readonly safeStorage: SecureStorage) {}

  private available(): void {
    if (!this.safeStorage.isEncryptionAvailable() || this.safeStorage.getSelectedStorageBackend?.() === "basic_text") {
      throw new Error("Secure system storage is unavailable. Desktop sign-in cannot be persisted.");
    }
  }
  read(): Stored | null {
    this.available();
    try {
      const data = JSON.parse(this.safeStorage.decryptString(fs.readFileSync(this.file))) as Stored;
      if (data.version !== 1 || !validRefresh(data.refreshToken) || !Number.isFinite(data.expiresAt) || data.expiresAt < 1 || typeof data.pendingLogout !== "boolean" ||
          !data.server || data.server.apiNamespace !== "/api/v2" || typeof data.server.serverUrl !== "string" ||
          typeof data.server.oauthWebOrigin !== "string") throw new Error();
      const url = new URL(data.server.serverUrl);
      if (url.origin !== data.server.serverUrl || url.username || url.password ||
          !(url.protocol === "https:" || url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname))) throw new Error();
      return data;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw new Error(SESSION_ERROR);
    }
  }
  readRevocations(): Stored[] {
    this.available();
    try {
      const values: unknown = JSON.parse(this.safeStorage.decryptString(fs.readFileSync(`${this.file}.revocations`)));
      if (!Array.isArray(values)) throw new Error();
      return values.map(value => {
        const data = value as Stored;
        const url = new URL(data.server.serverUrl);
        if (data.version !== 1 || !validRefresh(data.refreshToken) || !Number.isFinite(data.expiresAt) || data.expiresAt < 1 ||
            data.pendingLogout !== true || data.server.apiNamespace !== "/api/v2" || typeof data.server.oauthWebOrigin !== "string" ||
            url.origin !== data.server.serverUrl || url.username || url.password ||
            !(url.protocol === "https:" || url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname))) throw new Error();
        return data;
      });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw new Error(SESSION_ERROR);
    }
  }
  writeRevocations(values: Stored[]): void { this.writeEncrypted(`${this.file}.revocations`, values); }
  write(data: Stored): void { this.writeEncrypted(this.file, data); }
  private writeEncrypted(file: string, data: unknown): void {
    this.available();
    const encrypted = this.safeStorage.encryptString(JSON.stringify(data));
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    const temp = `${file}.${randomBytes(12).toString("hex")}.tmp`;
    try {
      fs.writeFileSync(temp, encrypted, { mode: 0o600, flag: "wx" });
      fs.renameSync(temp, file);
    } finally { try { fs.unlinkSync(temp); } catch { /* already moved */ } }
  }
  clear(): void { try { fs.unlinkSync(this.file); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; } }
}

export class DesktopSessionManager {
  private handoffIdentity: DesktopSessionPayload["identity"] | null = null;
  /** Native-only snapshot; a restored session must be refreshed before use. */
  identityForHandoff(): { generation: number; identity: DesktopSessionPayload["identity"] | null } {
    return { generation: this.generation, identity: this.handoffIdentity ? { ...this.handoffIdentity } : null };
  }
  private current: Stored | null = null;
  private flight: Promise<PublicDesktopSession | null> | null = null;
  private generation = 0;
  private revocationFlight: Promise<void> | null = null;
  private unrecordedRevocations: Stored[] = [];
  private controller: AbortController | null = null;
  constructor(private readonly store: DesktopSessionStore, private readonly fetcher: typeof fetch) {}

  accept(session: DesktopSessionPayload, server: DesktopServerConnection): PublicDesktopSession {
    const payload = parseDesktopSession(session);
    if (this.unrecordedRevocations.length) throw new Error("Server sign-out is pending. Reconnect before signing in again.");
    if (this.store.readRevocations().some(value => value.expiresAt > Date.now())) throw new Error("Server sign-out is pending. Reconnect before signing in again.");
    const previous = this.store.read();
    if (previous?.pendingLogout && previous.expiresAt > Date.now()) throw new Error("Server sign-out is pending. Reconnect before signing in again.");
    const saved: Stored = { version: 1, server, refreshToken: payload.refreshToken,
      expiresAt: Date.now() + payload.refreshExpiresIn * 1000, pendingLogout: false };
    this.store.write(saved);
    this.generation++;
    this.controller?.abort();
    this.current = saved;
    this.handoffIdentity = { ...payload.identity };
    return { accessToken: payload.accessToken, expiresIn: 300, server };
  }

  /** Login and restore both drain revocations against the original saved origin. */
  async prepareLogin(): Promise<void> {
    if (this.revocationFlight) return this.revocationFlight;
    const generation = this.generation;
    const work = (async () => {
      if (this.unrecordedRevocations.length) {
        this.store.writeRevocations([...this.store.readRevocations(), ...this.unrecordedRevocations]);
        this.unrecordedRevocations = [];
      }
      for (const saved of this.store.readRevocations()) {
        if (saved.expiresAt > Date.now()) await this.post(saved.server, "logout", saved.refreshToken);
        this.removeRevocation(saved);
      }
      const saved = this.current ?? this.store.read();
      if (saved?.pendingLogout) {
        if (saved.expiresAt > Date.now()) await this.post(saved.server, "logout", saved.refreshToken);
        if (generation === this.generation) { this.current = null; this.store.clear(); }
      }
    })().catch(() => { throw new Error("Server sign-out is pending. Check your connection and retry sign-in."); });
    this.revocationFlight = work;
    try { await work; } finally { if (this.revocationFlight === work) this.revocationFlight = null; }
  }

  private removeRevocation(saved: Stored): void {
    this.store.writeRevocations(this.store.readRevocations().filter(value =>
      value.refreshToken !== saved.refreshToken || value.server.serverUrl !== saved.server.serverUrl));
  }

  async refresh(server: DesktopServerConnection): Promise<PublicDesktopSession | null> {
    if (this.flight) return this.flight;
    const generation = this.generation;
    const controller = new AbortController();
    this.controller = controller;
    const work = (async () => {
      await this.prepareLogin();
      if (generation !== this.generation || controller.signal.aborted) throw new Error(SESSION_ERROR);
      const saved = this.current ?? this.store.read();
      if (!saved) { this.handoffIdentity = null; return null; }
      if (saved.expiresAt <= Date.now()) { this.current = null; this.handoffIdentity = null; this.store.clear(); return null; }
      if (saved.pendingLogout) {
        this.handoffIdentity = null;
        await this.post(saved.server, "logout", saved.refreshToken, controller.signal);
        if (generation === this.generation) this.store.clear();
        return null;
      }
      if (saved.server.serverUrl !== server.serverUrl || saved.server.apiNamespace !== server.apiNamespace) throw new Error(SESSION_ERROR);
      const result = parseDesktopSession(await this.post(saved.server, "refresh", saved.refreshToken, controller.signal));
      if (generation !== this.generation || controller.signal.aborted) throw new Error(SESSION_ERROR);
      const next = { ...saved, refreshToken: result.refreshToken,
        expiresAt: Math.min(saved.expiresAt, Date.now() + result.refreshExpiresIn * 1000) };
      this.store.write(next);
      this.current = next;
      this.handoffIdentity = { ...result.identity };
      return { accessToken: result.accessToken, expiresIn: result.expiresIn, server: saved.server };
    })().catch(error => {
      if (error instanceof SessionRejected && generation === this.generation) {
        this.current = null;
        this.handoffIdentity = null;
        this.store.clear();
      }
      throw new Error(SESSION_ERROR);
    });
    this.flight = work;
    try { return await work; } finally { if (this.flight === work) this.flight = null; if (this.controller === controller) this.controller = null; }
  }

  async logout(): Promise<{ pending: boolean }> {
    this.handoffIdentity = null;
    const generation = ++this.generation;
    this.controller?.abort();
    let saved = this.current;
    this.current = null;
    try { saved ??= this.store.read(); }
    catch { this.store.clear(); throw new Error(SESSION_ERROR); }
    if (!saved) return { pending: false };
    if (saved.expiresAt <= Date.now()) { this.store.clear(); return { pending: false }; }
    const pending = { ...saved, pendingLogout: true };
    let recorded = true;
    try { this.store.write(pending); }
    catch { recorded = false; this.store.clear(); }
    try {
      await this.post(saved.server, "logout", saved.refreshToken);
      if (generation === this.generation) this.store.clear();
      return { pending: false };
    } catch {
      if (!recorded) {
        this.unrecordedRevocations.push(pending);
        throw new Error(SESSION_ERROR);
      }
      return { pending: true };
    }
  }

  async reject(session: DesktopSessionPayload, server: DesktopServerConnection): Promise<void> {
    const payload = parseDesktopSession(session);
    let saved = this.current;
    try { saved ??= this.store.read(); } catch { /* still try revocation if encryption is unavailable */ }
    if (saved?.refreshToken === payload.refreshToken && saved.server.serverUrl === server.serverUrl) {
      await this.logout();
      return;
    }
    // An unaccepted grant has its own encrypted queue; never overwrite an older login/tombstone.
    const pending: Stored = { version: 1, server, refreshToken: payload.refreshToken,
      expiresAt: Date.now() + payload.refreshExpiresIn * 1000, pendingLogout: true };
    let recorded = false;
    try {
      const values = this.store.readRevocations();
      if (!values.some(value => value.refreshToken === pending.refreshToken && value.server.serverUrl === server.serverUrl)) {
        this.store.writeRevocations([...values, pending]);
      }
      recorded = true;
    } catch { /* encryption unavailable: never fall back to plaintext */ }
    try {
      await this.post(server, "logout", payload.refreshToken);
      if (recorded) this.removeRevocation(pending);
    } catch {
      if (!recorded) {
        this.unrecordedRevocations.push(pending);
        throw new Error("Desktop sign-out could not be saved securely. Check your connection and retry.");
      }
      // Otherwise the encrypted refresh remains queued for the next restore/login attempt.
    }
  }

  private async post(server: DesktopServerConnection, operation: "refresh" | "logout", refreshToken: string, signal?: AbortSignal): Promise<unknown> {
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) controller.abort();
    const timer = setTimeout(abort, 10000);
    try {
      const response = await this.fetcher(`${server.serverUrl}/api/v2/auth/osir/desktop/${operation}`, {
        method: "POST", headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ refreshToken }), signal: controller.signal, credentials: "omit", redirect: "error", cache: "no-store",
      });
      if (operation === "logout") {
        await response.body?.cancel();
        // Only the application's idempotent 204 acknowledges revocation. Gateway
        // 401/403/5xx must retain the tombstone; they do not prove the sid is gone.
        if (response.status !== 204 || response.redirected) throw new Error();
        return null;
      }
      if (response.status === 401 || response.status === 403) { await response.body?.cancel(); throw new SessionRejected(); }
      if (!response.ok || response.redirected) { await response.body?.cancel(); throw new Error(); }
      if (!response.body) throw new Error();
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > 65536) throw new Error();
          chunks.push(value);
        }
        return JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
    } finally { clearTimeout(timer); signal?.removeEventListener("abort", abort); }
  }
}
