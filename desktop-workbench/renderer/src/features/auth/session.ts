import type { StoredSession } from "@/features/auth/types";
import { getDesktopWorkbenchBridge } from "@/features/desktop/bridge";

const SESSION_KEY = "aa.session.v1";
let nativeSession: StoredSession | null = null;
const usesNativeSession = () => Boolean(getDesktopWorkbenchBridge()?.auth?.refreshSession);

export function loadStoredSession(): StoredSession | null {
  if (typeof window === "undefined") return null;
  if (usesNativeSession()) {
    window.localStorage.removeItem(SESSION_KEY);
    return nativeSession;
  }
  try {
    const raw = window.localStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<StoredSession>;
    if (!parsed.accessToken || !parsed.userId || !parsed.role) return null;
    return {
      accessToken: parsed.accessToken,
      userId: parsed.userId,
      role: parsed.role,
      serverUrl: typeof parsed.serverUrl === "string" ? parsed.serverUrl : undefined,
    };
  } catch {
    return null;
  }
}

export function saveStoredSession(session: StoredSession): void {
  if (usesNativeSession()) {
    nativeSession = session;
    window.localStorage.removeItem(SESSION_KEY);
    return;
  }
  window.localStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

export function clearStoredSession(): void {
  nativeSession = null;
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(SESSION_KEY);
}
