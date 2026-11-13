"use client"

import * as React from "react"
import { Download } from "lucide-react"
import { useTranslations } from "next-intl"
import { toast } from "sonner"
import { useAuth } from "@/components/auth/auth-context"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Progress } from "@/components/ui/progress"
import { Spinner } from "@/components/ui/spinner"
import { getDesktopWorkbenchBridge, type DesktopUpdateState } from "@/features/desktop/bridge"

type UpdateContext = { state: DesktopUpdateState | null; open: () => void }
const Context = React.createContext<UpdateContext>({ state: null, open: () => undefined })

export function DesktopUpdateProvider({ children }: { children: React.ReactNode }) {
  const t = useTranslations("desktopUpdates")
  const { session, isAuthenticated, loading, screen } = useAuth()
  const serverUrl = !loading && isAuthenticated && screen === "app" ? session?.serverUrl?.trim() || null : null
  const sessionKey = serverUrl ? `${session?.userId}:${serverUrl}` : null
  const [snapshot, setSnapshot] = React.useState<{ sessionKey: string | null; state: DesktopUpdateState } | null>(null)
  const state = sessionKey && snapshot?.sessionKey === sessionKey ? snapshot.state : null
  const [pending, setPending] = React.useState(false)
  const [cancelling, setCancelling] = React.useState(false)
  const [manualOpen, setManualOpen] = React.useState(false)
  const generation = React.useRef(0)
  const accept = React.useCallback((next: DesktopUpdateState | null) => {
    if (next) setSnapshot((current) => !current || current.sessionKey !== sessionKey || next.revision >= current.state.revision
      ? { sessionKey, state: next } : current)
  }, [sessionKey])

  React.useEffect(() => {
    const updates = getDesktopWorkbenchBridge()?.updates
    if (!updates?.syncSession) return
    ++generation.current
    setPending(false)
    setCancelling(false)
    setManualOpen(false)
    let disposed = false
    const receive = (next: DesktopUpdateState | null) => { if (!disposed) accept(next) }
    const unsubscribe = updates.onState(receive)
    void updates.syncSession(serverUrl).then(receive).catch(() => undefined)
    return () => {
      ++generation.current
      disposed = true
      unsubscribe()
      void updates.syncSession(null).catch(() => undefined)
    }
  }, [accept, serverUrl])

  const perform = React.useCallback(async (action: "open" | "ignore" | "download" | "check") => {
    const updates = getDesktopWorkbenchBridge()?.updates
    if (!updates || !serverUrl) return
    const currentGeneration = generation.current
    setPending(true)
    try {
      const next = await (action === "check" ? updates.syncSession(serverUrl) : updates[action]())
      if (currentGeneration === generation.current) {
        accept(next)
        if (action === "ignore" && !next?.dialogOpen) setManualOpen(false)
      }
    } catch {
      if (currentGeneration === generation.current) toast.error(t("errors.actionFailed"))
    } finally {
      if (currentGeneration === generation.current) setPending(false)
    }
  }, [accept, serverUrl, t])
  const open = React.useCallback(() => {
    setManualOpen(true)
    if (state?.available && state.phase !== "downloaded") void perform("open")
  }, [perform, state?.available, state?.phase])
  const cancel = React.useCallback(async () => {
    const updates = getDesktopWorkbenchBridge()?.updates
    if (!updates || cancelling || state?.phase !== "downloading") return
    const currentGeneration = generation.current
    setCancelling(true)
    try {
      const next = await updates.cancel()
      if (currentGeneration === generation.current) accept(next)
    } catch {
      if (currentGeneration === generation.current) toast.error(t("errors.actionFailed"))
    } finally {
      if (currentGeneration === generation.current) setCancelling(false)
    }
  }, [accept, cancelling, state?.phase, t])
  const busy = pending || cancelling || state?.checking || state?.phase === "downloading" || state?.phase === "opening"
  const errorMessage = state?.errorDetail?.trim() || (state?.error ? t(`errors.${state.error}`) : null)
  const handoff = t(getDesktopWorkbenchBridge()?.platform === "darwin" ? "installerOpenedMac" : "installerOpenedWindows")
  const signatureNotice = state?.artifact ? t(state.artifact.systemSignatureDeclared === false
    ? state.artifact.platform === "darwin" ? "requiredNotarizedMac" : "requiredAuthenticodeWindows"
    : state.artifact.systemSignature === "unsigned"
    ? state.artifact.platform === "darwin" ? "unsignedMac" : "unsignedWindows"
    : state.artifact.systemSignature === "developer-id-notarized" ? "declaredNotarizedMac" : "declaredAuthenticodeWindows") : null
  const checkFailed = state?.error === "checkFailed"
  React.useEffect(() => {
    if (checkFailed && errorMessage) toast.error(errorMessage)
  }, [checkFailed, errorMessage])
  React.useEffect(() => {
    if (state?.phase === "downloaded") toast.message(handoff)
  }, [state?.phase, handoff])
  const progress = state?.totalBytes ? Math.min(100, Math.floor(state.downloadedBytes / state.totalBytes * 100)) : null

  return (
    <Context.Provider value={{ state, open }}>
      {children}
      <Dialog open={Boolean(state && (manualOpen || (state.available && state.dialogOpen)))}>
        <DialogContent
          showCloseButton={false}
          onPointerDownOutside={(event) => event.preventDefault()}
          onInteractOutside={(event) => event.preventDefault()}
          onEscapeKeyDown={(event) => event.preventDefault()}
        >
          <DialogHeader>
            <DialogTitle>{t(state?.checking ? "checking" : state?.available ? "title" : "checkTitle")}</DialogTitle>
            <DialogDescription>{t("description")}</DialogDescription>
          </DialogHeader>
          <div className="flex items-center justify-between gap-4 text-sm">
            <span>{t("currentVersion", { version: state?.currentVersion ?? "" })}</span>
            {state?.latestVersion ? <span>{t("latestVersion", { version: state.latestVersion })}</span> : null}
          </div>
          {state && (state.phase === "downloading" || state.phase === "opening") ? (
            <div className="flex flex-col gap-2" aria-live="polite">
              <Progress value={progress} aria-label={t("downloading")} />
              <p className="text-sm text-muted-foreground">
                {state.phase === "opening" ? t("opening") : progress === null
                  ? t("downloadedBytes", { size: formatBytes(state.downloadedBytes) })
                  : t("progress", { percent: progress, received: formatBytes(state.downloadedBytes), total: formatBytes(state.totalBytes ?? 0) })}
              </p>
            </div>
          ) : null}
          {errorMessage ? <p role="alert" className="break-words text-sm text-destructive">{errorMessage}</p> : null}
          {signatureNotice ? <p role="note" className="text-sm text-muted-foreground">{signatureNotice}</p> : null}
          {state?.phase === "downloaded" ? <p role="status" className="text-sm text-muted-foreground">{handoff}</p> : null}
          {state && !state.available && !state.error && !state.checking && state.latestVersion ? <p role="status" className="text-sm text-muted-foreground">{t("upToDate")}</p> : null}
          <DialogFooter>
            <Button variant="outline" disabled={busy} onClick={() => state?.available && state.phase !== "downloaded" ? void perform("ignore") : setManualOpen(false)}>{t(state?.available && state.phase !== "downloaded" ? "ignore" : "close")}</Button>
            {state?.phase === "downloading" ? <Button variant="outline" disabled={cancelling} onClick={() => void cancel()}>{t(cancelling ? "cancelling" : "cancel")}</Button> : null}
            <Button disabled={busy} onClick={() => void perform(!state?.available || state.error === "downloadNotConfigured" ? "check" : "download")}>
              {busy ? <Spinner /> : <Download data-icon="inline-start" />}
              {t(!state?.available || state.error === "downloadNotConfigured" ? "retryCheck" : state.phase === "downloaded" || state.error === "openFailed" ? "openInstaller" : "updateNow")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Context.Provider>
  )
}

export function DesktopUpdateButton() {
  const { state, open } = React.useContext(Context)
  const t = useTranslations("desktopUpdates")
  if (!state?.available && !state?.error) return null
  const label = t(state.available ? "entry" : "checkUnavailable")
  return (
    <Button variant="ghost" size="icon" className="relative shrink-0" onClick={open} title={label} aria-label={label}>
      <Download />
      <Badge variant="notification" className="absolute right-1 top-1 size-1.5 rounded-full p-0" aria-hidden="true" />
    </Button>
  )
}

function formatBytes(bytes: number): string {
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}
