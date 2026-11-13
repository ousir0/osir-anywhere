// One recovery generation owns its requests and buffered wire events.
export class SessionRecoveryGuard {
  version = 0
  snapshotRequired = false
  private count = 0
  private bytes = 0
  private requests = new Set<AbortController>()

  private readonly deadlineMs: number
  private readonly maxEvents: number
  private readonly maxBytes: number

  constructor(deadlineMs = 15_000, maxEvents = 256, maxBytes = 4 * 1024 * 1024) {
    this.deadlineMs = deadlineMs
    this.maxEvents = maxEvents
    this.maxBytes = maxBytes
  }

  invalidate(): void {
    this.version += 1
    this.snapshotRequired = true
    this.clearBuffer()
    for (const request of this.requests) request.abort()
  }

  isCurrent(version: number): boolean { return version === this.version }

  snapshotApplied(version: number): void {
    if (this.isCurrent(version)) this.snapshotRequired = false
  }

  retain(wireBytes: number): boolean {
    if (this.count + 1 > this.maxEvents || this.bytes + wireBytes > this.maxBytes) {
      this.invalidate()
      return false
    }
    this.count += 1
    this.bytes += wireBytes
    return true
  }

  clearBuffer(): void { this.count = 0; this.bytes = 0 }

  async request<T>(read: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const controller = new AbortController()
    this.requests.add(controller)
    let timeout: ReturnType<typeof setTimeout> | undefined
    const aborted = new Promise<never>((_resolve, reject) => {
      controller.signal.addEventListener("abort", () => reject(new Error("Session recovery interrupted")), { once: true })
      timeout = setTimeout(() => controller.abort(), this.deadlineMs)
    })
    try {
      // Race as well as abort: a test transport or hung decoder may ignore the signal.
      return await Promise.race([read(controller.signal), aborted])
    } finally {
      clearTimeout(timeout)
      this.requests.delete(controller)
    }
  }
}
