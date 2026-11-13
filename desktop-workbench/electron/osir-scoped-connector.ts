import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import fs from "node:fs";
import type { PublicDesktopSession } from "./desktop-session";

const ORIGIN = "https://anywhere.osirclaw.com";
const ROOT = "/Users/ouwei/agents-anywhere";
const CLI = "/private/tmp/osir-compat-cli-n7c578iu/codex";
type Ready = { connectorId: string; runtimeId: string; projectId: string; workspace: string };

/** Local development only. Owns a separate, bounded test runtime, never M0. */
export class OsirScopedConnector {
  private child: ChildProcessWithoutNullStreams | null = null;
  private ready: Ready | null = null;
  private starting: Promise<Ready> | null = null;
  private stopping: Promise<void> | null = null;
  constructor(private readonly options: {
    configPath: string;
    refresh: () => Promise<PublicDesktopSession | null>;
    fetcher: typeof fetch;
    log: (message: string) => void;
    project?: boolean;
    resolveProxy?: () => Promise<string>;
  }) {}

  start(): Promise<Ready> {
    if (this.stopping) return Promise.reject(new Error("测试连接正在断开，请稍后重试。"));
    if (this.ready && this.child) return Promise.resolve(this.ready);
    if (this.child && !this.starting) return Promise.reject(new Error("上次测试连接仍在退出。"));
    return this.starting ??= this.launch().finally(() => { this.starting = null; });
  }

  private async launch(): Promise<Ready> {
    const saved = JSON.parse(fs.readFileSync(this.options.configPath, "utf8"));
    if (saved.serverUrl !== ORIGIN || (!this.options.project && saved.syncExistingOnConnect !== false) ||
        !/^conn_[A-Za-z0-9_-]{1,128}$/.test(saved.connectorId) ||
        typeof saved.connectorToken !== "string" || saved.connectorToken.length < 20) {
      throw new Error("测试连接要求已有 OSIR 设备绑定，且关闭既有会话同步。没有启动普通 Connector。");
    }
    const session = await this.options.refresh();
    if (!session || session.server.serverUrl !== ORIGIN) throw new Error("请先登录当前 OSIR Anywhere 服务。 ");
    const route = await this.options.resolveProxy?.() ?? "DIRECT";
    const localProxy = /^PROXY (127\.0\.0\.1|localhost):(\d+)(?:;|$)/.exec(route);
    const desktopProxy = localProxy ? `http://${localProxy[1]}:${localProxy[2]}` : null;
    const child = spawn(`${ROOT}/connector/.venv/bin/python`, ["-m", this.options.project
      ? "connector.server.osir_project_connection" : "connector.server.osir_scoped_connection"], {
      cwd: `${ROOT}/connector`,
      env: { PATH: "/usr/bin:/bin", HOME: this.options.project ? "/Users/ouwei" : `${ROOT}/.local-dev/connection-verification-20261113`, PYTHONNOUSERSITE: "1" },
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.child = child;
    // Secrets stay in the pipe; no argv/env/log or additional credential copy.
    child.stdin.write(JSON.stringify({ accessToken: session.accessToken,
      desktopDevice: { serverUrl: ORIGIN, connectorId: saved.connectorId, connectorToken: saved.connectorToken },
      syncExistingOnConnect: false, compatibilityCli: CLI,
      ...(this.options.project ? { projectWorkspace: "/Users/ouwei/cc-switch-osir-client", desktopProxy } : {}) }) + "\n");
    return new Promise<Ready>((resolve, reject) => {
      let pending = "";
      const timer = setTimeout(() => {
        child.stdin.end("stop\n");
        reject(new Error("测试连接准备超时；已请求断开。"));
      }, 110000);
      child.stderr.on("data", () => {}); // Native/network stderr never enters user logs.
      child.stdout.on("data", (chunk: Buffer) => {
        pending += chunk.toString("utf8");
        if (pending.length > 16384) { child.stdin.end("stop\n"); return; }
        for (let split; (split = pending.indexOf("\n")) >= 0;) {
          const line = pending.slice(0, split); pending = pending.slice(split + 1);
          try {
            const event = JSON.parse(line);
            if (event.phase === "scoped-connection-ready") {
              this.ready = { connectorId: event.connectorId, runtimeId: event.runtimeId,
                projectId: event.projectId, workspace: event.workspace };
              clearTimeout(timer); resolve(this.ready);
              this.options.log(this.options.project ? "已连接 OSIR 云端，正在分批同步已授权项目的 Codex 会话。"
                : "授权测试目录已连接 OSIR 云端；仅同步本次新建的文字会话。");
            } else if (event.phase === "scoped-turn-synced") {
              this.options.log(`测试会话已同步：${String(event.sessionId).replace(/[^A-Za-z0-9_-]/g, "")}，${Number(event.messages)} 条消息。`);
            } else if (event.phase === "scoped-connection-failed") {
              clearTimeout(timer);
              reject(new Error(event.code === "osir_model_binding_unavailable"
                ? "请打开支持模型联动的 OSIR 客户端，确认 Codex 已连接后再重试。"
                : "测试连接准备或执行失败；没有启动普通 Connector。"));
            }
          } catch { /* No untrusted output is rendered or logged. */ }
        }
      });
      child.once("error", () => { clearTimeout(timer); reject(new Error("无法启动测试连接。")); });
      child.once("close", (code) => {
        clearTimeout(timer);
        if (this.child === child) { this.child = null; this.ready = null; }
        this.options.log("授权测试目录连接已关闭。");
        reject(new Error(`测试连接已结束（${code ?? "signal"}）。`));
      });
    });
  }

  stop(): Promise<void> {
    return this.stopping ??= this.close().finally(() => { this.stopping = null; });
  }

  private async close(): Promise<void> {
    const child = this.child;
    const selected = this.ready;
    if (!child) return;
    child.stdin.end("stop\n");
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("测试执行仍在退出，请等待本地限制期限结束。")), 55000);
      child.once("close", () => { clearTimeout(timer); resolve(); });
    });
    if (!selected) return;
    // Refresh via the SAME app manager; do not race a second session store.
    const session = await this.options.refresh();
    if (!session || session.server.serverUrl !== ORIGIN) throw new Error("本机已断开；云端 Runtime 状态需重新登录后确认。");
    const response = await this.options.fetcher(`${ORIGIN}/api/v2/connectors/${selected.connectorId}/runtimes/${selected.runtimeId}/active`, {
      method: "PUT", headers: { Authorization: `Bearer ${session.accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ active: false }), credentials: "omit", redirect: "error", signal: AbortSignal.timeout(15000),
    });
    if (!response.ok || (await response.json()).active !== false) throw new Error("本机已断开；云端停用确认失败。");
  }
}
