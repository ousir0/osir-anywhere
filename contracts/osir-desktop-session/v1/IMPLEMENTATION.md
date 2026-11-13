# 实施交接（2026-11-13）

## 状态与发布依赖

本轮源码已实现并通过下列检查，**未部署云端、未重打包或启动真实安装版**。
云端 r1 没有本合同的三个 desktop 路由；新版 Desktop 已直接调用新接口，
**没有自动退回旧 300 秒会话**。因此必须先审查、升级配套 Anywhere Server，
再重建并发布 Desktop。旧客户端的 `/auth/osir/exchange` 仍保留兼容。

Renderer 本轮有修改，之前成功的 `build:web` 和精简 POC 不能作为最终产物；
主代理需重新构建 renderer / Main / 安装包。本轮未修改默认地址、打包脚本或 CHANGELOG。

## 实现文件

- Server：`agent_server/api/osir_auth.py` 新增 desktop exchange/refresh/logout；
  `services/osir_desktop_auth.py` 管身份与账号状态；`infra/osir_sessions.py`
  新增独立 desktop 命名空间；`core/auth.py` 增加受众/用途与专用 refresh 派生；
  `deps.py` 对 HTTP/WebSocket 的 desktop access 校验正确 registry。
- Main：`electron/desktop-session.ts` / 测试负责 safeStorage 加密原子文件、
  7 天绝对截止、单飞刷新、退出并发防复活、加密待撤销记录及错误脱敏。
  `desktop-oauth.ts` / 测试换取完整 native session；`main.ts` 仅发布 access，
  Flow 负责撤销未接收的新会话并加密保留失败重试，登录前/退出时停止本机 Connector。
- IPC / renderer：`preload.ts`、`features/desktop/bridge.ts`、
  `components/auth/auth-context.tsx`、`features/auth/session.ts` 完成恢复、
  到期前/唤醒续期与退出；原生模式 access 只放内存，清理旧 localStorage access。
- 显式设备操作：`features/desktop/desktop-connector-context.tsx` 登录只恢复元数据；
  `components/onboarding/desktop-onboarding-page.tsx` 要求明确允许连接并提供不连接入口。
  为封堵启动后台的旧自动连接路径，额外最小修改 `electron/backend/protocol.ts`、
  `backend/state.ts`：Main 传 `requireExplicitConnection=true`，不启动已保存设备。
  同 owner/origin 的已有绑定仍保留；工作目录不构成文件系统 sandbox。

## 验证结果

- 隔离 Server：183 passed（desktop session、原桌面断言、Web SSO、架构边界、日志脱敏）。
  命令：从仓库根运行 `server/.venv/bin/python server/tests/run_osir_auth_tests.py
  tests/test_osir_desktop_session.py tests/test_osir_web_auth.py tests/test_osir_auth.py
  tests/test_architecture_boundaries.py tests/test_osir_logging.py`。
  Runner 新建随机含 `test` 名称的 PostgreSQL DB 与随机独立角色/密码，
  子进程不继承业务配置；finally 删除数据库和角色。最后一轮 DB 为
  `agents_anywhere_test_osir_048c35e42c80`，脚本正常退出并清理。Redis 为进程内合成实例。
- Main：TypeScript 编译通过；全部 `dist/electron/*.test.js` 和
  `dist/electron/backend/*.test.js`：182 passed、1 skipped、0 failed（含下方 P2 修复的完整 Main 回归）。
  覆盖 OAuth loopback/取消、IPC 不发送 refresh、安全存储不可用、重启恢复、
  单飞、离线退出、退出/刷新竞争、禁止启动旧 Connector。
- Renderer：类型检查通过；`desktop-persistent-auth`、`desktop-onboarding-page`、
  `desktop-oauth-cleanup`、`desktop-connector-consent` 四组定向测试：10 passed。
- 本轮新增/主要服务端文件 ruff 通过，`git diff --check` 通过。
  `deps.py` 全文件 ruff 仍有既存两个 FastAPI `Depends` 的 B008，未扩展处理。
- TS/headless 检查使用本机 Node 26.13.0。已有 Homebrew Node 22 因动态库缺失无法启动；
  本轮未修改系统 Node。声明支持的 Node 22 与真实 Electron 验证由主代理最终构建负责。

## 明确缺口

1. 未对 r1 云端部署新路由；未验证真实系统安全存储、浏览器授权到新云端、
   跨 5 分钟/重启/离线恢复和真实安装包。不能用 headless 成功代替这些验收。
2. Client 自动交接 assertion 尚未接入；只接受现有独立 desktop 浏览器断言。
   主站退出即时撤销所有 Anywhere 会话仍需要独立 backchannel 工作。
3. 账号退出只停止受管理的本机 Connector，不等于撤销所有设备凭据。
   安全存储失败或服务器不可达会明确报退出未完成/撤销待处理。
4. 本轮不进行生产设备 Agent 对话；没有实现文件系统 sandbox。
5. 主代理负责最终 CHANGELOG、版本/配套发布记录、打包默认值/脚本与真实本地验收。


## 独立审查 P2 收尾

- 登录 IPC 在健康检查/打开新 OAuth 前执行 `prepareLogin()`，原进程中离线退出后
  恢复网络可直接重试；旧 refresh 只发到旧 origin，失败保留记录、拒绝新授权。
- Exchange 一拿到 Desktop 凭据就交给 Flow 管理清理所有权；源站 logout 等待中取消、
  exchange 响应时取消、Main accept 前/后取消或 Main 接收失败，都撤销未交付会话。
  Main 明确返回是否接收，成功交付不撤销。撤销请求有独立 10 秒上限，不继承取消 signal。
- 未接收凭据先写独立 `.revocations` 加密队列，失败保留原 refresh；恢复/登录时排空。
  队列不覆盖旧 active/tombstone，成功撤销仅移除对应 origin/token。
  加密和网络同时不可用时仅能保留进程内重试，无法保证进程丢失后的持久回收；无明文降级。
- 合成回归执行真实 Main IPC/回调、实际 OAuth Flow 与 session manager，身份/Anywhere
  请求为 mock，只有本地 loopback callback 使用真实 HTTP。覆盖跨源站、断网恢复、
  五个取消窗口、失败重试、密文/0600、不暴露 refresh、10 秒超时。
- 最后一轮全 Main 日志：`/tmp/osir-desktop-session-main-tests-p2.log`。
  本轮 P2 未改 renderer、Server、默认地址、打包脚本或 CHANGELOG；Server 写集可冻结。
  仍需基于先前 renderer 变更及本轮 Main 变更进行最终重建。

- Halley 补充复核：网关 401/403 不代表云端 sid 已撤销。现仅认可 logout 的无重定向
  204；200/401/403/503 均保留 tombstone/队列。新增四组跨 origin、prepareLogin、
  refresh-drain 与后续 204 恢复回归；refresh 本身的 401/403 仍清除失效本地会话。
- Halley 已独立复跑原两项 P2 的 7 个完整流程回归并确认全部通过。

- 最终只读复核：Halley 确认原两项及补充 P2 均解除。另独立内存加载真实 TS
  7/7 验证（200/401/403/503/redirected204 保留待撤销及原 origin；refresh401/403
  清除活跃会话）通过，复核期间源码未变。本次 Desktop session 写集可冻结。
  该结论仅限源码/合成回归，不代表部署或真实客户端端到端已通过。
