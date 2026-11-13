# OSIR Anywhere 本地与云端连接验收

日期：2026-11-13。使用阿里云 `https://anywhere.osirclaw.com`。

## 已验证结果

| 链路 | 实测结果 |
| --- | --- |
| 桌面账号 | 已授权身份登录；系统加密存储恢复及真实刷新成功，access 有效期 300 秒 |
| 本机到云端 | 新独立设备认证成功、WSS 握手成功，账户 API 确认 online |
| 云端到本机 | 云端主动发现及账户 API 触发发现均得到本机响应，共 2 次 RPC |
| 断开回收 | WSS 关闭后账户 API 确认 offline，诊断进程 exit=0、stderr=0 |
| 新桌面安装包 | 实机恢复登录并进入工作台；等待明确连接，未拉起 OSIR Connector |
| 网页账号 | 当前 Chrome 新标签页自动恢复登录，设备列表与桌面一致 |
| 历史与目录 | 旧设备与新诊断设备的会话、项目、运行实例和消息计数均为 0 |

双向连接实测时间：2026-11-13 20:51:37（北京时间）。
独立诊断设备：`conn_6fb4255b5f21c56bb9ff5068`。
只响应空 `runtime.discover`，其余操作均拒绝，不创建历史扫描、文件或终端服务。
测试结束主动断开，因此界面显示离线是预期结果。

这证明真实账号下的认证、双向通道和断开状态正确。固定 Agent 对话、网页发消息、
Codex Desktop 同线程接管以及 OSIR Client 一次性交接需分别验证，不能由连接成功推导。

## 本地交付与证据

- 新包：`/Users/ouwei/OSIR Anywhere Idle Verified POC 20261113/mac-arm64/OSIR Anywhere.app`。
  普通文件共 420,111,083 字节（400.65 MiB）；未签名/公证，仅供本地验收。
- 脱敏结果：`.local-dev/connection-verification-20261113/result.json`。
- 桌面截图：`.local-dev/connection-verification-20261113/idle-workbench.png`。
- 网页截图：`.local-dev/connection-verification-20261113/cloud-workbench.png`。
- 定向桌面会话与门禁测试 25/25；native runner 与云端诊断相关测试合计 31/31 通过，ruff 与 diff 检查通过。
- 更完整过程：[客户端实施记录](OSIR-ANYWHERE-CLIENT-IMPLEMENTATION-2026-11-13.md)。

用户只授权空测试目录与新测试对话；不能开放 Home 或自动同步旧 Codex 历史。
隔离执行和单会话进展见 [原生隔离验证](OSIR-ANYWHERE-ACCEPTANCE-ISOLATION-2026-11-13.md)。

反思：双向连接已经实证；产品可用性仍须以实际对话和授权交接分别验收。

## Agent 对话的明确边界

本轮受限 Codex 完整初始化仍失败（最新 0.93 秒、exit=1、无已接受事件）；
不影响已完成的独立双向连接验证。云端单会话 adapter 没有实际运行，
网页发送、真实回复和 Codex Desktop 接管均未验收。
当前安装包仅为已验证 gate/登录 POC；不要据此开放 Home 或同步旧会话。
