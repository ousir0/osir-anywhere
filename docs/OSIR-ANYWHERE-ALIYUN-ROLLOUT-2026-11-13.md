# OSIR Anywhere 阿里云落地记录

日期：2026-11-13。用户已明确授权将 Anywhere 云端部署到现有阿里云主机，OSIR API 继续负责统一账号和控制台入口；不把 Anywhere 的数据库、消息中转和附件放进雨云主站。

**当前结论：云端首版已部署并完成真实 Chrome 登录验收，可在 `https://anywhere.osirclaw.com` 使用。** OSIR 控制台入口会打开新标签页，主站已登录时自动进入 Anywhere；刷新恢复、Anywhere 退出及再次复用主站登录已通过。当前没有在线 Connector，也没有真实模型对话验收。仅建议少量可信账号验证，不能据此宣布全面多端生产可用。

## 已验证现状

- 阿里云：x86_64、2 vCPU、总内存 1870 MiB，可用约 1104 MiB，Swap 已用约 580 MiB；根盘 40 GiB、剩余约 19 GiB。2026-11-13 13:18–13:20 北京时间短时观察，不是高峰容量证明。
- 已有 Nginx、Podman 4.9.4（docker 命令兼容入口）、其他业务与数据库。保护既有业务，不复用其数据库账号/表、Redis 或生命周期，不停止服务释放资源。
- 本机直连与旧跳板均被远端关闭；通过仓库规定的 Tailscale 雨云入口作为 SSH 转发可连接阿里云。雨云仅作连接跳板；任何主站身份功能发布仍走其正式发布流程。
- 独立域名 `anywhere.osirclaw.com` 已解析到阿里云，TLS 证书已签发至 2027-02-11；应用 HTTPS 虚拟主机已启用，无账号边界探针与真实 Chrome 登录均通过。

## 首版部署边界

- 本机构建 Next 静态页面；阿里云不运行 Next 编译器、Node SSR 或模型 Runtime。
- 单进程 FastAPI + 1 个事件工作线程，专属 PostgreSQL、Redis AOF/noeviction、附件持久目录；Redis 队列不得作为可清空缓存。
- 只绑定主机 loopback 后交给现有 Nginx 的独立虚拟主机；不公开数据库/Redis 端口。
- 以实际测量调整 CPU/内存/连接池/消息队列限额。此主机适合受限验证，不预先承诺用户数、可用性或生产峰值并发。
- 版本目录与 current 指针、独立环境凭据（0600）、启动服务、健康/就绪检查、可回退版本和备份均只作用于 OSIR Anywhere。
- 备份覆盖 PostgreSQL、Redis 持久数据和附件的一致性边界；只备份数据库不足以恢复尚在 Redis 的会话消息。保留策略先文档化，未确认用户数据保留期前不自动删除会话。

## 登录合同

桌面沿用独立 `osir-anywhere-desktop` + loopback PKCE；Web 必须使用另一个 client `osir-anywhere-web`，不放宽桌面 callback 规则。

1. 控制台新标签页或独立网页打开 Anywhere `/api/v2/auth/osir/web/start`。
2. Anywhere 产生 state、PKCE，Redis 保存短时事务，HttpOnly Cookie 绑定浏览器，跳转 OSIR `/auth/anywhere/authorize`。
3. OSIR 已登录时自动签发短期一次性授权码；未登录时正常登录并恢复授权。只返回到配置的精确 HTTPS callback。
4. Anywhere callback 服务端调用 OSIR `/api/v1/auth/anywhere/token` 换取专用 60 秒签名断言，严格验签和原子防重放后映射 member 账号。
5. 浏览器只收到 Anywhere HttpOnly 会话 Cookie，API access token 保留在页面内存；会话支持短期 token、刷新、单设备登出、过期和撤销，不向 Anywhere 提供 OSIR access/refresh token。

专用 API：GET `/api/v1/auth/anywhere/capabilities`；POST 网站鉴权 `/api/v1/auth/anywhere/authorize`；POST PKCE 换码 `/api/v1/auth/anywhere/token`。配置 `desktop_auth.anywhere.web_enabled` 与 `web_origin`，默认关闭。

## 并行分工和验收

- API：Web 专用授权码/断言、网站授权页和控制台新标签页入口。
- Anywhere Server：Web 回调、独立会话与撤销、OSIR-only 登录边界、实时通道鉴权。
- Anywhere Web：OSIR 登录模式、Cookie 恢复/内存 token/续期/登出、静态构建。
- 架构审查：原项目 PG/Redis/附件职责、消息持久性、多端同步、横扩和容量风险。
- 主任务：真实主机勘察、部署配置、备份/回退、跨仓库联调和最终公网验收。

测试数据库必须随机且名字含 `test`，绝不能指向生产或开发库。不得提交凭据或向公共 origin 推送。仅在实测通过后记录已完成；网页可访问、单元测试通过和真实远程 Agent 对话是三个不同的验收结果。

## 反思

迁移到另一台服务器解决的是主站资源隔离，并不会自动补齐会话撤销、消息持久性、多端权限或备份。首版先把这些边界验证清楚，再扩大使用范围。

## 用户补充：安装后的账号与模型交接

用户要求先记下、云端完成后再启动专门 Agent：OSIR Client 安装/启动 Anywhere 应复用已完成的账号连接，并将已配置供应商与模型能力适配到本地 Agent，尽量免手工配置。独立登录会话和模型凭据分别设计，不复制长期 token、不自动扩大设备权限。完整待办见 `OSIR-ANYWHERE-CLIENT-HANDOFF-BACKLOG-2026-11-13.md`。

## 部署过程与构建证据（最终状态见文末）

- 专属 PG18 / Redis8 / API systemd 服务均 active，空业务库已迁移到 `v2_44`。运行账号 `osir_anywhere_app` 与迁移管理员分离；容器数据库无宿主公网端口。
- 最终源上下文归档 SHA-256：`e94df35abd0f269d538216ae029e24ad1105e98dba5e748773635af644ab202a`；清单明确包含未提交代码，不把旧 Git HEAD 冒充本次实现。
- API 镜像 `localhost/osir-anywhere:cloud-20261113-r1`，ID `f6197731e2746b545f41b0de5d7393467259c8dbc5247c9f9942a5606fa1cf3a`，586,316,702 字节，非 root、只读根文件系统、384 MiB 限额、loopback `18180`。较大的 Claude SDK 留在服务端，不把云镜像大小当作桌面瘦身结果。
- Web 398 文件，压缩传输 8,302,874 字节，逐文件 SHA-256 已校验到版本化静态目录；不运行 Node SSR。
- Server 268 项回归、Web 53 项定向检查/类型/协议/导出通过；云端 loopback 12 项无账号探针通过。真实 SSO、设备授权、模型对话仍分开待验收。
- 2026-11-13 05:59:59 UTC 观测：MemAvailable 970 MiB、根分区余 16.93 GiB、Redis 1.63 MiB、AOF 写入正常、无淘汰。是空业务静态观测，不是并发性能基准。
- 专属五分钟资源巡检已启用，状态只存 root 私有文件；阈值为可用内存 400 MiB、余盘 6 GiB、Redis 36 MiB 或持久化失败。未配置外部通知和自动扩容，不自动删除会话/备份。
- 身份源使用基于实际线上 `d5bc231a945cc6540659de1142e2ea4659c9f926` 的独立候选 `/Users/ouwei/sub2api-anywhere-cloud-release-20261113`，原较旧工作区不用于覆盖生产。

## 首版仍存在的边界

- OSIR 主站退出或停用尚无向 Anywhere 推送的统一撤销通知；Anywhere 自身退出/本地停用/短 token/独立会话撤销有效，不能宣称全平台单点登出已实现。浏览器长期会话最长 7 天；扩大到外部用户前应补账号禁用/撤销回传。
- 尚无按用户的会话/附件配额、存储计费和自动保留期；Nginx 请求/连接/32 MiB body 限额不能替代存储配额。当前适合有限验证，需用容量结果决定上线范围，避免少量持续上传耗尽磁盘。
- 原生手机端未适配 OSIR 登录；桌面自动续期及模型交接仍属于后续客户端工作。Connector 离线时，云端历史可看但无法执行本地 Agent。

## 备份与恢复首次验收

- 自有 API 优雅暂停后，PG custom dump + Redis SAVE RDB + files 归档成功，API 在 finally 恢复并稳定运行。首次为未开放的空业务环境，没有中断真实用户会话。
- 备份 `backup-20261113T060604Z-67ae9ac103ce`，清单与四项文件 SHA-256 通过；独立 SSH 回取本机忽略目录（0700/0600）后再次完整校验通过，不含安装秘密。它是业务备份异地副本，完整灾备仍需独立私密保存密钥。
- 隔离恢复 `osir-anywhere-test-b9e3325ae40a4d9d` 成功，PG schema/对象/逐表计数、RDB 加载/校验和、附件引用检查通过。测试容器/内部网络按 ID+label 清理，报告保留。测试 PG 256 MiB/0.25CPU、Redis 96 MiB/0.25CPU 的 cgroup 实际限额已核验。
- 第一次隔离运行因 Podman4 network create 返回名称而非 ID 被正确拒绝，未启动恢复容器；修正为 inspect 取 ID 并同时验证名称/label 后重新执行成功。失败报告保留。
- 当前没有真实对话/附件，所以本次附件引用计数为零；不能称作真实用户对话恢复验收。

## OSIR API 构建冻结

- 精确源码提交 `47582156dfb89a61c9829e778b07e3a58ba44f18`（本地分支，无 push），包含线上基线和本次身份/入口/发布保护。干净工作树、完整来源审查、迁移摘要、变更记录、发布安全 115 项、升级关键测试通过。
- 通过核验的 Linux/amd64 Go 1.27.3 容器在本机构建，发布包 `20261113-osir-anywhere-47582156d-r1`；静态与二进制同源封存。
- 专属 Ed25519 私钥已在 OSIR API 主机受控目录生成，0600；发布包仅存私钥路径和公开 key ID，私钥内容不进包。既有桌面授权/支付/代理商配置一同封存，支付基线改为当前实际已合流的 `d5bc231a945cc6540659de1142e2ea4659c9f926`。
- 本段记录构建冻结时点；其后上传、预检、预热、切流及真实 SSO 均已完成，最终状态如下。

## 最终公网与真实浏览器验收（2026-11-13）

- OSIR API 标准发布 `20261113-osir-anywhere-47582156d-r1` 依次通过 upload、preflight-only、stage-only、cutover；源工作树保持干净且构建后未修改。预热与切流前分别完成数据库 custom dump 及 pg_restore 可读校验，既有支付、代理商域名及桌面授权门禁通过，没有手工修改线上 unit 或停服发布。
- 实际 Web 端口 `19094`，Web 与 scheduler 均运行 `47582156dfb89a61c9829e778b07e3a58ba44f18`，NRestarts=0；主站静态 current 指向相同 release。原 `d5bc231a945cc6540659de1142e2ea4659c9f926` Web 已在 2026-11-13 14:37:14 +0800 完成连接排空并转入冷备，冷备 timer active；程序、静态、hold 与回退材料保留。
- 阿里云 HTTPS 独立 vhost 已启用，公网 12 项鉴权/Origin/回调探针及静态品牌、安全响应头、私有 ready 禁止公开均通过；上游注册、密码登录与公开分享继续关闭。
- Chrome 使用用户已有主站登录，实际点击控制台「OSIR Anywhere」入口，新标签页自动完成回调，直接出现 `OSIR member` 工作台；没有复制浏览器令牌。实际刷新后恢复成功，Anywhere 自身退出回到登录页，再次点击 OSIR 登录可免密返回。没有测试主站退出后统一撤销，也没有测试原生手机登录。
- 首次浏览器验收发现旧品牌弹窗、上游安装包引导与原生手机扫码说明残留；已在 OSIR 模式修正，并明确手机先使用网页版、OSIR 桌面公开安装包/原生手机授权尚未开放。保留原项目许可证及来源说明，非 OSIR 构建保留上游行为。
- 最终 Web 静态 `cloud-20261113-web-r3`，410 文件，27,097,004 字节；压缩包 9,149,606 字节，SHA-256 `07557f60a50486c0257a636eb324aefeef97451bc2de6911edc6f9428c940e89`。保留前版 `_next/static` 资源，完整文件摘要与写入后读回校验通过，再按 expected-current 原子切换，未重启 API。类型检查、39 项授权定向回归及 OSIR static export 通过；新模板没有引入 Node SSR。
- 2026-11-13 06:49:28 UTC 实测：MemAvailable 988 MiB、Swap 已用 690 MiB、余盘 16.79 GiB，Redis 1.78 MiB/AOF 正常/零淘汰；API/PG/Redis 均 active，API NRestarts=0，就绪检查通过，无本机资源告警。属于单账号、无设备无会话条件的短时观测，不是负载容量证明。
- 本机证据位于忽略目录 `.local-dev/aliyun-deploy/`：`api-final-verification.json`、`api-cold-standby-final.log`、`aliyun-web-r3-activation.log`、`aliyun-post-sso-status.log`、`cloud-20261113-web-r3.manifest.json`、`osir-anywhere-sso-verified.jpg`。均不含可用认证令牌或私钥。
- 最终 Web 源码另存 `cloud-20261113-web-r3-source.tar.gz`，2,446,733 字节、SHA-256 `2e7bcc18ad15ae9ac5e6e2432c63b88f2850ae74f11b2cc3fb499e868e33fba8`；逐一匹配构建清单的源文件摘要，并记录 79 个现有直接依赖版本。它保留脏工作树的实际源内容，不冒称 Git HEAD，也不把直接依赖版本记录当作逐字节可复现构建保证。

## 接下来的本地协同

云端完成后已启动独立 Agent 核对 OSIR Client 现有授权、工具管理、供应商/代理和 Codex/Claude 配置入口，先产出有源码依据的最小交接合同与任务分工。目标是安装/打开后最少配置即可让本地 Agent 用已有模型完成真实对话；目前已安装 OSIR Client 0.1.9 和 Anywhere 本地开发包没有在本次云端阶段重新打包或更新。

仍需补齐主站禁用/退出撤销回传、每用户存储配额、自动备份与异机秘密保管、真实历史恢复、多设备与真实模型对话。既有首次空库备份/恢复不能替代这些结果。

## 后续 OSIRAPI 生产基线交接（2026-11-13）

来自升级维护会话 `升级 osirapi 至 v0.2.21` 的正式交接：主站已标准发布到
`20261113-i18n-2e2243396-r1`，完整 SHA
`2e22433967d9399ff73fc2d82d68412c54371518`；Web 19095、scheduler 19089
与静态 current 一致。上文 `47582156…` / Web 19094 是本项目首次授权落地
时的历史记录，不能再作为后续发布的实时 expected-current。

维护要求：未来 OSIRAPI 发布必须重新只读核实生产 Web/scheduler/static
基线，并证明候选包含 `2e22433967d9399ff73fc2d82d68412c54371518` 为祖先；
按锁文件安装依赖，执行维护仓新增的自动发布门禁。源码、锁文件、实际依赖
及构建产物必须一致，不能只核对 package.json 的版本声明。涉及国际化时，
必须执行真实带参数文案渲染，并检查主站/代理商年份与品牌替换、微信登录
按钮及桌面/Anywhere 授权；不能只以版本号判断故障。

该维护会话报告：主站、6 个代理商、API/wxapi 已使用 vue-i18n 11.4.16，
公网中英文各 759 条含参文案通过；两个独立 GrowthPay 历史 pay/pages
保持原状，各 662 条插值正常。历史支付站点不得因库版本不同就顺手重建。
这些是来源会话的验收结果，本会话没有重复全部检查。

本次仅更新维护与交接记录，没有修改升级工作树或封存包，没有重启/回滚
OSIRAPI 或原基线。旧实例只按已建立的冷备排空流程处理。阿里云 Anywhere
仍独立部署；其镜像版本、配套客户端验收不得与主站生产 SHA 混为一项。
