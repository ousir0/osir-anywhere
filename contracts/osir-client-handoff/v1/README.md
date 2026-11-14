# OSIR Client handoff v1

状态：**合同定版，配套实现中，未完成真实安装互操作验收、未上线。** 本目录只增加协议、
Schema、合成 fixtures；Client native DTO/authorize 已有独立改动，API 三 route 的本地
实现已写入配套仓库，Anywhere/transport 配套仍在推进。不代表完整入口或正式安装包已支持，不得据此部署。

依据：[交接设计 §4.1/§4.2](../../../docs/OSIR-ANYWHERE-CLIENT-HANDOFF-DESIGN-2026-11-13.md)
与 [Desktop session 合同](../../osir-desktop-session/v1/README.md)。本合同补齐前者的
字段和状态机，并提出对后者 exchange 请求的扩展；**未修改现有 session 合同或业务**。

## 1. 本次产品决定优先

最新产品决定覆盖旧设计 §4.2 的 `anywhere:handoff` scope 迁移/再次浏览器授权流程：
用户已经登录 Client 后，点击安装/打开并连接 Anywhere，不再要求登录或重复配置。
专用、显式启用的第一方 handoff authorize 接口，接受当前有效的
`token_use=desktop, client_id=osir-desktop, aud=osir-account-api` 源 session，
要求其 scope **包含完整独立词项 `account:read`**。其他已有合法 Client scopes 可保留，
不添加 `identity:read`，不篡改旧 token/grant，不新增 scope 前置门槛。
客户端识别新能力后才能显示/触发此操作。安装/打开动作须明确表达用当前 Client
账号登录、连接本机及使用已配置工具；仅后台恢复登录、页面加载、下载完成或 capability
探测不得触发。此用户动作覆盖下面固定三项委托：

```json
["identity", "connect-local", "bootstrap-configured-tools"]
```

它们以固定顺序完整出现，不允许子集、额外值或重复值；写入 authorize 和签名 claims。
这里定版的是该明确用户动作下的授权策略，不是静默授予所有 `account:read` API
同等能力。旧 `/auth/desktop/anywhere/assertion` 仍仅接受
`osir-anywhere-desktop + identity:read`；Web、普通账户 JWT、API key 和其他 client
不能调用新 authorize。

**确切技术边界：**现有 `account:read` 原本不包含跨产品身份委托，新专用路由使这类
源会话获得该额外用途，必须作为有意的服务端策略变更审查。Bearer、`client_id` 或
body 的 `actions` 都不能让 API 远程证明一次真实点击、正版二进制或本机 PID。
API 能检查 session/账号/绑定；可信原生交互与双向 IPC 校验负责接收应用和用户动作。
持有被盗且仍有效的这类源 token 的攻击者也可能构造自己的握手；PKCE 本身不能消除
这个风险。本合同不虚构客户端 attestation，也不因此恢复旧提案的再次登录要求。

## 2. 固定端点、封装和限额

OSIR origin 固定 `https://osirclaw.com`，只新增下面三个 route；不得接受调用方提供的
issuer、兑换 URL、redirect/callback 或目标站点。所有 JSON 使用 UTF-8。

| 方法/路径 | 请求 | 成功 Schema |
| --- | --- | --- |
| GET `/api/v1/auth/desktop/anywhere/handoff/capabilities` | 无 body、query、Authorization 或 Cookie | `schema.json#/$defs/capabilitiesResponse` |
| POST `/api/v1/auth/desktop/anywhere/handoff/authorize` | 唯一源 Client Bearer；`schema.json#/$defs/authorizeRequest` | `schema.json#/$defs/authorizeResponse` |
| POST `/api/v1/auth/desktop/anywhere/handoff/token` | 无 Authorization/Cookie；`schema.json#/$defs/tokenRequest` | `schema.json#/$defs/tokenResponse` |

OSIR 成功为 HTTP 200 的 `{code:0,message:"success",data:…}`；错误为
`{code:<HTTP status>,message:<固定安全文本>,reason:<固定机器码>}`，本合同不返回
`metadata`、错误 `data` 或上游错误体。所有响应（包括关闭、错误、限流）必须
`Cache-Control: no-store` 和 `Pragma: no-cache`。拒绝 redirect、query、压缩请求、
Cookie、重复 Authorization、非 JSON POST、重复/未知/大小写错误的字段、null、数组
根、非字符串字段和尾随 JSON。POST 最多 4096 UTF-8 字节；响应/decoded JWT payload
最多 16384 字节，IPC 单帧最多 4096 字节，desktop exchange 最多 12288 字节。
字节上限和重复键检测须在 Schema 之前实施；Schema 本身不能检测被 JSON parser
覆盖的重复键。整数拒绝浮点/exponent 原始表示；JWT 时间必须是 JSON 整数。

每源 IP 每分钟上限：capabilities 60、authorize 10、token 20；源 sid 的 authorize
另限 10 次/分钟。Redis/限流依赖失败关闭；429 只表示限流，依赖故障用 503。
不得从审计中间件采集这些请求/响应 body、Authorization/Cookie 或 query；日志只记
route、阶段、固定错误码及脱敏关联 ID。

capabilities 的 data 固定为
`{enabled,protocolVersion:1,recipientClientId:"osir-anywhere-desktop",targetOrigin:
"https://anywhere.osirclaw.com",codeExpiresIn:60,requiredScope:"account:read",allowedActions:[…]}`。
关闭时保留这些非秘密固定字段，`enabled=false`，POST 返回 `capability_unavailable`。
仅在专用 handoff opt-in、desktop auth、专用 signer、源 session 存储及配套接收能力
配置齐全时启用；不能从普通 desktop/Web 开关推断 handoff 已启用。
本地 API 实现配置名 `desktop_auth.anywhere.handoff.enabled`（默认 false，对应 env
`DESKTOP_AUTH_ANYWHERE_HANDOFF_ENABLED`）；尚未部署或启用，不代表线上已有此能力。
Client 按现有 capability 预算缓存 60 秒，不后台轮询；能力就绪不等于用户已授权动作。

## 3. 原生启动和握手

Client 先核验安装路径、bundle 身份及下面的可信构建证明，再启动 Anywhere，仅增加
非秘密参数 `--osir-client-handoff-flow <flowId>`。`schema.json#/$defs/nativeLaunch` 表示
该参数唯一可传的数据 `{flowId}`，不是可执行命令模板。URL、argv、安装器、manifest
中不得出现 code、state、verifier、assertion、源 token、模型 Key 或代理租约。
未安装时先走单独受控安装事务，接收端就绪才开始 60 秒码流程；安装器不带凭据。

Client 生成 32 随机字节 flowId。Anywhere Main 生成独立的 32 随机字节 state、
32 随机字节 receiverInstanceId、48 随机字节 verifier，均无 padding base64url。
flowId/receiverInstanceId 的 wire 边界为 32–128 个 base64url 字符，与 Client native DTO
一致；本端默认生成 32 bytes/43 字符。state/challenge/code 必须 canonical 32 bytes/43 字符。
receiverInstanceId 每 flow 重建；verifier 只在 Main 内存，不交给 Client/renderer。
挑战为 `base64url(SHA256(ASCII(verifier)))`，仅 S256。

`schema.json#/$defs/nativeHandshake` / authorize 使用同一 camelCase 完整对象：

```text
{version:1, flowId, receiverInstanceId, state, codeChallenge,
 codeChallengeMethod:"S256", recipientClientId:"osir-anywhere-desktop",
 targetOrigin:"https://anywhere.osirclaw.com", actions:[…]}
```

Client 在当前用户私有目录提供 Unix socket；目录 0700、socket 0600，拒绝符号链接，
双方校验 peer UID/PID、实际可执行进程路径和安装构建身份。仅 flowId、同 UID 或
bundle 名称不够。接收端可信证明接受以下两种方式，不以缺少 Apple 公证或
Authenticode 直接拒绝当前产品构建：

- 原生系统签名：验证批准的签名身份、安装包完整性与 peer 进程所属构建。
- signed-manifest build pin：用发行信任根验证清单签名，清单绑定产品/版本/平台/
  架构及精确 bundle-tree SHA-256；本机重算完整树，再将 peer 实际路径/UID/PID
  绑定该已核验安装构建。清单必须覆盖全部 bundle 成员（含资源、嵌套可执行文件、
  frameworks），拒绝额外/缺失成员及逃逸路径，固定文件类型/执行位/符号链接目标。
  tree digest 的规范化算法/manifest 格式复用主控发行合同，不能用任意目录 hash
  冒充；主控尚未提供可验证清单时报告 receiver_untrusted，不自动降低校验。

未经验证的包失败关闭；无需关闭或绕过系统 Gatekeeper。验证到启动/IPC 的期间
须防止构建替换，握手时再次绑定实际 peer 构建；单独校验磁盘树不证明正在运行的
进程来自该构建。此目录不另造发行清单、系统签名工具或信任根配置。
Windows named pipe/SID ACL 待实现，不能声称本合同已提供该平台的接收端认证。

Main 必须先登记唯一 pending，再发送握手；Client 校验收到的 flowId 等于本次启动值，
且所有动作等于用户触发的固定委托。每 flow 一个 pending，总等待最多 300 秒；
并发重复点击复用本次 pending 或明确拒绝，不创建重复连接。收到 code 后，Client
仅在已认证的同一 IPC 连接发送 `schema.json#/$defs/nativeCodeDelivery`：
`{flowId,state,code,expiresIn,configuredToolTypes}`。expiresIn 是剩余秒数 1–60，不能重置码期限。
`configuredToolTypes` 为 required、允许空数组，值仅为按 `claude,codex,dsh` 固定顺序
排列的去重子集（最多 3 项），来自 Client native 已验证连接状态的本次快照；不从
renderer 或仅存在的配置文件推断。这里只携带非秘密工具类型，不含 key、path、model
或连接凭据；只留在已验证的本机 IPC，不进入 API authorize/token、JWT、Anywhere
exchange 请求或云 config，也不因此新增工具授权。
Main 比较 flowId/state 和进程 pending，目标 origin 固定，不从 renderer 接收身份。

取消、超时或进程退出立即销毁本机 pending/秘密，拒绝所有迟到消息；消费类 POST
不盲目重试，结果不确定时废弃 flow，重新建立独立握手。三 route 中没有取消接口：
本机取消不等于尚未消费的云端 code 已立即撤销，它仍受 60 秒和源 sid 检查约束；
不得宣称有额外云端即时取消能力。

## 4. authorize 与 source session

Client 原生将上面的握手对象原样作为 JSON POST 到 authorize；无 verifier 或 account
ID。源 Bearer 只发 OSIR，源 refresh 也只按现有 Client 流程发 OSIR，不进入 IPC。
API 必须重新验签/校验过期，严格检查源 token 的用途/client/单一受众/合法 scope，
查活跃 source sid，匹配 sub、tokenVersion、client、scope，检查源 session 到期/撤销、
账号 active 及租户上下文；不能相信 renderer、body account ID 或未类型化的上下文。
scope 含 `account:read` 的判定必须精确词项匹配，不是子串匹配。

Client 原生在网络调用前后核对 AuthManager generation/account，切换或退出后
拒绝迟到结果，code 不交给新账号的 pending。现有 native DTO/AccountClient 已加入
相关字段与请求边界，尚未接 launch；不能将这部分进度等同完整交接可用。

成功回 envelope data：`{code,expires_in:60,recipient_client_id:
"osir-anywhere-desktop",audience:"osir-anywhere-server"}`，只回 Client 原生调用方。
code 为 32 CSPRNG 字节的 canonical base64url（43 字符）；仅存其 SHA-256 hash。
记录必须包含：flowId、源 sid/sub/tokenVersion/client/scope、recipient、audience、
receiverInstanceId、targetOrigin、state hash、S256 challenge/method、固定 actions、
createdAt/expiresAt 与消费状态。源 sid 和 tokenVersion 不发到 Anywhere/浏览器。

## 5. token 与一次性消费

Main 向固定 OSIR token route POST snake_case OAuth 对象：

```text
{grant_type:"urn:osir:params:grant-type:anywhere-handoff",
 client_id:"osir-anywhere-desktop",code,code_verifier,state,
 receiver_instance_id,target_origin}
```

**没有 `flow_id` 输入**：API 从 code 记录取 flowId，写入 assertion，再由 Main/Anywhere
exchange 与 pending 的 flowId 比较，避免增加另一个可选命名。所有字段均 required。
先严格校验字段/常量，再比较 code 记录 recipient/origin/receiver、state hash 和
S256 verifier；60 秒以 API 签发时钟计，`now >= expiresAt` 拒绝。
再次查原 source sid 有效性及账号 active/tokenVersion/租户，匹配记录中的源身份，
不要求把源 access/refresh 带给接收方，也不因原 access 自然到期就绕过 sid 检查。
code 的最终源 sid 检查与原子消费必须对 session 撤销操作有可定义的线性化顺序
（同一事务/Lua，或等效存储保证）；已完成源撤销后才线性化的换码不得成功。
账号变更与换码按服务端权威读取点排序，不声称跨 DB/Redis 有不存在的全局事务。

并发只能一个调用消费成功；Redis 不可用失败关闭。错 state/PKCE/绑定不能生成
assertion。过期/未知/已消费 code、源 sid 已撤销或记录不匹配统一 `invalid_handoff`。
验证成功、消费完成后签发独立 handoff assertion；失败/响应丢失也不恢复 code。
此接口不创建 OSIR account/refresh grant。

## 6. assertion 的严格类型、claims 和 signer

token 成功 envelope data 仅四字段：`{assertion,token_type:
"urn:osir:params:token-type:anywhere-handoff",expires_in:60,audience:
"osir-anywhere-server"}`。Header 仅 `alg:"EdDSA"`、
`typ:"osir-anywhere-handoff+jwt"` 和有界 `kid`。
Decoded payload 的字段名在 `schema.json#/$defs/assertionClaims` 定版：

```text
{iss:"https://osirclaw.com",aud:"osir-anywhere-server",
 sub:<正数十进制字符串>,client_id:"osir-anywhere-desktop",jti,iat,exp,
 flow_id,receiver_instance_id,state_hash,target_origin,code_challenge,
 code_challenge_method:"S256",actions:[…]}
```

sub 在 1..9223372036854775807 内，禁止 JS number 转换；jti 为全新 32 CSPRNG 字节。
`exp=iat+60`，Unix 秒整数，拒绝未来 iat、`now >= exp`，不延长 TTL。
`state_hash=base64url(SHA256(ASCII(state)))`；流、接收端、origin、challenge 和 actions
都来自已经校验的 code 记录，不能从任意 body 补造。仅身份/交接约束；不带邮箱、角色、
source sid、账户 access/refresh、模型 Key 或配置路径。

复用现有 **专用 PKCS#8 Ed25519 signer/JWKS**，不复用账户 HS256 secret、不自动生 key。
issuer 固定；JWKS 固定 `/api/v1/auth/desktop/anywhere/jwks`，`kid` 1–64 ASCII
字母/数字/`_`/`-`。API 实例使用同一批准 key/kid；沿用安全文件权限和进程级缓存，
key 变更走正常候选进程发布。这里不读取 key、不决定其值、不创建部署配置。
普通登录 assertion 的 typ/token_type/允许来源保持不变，不能只加 claims 后继续用旧 typ。

## 7. Anywhere desktop exchange：由已验证 typ 判别的 union

扩展目标为 POST `/api/v2/auth/osir/desktop/exchange`，请求 Schema：
`schema.json#/$defs/desktopExchangeRequest`。JSON 外层不用额外 `kind/type`，有且仅有两支：

```text
browser: {assertion:<osir-anywhere-login+jwt>}
handoff: {assertion:<osir-anywhere-handoff+jwt>,handoff:{
  flowId,state,receiverInstanceId,codeVerifier,targetOrigin}}
```

Schema 以 `handoff` 存在与否构成互斥 oneOf；真正可信的 discriminator 是**验签后**
header `typ`。browser 支只接受 desktop login typ + desktop client；handoff 支只接受
handoff typ，强制全部五项。禁止 Web assertion、源 Client token、交叉分支、未知字段
和无 handoff 证明的 handoff typ；未验签 decode 只能用于有界分派，不能认证。
不得把旧 verifier 丢弃扩展字段后的普通 identity 当作 handoff 校验结果。

Main 在请求前匹配 pending；Anywhere Server 独立验签、issuer/单一字符串 audience、
typ/client/iat/exp/sub，再比较 flow_id、receiver_instance_id、target_origin、
state_hash 与 S256(codeVerifier)，以及精确 actions。Server 的固定 public origin 必须
等于 targetOrigin，不能用调用方 body 选择站点。
成功校验后，对 issuer+jti（hash，使用所有 OSIR assertion 共用的 replay registry）
做 Redis 原子 SET NX，保留到 exp；重复、过期或依赖失败拒绝。先消费 jti，再映射
账号并建独立 Anywhere sid；下游失败/响应丢失不恢复 jti。相同 sub 不按邮箱合并，
现有不同账号必须 `account_mismatch`，不能静默覆盖原设备/运行时身份。

本合同只定义新 exchange 的**请求扩展**。成功仍使用现有 desktop-session 响应和
7 天绝对 refresh/退出管理；不在这里改变该生命周期，也不影响旧
`/api/v2/auth/osir/exchange`：旧入口必须拒绝 handoff typ，不能成为绕过绑定的入口。
source Client 退出使未兑换 code 失效；已签 assertion 有最长 60 秒残余窗口，已建立
Anywhere sid 独立管理。本协议没有即时跨产品全局撤销/backchannel。

actions 允许复用原生已批准的本机连接和已配置工具，不授权任意目录/命令、远程下载
脚本、另一个账号的配置或向云端上传模型 Key。连接/工具绑定必须核对签名身份、
issuer/sub、origin、owner 和修订号；缺配置应报告明确阻塞，不凭此合同声称有配置。
模型描述符/Connector bootstrap 的具体合同不在此目录；不得因认证成功自动扩大权限。

## 8. 固定错误与未完成能力

`schema.json#/$defs/errorResponse` 固定 status/reason/message 对应关系；客户端按 reason
显示本地安全文本，不回显请求或上游异常。

| HTTP | reason | 适用边界 |
| --- | --- | --- |
| 400 | invalid_request | JSON/字段/常量/格式错误 |
| 401 | invalid_source_session | authorize 源 Bearer/session/账号无效 |
| 401 | invalid_handoff | token/exchange 绑定失败、过期或重放 |
| 403 | capability_unavailable | 未 opt-in 或配套功能关闭 |
| 403 | receiver_untrusted | 原生接收端验证失败；本机固定错误，不代表 API 验过 PID |
| 403 | consent_required | Client 没有本次明确操作；不是重新登录或新 scope 要求 |
| 409 | account_mismatch | 原有账号/owner 与目标身份不一致 |
| 429 | rate_limited | 请求超预算 |
| 503 | dependency_unavailable | Redis/账号存储/signer 等依赖故障 |

OSIR route 使用 envelope；本机 IPC 用本地固定错误；Anywhere 错误沿用其既有安全
错误封装，不把 OSIR envelope 强加给 Anywhere。上表 reason 在实现间须稳定映射。
本目录没有新增 cancel route、安装分发、设备审批、模型 Key 导出、任意 callback、
接收端 attestation、业务路由或生产开关。Client/API/Anywhere 配套实现分别推进；
实际安装包认证、完整入口、互操作验收及发布均未在本合同交付中完成。

## 9. Schema、合成 fixtures 与验证

只交付本 README、`schema.json`、`fixtures.json`。Schema 使用 JSON Schema 2020-12，
各消息以 `schema.json#/$defs/<name>` 引用；根 Schema 对应 authorizeRequest。
所有 wire 对象封闭，字段有长度/常量边界。flow/receiver 接受 32–128 字符，
state/challenge/code/hash/jti 为 canonical 32-byte base64url（43 字符），
verifier 固定 64 字符（48 bytes）。不使用省略号或 `<token>` 充当可校验 fixture。

fixtures 中每项有 `name`、`definition`、`valid`、`value`，负例应被对应 Schema
拒绝。`flow` 引用同一组合成消息，用于核对 state hash、S256、flow/receiver/origin、
actions、JWT typ 和 exp-iat。JWT 是合成 payload 加全零签名，**不能通过真实验签**；
固定 iat 不代表当前有效凭据。fixtures 不含真实 source token、refresh 或私钥。
本目录不增加验证框架；可用 Server 已有 jsonschema 依赖离线加载 Schema/fixtures，
按每项 definition 校验并对照 valid，再核对 flow 的跨消息关联。

Schema 不能证明随机熵、真实签名、真实点击、源 sid/账号查询、存储原子性、
撤销竞态或 jti 消费；结构校验不冒充运行时测试。实施时另测：旧有效
`osir-desktop + account:read` 无需新登录即能换码；Web/其他 client/失效 source sid
拒绝；code/jti 并发只能一次成功；源撤销/账号切换竞态；错 state/receiver/PKCE/
origin/flow/actions；重复键/限额；source 凭据、模型 Key 不出 IPC/argv/日志/云配置；
原 browser/Web/旧 exchange 路径不接受 handoff typ；完整 signed-manifest 构建认证。

## 10. 本地实现验收与部署边界（2026-11-15）

本地实现位于 `/Users/ouwei/sub2api-new/backend/internal/`：
`service/desktop_anywhere_handoff.go`、`repository/desktop_handoff_store.go`、
`handler/auth_desktop_handoff.go`、`server/routes/auth_desktop_handoff.go` 及对应测试；
注册/config/旧码兑换路径只有必要的接入与隔离改动。没有修改 Client/Anywhere Main，
没有部署、发布或修改公开版本。三条 route 的启用状态不能由本文推断。

本地合成验收已通过：

- Go 的 config/service/handler/routes 四组 `TestHandoff*` 窄测；包含旧
  `account:read` 无新登录、普通 assertion 隔离、12 路换码只成功一次、PKCE/state/
  receiver 绑定、源注销发生在最终原子消费前的竞态、source 缺失/过期及身份/
  client/scope/version 变更、60 秒存储 TTL、原始凭据不入 code 记录、feature flag
  关闭后禁止兑换、固定三 actions 及错误 actions 拒绝。
- Go HTTP handler 直接运行共享 fixtures 的 43 个 authorize/handshake/token 正反例；
  需要显式 `OSIR_HANDOFF_CONTRACT_FILE` 指向本目录 `fixtures.json`，缺省跳过此项。
- Python JSON Schema 2020-12 校验、113 个结构 fixtures、8 个语义反例、85 种
  `configuredToolTypes` 列表组合；工具列表不进入 HTTP/JWT。
- Go 实际临时 Ed25519 签发 → Schema → 现有 Python verifier 和 desktop exchange
  合成互操作；使用 mock JWKS、fakeredis 和真实 `OsirAssertionReplay`，12 路后续
  jti 重放均拒绝，错误 proof 和普通登录 verifier 的交叉使用均拒绝。
  公钥/短期 assertion/proof 仅写入权限 0600 的任务临时文件并删除，无源 token/私钥。
- 配套 Server 现有 `test_osir_client_handoff.py` 的 17 项独立 unittest 通过；全部
  MockTransport/ASGITransport，无数据库或真实 API。此前的 29 项实际 Lua 合成
  检查也已通过；最终 Go 窄测已解除暂停前的资源阻塞。

复验 Go（在配套 backend，使用已缓存 Go 1.27.3；不下载依赖）：

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOMAXPROCS=2 \
OSIR_HANDOFF_CONTRACT_FILE=/Users/ouwei/agents-anywhere/contracts/osir-client-handoff/v1/fixtures.json \
/Users/ouwei/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.3.darwin-arm64/bin/go test \
-p 1 -vet=off -tags unit -gcflags=all=-dwarf=false -ldflags='-w -s' \
./internal/config ./internal/service ./internal/handler ./internal/server/routes \
-run '^TestHandoff' -count=1 -timeout=90s
```

`TestHandoffGoPythonInteropFixture` 仅在显式设置
`OSIR_HANDOFF_INTEROP_FIXTURE_FILE` 时导出全新合成用户的 public JWKS、60 秒
assertion 及 proof；路径必须绝对、文件必须不存在，绝不导出源 access/refresh 或私钥。
跨语言验证须紧接 Go 签发完成，在 60 秒内使用真实 verifier 和 mock JWKS；
`fixtures.json` 的全零签名不是该验签输入。没有新增验证工具或更改 Server 业务。

复验配套 Python（在 Server；不会加载 pytest/conftest 或数据库）：

```sh
./.venv/bin/python -B -m unittest discover -s tests -p test_osir_client_handoff.py -v
```

**运行时启用条件**：`DESKTOP_AUTH_ENABLED=true`、
`DESKTOP_AUTH_WEBSITE_ORIGIN=https://osirclaw.com`、
`DESKTOP_AUTH_ANYWHERE_ENABLED=true`、
`DESKTOP_AUTH_ANYWHERE_ISSUER=https://osirclaw.com`、有效且有界的
`DESKTOP_AUTH_ANYWHERE_KEY_ID`、绝对路径的专用 PKCS#8 Ed25519
`DESKTOP_AUTH_ANYWHERE_PRIVATE_KEY_FILE`（普通文件、无 group/other 权限），再显式
`DESKTOP_AUTH_ANYWHERE_HANDOFF_ENABLED=true`。后者默认 false，不要求 Web SSO 开关。
Redis code/session/限流存储和账号存储必须可用；复用同一 Redis 的撤销/原子机制，
不是 Redis Cluster 跨 slot 事务。Anywhere 必须先准备好相同 JWKS/issuer/typ 的
verifier、jti guard 与 `OSIR_CLIENT_HANDOFF_ENABLED`；Client 必须完成已验证 native
IPC/用户动作/安装构建验证。API capability 不远程证明接收端构建或真实点击，
operator opt-in 负责确认配套就绪。以上仅说明条件，没有读取或填写生产配置。

**现有部署入口**：`/Users/ouwei/sub2api-new/docs/releases/RAINYUN_RELEASE.md`，
唯一 launcher `/Users/ouwei/sub2api-new/tools/release_rainyun.sh`。未来发布仍须按该
runbook 的干净候选、精确 SHA、封包/预检/预热/切流门禁执行，本文不授权执行。
当前 `tools/rainyun_release_env.py` 的发布环境白名单尚不接受
`DESKTOP_AUTH_ANYWHERE_*`，因此不能直接把新开关或 signer 配置加入
`RELEASE_ENV_SOURCE`，也不能声称正常发布链已能启用 handoff。此处是独立的发布
接入待办；不得绕过白名单或手改生产 env/unit。本次仅 backend/合同写集未改发布工具。

这些结果证明本地 HTTP/签名/存储契约可执行；真实安装、系统或 signed-manifest
构建认证、端到端 native IPC/launch、生产启用仍未验收，不能声称已上线。
