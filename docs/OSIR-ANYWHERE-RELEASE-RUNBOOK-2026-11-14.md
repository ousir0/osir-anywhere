# Anywhere 多平台构建与可恢复发版合同

日期：2026-11-14，当前状态更新于2026-11-15。本文为操作合同；后文历史交付说明保留原时点边界。最新正式版本为 **Anywhere2.2.1 runtime-r2 / Client0.1.11**，均完成对象存储公开读回、独立备份恢复及条件切换；用户可手动更新。最终包Claude真实对话通过，Codex运行与DSH隔离桥接通过，后两项真实对话及新版Client桌面自动接线仍待验收。详见 [11月15日发布记录](../../cc-switch-osir-client/docs/OSIR-RELEASE-0.1.11-2026-11-15.md)。

以下为11月14日历史发布记录：**当前状态：Anywhere 2.2.0 r4 与 Client 0.1.10 r3 均已正式发布。** Anywhere stable 已条件切换并完成独立备份恢复及验签；Client 正式 feed 已核对。正式Client 0.1.10/r2从stable下载并验签Anywhere DMG、Finder复制到隔离home、重新检测为已安装v2.2.0及准确路径均已通过；未启动新Anywhere实例，登录/模型不在此验收范围内。客户端Ready进度显示修复只在未发布源码，待下版带入。真实0.1.9→0.1.10自动更新三平台均已通过：ARM Mac、Intel Mac使用run `43565893214`；Windows x64使用Windows-only run `43566840149`。均包含真实UI点击、旧进程退出、安装器自动拉起新进程、同路径正式r3字节/原生版本窗口、DB25→26及合成数据保留。Windows旧失败为进程级测试home与NSIS重启后的数据目录不一致，改在干净托管runner默认用户home验证后通过；未修改产品包、更新源或迁移/保留门槛。正式源码为 Anywhere commit `0900e431bef40c69d043e5af6e74431f30d0ea2d`、Client commit `ec2b05bab6224334e91922cd70c71faf8e9aee89`。证据与历史过程见 Client 仓库的 [实施记录](../../cc-switch-osir-client/docs/OSIR-ANYWHERE-RELEASE-IMPLEMENTATION-2026-11-14.md)；未来发布使用新plan，已发布工件无需重包。

## 最低可用入口

仓库根目录执行；下列命令为操作合同，不代表本轮执行记录。

```sh
node desktop-workbench/scripts/osir-anywhere-source.mjs plan /absolute/source-spec.json
node desktop-workbench/scripts/osir-anywhere-source.mjs prepare /absolute/source-spec.json
node desktop-workbench/scripts/osir-anywhere-build.mjs plan /absolute/build-spec.json darwin-universal
node desktop-workbench/scripts/osir-anywhere-build.mjs prepare /absolute/build-spec.json darwin-universal
node desktop-workbench/scripts/osir-anywhere-build.mjs prepare /absolute/build-spec.json win32-x64
node desktop-workbench/scripts/osir-anywhere-release.mjs plan /absolute/release-spec.json
node desktop-workbench/scripts/osir-anywhere-release.mjs prepare /absolute/release-spec.json --signing-key /Users/ouwei/.config/osir-anywhere-release/manifest-signing.pem
node desktop-workbench/scripts/osir-anywhere-release.mjs upload /absolute/release-spec.json
node desktop-workbench/scripts/osir-anywhere-release.mjs publish /absolute/release-spec.json
node desktop-workbench/scripts/osir-anywhere-release.mjs restore /absolute/backup/RELEASE_ID /absolute/new-restore --public-key /Users/ouwei/agents-anywhere/desktop-workbench/build/release-public.pub
```

`plan` 只读、不联网；`prepare` 构建或签名本地字节；`upload` 只上传不可变版本路径并完整公开读回；只有 `publish` 可在备份恢复后条件更新 stable。发布不是 build 的隐含副作用。签名私钥只通过 `--signing-key` 文件路径传给本地 prepare，不经过环境变量、recipe、CI、源码或 JS/renderer 编译子进程。测试只生成临时测试密钥。

发布 `plan` 必须已有最终原包和真实原生验收报告；无这些输入时仍可准备源码、构建合同和执行离线测试，但不能伪造完整发布计划通过。

## 当前合同与阻碍

- 固定 public manifest：`https://osirvedio.cn-nb1.rains3.com/osir-anywhere/releases/stable.json`。
- 私有 dedicated repo：主任务已创建 `ousir0/osir-anywhere`，bootstrap commit `edde4216ed7e6b6a45d312303035a55b9e953978`，preflight run `43504905639` 已成功。这不是产品源码冻结或安装器验收。
- 主任务已实测四类 runner 的平台/架构；当前构建标签显式为 `macos-15`、`windows-2022`、可选 `windows-11-arm`。Universal 后续还须 `macos-15-intel` 原生验收。不开启 `macos-14`。
- 主任务已实测 RainS3 条件创建、重复创建 412、错误 If-Match 412、正确 If-Match 和公开全量 200。证据 `/Users/ouwei/.codex/release-evidence/20261114-anywhere-ci-control-storage.json`。仅操作了测试前缀；stable 没有因此切换。
- 已发布合同：Anywhere **2.2.0**、Client **0.1.10**；stable manifest 要求 `minimumClientVersion:0.1.10`、`minimumServerVersion:2.2.0`。之前关于候选冻结、原包验收和云端配套的阻塞均为历史状态，不代表当前仍待发布。
- 当前无 Developer ID 证书；workflow 明确生成 unsigned candidate。RSA 清单签名不能代替 Apple 公证或 Authenticode。
- Meitner 负责 `desktop-workbench/scripts/osir-native-smoke.mjs` 及 test，主会话负责 workflow 原生验收聚合；本工具不重复实现或代写原生 smoke。当前专用 workflow 交付构建主体，不能称为完整发版已实机通过；publisher 对缺失最终原包、跨版本数据保留和 PATCH 更新发现报告保持拒绝。

## 来源快照：逐文件白名单

source spec：

```json
{
  "checkout": "/Users/ouwei/agents-anywhere",
  "gitHead": "40_HEX_REVIEWED_UPSTREAM_HEAD",
  "files": [".gitignore", "desktop-workbench/package.json", "逐文件列出全部受审构建输入"],
  "outputDirectory": "/absolute/new-reviewed-snapshot"
}
```

`files` 不接受通配符、目录、路径逃逸、链接、`.env`、私钥或存储凭据。只复制这些文件及执行权限，记录每项大小/SHA-256、upstream HEAD 和整体 sourceSha256。它允许显式审阅的工作树改动，不能把 HEAD 单独当作源码字节身份。准备目标必须全新，工具不清理其他输出，也不自动提交或推送。

生成 `osir-source.json`；该文件记录 sourceSha256，但不把自己纳入 source.files，所以没有自引用。CI 逐项校验源码字节，同时拒绝额外受 Git 跟踪或未被忽略的输入。Git 忽略的 lock、依赖及编译目录不因此成为可发布源码。

**构建候选交付：** `/Users/ouwei/.codex/release-evidence/20261114-anywhere-build-source-candidate-final.json` 是逐文件 reviewList 与只读哈希盘点，仍须主会话审阅并冻结；没有自动生成源码快照、提交、推送或 dispatch。它基于原 858 项名单补齐 build-only workflow、recipe、构建/发布工具及测试、真实 OAuth 证据和 Ramanujan 的最终 installer 源码。保留现有 README、第三方字体许可、Connector 源码/README/pyproject、logo、图标、entitlements、公钥、配置和 `server/pyproject.toml`（仅供 build-info 读取版本）。根没有 LICENSE，不要求不存在的文件。

**刻意分离的验收 harness：** `osir-native-smoke.mjs`、`osir-native-smoke.test.mjs`、`osir-native-acceptance-aggregate.mjs`、`osir-native-acceptance-aggregate.test.mjs` 不进入产品构建名单；后续 provision/helper/tests 和 `.github/workflows/osir-anywhere-artifact-acceptance.yml` 也只进入独立受审 harness。它们不是产品构建依赖。主会话可立即冻结 build-only 源并构建 Universal/Win x64，后续验收下载原 artifact，绑定 receipt/source/config/signature/原包 hash，不修改、重打包或重构建成功原包。

专用仓库 bootstrap 的 `README.md`、`.github/workflows/osir-runner-preflight.yml` 与 `.github/workflows/osir-windows-arm-dependencies.yml` **明确排除该产品快照**。产品根 README 使用受审上游 README 三语版本；bootstrap 保留在其原控制分支/提交，不删除。主任务应在独立快照分支提交精确名单及生成的 `osir-source.json`，不能附加 bootstrap 文件绕过 verifySource。锁文件单独作为依赖证据分发，不提交产品源；`_reference/`、`_deprecated/`、无关 CI、秘密和编译输出排除。

## CI recipe、共享依赖与缓存

recipe 是受审源文件，只允许以下顶层字段。**禁止 sourceSha256、生成的 checkout 路径或私钥**：

```json
{
  "releaseId": "FINAL_RELEASE_ID",
  "config": {
    "OSIR_IDENTITY_API_ORIGIN": "https://REVIEWED_IDENTITY_ORIGIN",
    "OSIR_IDENTITY_WEB_ORIGIN": "https://REVIEWED_IDENTITY_WEB_ORIGIN",
    "OSIR_ANYWHERE_API_ORIGIN": "https://REVIEWED_ANYWHERE_ORIGIN",
    "OSIR_ANYWHERE_OAUTH_WEB_ORIGIN": "https://REVIEWED_OAUTH_ORIGIN",
    "OSIR_ANYWHERE_OAUTH_CONTRACT_VERIFIED": "1"
  }
}
```

根 `osir-build-recipe.json` 的 OAuth 标志依据同合同既有真实验收：`docs/OSIR-ANYWHERE-CONNECTION-VERIFICATION-2026-11-13.md` 与 `docs/OSIR-ANYWHERE-ALIYUN-ROLLOUT-2026-11-13.md`。recipe 的 `oauthEvidence` 指定 `basis:"prior-contract-real-desktop-and-browser-verification"`、`scope:"candidate-build-only"`、`requiresFinalPackageReverification:true` 和两份文档的原始字节 SHA-256；CI 同时核对它们在 source.files 中且字节未变。Client 旧 AUTH-VERIFICATION 文档只有合成/loopback 测试，不能单独支撑真实 flag。当前根 recipe 是可审阅构建草稿，不表示新最终包 OAuth 已通过；新包仍须复验。旧的 MAC/WIN_UPDATE_URL 被固定签名 manifest 取代，不能继续传给新 resolver。

workflow dispatch 显式传入 `source_commit`（完整专用仓库 SHA）、`source_sha256`、`recipe_sha256`（原始 recipe 文件字节的 SHA-256）。dispatch 所选 workflow ref 也必须指向该同一提交：helper 核对 `GITHUB_WORKFLOW_SHA`，不能用另一版本 workflow 构建被审源码。sourceSha 从 dispatch 读取，不嵌入 recipe。CI 在 `$RUNNER_TEMP` 生成 build-spec，不在冻结源码外附加 JSON。recipe 本身仍在逐文件名单内并校验原始字节哈希，不存在指纹循环。

CI 的 spec helper 同时经 `GITHUB_ENV` 输出实际 runner 的临时路径，避免在不允许 `runner` context 的 job env 中写 `${{ runner.temp }}`。spec 必须在源码目录外，recipe 必须是 `source.files` 中精确的根 `osir-build-recipe.json`；不放宽额外 JSON 输入。

resolve job 只解析一次 Yarn lock，导出为单独 CI artifact 与 SHA-256。各目标下载同一 lock，先比对 raw-byte digest，再 `yarn install --immutable --mode=skip-build`。打包回执记录 lock hash、安装状态 hash、Node 版本；release 合包拒绝多平台 config 或 lock 不一致。失败 job 重跑从 resolve job 原输出取得 artifact 名称，不用新 run_attempt 误指不存在的 lock。若整轮重跑得到新锁，则是新的依赖身份，不能混用旧成功包。

下载缓存显式覆盖 Yarn store、Electron、electron-builder、uv、Python 下载目录。native cache key 包含目标、Node 22、recipe/config 指纹、同一 lock SHA、uv/Python 下载脚本指纹；不缓存 build/uv、build/python、dist、renderer/out 或安装包。命中缓存仍重验下载摘要、重建并执行来源门禁。当前记录 compile/runtime 与 package/sign/verify 耗时；未承诺提速百分比，排队/安装/验收等完整分段计时仍待原生 CI 实测。

每目标独立 runner/checkout；本机多个任务不得共享 build/、dist/、renderer/out。工具在 checkout Git 目录放互斥锁与目标绑定。成功 build-receipt 在源/配置/依赖相同时复用精确包；重跑不能因另一平台失败而重新签成功包。

`--skip-build` 必须有工具生成的 `OSIR_ANYWHERE_BUILD_SPEC`，并通过源码、有效配置、环境配置、依赖状态和编译产物树摘要；直接调用旧 dist 的裸 `--skip-build` 会失败。完整构建使用 `build prepare`，包装失败后可在同 spec、同目标下用 `build prepare ... --skip-build` 重试。换源码/配置/依赖必须用新的隔离 checkout/state。

Windows ARM64 runner 已可用，Epicurus 正负责真实依赖预检；不能把 runner 能启动等同于 Electron/Python/uv/原生依赖已通过。默认 all 只覆盖 Mac Universal 与 Win x64。可选 ARM 的 recipe 使用以下引用，拒绝原先纯 boolean 声明：

```json
"windowsArm64Evidence": {
  "reportPath": "reviewed-evidence/windows-arm64-dependencies.json",
  "reportSha256": "64_HEX_RAW_REPORT_SHA256"
}
```

报告须纳入 `source.files`，本身不嵌入 sourceSha，避免重新引入循环。报告最低字段：`schemaVersion:1`、`result:"passed"`、`runner:{label:"windows-11-arm",platform:"win32",arch:"arm64",runId,runAttempt}`、`checks:{electron:true,python:true,uv:true,nativeDependencies:true}`。`inputs:[{path,sha256}]` 必须精确绑定 `desktop-workbench/package.json`、`desktop-workbench/renderer/package.json`、`connector/pyproject.toml`、`desktop-workbench/scripts/prepare-uv.mjs`、`desktop-workbench/scripts/prepare-python.mjs` 的真实源字节。原生安装器验收仍另行必做，不能靠该预检声明支持完成；build plan/receipt 记录报告 SHA。实际报告若不同，主会话先审阅并对齐合同，再启用 ARM。

## 签名清单与系统身份

RSA-SHA256 PKCS#1 v1.5 封套：

```json
{"payload":"BASE64_OF_JSON_BYTES","signature":"BASE64_OF_RSA_SHA256_SIGNATURE"}
```

payload 固定 `schemaVersion:1`、`productId:"osir-anywhere"`、`channel:"stable"`，包含 releaseId/version/publishedAt、可选 minimumClientVersion/minimumServerVersion、artifacts。每项含 platform、arch、url、size、sha256、filename，新增受 RSA 签名保护的 **systemSignature**：

| systemSignature | 必需的原包检查 |
| --- | --- |
| unsigned | Mac 原 DMG 完整性通过，包内 app 确实未签名或有效 ad-hoc；Windows 最终 EXE 为 NotSigned |
| developer-id-notarized | 原 DMG 内 app 为 Developer ID Application，codesign 深度校验通过，DMG stapler 与 Gatekeeper 均通过 |
| authenticode | Windows 最终 EXE 的 Get-AuthenticodeSignature 返回 Valid |

`HashMismatch`、不受信任、损坏签名不能降格成 unsigned。Developer ID 已签但未证实公证的中间状态不属于这三种可发布身份，直接阻断，不能伪装成 unsigned/notarized。Mac 检查只读挂载最终 DMG 的真实 app；检查结束只卸载本次临时 mount。没有跳过用户系统确认或移除用户 App 隔离属性。

构建产生 `system-signature.json` 原始 probe 报告，artifact 和 receipt 均绑定报告摘要；publisher 重新从报告推导分类，拒绝只指定 boolean。清单签名保护该分类。Electron 和 Client verifier 须接受并执行同一字段。当前证书不可用时只允许准确声明 unsigned，且 release spec 须有 `allowUnsigned:true` 与可公开审阅的 unsignedReason。

公钥 `desktop-workbench/build/release-public.pub` 已加入 extraResources，安装后是 `resourcesPath/build/release-public.pub`，不使用 `.pem` 后缀。私钥保持主任务的 0600 私有文件。

## release spec

```json
{
  "schemaVersion": 1,
  "channel": "stable",
  "releaseId": "FINAL_RELEASE_ID",
  "version": "2.2.0",
  "publishedAt": "2026-11-14T00:00:00.000Z",
  "sourceSha256": "64_HEX_SOURCE_SHA256",
  "upstreamGitHead": "40_HEX_UPSTREAM_HEAD",
  "expectedCurrent": {"releaseId": null, "sha256": null},
  "publicKeyPath": "/Users/ouwei/agents-anywhere/desktop-workbench/build/release-public.pub",
  "stagingDirectory": "/absolute/stage",
  "backupDirectory": "/absolute/independent-backups",
  "restoreDirectory": "/absolute/restore-tests",
  "allowUnsigned": true,
  "unsignedReason": "No official platform certificate; unsigned installation requires OS confirmation",
  "minimumClientVersion": "0.1.10",
  "minimumServerVersion": "2.2.0",
  "builds": [
    {"directory":"/absolute/darwin-universal", "acceptancePath":"/absolute/darwin-universal/acceptance.json", "acceptanceSha256":"64_HEX_REVIEWED_REPORT"},
    {"directory":"/absolute/win32-x64", "acceptancePath":"/absolute/win32-x64/acceptance.json", "acceptanceSha256":"64_HEX_REVIEWED_REPORT"}
  ]
}
```

null/null 仅表示人工已确认 stable 尚不存在；非首次发布必须固定审阅时 current 的 releaseId **及完整封套字节 SHA-256**，不是执行时自动接受当前值。publishedAt 固定一次，同 spec 重试不变。发布 plan 还绑定发布工具及 dist/config helper 摘要；工具改变后须新 plan/staging，已成功平台包可复用，只重新验证相关证据。

## 对象读回、备份与恢复

存储 adapter 只读原始 `~/.config/osir-client-release/rains3.json`，先核对其仍为 Client endpoint/bucket/region/prefix/public_base，再使用同桶固定的 `osir-anywhere/releases` 路径；不修改文件，不生成 derived credentials，不调用或改造 Client uploader。

工件、清单、签名 provenance、原生证据和依赖解析证据写到 `RELEASE_ID/filename`。先 HEAD；存在则完整公开读回验证，不覆盖；不存在使用 If-None-Match:* PUT。即使竞争返回 412，也必须完整读回，摘要不符即停止。单文件上限 5GiB，超出拒绝，不用无条件 multipart 覆盖。主站不收发安装包字节。

### RainS3 小对象节流与有限读重试

`desktop-workbench/scripts/osir-anywhere-storage.mjs` 已持久应用本次节流修复，并有既有 **39/39** 相关测试通过记录。默认对不超过1MiB的小对象操作间隔600ms，可用 `OSIR_ANYWHERE_STORAGE_INTERVAL_MS` 调整（范围0至60000ms）。GET/HEAD 遇到 HTTP 503 时，仅当 `Retry-After` 是0至60秒的整数且最多未重试两次，才等待后重试；重签请求以避免SigV4签名过期。其他状态、无效/过长 Retry-After 与传输错误均失败关闭。PUT，包括不可变对象条件写和stable CAS，**不自动重试**；结果不确定时先核对远端状态/回执，禁止盲目重写。

读回仍须无重定向、直接 HTTPS 200、无内容编码、精确 Content-Length 与 SHA-256；保留90秒停滞超时、对象总时限及错误脱敏。不打印凭据、Authorization、服务端错误响应体或敏感 headers。失败副本和 package attempt 保留，不能为重试删除其他输出。本次 r4 已完成发布，原prepared plan因工具指纹变化已过期；任何未来发布都要重新plan，不能用旧plan续发。

publish 前再次从公开对象地址独立读取到 backup，不以 staging 副本充数；backup/stage/restore 不得相互嵌套或通过链接重叠。独立恢复到新目录，逐文件重新核对 index、字节和签名清单，保留 previous-stable 封套及恢复回执。**目录隔离不能证明独立磁盘故障域**；生产操作人应将 backup 放独立存储/离线介质并确认容量。本机剩余约 7GB，不能在本机做大包构建或盲目保留多份包。

独立 `restore` 也强制传入外部受信公钥，校验 manifest 与 provenance 的 RSA 签名，再按签名绑定的 plan 核对所有原包、构建回执、系统签名、来源、依赖锁与原生证据。只改备份文件并重写本地校验索引仍会失败；不能把备份自带的任意新公钥当成信任根。恢复输出保留，不启动安装、不修改 stable。

主会话于 **2026-11-14** 用新鲜 Chrome 核实 RainS3：空间 10GB、流量 50GB，已用空间约 2.1GB、流量约 2.7GB；流量 **2026-12-02** 重置，套餐 **2026-12-09** 到期。上述是人工核实记录，不是工具自动查询余额。按当前实现，首次 `upload` 每对象完整公开读回一次；`publish` 再全量校验并独立下载备份，已有备份可复用但仍验哈希。正常首次发版约需 3 倍安装包总量的对象读取流量，重试另计；本地 staging/backup/restore 也各占一份。主任务须按最终原包实际大小判断可用空间与剩余流量，不删除既有输出腾空间，不把主站作为字节中转。

完成后重新权威 GET stable，核对预期 envelope hash、releaseId、ETag，再 If-Match 切换；初次发布 If-None-Match:*。没有无条件 PUT 回退。写前先保存 publish-intent；写后权威 GET 和公开完整读回都要等于精确候选封套。

如 CAS 响应丢失，重试 publish 只对账：current 精确等于候选则确认已成功，绝不二次写；current 不一致则停止并要求主任务核对。旧 stable 保存在独立备份，后续回退必须人工审阅当前 ETag 后走条件切换，不能照抄旧 receipt 或自动覆盖。独立 restore 命令只恢复本地文件，不改 stable。

## 原生验收报告：不从 headless 推导

acceptance.json 必须包含 schemaVersion=1、sourceSha256、configSha256、target、artifactSha256、systemSignatureReportSha256、result=passed、nativeMachines、checks 与 evidence。Mac Universal 的 nativeMachines 必须同时有 darwin-arm64/darwin-x64；Win x64 为 win32-x64。evidence 是真实日志/截图相对路径、大小、SHA-256，随原包证据保留。

checks 每项必须真实执行通过：installer、launch、connector、python、uv、upgradeDataPreserved、updateDiscovery。需要原生安装/启动、最终包内 Python/uv 与 Connector 实际运转、隔离数据跨版本保留，以及仅 Desktop PATCH/Server 版本不变时能发现新版本。报告和原始证据经主任务审阅后把报告字节摘要写进 release spec。工具不自动生成通过结论；单元测试的合成报告仅位于临时目录。

Meitner 的 smoke 与主会话聚合应把同一最终 installer 分发给 macos-15、macos-15-intel、windows-2022，ARM 正式支持后再加 windows-11-arm；执行受控安装、真实窗口、Connector 活动与隔离升级数据检查，报告绑定 artifact/source/config/signature hashes。单机 smoke 的 partial/incomplete 报告或同包重开不能替代正式 acceptance；需另有不同前版到新包的实际数据保留和 Server 不变的 Desktop PATCH 更新发现证据。主任务统一调度，不触碰用户正在运行的 Client/Anywhere 正式应用。

## 已做验证

本轮执行 **38/38** 相关 Node headless tests（含已有 build/package helper tests），`git diff --check` 通过。覆盖来源白名单、recipe 原始字节与自引用拒绝、秘密隔离、skip-build 指纹、同锁、ARM 真实报告/依赖输入绑定、RSA 篡改、unsigned/损坏签名区分、全量读回、失败续跑、带外部信任根的独立备份恢复、预期 current、CAS 并发及响应丢失对账。尚未运行最终原生 build/smoke，未用正式私钥签名/读取存储凭据，未上传或发布。

workflow 通过 actionlint v1.7.7 表达式/结构检查（禁用本机未配置的 shellcheck/pyflakes）；该旧版不认识主任务已实测可用的 `windows-11-arm`，只忽略这一条标签诊断，不忽略表达式或其他错误。复验命令：

```sh
node --test desktop-workbench/scripts/osir-anywhere-*.test.mjs desktop-workbench/scripts/desktop-build-config.test.mjs desktop-workbench/scripts/desktop-package-config.test.mjs
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7 -shellcheck= -pyflakes= -ignore 'label "windows-11-arm" is unknown' .github/workflows/osir-anywhere-native-build.yml
git diff --check
```

**冻结边界：本工具主体 ready 可纳入主会话最终源审阅；不代表最终发行已批准。** 主会话仍负责收敛并冻结源码/recipe/版本 SHA、云端 2.2.0 配套、Meitner 原包 smoke 与跨版本/PATCH 聚合、Epicurus ARM 证据取舍、真实 CI 调度和最终 stable 切换。

反思：可恢复和真实性门禁已经进入工具合同，但真实安装/Connector/跨版本数据保留仍需要最终原包证据；不能把工具测试数量当成正式包验收结论。
