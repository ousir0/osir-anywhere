# Anywhere 2.2.1 revision 2 原包原生升级验收

本独立 harness 从旧成功 harness `91fcddfb8b06a6f3c46dcc083780d128de0fdc8c` 创建，仅更新 r2 候选绑定及必要的 revision 发现对照。最终产品源码、安装包和编译输出不修改。本地合成测试不等于新包原生验收通过。

## 固定产品与独立控制

| 项目 | 精确值 |
| --- | --- |
| Repository | `ousir0/osir-anywhere`，已授权 public |
| Product commit | `b95e4498b418eb582c37ae17284fa0699ef1345c` |
| Source SHA256 | `d2f00392890f4b7f38d0d4faad82e5d900206eba9440b7674d1488cf9126ba66` |
| Recipe SHA256 | `e9c517add26144970e288de50d882935fe09ec9283db420bd3228370711b07d9` |
| Release identity | `osir-anywhere-2.2.1-20261115-r2`，`releaseRevision=2` |
| Producer run | `43715039594`；attempt、成功平台 job 和工件身份以新原始证据为准 |
| Upgrade control branch | `codex/anywhere-221-r2-upgrade-acceptance-20261115` |
| Upgrade local Git worktree | `/Users/ouwei/.codex/release-evidence/20261115-anywhere-221-r2-upgrade-acceptance/harness-checkout` |
| Smoke harness SHA | `8da80c839c714e1b3c8d6989559f02a8a09c52b2`，原逻辑原样复用 |
| Smoke control branch | `codex/anywhere-221-smoke-readiness-20261114` |
| Smoke local Git checkout | `/Users/ouwei/.codex/release-evidence/20261114-anywhere-release-control` |

上述两个 Git checkout 共享 control repo。`20261115-anywhere-221-r2-native-control` 是旧证据目录，其 `harness-checkout` 子目录才是旧 r2 upgrade worktree；不能把证据目录当作 Git checkout。

`all` 为 Mac ARM、Mac Intel、Windows x64。Mac 两机复用同一 Universal artifact；Mac 优先用 `darwin-universal`。Windows ARM64 仍需单独审核其工件和平台证据，不在 `all` 中。

## 保留的原生验收

- 原始最终安装包只下载、校验和安装，不重建、不重签。producer 仓库身份、workflow、commit、attempt、成功原生 job、artifact ID/name、完整 ZIP digest 都重新验证。
- 延用真实 GUI、窗口身份、welcome、正常退出、安装前后数据与 localStorage 保留等已有门禁。失败保留原始证据。
- 延用 GitHub-hosted 干净 VM 中的 test-only `2.2.0` version-only derivative；只替换 package.json 的一个版本 token，复用原包编译输出。这不是已发布历史 2.2.0 的迁移证据。
- 衍生 baseline 的准备和原包验收在独立 hosted VM；不会在本机打包或启动产品。独立工具版本维持 electron-builder 26.18.1、asar 3.4.1、TypeScript 6.0.3。
- 系统签名分类和原生 PE/bundle 版本检查维持原逻辑；不假定 `releaseRevision` 一定映射到 OS 原生版本的第四段。

## 新增 revision 发现验收

直接执行最终 ASAR 的 `DesktopUpdateService` 与 `readPackagedRevision`。后者从可信 `app.getAppPath()` 读取 `dist/build-info.json`，必须得到已安装 revision 2；缺失、旧格式、错误版本或 revision 均不能冒充新包。

临时 RSA key 只在内存中；所有 fetch 由合成 fetcher 接管，没有网络 fallback。顺序为：

1. Server health 控制：2.2.0。
2. 清单 2.2.1 revision 2：无更新。
3. 清单 2.2.1 revision 3：有更新、dialogOpen、适用 artifact、无错误。
4. 清单 2.2.1 revision 0：无更新，防止降级。
5. 清单 2.2.2 revision 0：仍发现 PATCH 更新。
6. 坏签名：checkFailed。
7. Server health 控制：仍为 2.2.0。

共九次有序 GET（含两次兼容 health），五份签名 envelope；四份有效、一份故意损坏。报告保存 actualVersions、actualRevisions、状态、请求和原始 envelope；下载/安装调用必须为零。产品的六个 TS 模块由独立 product checkout 读取并按 source inventory 校验，CI sparse checkout 包含 release-build-info.ts。

这证明包内原生服务发现更新，不证明生产 feed、生产密钥、renderer 更新 UI、真实 OAuth、模型或用户交互安装确认。Mac account-free fixture 保留 mock keychain，不能当作真实凭据迁移证据。

## 严格 bindings 契约

沿用 smoke 的 schemaVersion 1，**不增加顶层 revision 字段**，否则旧 smoke 会拒绝。顶层字段必须恰为：

```text
schemaVersion, repository, sourceCommit, sourceSha256, recipeSha256,
configSha256, dependencyLockSha256, version, artifacts
```

固定 repository/product/source/recipe/version 如上；config 与 dependencyLock 从新原包收据及 raw resolved-yarn.lock 计算，跨平台必须一致。每个 artifacts 条目恰为：

```text
target, runId, runAttempt, artifactId, archiveSha256, receiptSha256,
artifactSha256, artifactSize, systemSignatureReportSha256
```

仅 win32-arm64 另需 windowsArm64EvidenceSha256。archiveSha256 是完整 GitHub ZIP 的 API digest；artifactSha256/size 是 ZIP 内最终 DMG/EXE；receiptSha256 和 signature digest 均对原始文件字节计算。不能互相替代。

revision 通过固定 recipeSha256、`receipt.plan.releaseRevision === 2`、精确 releaseId 和最终安装 ASAR build-info 三层绑定。新 upgrade CI 每个有原包的阶段复核 receipt；任一字段不符即失败。

生成输入为新 run/完整 jobs/artifacts API 原始快照，加各目标原始 build-receipt.json、compiled.json、source-provenance.json、system-signature.json、resolved-yarn.lock。只读本地 evidence 生成 bindings；旧 r2 prepare-controls.mjs 的 run/ID/lock 不可复用。元数据审核不等于完整 ZIP/installer 校验；后者仍由原生 runner 强制执行。

bindings_json 使用 `JSON.stringify(bindings) + '\n'`，bindings_sha256 对这份完整 raw UTF-8 字节（含末尾换行）计算。smoke 与 upgrade 共用完全相同的 raw bindings。dispatch payload 为：

```text
ref: 各自独立 harness branch
inputs: {harness_commit: 对应精确 40 位 SHA,
         bindings_json: raw 原文, bindings_sha256: raw SHA256,
         target: darwin-universal | win32-x64 | all}
```

smoke workflow `osir-anywhere-artifact-acceptance.yml`（417788808）；upgrade workflow `osir-anywhere-upgrade-acceptance.yml`（417813131）。工作流 ref 和 harness_commit 必须一致，均不能用 product commit 代替。本任务仅推送独立 harness 分支；原包下载、真实 binding、workflow dispatch 和发布均由主控执行，本任务不派发 workflow。


## 本次增量验证（2026-11-15）

- 旧成功 harness 已确认 HEAD 为 `91fcddfb8b06a6f3c46dcc083780d128de0fdc8c`，工作区干净；新分支从此提交独立创建。
- 新产品 detached sparse checkout 的 HEAD、source inventory fingerprint、recipe 原始字节 SHA256、releaseId/releaseRevision 均与上表一致。仅读取 6 个已校验的更新发现 TypeScript 模块作为合成测试输入。
- Node `22.22.2` 定向测试：**7 passed / 0 failed / 0 skipped**。覆盖精确产品 pin、拒绝旧 r1/混合 pin、receipt revision 2、新 revision 常量、序列化真实更新服务的 2→3 发现及错误 revision 拒绝；另包含既有独立工具版本控制。日志保存在独立目录 `../r2-pins-focused-tests.log`。
- 执行两个测试文件 `osir-native-upgrade-acceptance.test.mjs` 和 `osir-native-upgrade-acceptance.ci.test.mjs`，使用 `--test-name-pattern='upgrade plan binds|previous r1|upgrade receipt|r2 discovery constants|serialized probe exercises|same public revision discovery|discovery uses|versions'`。`OSIR_UPGRADE_TEST_SOURCE_ROOT` 指向冻结新产品 sparse checkout；binding 使用明确的合成工件字段，仅用于本地测试，不能用于真实 workflow dispatch。
- 本次仅变更 upgrade harness 的新产品/revision pin、必要测试及说明；smoke 逻辑、原生 second-instance 门禁和 connector 测试均未修改或重复执行。未运行原包原生验收、未下载原包、未派发 workflow、未修改生产配置。
- 交接时由主控将新原包生成的完整 bindings 原始字节及 SHA256 传给 workflow，并令 `harness_commit` 与所选 workflow ref 对应同一精确提交。Producer `43715039594` 的 artifact/run attempt/receipt/installer/signature/lock 仍由真实证据绑定，本次不将合成数据或口头 ZIP 摘要写成生产 binding。
