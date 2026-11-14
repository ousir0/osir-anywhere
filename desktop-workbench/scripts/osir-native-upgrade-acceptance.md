# Anywhere 2.2.1 revision 1 原包原生升级验收

本独立 harness 继承已通过的 r2 upgrade `98444e185f84650b4dc71bee1fea5e032ab066a0`，仅更新候选绑定并追加同公开版本的 revision 发现验收。最终产品源码、安装包和编译输出不修改。本地合成测试不等于新包原生验收通过。

## 固定产品与独立控制

| 项目 | 精确值 |
| --- | --- |
| Repository | `ousir0/osir-anywhere`，已授权 public |
| Product commit | `27b001b80ee3df91f37e3cb9ea70fe007f530b33` |
| Source SHA256 | `5f5d727080f81d01e1749df028daa3cfcb8c4a1eb126be9d3999745861ce6b9a` |
| Recipe SHA256 | `258b01591b9d82cfdfae5b0dcb4a22a01fd4e65502fd7c042d5bed69b2d56bb7` |
| Release identity | `osir-anywhere-2.2.1-20261115-r1`，`releaseRevision=1` |
| Producer run | `43631758068`；attempt、成功平台 job 和工件身份以新原始证据为准 |
| Upgrade control branch | `codex/anywhere-221-r1-handoff-acceptance-20261115` |
| Upgrade local Git worktree | `/Users/ouwei/.codex/release-evidence/20261115-anywhere-221-r1-acceptance/harness-checkout` |
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

直接执行最终 ASAR 的 `DesktopUpdateService` 与 `readPackagedRevision`。后者从可信 `app.getAppPath()` 读取 `dist/build-info.json`，必须得到已安装 revision 1；缺失、旧格式、错误版本或 revision 均不能冒充新包。

临时 RSA key 只在内存中；所有 fetch 由合成 fetcher 接管，没有网络 fallback。顺序为：

1. Server health 控制：2.2.0。
2. 清单 2.2.1 revision 1：无更新。
3. 清单 2.2.1 revision 2：有更新、dialogOpen、适用 artifact、无错误。
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

revision 通过固定 recipeSha256、`receipt.plan.releaseRevision === 1`、精确 releaseId 和最终安装 ASAR build-info 三层绑定。新 upgrade CI 每个有原包的阶段复核 receipt；任一字段不符即失败。

生成输入为新 run/完整 jobs/artifacts API 原始快照，加各目标原始 build-receipt.json、compiled.json、source-provenance.json、system-signature.json、resolved-yarn.lock。只读本地 evidence 生成 bindings；旧 r2 prepare-controls.mjs 的 run/ID/lock 不可复用。元数据审核不等于完整 ZIP/installer 校验；后者仍由原生 runner 强制执行。

bindings_json 使用 `JSON.stringify(bindings) + '\n'`，bindings_sha256 对这份完整 raw UTF-8 字节（含末尾换行）计算。smoke 与 upgrade 共用完全相同的 raw bindings。dispatch payload 为：

```text
ref: 各自独立 harness branch
inputs: {harness_commit: 对应精确 40 位 SHA,
         bindings_json: raw 原文, bindings_sha256: raw SHA256,
         target: darwin-universal | win32-x64 | all}
```

smoke workflow `osir-anywhere-artifact-acceptance.yml`（417788808）；upgrade workflow `osir-anywhere-upgrade-acceptance.yml`（417813131）。工作流 ref 和 harness_commit 必须一致，均不能用 product commit 代替。仅由主控 push/dispatch；本任务只做本地 commit。
