# Anywhere 2.2.1 revision 3 原包原生升级验收

本独立 harness 从 r2 成功提交 `b6c70798d3e6ac9c8978a6c3e8c218541cfbd1f3` 创建，仅更新最终 r3 产品身份、revision 发现对照、对应测试与说明。smoke、原生安装/窗口/退出、数据保留、系统签名和清单验签门禁保持既有实现。不修改产品源码、最终原包或发布工具。

## 精确身份

| 项目 | 值 |
| --- | --- |
| Repository | `ousir0/osir-anywhere` |
| Product commit | `b66bc2ac1f94c4fb868e66c452cc8364d7cd301e` |
| Source SHA256 | `dde3f6be0c791818fb65af26023e64712f9b8035bd4c2013bcfda008a1f28b12` |
| Recipe SHA256 | `5d92fb0f008fabf3dab99d445c4c3f7d74248c886b1f656eb73e9c5a036594c8` |
| Release identity | `osir-anywhere-2.2.1-20261116-r3`，`releaseRevision=3` |
| Public version | `2.2.1` |
| Producer run | `43738311505`，attempt1；成功 job、artifact ID 与 ZIP hash 必须另行核验 |
| Upgrade branch | `codex/anywhere-221-r3-upgrade-acceptance-20261116` |
| Local harness | `/Users/ouwei/.codex/release-evidence/20261116-anywhere-221-r3-acceptance/harness-checkout` |
| Smoke harness | `8da80c839c714e1b3c8d6989559f02a8a09c52b2`，原逻辑复用 |
| Smoke branch | `codex/anywhere-221-smoke-readiness-20261114` |

升级 workflow ref 与 `harness_commit` 必须对应同一精确提交，不能用产品 SHA 替代。无运行时产品 pin 覆盖入口；CI plan、receipt 和最终安装 ASAR 三层核验来源及 revision。

## 验收范围与边界

- `darwin-universal` 在 `macos-15` ARM 与 `macos-15-intel` 原生检查同一份最终 DMG；Windows x64 在 `windows-2022` 检查其原始 EXE。`all` 不包含 Windows ARM64。
- 每份最终原包均绑定 producer repository/workflow/head/attempt/成功平台 job/artifact ID/name、完整 ZIP hash、receipt、source/config/shared lock、系统签名报告与安装器字节。不重建、不重包或重签成功原包。
- Mac 可以在自身 producer job 成功后优先开始验收；预收集不代表整个 producer run 已通过。最终汇总仍核对完整 producer 和所有必需机器的真实完成状态。
- 沿用干净 GitHub-hosted VM 的 test-only `2.2.0` version-only derivative：只替换一个 package.json 版本 token，复用最终包编译输出。这不是历史正式 2.2.0，也不是实际 r2→r3 迁移证据。
- Mac account-free fixture 保留既有 mock keychain，只用于合成账户隔离；不能宣称覆盖真实钥匙串、OAuth、凭据迁移或 Euclid 补丁的真实账户验收。不触碰本机生产应用。
- 无 Developer ID 时沿用既有 ad-hoc 封装，报告 `systemSignature:unsigned`，不称为公证；RSA 清单签名不能替代系统签名。

## 同公开版本 synthetic revision discovery

在最终 ASAR 的真实 `DesktopUpdateService` 和 `readPackagedRevision` 上执行：安装 build-info 必须为 `2.2.1/revision3`；合成清单依次提供 revision3（无更新）、revision4（有更新）、revision0（拒绝回退）、PATCH2.2.2/revision0（有更新）和损坏签名（checkFailed）。Server health 前后保持2.2.0。

保留九次有序 GET、五份原始 envelope、四份有效与一份故意损坏签名、零下载/安装调用。临时 RSA 私钥只在内存，fetcher 无真实网络 fallback。报告必须记录准确 actualVersions/actualRevisions；不把 synthetic 清单称为生产 feed，不把更新发现称为实际安装迁移。

## bindings 与派发

保持 smoke schemaVersion1，顶层字段恰为：

```text
schemaVersion, repository, sourceCommit, sourceSha256, recipeSha256,
configSha256, dependencyLockSha256, version, artifacts
```

每个 artifact 恰为：

```text
target, runId, runAttempt, artifactId, archiveSha256, receiptSha256,
artifactSha256, artifactSize, systemSignatureReportSha256
```

不增加顶层 revision。revision 由固定 recipe hash、原始 receipt 的 releaseId/releaseRevision 与包内 build-info 严格绑定。跨平台 config 和 resolved-yarn.lock 原始字节必须一致。

同一目标组的 smoke/upgrade 使用完全一致的 `JSON.stringify(bindings)+'\n'` 原始字节与 SHA256。Mac 优先组与后续 Windows 组各保留独立 bindings/run/evidence，不混 run 身份；最终按原包目标聚合。

派发输入保持 `harness_commit, bindings_json, bindings_sha256, target`。smoke workflow 为 `osir-anywhere-artifact-acceptance.yml`；upgrade 为 `osir-anywhere-upgrade-acceptance.yml`。本任务负责 producer、收集、验收和独立复核；不执行发布、trust 或生产应用操作。

## 本地验证

Node22.22.2（本机已有；CI仍固定22.23.2）执行 upgrade 两个测试文件、artifact CI 测试及 aggregate 测试，共70 passed / 0 failed / 0 skipped。序列化探针测试从上述最终冻结源读取六个 TS 模块，并逐项核对 source inventory 字节；工件字段为明确的 unit-only synthetic fixture，未用于实际派发。

日志：`/Users/ouwei/.codex/release-evidence/20261116-anywhere-221-r3-acceptance/logs/01-focused-tests.log`。这里只是 harness headless 结果；最终原包三机验收状态须看后续真实 CI 证据。
