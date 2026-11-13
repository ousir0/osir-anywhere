# Anywhere 原构建工件独立验收 harness

日期：2026-11-14。这个 harness 不进入产品 source freeze；不修改 candidate JSON、root recipe、build-only workflow 或产品构建工具。产品构建与本次验收的 commit **分别锁定**。本文件记录执行合同，不表示已运行原生验收。

## 入口与范围

- Workflow：`.github/workflows/osir-anywhere-artifact-acceptance.yml`。
- CI helper：`desktop-workbench/scripts/osir-artifact-acceptance-ci.mjs`、对应 `.test.mjs`。
- 原生实现：Meitner 的 `osir-native-smoke.mjs` / `osir-native-smoke-provision.mjs`。不得以 CI helper 的 metadata 检查代替真实 smoke。
- 主线程最终使用 `osir-native-acceptance-aggregate.mjs` 聚合每架构五项 smoke 与两项 upgrade 的真实原始报告；本 workflow 不制造完整 publisher acceptance。

主控已授权默认使用 **disposable-clean-runner**：真实 GitHub-hosted 一次性原生 GUI runner、无产品凭据、产品进程环境白名单、只用合成数据，不登录真实账号，不调用真实模型，不写真实项目。记录 `networkPolicy: unrestricted-no-product-credentials`，公网可能可达；不能称为网络隔离或用 `UV_OFFLINE` 宣称整个进程树断网。依赖缓存和解析锁仍可用于稳定复现 Python 依赖。

## 受审输入

主线程提交独立 harness 后，dispatch 的 workflow ref 与 `harness_commit` 必须精确一致。helper 核对 `GITHUB_WORKFLOW_SHA`、实际 checkout HEAD、GitHub-hosted 身份和专用私有仓库。对执行用 workflow/helper/common/native-smoke/provision/signature 脚本另将 checkout 原始字节与该 commit 的 Git blob 逐项比较，换行转换也拒绝。保留主控已审阅的 `.gitattributes`；无需修改产品 freeze。

`bindings_json` 是主线程审阅的最终原包身份，`bindings_sha256` 是该输入字符串**原始 UTF-8 字节**的 SHA-256，包括空格和结尾换行。它不是产品源码文件，不回写 source snapshot；不得把它加到原产品 source.files。以下占位值必须由成功的真实 build receipts/API metadata 填充：

```json
{
  "schemaVersion": 1,
  "repository": "ousir0/osir-anywhere",
  "sourceCommit": "FULL_FINAL_PRODUCT_SNAPSHOT_SHA",
  "sourceSha256": "REVIEWED_SOURCE_SHA256",
  "recipeSha256": "REVIEWED_RAW_RECIPE_SHA256",
  "configSha256": "REVIEWED_EFFECTIVE_CONFIG_SHA256",
  "dependencyLockSha256": "SHARED_RESOLVED_YARN_LOCK_SHA256",
  "version": "2.2.0",
  "artifacts": [
    {
      "target": "darwin-universal",
      "runId": 123,
      "runAttempt": 1,
      "artifactId": 456,
      "archiveSha256": "GITHUB_ARTIFACT_DIGEST_WITHOUT_SHA256_PREFIX",
      "receiptSha256": "RAW_BUILD_RECEIPT_SHA256",
      "artifactSha256": "ORIGINAL_DMG_SHA256",
      "artifactSize": 123456,
      "systemSignatureReportSha256": "RAW_SYSTEM_SIGNATURE_REPORT_SHA256"
    }
  ]
}
```

`target=all` 需要 darwin-universal **及** win32-x64 两项。仅验 Mac 可选 `darwin-universal`，会同时派 `macos-15` ARM 与 `macos-15-intel` Intel，严格复用同一个 Universal artifact ID/hash。Win x64 用 `windows-2022`。Windows ARM 仅显式选 `win32-arm64`；该项还强制给 `windowsArm64EvidenceSha256`，与原 build plan 及 source inventory 中的依赖预检报告指纹一致。ARM runner 能启动本身不构成支持完成。

不同目标可来自不同成功 run/attempt，但源码、配置、recipe、共享 Yarn lock 和版本必须完全一致。整体 run 尚在进行、其他目标打包中或失败，均不妨碍立即复用已成功目标；该目标 job 自身必须真实 success，并有完整、不可变的原 build receipt。失败 job 留下的 partial artifact 不可接受。

核对已保存的 bindings 输入可执行：

```sh
node --input-type=module - /absolute/reviewed-bindings.json <<'JS'
import fs from 'node:fs';
import crypto from 'node:crypto';
const raw = fs.readFileSync(process.argv[2]);
console.log(crypto.createHash('sha256').update(raw).digest('hex'));
JS
```

通过 GitHub UI/API 将文件内容原样作为 `bindings_json`；不要用会丢结尾换行的 shell command substitution。CLI 调度可由主线程用 JSON stdin：

```sh
node --input-type=module - /absolute/reviewed-bindings.json FULL_HARNESS_SHA FROZEN_HARNESS_BRANCH <<'JS'
import fs from 'node:fs';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
const raw = fs.readFileSync(process.argv[2]);
const body = {ref:process.argv[4], inputs:{harness_commit:process.argv[3], bindings_json:raw.toString('utf8'),
  bindings_sha256:crypto.createHash('sha256').update(raw).digest('hex'), target:'all'}};
const result = spawnSync('gh', ['api','repos/ousir0/osir-anywhere/actions/workflows/osir-anywhere-artifact-acceptance.yml/dispatches',
  '--method','POST','--input','-'], {input:JSON.stringify(body),stdio:['pipe','inherit','inherit']});
process.exitCode = result.status ?? 1;
JS
```

上述是主线程后续操作合同，本任务没有执行 dispatch。workflow 若尚未注册到仓库默认分支，由主线程先单独审阅注册，再以精确 harness 分支调度；不能让未审 workflow 运行在产品 source commit 上。

## 实际流水线

1. **review**：读取限定仓库的 GitHub API metadata，核对原 build workflow 路径、source commit、run/attempt、私有 repo ID、artifact ID/name/完整 archive digest、真实目标 job 与 runner 标签。metadata 请求 30 秒超时、4MiB 上限、禁重定向；不输出 token、错误响应体或 headers。
2. **warm-cache**：每真实机器重新下载其固定 ID 的原 build archive。`download-artifact@v8` 禁止摘要不符继续；helper 再流式读取完整 zip SHA-256，安全解包精确六项输入：最终 installer、build-receipt、compiled receipt、source provenance、system signature report、resolved Yarn lock。逐项核对原字节和 reviewed bindings。只调用原包中实际 uv/Python 和复制的 packaged Connector 预热依赖。
3. **cache transfer**：保存 cache tree、解析后的 Python `uv.lock`、原始日志与 report；先校验全树，再 tar 保留 uv 缓存内的链接/权限，不让 artifact zip 解引用改变指纹。transfer 绑定 report/tree/archive/hash、原包 receipt、实际机器、harness commit/run/attempt。
4. **native-smoke**：新的同类一次性 runner 再下载**同一个原 build artifact**，重复原包绑定，接收精确 cache bundle。Python 3.12 仅负责 harness 的 zip/tar 安全解包，产品运行时只认 installer 内实际 Python。cache 解包拒绝路径逃逸、外部链接和特殊文件，并重新全树核对。随后调用 Meitner 的实际 `run … --runner-mode disposable-clean-runner` CLI，五项原生检查只能来自真实执行。
5. **raw evidence**：成功、失败都收集 JSON/probe/截图/lock 等原始证据，并验 report 中每个 evidence hash。工作目录中的安装副本、cache、副本账户运行数据不重复上传。再次核对原 installer/receipt/signature 字节。每机输出 `smoke/native-smoke.json` 及其原始相对路径 evidence，主线程可直接交给 aggregate。CI evidence index 永远 `releaseAcceptance: incomplete`；不填 upgrade/discovery 通过标志。

工具没有产品构建、重打包、重签名、上传对象存储或 stable 切换命令。下载 GitHub artifact 容器不是重新生成 installer；原 DMG/EXE 字节始终是受审原包。

## 剩余验收边界

- Meitner 的 clean-runner CLI 已接线：`run --spec ABS --cache ABS --cache-report ABS --cache-report-sha256 SHA --output NEW_ABS --runner-mode disposable-clean-runner`。collector 强制 report 的 `runnerMode` / `networkPolicy` 准确、`networkIsolationClaimed:false`、`fullSmokeOfflineClaimed:false`，provision 成功且未改变全局网络状态。strict 模式原有失败结果不能冒充 clean 模式结果。harness 仍需主线程审阅提交并实际执行，CLI 测试不能代替真实原生结果。
- Ramanujan 的 upgrade helper 需支持现有原包输入。原 build artifact 没有完整 dist/renderer/out/node_modules 编译树，不能靠一份 compiled.json 声称这些输出仍可用。他正在实现从原最终包独立提取/复用的 test-only baseline 路径；衍生 baseline 不可发行，不修改最终原包，须保留受控版本与更新探针边界。
- 本 workflow 当前交付五项 smoke 的真实接线；跨版本数据保留与 PATCH discovery 需独立真实 upgrade 报告后再聚合。publisher 门禁不变。
- 无官方证书时原包仍准确记 unsigned；有效 ad-hoc 不等于 Developer ID 公证。损坏签名拒绝，不能借 clean 模式绕过系统签名检查或 Gatekeeper/SmartScreen。
- 当前产品 r2 的 commit/source/run 和 artifact ID/digest 以主线程最终绑定为准；不能把首轮失败 run 的 DMG 或尚未完成的 r2 job 当作成功安装包。

## 本轮本地验证

独立 helper 14 项测试覆盖真实 provision CLI 参数对齐、raw bindings、source/harness 分离、原始换行漂移、成功目标复用、metadata 诊断脱敏、原包替换、zip/tar 逃逸、缓存/lock 损坏、架构绑定、网络政策准确披露与失败证据保留。另与 Meitner smoke/provision focused tests 联合验证。workflow 通过 actionlint；旧 actionlint 只忽略已实测新 runner 标签的识别诊断。没有下载真实安装包、启动 Electron/Connector、调度 CI 或发布。

```sh
node --test desktop-workbench/scripts/osir-artifact-acceptance-ci.test.mjs
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7 -shellcheck= -pyflakes= -ignore 'label "windows-11-arm" is unknown' -ignore 'label "macos-15-intel" is unknown' .github/workflows/osir-anywhere-artifact-acceptance.yml
git diff --check
```
