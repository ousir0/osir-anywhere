# Anywhere 2.2.1 原包原生升级验收

本独立 harness 基于已成功版本 `20f79cd6d7cc4986238c6c7a8da2fdfa015f76af`（旧原生验收 run `43556674389`）适配。仅准备验收工具；不改产品、版本、feed，不发布，不操作本机应用。新版本原生验收尚未执行，小型回归不等于原生验收通过。

## 冻结输入与范围

| 项目 | 固定值 |
| --- | --- |
| Product commit | `a85a573f7a424eb1ca557fc43b8d84e4d8ec000d` |
| Source SHA256 | `50f155a61d75222134446cdb094645faa80677ea80a66a0fa02a578ca3fc85ad` |
| Recipe SHA256 | `2f9e9ab2b224b2d41e20e002132d3f6ad63773507271ecaf85bc323ef1ed01fa` |
| 原包生产 run | `43600642383`，attempt `2`；须等待对应平台 job 真正成功并审阅工件 |
| Final Desktop | `2.2.1`，原始安装包不重建、不修改、不重签 |
| Test-only baseline | 从该原包/冻结源派生 `2.2.0`，不是已发布的历史版本 |
| 合成更新发现 | Desktop `2.2.1 → 2.2.2`，最低 Server 与 health 始终 `2.2.0` |

`target=all` 覆盖 Mac ARM、Mac Intel、Windows x64。Mac 两机消费同一个 Universal 原包。`darwin-universal` 可先独立验证 Mac；Windows ARM64 只有提供相应原包绑定才可选择。

## 已发布 2.2.0 基线核对

2026-11-14 只读读取 stable，原始 envelope SHA256 为 `a2cf4b020ef4aca49fbc0e27d8c0332b1d1c30eec1e9f1fe4a43fcaf433b857a`，payload 指向 `osir-anywhere-2.2.0-20261114-r4`，最低 Server `2.2.0`。这里核对了 raw hash 与 payload，未重新下载整包或独立验签，不构成历史升级已通过证据。

对象共同前缀：

```text
https://osirvedio.cn-nb1.rains3.com/osir-anywhere/releases/osir-anywhere-2.2.0-20261114-r4/
```

| 对象 | bytes | SHA256 |
| --- | ---: | --- |
| `osir-anywhere-2.2.0-darwin-universal.dmg` | 303968518 | `0c9bc8d94cfc2682807e34534e1e1fe78f67171cf400bbda4371626fc42cdedb` |
| `osir-anywhere-2.2.0-win32-x64.exe` | 143543056 | `b7b07c4f643b7e0c32d0b0d65d91966619eac4fd6ddbedd54987d6143a4c27c9` |

真实历史包具备可用的对象地址与清单身份。但当前工具强制基线共用最终源码、配置、编译输出和唯一 metadata diff，并在跨 job 转交时重新核对这些证据。为避免扩展成双基线新工具，本轮按授权保留 test-only derivative。报告始终 `kind=controlled-version-only-derivative`、`releaseEligible=false`、`historicalBaseline=false`；不得改成历史迁移成功。主代理另补本机真实已发布 2.2.0 → 2.2.1 与真实对话验收。

## 保留的门禁

- 生产者必须是已公开的 `ousir0/osir-anywhere`，仍严格核对 repository 名称/ID、workflow、commit、attempt、native job success、artifact ID/名称、archive SHA256。公开仓库不再被旧 private-only 条件误拒绝。
- raw bindings 的 SHA256、source/recipe/config/共享 dependency lock、build receipt、原始 installer size/hash、系统签名报告均重新绑定。升级 workflow 额外固定上表的 product commit/source/recipe/version。
- 每架构 `review → prepare-baseline → native-upgrade`；prepare 和实际安装在不同干净的 GitHub-hosted VM，不能通过删真实用户数据制造干净前提。
- baseline 仅替换冻结 `desktop-workbench/package.json` 的一个 version token，其余源码字节不变；原包编译输出只提取复用，renderer 不重编译。独立打包工具固定 `electron-builder@26.18.1`、`@electron/asar@3.4.1`、`typescript@6.0.3`，禁止产品 install scripts。
- 原包和 baseline 均验证实际 native 系统签名。Mac ad-hoc 必须完整有效，不能把破损签名算 unsigned；Windows 校验 PE ProductVersion/FileVersion 仅 exact 或 exact + `.0`，ASAR version 精确相等。
- 真实 GUI 会话必须通过 OSIR 窗口身份、welcome 品牌和可见可用登录按钮再截图；Loading、inspect timeout、强制杀掉代替正常退出均不算通过。
- baseline 原生安装并启动，写入合成偏好/文件/localStorage；最终原包覆盖同一路径。分别核对安装前后、最终启动后及正常退出后的数据 hash、同一 userData/origin。
- 最终 app.asar 内真正的 DesktopUpdateService 使用临时 RSA 公钥/合成 fetcher；检查无更新、PATCH 可更新、坏签名拒绝和六次有序 GET。Server 前后与兼容请求均为 `2.2.0`，不下载或打开合成安装包。
- 报告保留每项非空 raw evidence 的 size/hash、同一 harness SHA/run/attempt/machine 的 baseline transfer，拒绝目录逃逸、换包、漏项、混平台；失败留证，不能注入假通过。

Mac account-free fixture 仍用 `--use-mock-keychain` 防止无人值守提示阻塞；不证明真实钥匙串授权、加密凭据迁移、真实 OAuth/模型、生产 feed/网络、renderer 更新 UI 或用户交互安装确认。真实候选 UI/SSO 必须不加此参数。运行策略 `unrestricted-no-product-credentials`，不声称离线隔离。基线是 synthetic 版本，但安装/GUI/数据验收仅在真实 native CI 成功后才可标 passed。

## 绑定输入格式

复用原包 smoke 的严格 schema，不加历史包或 test-only baseline。以下为**不可直接 dispatch 的格式模板**；所有占位 hash、0 ID/size 必须由已下载并审阅的实际工件填入。不要根据文件名猜 hash，不用 archive SHA 替代 installer SHA。

```json
{
  "schemaVersion": 1,
  "repository": "ousir0/osir-anywhere",
  "sourceCommit": "a85a573f7a424eb1ca557fc43b8d84e4d8ec000d",
  "sourceSha256": "50f155a61d75222134446cdb094645faa80677ea80a66a0fa02a578ca3fc85ad",
  "recipeSha256": "2f9e9ab2b224b2d41e20e002132d3f6ad63773507271ecaf85bc323ef1ed01fa",
  "configSha256": "<same-reviewed-config-sha256-for-both-platforms>",
  "dependencyLockSha256": "<same-reviewed-resolved-yarn-lock-sha256-for-both-platforms>",
  "version": "2.2.1",
  "artifacts": [
    {
      "target": "darwin-universal",
      "runId": 43600642383,
      "runAttempt": 2,
      "artifactId": 0,
      "archiveSha256": "<github-artifact-archive-sha256>",
      "receiptSha256": "<raw-build-receipt-json-sha256>",
      "artifactSha256": "<original-dmg-sha256>",
      "artifactSize": 0,
      "systemSignatureReportSha256": "<raw-system-signature-json-sha256>"
    },
    {
      "target": "win32-x64",
      "runId": 43600642383,
      "runAttempt": 2,
      "artifactId": 0,
      "archiveSha256": "<github-artifact-archive-sha256>",
      "receiptSha256": "<raw-build-receipt-json-sha256>",
      "artifactSha256": "<original-exe-sha256>",
      "artifactSize": 0,
      "systemSignatureReportSha256": "<raw-system-signature-json-sha256>"
    }
  ]
}
```

## 执行命令（由主控在原包工件成功后执行）

独立控制 branch：`codex/anywhere-221-native-acceptance-20261114`。仅推该新 branch，remote 必须为 `ssh://git@ssh.github.com:443/ousir0/osir-anywhere.git`，不移动产品、旧运行 harness 或其他 ref。freeze harness 后若有更改必须新 SHA、新 dispatch，不 rerun 旧 harness run。

```bash
cd /Users/ouwei/.codex/release-evidence/20261114-anywhere-release-control
HARNESS_SHA="$(git rev-parse HEAD)"
BINDINGS=/absolute/reviewed-221-bindings.json
BINDINGS_SHA256="$(/Users/ouwei/.nvm/versions/node/v22.22.2/bin/node --input-type=module -e 'import {readFileSync} from "node:fs"; import {createHash} from "node:crypto"; console.log(createHash("sha256").update(readFileSync(process.argv[1])).digest("hex"))' "$BINDINGS")"
gh workflow run osir-anywhere-upgrade-acceptance.yml \
  --repo ousir0/osir-anywhere \
  --ref codex/anywhere-221-native-acceptance-20261114 \
  -f harness_commit="$HARNESS_SHA" \
  -F bindings_json=@"$BINDINGS" \
  -f bindings_sha256="$BINDINGS_SHA256" \
  -f target=all
```

Mac 优先可用 `-f target=darwin-universal`，随后同一绑定跑 `win32-x64`；不能把单平台完成写成 all。工具对实际原包 job 独立核验，允许复用大 run 内已成功的平台，不因另一个平台失败而重构已成功包。

`prepare-baseline` 内部产出 `baseline-receipt.json` 与 `TEST-ONLY-*` 安装包；`prepared` 只代表基线准备成功。转交到干净 native job 后，报告为 `native-upgrade-acceptance.json`，两项 checks 必须都 true 且 `evidenceMode=native/result=passed`。每机保留 evidence artifact，再与独立 smoke 的五项门禁一起聚合；任何本地模拟都不能替代这些证据。

## 小型回归

CI review 自动对 upgrade、CI glue 和原包 producer/transfer 合约执行 node tests，独立安装测试工具，所需五个 Electron TS 模块必须从冻结 product checkout 读取并校验 source inventory。回归不安装或启动本机 app。新增反例保证 Desktop 改为 2.2.1 后 Server 仍 2.2.0，错误地同升 Server、minimumServer 变动、错误健康版本和其他 source/recipe/version 均不能被接受。

本轮本地使用 Node `v22.22.2`、现有独立 `NODE_PATH` 与 byte-verified 冻结产品测试源码执行上述三个 test 文件：**64 passed、0 failed、0 skipped**。原始日志 `/tmp/osir-anywhere221-harness-regression.log`。全部是合约/模拟控制回归，不是新包原生验收结果。
