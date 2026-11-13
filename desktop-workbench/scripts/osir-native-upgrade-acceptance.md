# Anywhere 原生升级验收 helper（独立于产品冻结源）

此工具补两项门禁：`upgradeDataPreserved`、`updateDiscovery`。只新增同前缀脚本及独立 upgrade workflow；不改产品、发布器、既有 smoke/provision/workflow。CI 只把 test-only baseline 和证据上传为当前验收 run 的短期 artifact，不发布 release。

**当前工具测试不代表原生验收通过。** 必须在 remote CI 真正运行后，才可能得到 `result: "passed"`。本机不重建、不安装、不启动产品，不生成大测试包。

## 边界

- 2.1.0 baseline 是从最终 2.2.0 冻结源派生的 **test-only** 包。唯一源文件变化是 `desktop-workbench/package.json` 的 `/version`。不是曾发布的旧版，不使用旧签名已损坏的本机 POC，不证明历史数据库/旧 schema 迁移。
- 基线重封装必然生成不同安装器、应用版本资源和签名容器。Mac 用有效 ad-hoc 封装，分类仍为 `unsigned`；Windows 不使用 Authenticode 身份。原始与派生 package.json、逐文件源清单、差异、包 hash 和签名检查均留证，不把“唯一源 metadata 差异”描述成“安装包只有几个字节变化”。
- Windows 保留原 source inventory 的可执行位元数据，但 NTFS 不提供 POSIX mode 核验，报告明确 `sourceExecutableModeVerified: false`。所有文件字节仍须核对；Mac 同时核对 executable mode。
- 数据检查覆盖同一路径跨版本安装后的合成偏好、JSON/二进制文件和 renderer localStorage。Mac 执行只读 DMG → `ditto` → 同路径完整替换 `.app`；Windows 执行真实 NSIS `/S /currentuser /D=...`，`/D` 最后。不是交互式安装 UI 或完整 UI 自动更新验收。
- 更新发现从最终原包安装出的 **真实 app.asar DesktopUpdateService** 在 Electron Main 上下文调用。注入临时 RSA 公钥和合成 fetcher，Desktop 2.2.0 → 2.2.1、Server 固定 2.2.0，保留请求、状态、签名清单和坏签名对照。不是生产 feed、公钥、网络或 renderer 更新 UI 验收。
- 临时测试私钥只存在于 Electron 内存，不读写生产 private key，不下载合成安装包，不开真实账号、项目或模型。
- 主控批准的 runner 模式为 `disposable-clean-runner`：真实 GH-hosted 原生 GUI、无既有产品/SDK 凭据、子进程环境白名单。`networkPolicy: "unrestricted-no-product-credentials"`，**公网可能可达，不宣称 offline 或网络隔离**。应用自身可能进行无凭据公共 health/update 读取；合成探针日志只记录其自身注入的请求。
- 不删除 quarantine/Zone.Identifier，不关闭或绕过 Gatekeeper、SmartScreen、系统确认。系统阻止启动时验收失败。只退出工具自己创建的 PID/进程组，不按产品名结束应用。

## CLI

在独立受审 harness checkout 的 `desktop-workbench` 下使用 Node 22。harness 需要能解析 `typescript`（仅测试）、`@electron/asar`、`electron-builder`；按 harness 自己的依赖安装，不能把依赖安装回冻结产品源。

```sh
node scripts/osir-native-upgrade-acceptance.mjs --help
node --test scripts/osir-native-upgrade-acceptance.test.mjs

node scripts/osir-native-upgrade-acceptance.mjs prepare-baseline \
  --spec /absolute/prepare-spec.json --output /absolute/new-baseline

node scripts/osir-native-upgrade-acceptance.mjs run \
  --spec /absolute/run-spec.json --output /absolute/new-upgrade-evidence
```

参数未知、相对路径、已有输出目录均拒绝。成功 prepare 返回 `prepared`，成功 native run 返回 `passed`；其余非零退出。输出父目录应已存在。prepare 输出必须在真实 `$RUNNER_TEMP` 下，且与冻结 checkout 无包含关系。

**prepare 与 run 使用不同干净 GH job。smoke 与 upgrade run 也分别使用干净 job。** Windows prepare 为提取编译输出会安装原 NSIS 到独立路径，run 则要在尚无产品数据的 GUI account 中从 baseline 开始；不要在同一账户先 smoke 再 upgrade，也不要通过删数据来伪造干净前提。

## 最小独立 workflow / 冻结交付

新文件恰好 8 个，均相对于仓库根目录；产品和既有 harness 文件不在本次写集：

```text
.github/workflows/osir-anywhere-upgrade-acceptance.yml
desktop-workbench/scripts/osir-native-upgrade-acceptance.mjs
desktop-workbench/scripts/osir-native-upgrade-acceptance.runtime.mjs
desktop-workbench/scripts/osir-native-upgrade-acceptance.extract.mjs
desktop-workbench/scripts/osir-native-upgrade-acceptance.ci.mjs
desktop-workbench/scripts/osir-native-upgrade-acceptance.test.mjs
desktop-workbench/scripts/osir-native-upgrade-acceptance.ci.test.mjs
desktop-workbench/scripts/osir-native-upgrade-acceptance.md
```

在**独立 harness branch**纳入这 8 个文件，保留已有 harness 只读依赖。`osir-native-upgrade-acceptance.ci.mjs` 的 `REVIEW_FILES` 是完整运行依赖校验清单，`UPGRADE_FILES` 是本次精确写集。独立分支应包含共享 NativeAdapter 的 Windows PowerShell 5 修复（已有 smoke harness commit `a13d43f5aad2d6046b6c5cb9894d38ced69fb673`：`System.UInt16` 与 `$ErrorActionPreference='Stop'`），以及其后主控新增的 `validateWindowsMetadata` / `validateWelcome`，不能只停在旧 a13 版本。upgrade 继承共享硬件探测并导入共享校验器，不修改 smoke。不要移动当前 main `9853d8b` 或产品 ref。

原包提取、baseline/final 安装都调用共享 Windows PE 校验：ProductVersion 和 FileVersion 只接受 exact 或 exact + `.0`，拒绝其他修订。ASAR package.version 始终精确相等，不放宽为四段。每次真实 Electron session 在窗口身份检查后，还须通过共享 welcome 校验（真实 h1 品牌、可见且 enabled 的主登录按钮）才截图。保存 `baseline-renderer-welcome.json`、`final-renderer-welcome.json`、`discovery-renderer-welcome.json`；未就绪的最后观察也留证，Loading 不能通过。无需重做已通过的 Mac warm cache/smoke，升级 final 页提供独立 ready 证据。

主控沿用原 build run `43514290185` 的**已审核 raw bindings JSON**及其 SHA；这组输入与 smoke 相同，必须包含每个 artifact 的精确 ID、archive/receipt/installer/signature SHA。不要只传 run ID、不要混入 test-only baseline。`target=all` 为 Mac ARM、Mac Intel、Windows x64；Windows ARM 需单独选择且有对应原包绑定。

GitHub 要求新 `workflow_dispatch` 文件先存在于默认分支；仅推到新分支可能不能按新文件名 dispatch。为保持当前 main 不动，本文件还支持 `workflow_call`：主控在**新的独立 upgrade harness 分支**把已注册的 `.github/workflows/osir-anywhere-artifact-acceptance.yml` 用下面最小入口桥接（现有 Dalton 冻结 commit、共享工作树中的该文件均不改）。分支内入口和 8 个新文件需共同进入同一受审 SHA；没有动态 ref、复用本次提交的本地 callee。

```yaml
name: OSIR controlled upgrade entry
on:
  workflow_dispatch:
    inputs:
      harness_commit: {type: string, required: true}
      bindings_json: {type: string, required: true}
      bindings_sha256: {type: string, required: true}
      target: {type: string, default: all}
permissions:
  contents: read
  actions: read
jobs:
  upgrade:
    uses: ./.github/workflows/osir-anywhere-upgrade-acceptance.yml
    with:
      harness_commit: ${{ inputs.harness_commit }}
      bindings_json: ${{ inputs.bindings_json }}
      bindings_sha256: ${{ inputs.bindings_sha256 }}
      target: ${{ inputs.target }}
```

以下命令仅由主控在 review 后执行；本次没有提交、推送或 dispatch：

```sh
# 在独立 harness checkout 的仓库根目录；HARNESS_SHA 是独立分支的完整 40 位 SHA。
# bindings.json 是前一轮主控审核的原样 JSON 文件，保留原字节/换行。
gh workflow run osir-anywhere-artifact-acceptance.yml \
  --repo ousir0/osir-anywhere --ref "$HARNESS_SHA" \
  -f harness_commit="$HARNESS_SHA" \
  -F bindings_json=@/absolute/reviewed-bindings.json \
  -f bindings_sha256="$BINDINGS_SHA256" -f target=all

# 新 upgrade workflow 若已注册到默认分支，也可将上述入口名直接改为：
# osir-anywhere-upgrade-acceptance.yml

# 本地只跑小型单测，不执行 native prepare/run，也不写共享 dist。
node --test desktop-workbench/scripts/osir-native-upgrade-acceptance.test.mjs \
  desktop-workbench/scripts/osir-native-upgrade-acceptance.ci.test.mjs
```

workflow 分三阶段：`review → prepare-baseline → native-upgrade`。每架构单独产生并绑定 test-only baseline，prepare 与 run 是独立干净 VM；Mac 两台机器都消费同一个最终 Universal 原包。harness 使用独立临时目录里的固定 `electron-builder@26.18.1`、`@electron/asar@3.4.1`、`typescript@6.0.3`，禁依赖 install scripts，不向 frozen-source 安装依赖。原包 runtime 模块不重编译；只对 test-only baseline 重封装。

原 archive 复用 Dalton 的整包 SHA 校验/精确文件提取/收据绑定；baseline 转交额外绑定同一 harness SHA、当前 run/attempt、机器、父工件和每个 raw 文件 hash。上传路径是过滤后的 bundle/证据目录，临时 app/source/build 树不上传。每次 checkout `persist-credentials: false`，GitHub token 仅供受限元数据/工件下载步骤；产品进程使用环境白名单。

最终交给 aggregate 的 artifact 名：`osir-native-upgrade-evidence-MACHINE-RUNID-ATTEMPT`，根目录即 `native-upgrade-acceptance.json` + 全部相对 evidence，无需改主控 aggregate 参数合同。`evidence-index.json` 只是 CI 转交索引，不能替代这两项原生报告。任何失败保留已有 raw 文件，checks 不伪造通过。

本地验收：最新 24 项 upgrade 定向单测全部通过、0 skip（新增 Loading/禁用登录按钮拒绝、实际 upgrade Windows 安装路径对 PE 零修订的接受及其他修订/ASAR 非 exact 拒绝）。前轮 14 项既有 artifact harness 合同测试通过；CLI help、新 workflow 和文内桥接 YAML 解析通过，全部新增 MJS 语法检查通过。未跑本地 build/main typecheck/native 安装，未启动或停止本机产品。当前没有已知 helper 代码缺口；执行前需主控把独立分支入口与新 callee 一同 review/freeze。首次 native CI 仍可能暴露下文列出的封装/安装/GUI 差异，应据实修复而非放宽校验。

## 共用 spec

沿用 smoke 的精确 `expected` 字段，额外字段放在外层；哈希和 commit 必须来自主控独立审核，示例占位字符串不可直接执行。

```json
{
  "schemaVersion": 1,
  "buildReceiptPath": "/artifact/build-receipt.json",
  "finalInstallerPath": "/artifact/osir-anywhere-2.2.0-darwin-universal.dmg",
  "systemSignatureReportPath": "/artifact/system-signature.json",
  "expected": {
    "sourceSha256": "64-hex-from-reviewed-source",
    "configSha256": "64-hex-from-reviewed-build-receipt",
    "checkoutHead": "40-hex-frozen-product-commit",
    "upstreamGitHead": "40-hex-from-source-provenance",
    "version": "2.2.0",
    "target": "darwin-universal",
    "artifactSha256": "64-hex-reviewed-final-installer",
    "artifactSize": 123456,
    "systemSignatureReportSha256": "64-hex-reviewed-signature-report"
  },
  "runner": { "nativeMachine": "darwin-arm64", "mode": "disposable-clean-runner" }
}
```

`target` 为 `darwin-universal` / `win32-x64` / `win32-arm64`；`nativeMachine` 是实际机器及原生 Node 的 `darwin-arm64` / `darwin-x64` / `win32-x64` / `win32-arm64`。拒绝 Rosetta/架构翻译，Mac 同一个 Universal 包需 ARM、Intel 各跑一次。Windows ARM64 只有提供对应真实工件/runner 才有结果，不凭参数声明支持已验收。

主控当前 r2 冻结点：commit `7dccdd5ee7aa2486e5d7ca06b4664f9a43919261`，source `114dcda7a76169c2b3398898d1d8a2440745e201a1b8a66c41131f4de5107742`。工具不硬编码此点，必须按实际下载的同一批 receipt、compiled、source、lock、signature、installer 校验输入；不得混用前一轮包。

## prepare：现有最终 artifact 路径（推荐接 workflow）

在共用 spec 添加：

```json
{
  "baselineSource": {
    "mode": "final-installer-copy",
    "checkout": "/fresh/frozen-source-checkout",
    "compiledReceiptPath": "/artifact/compiled.json",
    "compiledReceiptSha256": "64-hex-reviewed-compiled-json",
    "dependencyLockPath": "/artifact/resolved-yarn.lock"
  }
}
```

冻结 checkout 需要匹配 expected commit，并带原 `osir-source.json` 及完整 allowlist 文件。不可复制开发者整个脏工作树。`electronVersion` 可选：若提供，必须与已绑定原 lock 中解析的精确版本一致。Mac 还核对原包 Electron Framework plist。

这个模式解决“build-only artifact 没有完整 dist/renderer/out/node_modules”的实际缺口：

1. 校验最终 receipt/installer/signature/source/compiled/lock。
2. 从最终原包只读 DMG 或独立 NSIS 安装中提取 app.asar；复制其中已编译 `dist`、`renderer/out`、runtime `node_modules`，以及 Resources 中的 `uv/python` 到冻结源独立副本。
3. 不重新编译 main/renderer，不改 Server/renderer 版本。只替换顶层 Desktop package.version。
4. 用独立 harness 的 electron-builder，仅重封装 test-only 2.1.0。Mac 使用有效 ad-hoc，Windows unsigned；不带生产签名秘密。
5. 核对原冻结源、原最终包、复用编译树在操作前后未变，记录 test-only 包系统签名与 SHA。

原 `compiled.json` 的 `outputsSha256` 包括不会发布的测试等文件。因此提取模式记录 `scope: "final-packaged-runtime-subset"`、`wholeCompiledTreeVerified: false`、`excludedCompilerAndTestOutputsReconstructed: false`，**不冒称复原并对上了整个原编译目录**。它依靠原安装包 hash、ASAR/config 核对和逐子树提取指纹绑定真实发布内容；编译收据仍须绑定同一 final build plan。

## prepare：可选原编译 checkout 路径

`mode: "compiled-checkout"`（或省略 mode）允许 reuse 原编译输出，但冻结 checkout 必须已包含完整 `dist/renderer/out/build/{uv,python}/node_modules/yarn.lock`。原 dependency lock、install state、Node 和 `outputsFingerprint` 都必须与 final build receipt/compiled 一致。这条路径不适用于只有当前 build-only artifact 的新 runner。

## baseline 产物转交

`prepare-baseline` 成功输出 `baseline-receipt.json`（`result: "prepared"`）、`TEST-ONLY-*.dmg|exe` 及 receipt.evidence 列出的所有同目录 raw 文件。`prepared` 不是 acceptance passed。

转交时只需这些文件，**不用上传** `baseline-source/`、`package/`、`final-asar-extracted/`、`final-extraction-install/` 或挂载/编译临时目录。它们只供该 disposable job 调试并随 VM 销毁；不能在目录仍挂载时递归清理。

下载后保留 basename 和相对关系。独立 pin `baseline-receipt.json` 的 SHA，再给每个 run job；helper 会重算所有 raw evidence、包、源差异、父工件及 compiled 绑定。

## run spec 与观察

在共用 spec 添加：

```json
{
  "baselineReceiptPath": "/baseline/baseline-receipt.json",
  "baselineReceiptSha256": "64-hex-reviewed-baseline-receipt"
}
```

run 只需原最终包、其 receipt/signature 和完整 baseline 证据；不需要 checkout/node_modules 原构建缓存。验证真实 GH-hosted、干净账户、活跃 GUI、硬件/Node 架构后：

1. 安装 baseline，验证系统签名、OSIR identity、2.1.0、架构、ASAR/config；真实启动已打包窗口。
2. 通过包内 DesktopSettingsStore 保存关闭开机/Connector自动启动等无账号偏好，播种带随机 nonce 的合成 JSON/二进制和 renderer localStorage，正常退出。
3. 留数据 hash；正常安装**未修改的最终 2.2.0 原包**到同一路径，启动前先核文件保留，再启动核偏好/文件/localStorage/相同 userData 和 origin，正常退出后再次核文件。
4. 再启动最终原应用，在 Main 的 loopback Node inspector 中调用原 app.asar DesktopUpdateService。临时 RSA feed 先返回 Desktop 2.2.0（无更新），再 2.2.1（有更新），坏签名则 checkFailed；Server 响应固定 2.2.0。前后控制读取和服务自己的兼容 health 请求分别标记，合成安装包不下载、不打开。

原 app.asar 模块路径、模块 hash、Electron/runtime/package 版本、请求顺序、临时公钥、三份合成封套、窗口截图/启动日志、每次系统命令和前后数据指纹均保留。私钥不落证据。正常退出/写盘不成立、任一真实状态不符合，不能报 passed。

## aggregate 对齐报告

固定路径：`OUTPUT/native-upgrade-acceptance.json`。只在 native 两项实际完成时：

```json
{
  "schemaVersion": 1,
  "scope": "native-upgrade-acceptance",
  "evidenceMode": "native",
  "result": "passed",
  "sourceSha256": "...",
  "configSha256": "...",
  "target": "darwin-universal",
  "artifactSha256": "...",
  "systemSignatureReportSha256": "...",
  "nativeMachines": ["darwin-arm64"],
  "networkPolicy": "unrestricted-no-product-credentials",
  "publicNetworkMayBeReachable": true,
  "networkIsolationClaimed": false,
  "offline": false,
  "checks": { "upgradeDataPreserved": true, "updateDiscovery": true },
  "baseline": {
    "kind": "controlled-version-only-derivative",
    "version": "2.1.0",
    "sourceSha256": "...",
    "derivedSourceSha256": "...",
    "artifactSha256": "...",
    "historicalBaseline": false,
    "releaseEligible": false,
    "metadataDiff": [{ "path": "desktop-workbench/package.json", "pointer": "/version", "before": "2.2.0", "after": "2.1.0" }]
  },
  "discovery": {
    "kind": "packaged-native-service-integration",
    "syntheticManifest": true,
    "temporaryTestKey": true,
    "serverVersionUnchanged": true,
    "actualVersions": { "desktop": "2.2.0", "manifestBaseline": "2.2.0", "manifestPatch": "2.2.1", "serverBefore": "2.2.0", "serverAfter": "2.2.0" }
  },
  "evidence": [{ "path": "desktop-discovery.json", "size": 1234, "sha256": "..." }]
}
```

`evidence` 中所有路径都相对 report 所在目录；size/hash 为实际非空 raw 文件，basename 不允许路径逃逸。实际报告含更多观察和完整 metadataDiff 哈希/byteOffset。传给主控 aggregate 的是该 report + 全部 evidence，而不是 baseline receipt；每架构另配独立 smoke 的 5 项。

失败为 `result: "failed"`，未执行 checks 保持 false，记录 failure 与实际尝试状态。依赖注入单测固定 `evidenceMode: "synthetic"`、`result: "simulated"`（若模拟成功），正式 checks **仍全 false**，结果另放 simulatedChecks，aggregate 会拒绝。不写未执行 true。

## 仍须 CI 真跑验证

当前实现尚未执行原生 baseline 重封装或安装/窗口/保留/发现流程。尤其需验证 Universal 重封装及 valid ad-hoc、Windows NSIS 同产品覆盖行为、实际 GUI inspector 可用性和 renderer origin 持久化。失败应交 raw 诊断，不能以此处单元测试替代正式原包验收。
