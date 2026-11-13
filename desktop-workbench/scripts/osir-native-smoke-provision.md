# Anywhere native smoke 的 CI 调用合同

当前入口使用主控授权的 **`disposable-clean-runner`**：真实 GitHub-hosted 原生 GUI runner、无既有产品/SDK账号目录、子进程环境白名单、原包严格 SHA/size/来源/签名校验。它允许未认证的公网健康/更新读取，明确记录 `networkPolicy: unrestricted-no-product-credentials`、`networkIsolationClaimed: false`、`fullSmokeOfflineClaimed: false`。不登录真实账号，不执行真实项目或模型请求。

`strict-loopback` 保留为可选模式；省略 `--runner-mode` 仍使用旧的严格模式，当前 workflow 必须明确传入新模式。旧模式的限制如下，**不再作为新模式的阻塞条件**：

- macOS 15.6 实测：Seatbelt `localhost` 允许 IPv4/IPv6 loopback、Unix IPC，但同时允许本机非 loopback 网卡 IP。外部 TEST-NET IPv4/IPv6 的 TCP/UDP 返回 `EPERM`，仍不足以满足严格合同。数字 IP 的 SBPL 规则编译失败：`host must be * or localhost in network address`。严格 preflight 因此失败，不生成 attestation，不启动产品。
- Windows：严格模式阻塞。按 EXE 的 Firewall 规则无法自动覆盖 NSIS 未知临时子程序、Connector 新建环境中的二进制。新 clean-runner 模式不设置 Firewall，而是实际检查 `OpenInputDesktop`、交互状态和非零 GUI session；没有可访问桌面时报告具体错误。
- clean-runner 的 Mac 验证 `/dev/console` 属于当前 runner 账户；两平台最终仍必须观察到原包 Electron 可见、加载完成的窗口及截图。GitHub 环境元数据只是来源记录，不冒充密码学签名的 runner attestation。

## 与已冻结 candidate 分离

候选 commit：`afe1a860bb55d520d1275b3a8fcd30a36fdbce0f`。harness 尚未包含在候选 source 中：单独提供并固定 harness SHA，不修改 candidate、不重新构建。

运行需要同目录的四个文件：

```text
osir-native-smoke-provision.mjs
osir-native-smoke.mjs
osir-anywhere-system-signature.mjs
osir-anywhere-release-common.mjs
```

最后两个使用 Dalton 已 review 的版本。传入 SHA 绑定的是原始最终 DMG/NSIS、build receipt、native signature report、source/config/commit，不是 harness。测试文件不需要进入运行工件。

Node 使用原生架构的 22.23.2+（当前 workflow 固定 22.23.2）；需要 GitHub disposable GUI runner；`run` / `warm-cache` 拒绝 local 或 self-hosted。不要为了绕过检查手动伪造 GitHub 环境变量。checkout 必须 `persist-credentials: false`，不向 job 注入真实用户账号、模型密钥或生产登录凭据。产品进程不会继承 GH/OAuth/API/签名 token、代理、SSH_AUTH_SOCK 或 SDK 路径覆盖。`.ssh` 可以存在，helper 不列举、不读取该目录。

## base spec

下面字段必须由已核对的构建输出与可信输入确定。SHA 都是完整小写 64 位，commit 是完整 40 位；不要传截断的 `56f553ce...`。不同 runner 只改变路径与 `nativeMachine`，保持同一原包身份。

```json
{
  "schemaVersion": 1,
  "buildReceiptPath": "/ABS/input/build-receipt.json",
  "finalInstallerPath": "/ABS/input/EXACT-RECEIPT-FILENAME.dmg",
  "systemSignatureReportPath": "/ABS/input/system-signature.json",
  "expected": {
    "sourceSha256": "FULL_REVIEWED_SOURCE_SHA256",
    "configSha256": "FULL_REVIEWED_CONFIG_SHA256",
    "checkoutHead": "afe1a860bb55d520d1275b3a8fcd30a36fdbce0f",
    "upstreamGitHead": "FULL_REVIEWED_UPSTREAM_COMMIT",
    "version": "VERSION_FROM_REVIEWED_RECEIPT",
    "target": "darwin-universal",
    "artifactSha256": "FULL_REVIEWED_FINAL_INSTALLER_SHA256",
    "artifactSize": 123,
    "systemSignatureReportSha256": "FULL_REVIEWED_SIGNATURE_REPORT_SHA256"
  },
  "runner": { "nativeMachine": "darwin-arm64" }
}
```

`expected` 仅接受上述九个字段。`artifactSize` 必须替换为真实字节数；文件名必须精确匹配 receipt。base 不填写 provenance 路径/hash，helper 在真实 hosted/账号/GUI 检查后生成；严格模式另要求网络探针全部通过。

架构矩阵：同一 `darwin-universal` DMG 在 `darwin-arm64` / `darwin-x64` 各原生运行；Windows 分别是 `win32-x64` / `win32-arm64` target 及同名 nativeMachine，要求独立原生 job。当前候选只 dispatch Universal + Windows x64，不代表 Windows ARM 已构建或验证。Rosetta / WOW 不计原生通过。

## 可选：严格隔离诊断，不需要安装包

macOS shell=bash，工作目录已包含 harness；所有输出目录必须尚不存在。

```bash
node "$GITHUB_WORKSPACE/harness/desktop-workbench/scripts/osir-native-smoke-provision.mjs" probe \
  --output "$RUNNER_TEMP/osir-policy-proof"
```

此入口只启动 Node echo fixture / 沙箱 Node 及其后代探针，不启动 Electron、Python、uv、Connector；不要求访问账号或安装包。测试网地址仅在沙箱中尝试，`TIMEOUT`、无路由、拒绝连接均不算隔离证明。当前 macOS 15.6 应非零退出，归档整个 `osir-policy-proof`。它不生成 disposable runner attestation。

## 独立在线预热 job

此 job 使用干净 disposable native runner；只展开/安装原包并执行包内 uv/Python 来解析依赖，不启动 Electron 窗口、不登录 Server。Mac ARM 与 Intel 缓存分别准备，不能复用对方的原生 wheel。缓存预热后，再复制到独立 source/cache/venv 目录，以 `uv --offline ... --locked anywhere-cli --help` 重建；必须实际生成新 `pyvenv.cfg` 并成功退出，才输出 `prepared`。默认 `offlineRehearsal.mode=uv-offline-only`，仅证明 uv 离线依赖重建，不宣称整个 job 无网络。Mac 可额外传 `--runner-mode strict-loopback`，给这轮缓存复跑加 deny-all-IP 沙箱及真实探针。

macOS shell=bash，已准备该 runner 的 `$RUNNER_TEMP/base.json`：

```bash
node "$GITHUB_WORKSPACE/harness/desktop-workbench/scripts/osir-native-smoke-provision.mjs" warm-cache \
  --spec "$RUNNER_TEMP/base.json" \
  --output "$RUNNER_TEMP/osir-dependency-prep"
shasum -a 256 "$RUNNER_TEMP/osir-dependency-prep/dependency-cache.json"
tar --exclude='./work' --exclude='./offline-policy' \
  -czf "$RUNNER_TEMP/osir-dependency-prep.tar.gz" \
  -C "$RUNNER_TEMP/osir-dependency-prep" .
```

`warm-cache` 用包内命令：`uv --no-config run --project COPY --python BUNDLED_PYTHON --no-python-downloads anywhere-cli --help`，仅此 job 允许获取公开 Python 依赖。报告记录 bundled uv/Python SHA、Connector source tree SHA、缓存 tree SHA 和解析后的 `connector-resolved-uv.lock` SHA。命令 stdout 输出 `reportSha256`；把该值固定到下游 job 的可信输入 `DEPENDENCY_REPORT_SHA256`，不能到离线 job 才对未知下载重新算 hash 并直接信任。缓存工件必须同时传递 report、lock、cache；用 tar 保留符号链接及文件模式，不能直接 upload-artifact 裸 cache 目录。

Windows shell=pwsh 的在线入口：

```powershell
node "$env:GITHUB_WORKSPACE/harness/desktop-workbench/scripts/osir-native-smoke-provision.mjs" warm-cache `
  --spec "$env:RUNNER_TEMP/base.json" `
  --output "$env:RUNNER_TEMP/osir-dependency-prep"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Get-FileHash "$env:RUNNER_TEMP/osir-dependency-prep/dependency-cache.json" -Algorithm SHA256
tar.exe --exclude='./work' --exclude='./offline-policy' -czf "$env:RUNNER_TEMP/osir-dependency-prep.tar.gz" -C "$env:RUNNER_TEMP/osir-dependency-prep" .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```

## 原生 clean-runner GUI job 的完整参数

先完成下载、checkout/setup-node、缓存解包。主线程提供可信 `DEPENDENCY_REPORT_SHA256` 及对应 runner 的 base spec。此模式不依赖 Seatbelt 或 Firewall；真实 GUI、系统安装策略或产品失败仍必须非零退出：

```bash
mkdir "$RUNNER_TEMP/osir-dependencies"
tar -xzf "$RUNNER_TEMP/osir-dependency-prep.tar.gz" -C "$RUNNER_TEMP/osir-dependencies"
node "$GITHUB_WORKSPACE/harness/desktop-workbench/scripts/osir-native-smoke-provision.mjs" run \
  --spec "$RUNNER_TEMP/base.json" \
  --cache "$RUNNER_TEMP/osir-dependencies/cache" \
  --cache-report "$RUNNER_TEMP/osir-dependencies/dependency-cache.json" \
  --cache-report-sha256 "$DEPENDENCY_REPORT_SHA256" \
  --output "$RUNNER_TEMP/osir-smoke" \
  --runner-mode disposable-clean-runner
```

Windows 同一 CLI，使用 `pwsh` 的反引号续行与 `$env:...` 路径（现有 workflow 使用 bash 同样可执行）。不再因严格 Firewall 未实现而阻塞 clean-runner。不要用没有 live provenance 的直接 smoke 调用绕过 helper。

行为：包 hash/size/身份/配置及原生系统签名检查 → 实际 DMG 复制或 NSIS 安装 → packaged Electron 可见窗口及截图 → 包内 uv/Python → `uv --offline --no-config run --locked ... anywhere-cli rpc`，验证真实 `connector.ready` 与 stdin EOF 后干净退出。依赖步骤固定锁文件和缓存 SHA，不回退到系统 Python、开发 venv 或在线补依赖；整个产品 smoke 的网络保持开放，不冒称离线。不删除 quarantine，不绕过 Gatekeeper/SmartScreen，坏系统签名仍阻止运行。

## 报告及归档

- 在线：`osir-dependency-prep/dependency-cache.json`，`scope=native-smoke-dependency-cache`，`result=prepared|failed`，`expected` 九个构建字段、`nativeMachine`、`provisionerSha256`、`uv` / `python` 文件身份、`connectorSourceSha256`、`cache.sha256`、带 size/SHA 的 `evidence`、时间与 `failure`。
- runner：`osir-smoke.provision/provision-report.json`，`scope=native-smoke-provision`，`result=passed|failed`、平台、`runnerMode`、`networkPolicy`、`networkIsolationClaimed`、时间、`failure`、`productExecutionState`。clean-runner 的 cleanup 是 `globalNetworkStateModified=false`、`networkPolicyRestorationRequired=false`，不伪造连通性恢复探针结果。严格模式另有真实 `parentConnectivityRestored` / `fixturesClosed`。`productExecutionState` 为 `not-attempted|unknown-until-smoke-report|install-attempted|launch-attempted|window-observed`；缺报告时保留 unknown，不假称未启动。
- clean-runner 原始证据：`gui-provenance.json`、`runner-isolation.json`（保留旧文件名兼容收集器，内容明确为 clean-runner provenance）、`effective-spec.json`。provenance 记录当前 processId、账号/home/host、runId/attempt/job、受白名单限制的 workflow/runner 元数据、helper SHA，实际 smoke 再检查 GUI 和同进程身份。
- 原始证据：`network-baseline.json`、`profile.sb`、`sandbox-preflight-process.json`、`network-preflight-proof.json`、`network-after.json`。诊断入口使用 `network-proof.json`；正式 stage 再产生与实际 smoke PID 绑定的 `network-proof.json`、`runner-isolation.json`、`effective-spec.json`。证明包括 TCP/UDP v4/v6、Unix IPC、非 loopback 正向对照、permission-denied 结果、继承策略的 Node 后代。实际 smoke PID 还会再次探测。`run` 失败可能根本没有 smoke 输出目录，这是拒绝执行的正确结果。
- 原包 smoke：`osir-smoke/native-smoke.json`，`scope=native-smoke`、`result=passed|failed`、`evidenceMode=native`，九个构建字段、`buildReceiptSha256`、`scriptSha256`、`nativeMachines`、`execution`、`checks` 和每项证据的 path/size/SHA；新增 `runnerMode` / `networkPolicy` / `networkIsolationClaimed=false` / `fullSmokeOfflineClaimed=false` / `hostedRunner` / `boundaries`。测试注入仅可得到 `evidenceMode=synthetic`、`result=simulated`。

workflow 无论成功失败都用 `if: always()` 归档 `osir-smoke.provision` 和存在时的 `osir-smoke`。预热/安装 work 目录很大，**不要把 work 一起打入 cache tar**；打包 cache、report、lock 和报告引用的原始 evidence。现有 Dalton `seal-cache` 正确保留所需证据并排除 work，可直接沿用。clean-runner 不改全局网络，正常 artifact 上传不需要恢复防火墙。严格模式的 fixture 在 finally 关闭并有父进程正向对照。

## 真实覆盖边界

本次本机执行了 62 项离线 focused 测试、语法检查及之前的 Mac 安全 policy-only 探针；未下载最终包、未 build、未运行真实 `warm-cache` 或产品 `run`，未启动 Electron 或真实 Connector。Windows GUI API 与两平台原包仍需 CI 实跑；不能把合成测试通过写成原生验收通过。

即使未来 smoke 通过，报告始终 `releaseAcceptance=incomplete`：真实账号登录/OAuth、生产 Server/模型会话、服务 RPC、升级用户数据保留、PATCH 更新发现、OS 交互安装确认均未覆盖，不能代替最终 acceptance gate。
