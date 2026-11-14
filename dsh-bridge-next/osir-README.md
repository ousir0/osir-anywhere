# OSIR Anywhere DSH host-only 私有插件（2.2.1）

本包由 Anywhere Desktop 的单一 Yarn 依赖环境构建，不发布到上游 npm。
包名 `@osir/anywhere-dsh-bridge`，插件 ID `osir-anywhere-dsh-bridge`。
入口 `lib/index.js`，仅复用 `DshRuntimeService`，不加载 clientUI、
Onboarding、账号服务、Connector 启动管理器，也不提供共享 stateRoot 默认值。

## 消费者契约

Desktop 打包资源为 `resources/dsh-bridge/osir-dsh-bridge.tgz` 和
`resources/dsh-bridge/package-info.json`（Mac 位于 app 的 Contents/Resources）。
清单字段：`schemaVersion:1`、`name`、`version`、`sha256`、`size`。
Client 先核对固定身份、原 tgz 的长度/SHA-256，再调用官方命令：

```sh
dsh plugin --profile desktop add /absolute/resources/dsh-bridge/osir-dsh-bridge.tgz
```

由 Client 向该插件配置注入唯一的 `osirConnectorDataDir` 绝对路径；安装 patch
中的 `config: {}` 刻意不包含机器路径，缺少配置时应拒绝启用。不得回退共享目录。
只连接 `<osirConnectorDataDir>/dsh-bridge/connector.json`，不启动旧独立 Connector。

启用前 Client 必须检查旧 `agents-anywhere-bridge-next` 插件和新插件的活动配置，
发现重复 Bridge/Onboarding 时明确阻断，不自动卸载上游插件。入口检查包括尚未就绪的服务和已排队 Runtime，再次检查 `agentsAnywhereRuntime`/`agentsAnywhereOnboarding`；跨进程重复连接
仍由原 Runtime 的 manager lock 阻断。插件 ID、Cordis 服务名及 RPC 服务名不同：
服务仍是 `agentsAnywhereRuntime` / `aa.dsh.v2.Bridge`，不可同时运行两套。

## 可复现构建

在 `desktop-workbench` 运行 `yarn bundle:dsh-bridge`，无需安装 DSH 开发工作树。
仅使用 Desktop Yarn lock 安装的 TypeScript `transpileModule`，逐文件生成 ESM。
DSH 模块保留为 peer，由官方宿主提供；`meshcall@0.3.0` 是唯一普通依赖，由官方
plugin add 解析（首次安装可能需要 registry 可用，不声称离线安装）。

helper 跟踪编译后静态 import/export 的闭包，保留相对目录，拒绝未审阅动态加载
与文件相对资源。两处包版本元数据读取经过精确校验；私有包自引用重写为自身
package.json，确保握手报告 2.2.1。Runtime 的配置 import 仅在私有打包时替换
为 osir-config，原上游默认入口/配置源码不改。类型专用 contracts 导入被消除，
若后续有值导入则自动纳入闭包。没有手工编译产物作为构建输入。

使用内置 USTAR+gzip 打包，仅普通文件、短路径，无 links/PAX，不运行上游 prepack。
构建回执 `dist/dsh-bridge/osir-build-receipt.json` 记录逐文件源码/编译器/lock/
原包摘要及 USTAR 格式，不随资源分发。release 门禁继续绑定完整来源、同一 Desktop
Yarn lock 和 dist 输出指纹；主线程须将回执 inputs 的精确名单加入候选源码。

验证：`node --test scripts/osir-dsh-bridge.test.mjs`；可额外设
`OSIR_DSH_TEST_NODE_MODULES=/absolute/disposable/node_modules` 运行解包后的真实
peer 模块加载、握手版本和重复注册测试。该路径仅用于测试，不进入构建输入。
未做正式 profile 安装、真实 Desktop 启动或最终安装器验收前不能宣称发布完成。
