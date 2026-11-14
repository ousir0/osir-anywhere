# 更新记录

## 2.2.1（2026-11-14）

### Codex 与 Claude

- 修复 OSIR 客户端模型目录较大时，无法添加 Codex 实例的问题。
- Claude 继续使用 OSIR 客户端中生效的原生 Claude 连接；账户密钥必须允许 Messages 请求。

### DSH 同步

- OSIR Anywhere 随安装包提供固定版本的 DSH 联络插件，配套 OSIR Client 0.1.11 在启动 DeepSeek Harness 时完成安装和连接配置。
- DSH 使用 OSIR Anywhere 的独立数据目录，避免接入历史独立版 Connector；已启用上游插件时会提示先处理冲突。

### 升级须知

- DSH 联动需要同时安装 OSIR Client 0.1.11 与 OSIR Anywhere 2.2.1，首次配置前关闭 DeepSeek Harness。
- Mac 安装包未经 Apple 公证，安装过程保留系统确认；DSH 插件首次安装需要可访问依赖下载服务。
