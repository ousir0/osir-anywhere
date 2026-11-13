# Desktop renderer 本地字体

2026-11-13 将原 `next/font/google` 使用的字体改为 `next/font/local`。
生产构建不再请求 `fonts.googleapis.com` / `fonts.gstatic.com`，不需要关闭 TLS 校验或依赖构建机代理。

## 字形和授权

- Geist 1.800：保留 normal 400、500、600、700。
- Geist Mono 1.701：保留 normal 400、500、600。
- Instrument Serif 1.000：保留 400 normal / italic。
- 字体家族、版本与本机原 Google Fonts 缓存一致；采用官方完整 TTF，避免仅迁移 latin 子集造成字符覆盖下降。
- 保留原有 CSS 变量、`display: swap` 及 Next 字体预加载；浏览器加载的是导出目录中的本地字体文件。
- 所有文件均按原始字节复制，未转换、裁剪、改名内部字体名称或重新生成字形。
- 三份上游 SIL Open Font License 1.1 原文位于 `public/fonts/licenses/`，会随静态导出复制到 `out/fonts/licenses/`。

## 来源和校验

字体及对应 `OFL.txt` 来自官方 `google/fonts` 仓库。经 macOS 已配置代理下载，TLS 校验保持开启。

- `geist.ttf`: https://raw.githubusercontent.com/google/fonts/main/ofl/geist/Geist%5Bwght%5D.ttf
- `geist-mono.ttf`: https://raw.githubusercontent.com/google/fonts/main/ofl/geistmono/GeistMono%5Bwght%5D.ttf
- `instrument-serif-regular.ttf`: https://raw.githubusercontent.com/google/fonts/main/ofl/instrumentserif/InstrumentSerif-Regular.ttf
- `instrument-serif-italic.ttf`: https://raw.githubusercontent.com/google/fonts/main/ofl/instrumentserif/InstrumentSerif-Italic.ttf

| 文件 | SHA-256 |
| --- | --- |
| `geist.ttf` | `73894e0448cae90a92b6c2f8732b7bb9acb7b94c418bff559dad4a18e1de9659` |
| `geist-mono.ttf` | `d00e590b8eb3a59acc329b2d044fd143ae935090b7da33199ebee27cc7de8196` |
| `instrument-serif-regular.ttf` | `498efd461f6ddfcb7a111bf9a565709d2085d48201d501ead960d93e84ffbb88` |
| `instrument-serif-italic.ttf` | `08939b8bdf534afec24ae0ef5e03f948940cd9a8fe08e7fecbad040e62327385` |

## 构建验证

在 `desktop-workbench/renderer/` 执行：

```sh
NEXT_OUTPUT=export node ../node_modules/next/dist/bin/next build
```

产物目录：`desktop-workbench/renderer/out/`。这只导出 renderer，不运行 Electron、不打包或安装 App。

网络排查：直连启用 Node 系统 CA 后仍超时；使用 `scutil --proxy` 中的本机 HTTP(S) 代理访问 Google Fonts 仍在 TLS 握手超时，访问官方 GitHub 原始资源正常。
未改系统 CA、代理、本地业务配置或 Web 项目，也未使用 `NODE_TLS_REJECT_UNAUTHORIZED=0`。

## 本轮实际结果（2026-11-13）

- 上述 `NEXT_OUTPUT=export` 命令退出码 0；默认 Turbopack 编译 11.3 秒，TypeScript 检查 4.9 秒，静态页面生成 5/5。
- 原 Google 缓存 Latin 子集与本地完整字体的版本、字符宽度和字形轮廓：1,987 项字符×字重比对通过。
- 所有原缓存子集的字符覆盖均保留；未用系统替代字体取代原字体家族。
- 导出的四个 TTF 与源文件 SHA-256 一致；三份 OFL 与上游下载原文一致并随产物分发。
- 临时本地 HTTP 校验：首页、登录页、预览页及其 93 个引用资源和三份许可证全部返回 200；服务校验后已关闭。
- 导出 HTML/CSS 无 Google Fonts 外部地址。未启动 Electron、未打包 App、未调用云端或改动原 App。
