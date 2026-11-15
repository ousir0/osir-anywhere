# Anywhere 2.2.1 revision 4 原包原生验收

独立 harness 基于上一轮 7dc1d1434870b5c99af5e61e3910575eb92c71ba，仅更新产品 pin、revision 对照、测试和说明。产品源码及固定构建分支不由此 harness 更改。

- Product: 940c226c5cc510607283f33edd27ef368d01f64e
- Source: 3cda5ade44dbee9a2d223a842438dec1367c4b04e80ef8340fb8796850c62626
- Recipe: a57576b450097ff41feb90647a1166e128c6a76c17fc6160301ebb20ce46c626
- Release: osir-anywhere-2.2.1-20261116-r4，public 2.2.1/revision4
- Producer: 43753334290 attempt1
- Upgrade ref: codex/anywhere-221-r4-upgrade-acceptance-20261116
- Smoke: 8da80c839c714e1b3c8d6989559f02a8a09c52b2，codex/anywhere-221-smoke-readiness-20261114

Mac ARM/Intel 使用同一原始 universal DMG，Windows x64 使用原始 EXE。Windows ARM64不选入。每份原包核对成功 job、artifact ID、ZIP/installer/receipt/source/recipe/config/shared-lock/system-signature hashes；原包不重建、重包或重签。

升级 baseline 为当前最终编译输出的 test-only 2.2.0 version-only derivative，不代表历史正式版或真实 r3→r4 用户数据迁移。合成账户不使用真实keychain/OAuth/用户数据。

最终包 build-info 必须为revision4；真实 packaged service 依次检查 2.2.1/revision4、revision5、rollback0、2.2.2/revision0与坏签名，Server固定2.2.0。九次GET、五份envelope、四真一坏RSA签名、零下载/安装调用；临时测试私钥仅内存。

保留安装/窗口/退出/数据/发现/验签全部门禁，Windows NSIS 180000ms与一次安装不变。上一轮可选Toolhelp诊断实际缺python；不能称为已原生验证，不作为验收通过依据。

签名沿用既有RSA清单和系统签名模式，Mac ad-hoc/unsigned不称Developer ID或公证。生产app不动，最终publish/trust切换由主线程持有。本目录初始无任何继承的成功状态。

本地定向回归结果另存r4 acceptance/logs；原生结果必须由新run证据确认。
