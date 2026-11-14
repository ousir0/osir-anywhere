# Windows binding reader 配对接口（2026-11-14）

通用正式入口：`connector.runtimes.codex.osir_binding`。
Windows 实现独占模块：`connector/runtimes/codex/osir_binding_windows.py`。

```python
def canonical_directory(path: pathlib.Path) -> pathlib.Path: ...
def read_secure(path: pathlib.Path, *, private: bool = False,
                maximum: int = 2 * 1024 * 1024) -> bytes: ...
```

失败抛 `OSError` 或 `ValueError`；不导入通用 binding，避免循环依赖。
通用层统一转换固定错误 `osir_model_binding_unavailable`，不输出底层路径/内容。

- `canonical_directory`：本机规范绝对目录，拒绝 UNC/device/ADS/`..`、junction/reparse 和不可信可写祖先；不是只检查最终组件。
- `read_secure`：从同一个已验证 handle 有界读取普通文件；固定各级目录，拒绝 reparse/竞争替换，校验当前 TokenUser SID owner 和 DACL。`private=True` 是 descriptor：显式受保护 DACL、当前用户与 SYSTEM 合同，拒绝 NULL DACL、非受信 ACE/写入/删除/改权限。父目录同样不得允许非受信修改；系统祖先允许系统/管理员所有，不能要求盘根为当前用户所有。
- config/catalog（`private=False`）仍校验当前用户 owner、不可信写权限、普通文件和无重解析；允许其现有可信只读共享权限，不要求复制 descriptor 的精确私有 DACL。
- Client producer 须创建符合合同的目录和临时文件，flush 后安全原子替换；不能先公开再补 ACL。reader 不为迁就旧 producer 放宽检查。
- 原生 Windows tests 必须区分 fixture 与真正 Client 生成 descriptor；Unix API/模拟 chmod 不算 Windows 通过。

通用模块只在 `os.name == 'nt'` 时延迟导入；模块缺失/任何校验失败均关闭，无降级。
