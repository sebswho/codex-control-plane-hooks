# 03 – 让 Windows Hook 只使用已发布 runtime

**What to build:** 让所有 Windows Hook 调用直接使用 setup 发布的专用 Python 3.12，在单个子进程中执行 Hook，并在任何 runtime 缺失或损坏场景拒绝回退到系统 Python。

**Blocked by:** 02 – 从普通 Windows 终端配置专用 runtime.

**Status:** ready-for-agent

- [ ] launcher 只读取经验证的 runtime 清单，不再调用 `where.exe` 或探测 `py.exe`、`python.exe`。
- [ ] runtime 缺失、schema 错误、路径漂移、reparse point 和非 Python 3.12 均不会执行系统解释器。
- [ ] `-I -S`、stdin/stdout/stderr 转发和子进程退出码保持现有 Hook 契约。
- [ ] PowerShell 5.1、PowerShell 7、Python 3.9/3.12 的适用自动化测试通过。
- [ ] packaged manifest smoke、release checker、Ruff 和 plugin validator 通过。
- [ ] Windows 10 Codex App 验证安装、重启、信任提示和缓存行为，并明确记录 launcher 内容是否影响 trust identity。
- [ ] 完成独立 PR；合并前不开始 Ticket 04。
