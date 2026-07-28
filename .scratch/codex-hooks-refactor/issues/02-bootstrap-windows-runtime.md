# 02 – 从普通 Windows 终端配置专用 runtime

**What to build:** 让 Windows 10 用户仅提供一个绝对 Python 3.12 路径，就能从普通终端确定性找到已安装插件的数据目录、创建版本化专用 venv，并原子发布可供 Hook 使用的 runtime 清单。

**Blocked by:** None – Ticket 01 completed on 2026-07-24.

**Status:** ready-for-agent

- [ ] 实施分支从 fork 当时最新 `main` 创建，且使用主工作树 Python 3.12 `.venv` 软链接进行开发验证。
- [ ] 显式 plugin-data override 优先；否则只接受默认或显式 Codex home 下唯一的插件数据候选。
- [ ] 零候选、多候选、相对路径、越界路径和 reparse point 均失败且不猜测。
- [ ] 只有 Python 3.12 venv 完成 smoke 后才原子发布新清单；失败保留旧清单与旧 runtime。
- [ ] 默认不删除任何旧 runtime；显式 prune 保护当前版本、至少保留两个版本，并跳过活跃或无法可靠检查的候选。
- [ ] setup 幂等测试、PowerShell 5.1/7 测试和脱敏用户诊断通过。
- [ ] 文档说明 venv 仍依赖基础 Python 安装，不宣称完全自包含分发。
