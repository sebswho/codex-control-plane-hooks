# 01 – 重新审查并批准拆分后的 proposal 套件

**What to build:** 将 Windows runtime 与 Hook 入口重构整理成一组范围受控、依赖清楚、可以逐个批准的 proposal，使后续代理无需重新解释原始大提案即可安全实施。

**Blocked by:** None – can start immediately.

**Status:** complete

- [x] Git 分支基线明确为 fork 当时最新 `main`，v0.2.6 只作为行为回归基线。
- [x] Windows runtime proposal 定义普通终端下的唯一 plugin-data 发现、零/多候选失败、默认不清理和显式 prune 保护。
- [x] Hook 入口工作拆为 core、policy engines、Git runner、manifest contract 四个领域 proposal 套件，并在套件内继续按模块边界拆分。
- [x] isolated-mode package bootstrap、专用 Git runner CLI 与 legacy 命令形状兼容步骤均有明确设计。
- [x] 外部 contract 同时覆盖响应 JSON、plugin-data 状态和一次性 runner artifacts。
- [x] Codex App trust/cache identity 的未验证推断已改为 Windows 10 实测假设。
- [x] 审查者确认阻塞意见已解决（2026-07-24 Standards PASS、Spec PASS）。
- [x] 用户已于 2026-07-24 明确批准 Windows runtime proposal，Ticket 02 已开放。
