# SessionStart 与 Stop adapters

状态：待批准
实施分支：从最新 `main` 创建 `feature/session-closure-adapters`
行为基线：上游 v0.2.8 `b6f86a49d8f2adca146d8eb99d0847b465e543d6` + 本地 parity merge `3b5fa54598a80d1fbed6683ff3d48b71e0146cb5`
依赖：`../subagent-adapters/proposal.md`

## 动机与目标

提取 SessionStart 与 Stop 的内部 Adapter，完成 Ticket 07 的 lifecycle 纵向切片，同时保持单一公开 façade。

## 设计

- `SessionStart` 初始化既有 lifecycle/session 视图，不改变持久化 schema。
- `Stop` 保留 unfinished transaction/pending reservation；无 active Agent 时按原规则清理 session JSON。
- 两个 Adapter 均由 `control_plane_hook.py` 路由，内部入口只作为模块和测试边界。
- façade fallback、fail-closed stderr 与退出码保持不变。

## 改动清单

- 新增 SessionStart、Stop 内部 Adapter。
- 增加响应、state、retention artifacts、lock sentinel、清理和 fallback contract。

## 兼容性、可观测性与非目标

state schema、timeout、statusMessage、manifest matcher 与 Stop 语义不变；不新增遥测，diagnostics 保持脱敏。

## TDD 与批准门

- [ ] 先写 SessionStart、active Agent、unfinished/pending retention、clean Stop 与 fallback contract。
- [ ] 新旧路由结果一致，并通过并发 state 测试。
- [ ] PowerShell/POSIX packaged smoke 通过。

SubagentStop Adapter 合并且本提案批准后方可实施；合并后 Ticket 07 完成。
