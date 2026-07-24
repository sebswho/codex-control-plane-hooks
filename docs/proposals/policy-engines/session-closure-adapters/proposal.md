# PreCompact 与 Stop adapters

状态：待批准
实施分支：从最新 `main` 创建 `feature/session-closure-adapters`
行为基线：v0.2.6
依赖：`../subagent-adapters/proposal.md`

## 动机与目标

迁移 session checkpoint 与 closure 两个 Adapter，完成 lifecycle 纵向切片。

## 设计

- `PreCompact` 只通过 lifecycle Interface 保存既有 checkpoint。
- `Stop` 保留 unfinished transaction/pending reservation；无 active Agent 时按原规则清理 session JSON。
- 两个 entrypoint 不经过旧 `dispatch()`。

## 改动清单

- 新增 PreCompact、Stop handler/entrypoint。
- 增加响应、state、retention artifacts、lock sentinel 与清理 contract。

## 兼容性、可观测性与非目标

state schema、timeout 与 Stop 语义不变；不新增遥测，diagnostics 保持脱敏。

## TDD 与批准门

- [ ] 先写 checkpoint、active Agent、unfinished/pending retention 和 clean Stop contract。
- [ ] 新旧入口结果一致，并通过并发 state 测试。
- [ ] PowerShell/POSIX packaged smoke 通过。

Subagent adapters 合并且本提案批准后方可实施；合并后 Ticket 07 完成。
