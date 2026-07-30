# SubagentStop adapter

状态：待批准
实施分支：从最新 `main` 创建 `feature/subagent-adapters`
行为基线：上游 v0.2.8 `b6f86a49d8f2adca146d8eb99d0847b465e543d6` + 本地 parity merge `3b5fa54598a80d1fbed6683ff3d48b71e0146cb5`
依赖：`../lifecycle-ledger/proposal.md`

## 动机与目标

提取 SubagentStop 的内部 Adapter，验证 lifecycle ledger 的 Agent closure 路径，同时保留 façade 路由和失败时的既有响应/stderr。

## 设计

- `SubagentStop` 由 `control_plane_hook.py` 路由到内部 Adapter，不成为新的公开 manifest 命令。
- Adapter 只通过 lifecycle Interface 变更 ledger，不直接读写 state 文件。
- façade 无法加载 Adapter 时继续使用既有兼容 fallback；错误输出不得泄露 payload。

## 改动清单

- 新增内部 handler 与 packaged smoke，不修改 `hooks.json` 命令形状。
- 增加响应、ledger 前后内容、lock sentinel 和 fallback contract。

## 兼容性、可观测性与非目标

响应、state schema、timeout、statusMessage 与 manifest matcher 不变；不新增遥测。

## TDD 与批准门

- [ ] 先写正常、并发、损坏 state 与 fallback contract。
- [ ] 新旧路由的响应/state/stderr 一致。
- [ ] PowerShell/POSIX smoke 和 lifecycle 测试通过。

Lifecycle Module 合并且本提案批准后方可实施。
