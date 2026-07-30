# Agent lifecycle ledger Module

状态：待批准
实施分支：从最新 `main` 创建 `feature/lifecycle-ledger`
行为基线：上游 v0.2.8 `b6f86a49d8f2adca146d8eb99d0847b465e543d6` + 本地 parity merge `3b5fa54598a80d1fbed6683ff3d48b71e0146cb5`
依赖：Phase 1: split protocol test and documentation ownership

## 动机与目标

将 SessionStart、SubagentStop 与 Stop 所需的 lifecycle state transition 封装为领域 Module，不改变公开 façade、fallback 或错误输出契约。

## 设计

- Module 通过 state Interface 执行锁内更新，不暴露锁、schema 或文件路径。
- 并发 lifecycle 更新不丢 ledger entry；Stop 保留 unfinished transaction 与 pending reservation。
- 无 active Agent 时按既有规则清理 session JSON，并保留 lock sentinel。

## 改动清单

- 新增 lifecycle Module，并让 façade 的兼容路由使用它。
- 固定并发 ledger、retention、清理与错误输出 contract。

## 兼容性、可观测性与非目标

state schema、timeout、manifest matcher、façade fallback 和默认行为不变；不新增网络遥测，诊断不记录 Agent 内容。

## TDD 与批准门

- [ ] 先写 SessionStart、SubagentStop、Stop、并发更新与 retention 测试。
- [ ] 证明锁 inode 不切换且损坏 state 继续 fail closed。
- [ ] 全部 lifecycle/state 测试通过。

Phase 1 完成且本提案批准后方可实施；可与 Ticket 05/08 并行。
