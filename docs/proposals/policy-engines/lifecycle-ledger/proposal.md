# Agent lifecycle ledger Module

状态：待批准
实施分支：从最新 `main` 创建 `feature/lifecycle-ledger`
行为基线：v0.2.6
依赖：`../../core-extraction/user-prompt-entrypoint/proposal.md`

## 动机与目标

将 Agent ledger、nested delegation、PreCompact checkpoint 与 Stop reconciliation 封装为一个领域 Module，不同时迁移事件 Adapter。

## 设计

- Module 通过 state Interface 执行锁内更新，不暴露锁、schema 或文件路径。
- 并发 start/stop 不丢 ledger entry；Stop 保留 unfinished transaction 与 pending reservation。
- 无 active Agent 时按既有规则清理 session JSON，并保留 lock sentinel。

## 改动清单

- 新增 lifecycle Module，并让旧入口通过兼容调用使用。
- 固定并发 ledger、checkpoint、retention 与清理 contract。

## 兼容性、可观测性与非目标

state schema、超时和默认行为不变；不迁移 handler，不新增网络遥测，诊断不记录 Agent 内容。

## TDD 与批准门

- [ ] 先写 nested delegation、并发更新、checkpoint 与 Stop retention 测试。
- [ ] 证明锁 inode 不切换且损坏 state 继续 fail closed。
- [ ] 全部 lifecycle/state 测试通过。

Ticket 04 合并且本提案批准后方可实施；可与 Ticket 05/08 并行。
