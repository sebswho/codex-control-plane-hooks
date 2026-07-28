# SubagentStart 与 SubagentStop adapters

状态：待批准
实施分支：从最新 `main` 创建 `feature/subagent-adapters`
行为基线：v0.2.6
依赖：`../lifecycle-ledger/proposal.md`

## 动机与目标

用两个独立事件 Adapter 验证 lifecycle ledger 的 Agent start/stop 路径。

## 设计

- `SubagentStart` 与 `SubagentStop` 各有 handler/entrypoint，不使用字符串 dispatch。
- 两者只通过 lifecycle Interface 变更 ledger，不直接读写 state 文件。

## 改动清单

- 新增两个 handler/entrypoint 与 packaged smoke。
- 增加 nested delegation、响应、ledger 前后内容和 lock sentinel contract。

## 兼容性、可观测性与非目标

响应、state schema 与 timeout 不变；不迁移 PreCompact/Stop，不新增遥测。

## TDD 与批准门

- [ ] 先写 start/stop、nested 与并发 contract。
- [ ] 新旧入口的响应/state 一致。
- [ ] PowerShell/POSIX smoke 和 lifecycle 测试通过。

Lifecycle Module 合并且本提案批准后方可实施。
