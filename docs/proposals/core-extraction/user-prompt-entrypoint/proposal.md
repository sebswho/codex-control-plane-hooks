# UserPromptSubmit tracer bullet

状态：待批准
实施分支：从当时最新 `main` 创建 `feature/user-prompt-entrypoint`
行为基线：v0.2.6
依赖：`../policy-state/proposal.md`

## 动机与目标

以一个业务风险较小的事件验证 bootstrap、protocol、policy 和 state Interface 能被独立 entrypoint 组合使用。

## 设计

- 新增 `UserPromptSubmit` handler 与专用 entrypoint 两个边界。
- entrypoint 调用 `protocol.run_hook("UserPromptSubmit", handler)`，不得经过旧字符串 `dispatch()`。
- 旧入口暂时保留并改用相同核心 Interface。

## 改动清单

- 新增 UserPromptSubmit handler、entrypoint 与打包 smoke。
- 增加新旧入口的响应、turn/grant/sensitive state 前后 contract。

## 兼容性、可观测性与非目标

不切换完整 manifest，不迁移其他事件；响应、state 与退出行为不变。不新增遥测，测试 artifacts 只保存脱敏差异。

## TDD 与批准门

- [ ] 先固定新旧入口响应和 plugin-data 前后内容。
- [ ] 先写错配事件 fail-closed 测试，再实现 handler/entrypoint。
- [ ] PowerShell 5.1/7、POSIX smoke 和全部既有协议测试通过。

前两份 core 子提案合并且本提案批准后方可实施；合并后 Ticket 04 完成。
