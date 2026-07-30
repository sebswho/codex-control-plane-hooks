# UserPromptSubmit tracer bullet

状态：已批准并实施（2026-07-30，待 PR/CI）
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

- 将 UserPromptSubmit 行为及其直接依赖收敛到 `control_plane/core.py`；旧入口只把该事件转交同一 handler，其他事件实现仍留在原位。
- 新增 UserPromptSubmit handler、entrypoint 与打包 smoke。
- 增加新旧入口的响应、turn/grant/sensitive state 前后 contract。

## 兼容性、可观测性与非目标

不切换完整 manifest，不迁移其他事件；响应、state 与退出行为不变。不新增遥测，测试 artifacts 只保存脱敏差异。

## TDD 与批准门

- [x] 先固定新旧入口响应和 plugin-data 前后内容。
- [x] 先写错配事件 fail-closed 测试，再实现 handler/entrypoint。
- [x] PowerShell 5.1/7、本地 package smoke 和全部既有协议测试通过；POSIX 由当前 PR CI 复验。

前两份 core 子提案合并且本提案批准后方可实施；合并后 Ticket 04 完成。
