# PreToolUse 与 PermissionRequest adapters

状态：待批准
实施分支：从最新 `main` 创建 `feature/pretool-permission-adapters`
行为基线：上游 v0.2.8 `b6f86a49d8f2adca146d8eb99d0847b465e543d6` + 本地 parity merge `3b5fa54598a80d1fbed6683ff3d48b71e0146cb5`
依赖：`../command-sensitive-policy/proposal.md`

## 动机与目标

用两个独立 Adapter 组合共享的 tool-gate 判定，同时保留不同响应 schema、reservation 与 claim 时机。

## 设计

- `PreToolUse` handler 创建或复用精确 reservation，不承载 Permission 响应形状。
- `PermissionRequest` handler 只 claim 匹配 reservation；missing、mismatch、replay 均 fail closed。
- 两者调用共享内部判定，但不通过事件字符串分支重新汇聚。

## 改动清单

- 新增两个 handler/entrypoint，并保持旧入口兼容。
- 增加 reservation、重复 PreTool、claim、replay、mismatch 的响应/state/artifact contract。

## 兼容性、可观测性与非目标

matcher、timeout、policy/state schema 与授权语义不变；不新增遥测，诊断不包含命令或敏感内容。

## TDD 与批准门

- [ ] 先写两个入口的失败/成功 contract，再实现最小 Adapter。
- [ ] 新旧入口的响应、session state 与 pending artifacts 一致。
- [ ] 全部 tool protocol 测试通过。

前置 policy Module 合并且本提案批准后方可实施；合并后 Ticket 05 完成。
