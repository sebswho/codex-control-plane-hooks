# PostToolUse effects adapter

状态：待批准
实施分支：从最新 `main` 创建 `feature/posttool-effects`
行为基线：上游 v0.2.8 `b6f86a49d8f2adca146d8eb99d0847b465e543d6` + 本地 parity merge `3b5fa54598a80d1fbed6683ff3d48b71e0146cb5`
依赖：`../pretool-permission/proposal.md`

## 动机与目标

把 tool 执行后的 receipt 消费、pending 清理、clone provenance 与敏感输出检查迁入独立 PostToolUse handler。

## 设计

- 仅匹配的成功/失败调用可消费或撤销相应 artifacts；identity/response mismatch 不误消费。
- remote success 与后续 upstream metadata write 分开记录，避免危险重试。
- handler 复用 sensitive policy，不复制扫描规则。

## 改动清单

- 新增 PostToolUse handler/entrypoint。
- 增加 receipt/status、pending、clone provenance、replay/expiry 和输出检查 contract。

## 兼容性、可观测性与非目标

schema、TTL、默认开关和 Git transaction 语义不变；不新增遥测，输出诊断保持脱敏。

## TDD 与批准门

- [ ] 先写成功、失败、缺失、mismatch 和 replay contract。
- [ ] 同时断言响应、session state、receipt/status 与 clone artifacts。
- [ ] 全部 tool/Git transaction 回归测试通过。

Ticket 05 合并且本提案批准后方可实施；合并后 Ticket 06 完成。
