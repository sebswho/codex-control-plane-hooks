# Git authorization 与 transaction ledger

状态：待批准
实施分支：从最新 `main` 创建 `feature/git-authorization-ledger`
行为基线：v0.2.6
依赖：`../repository-clone/proposal.md`、`../../policy-engines/posttool-effects/proposal.md`

## 动机与目标

迁移授权 capsule 与 transaction ledger，并通过新 tool 事件链验证 reservation → claim → runner → receipt 的完整一次性流程。

## 设计

- authorization 保持 positive clause、安全排除、scope mapping、continuation TTL 与 operation binding。
- ledger 保持 request/running/status、remote success/upstream write 分离、replay/expiry/篡改撤销和 Stop retention。

## 改动清单

- 新增 authorization 与 ledger 两个 Module，接入 PreTool/Permission/PostTool handlers。
- 增加 legacy/new shape 和完整响应/state/artifact contract。

## 兼容性、可观测性与非目标

policy/state/ticket/receipt schema、TTL、允许操作集合与默认关闭状态不变。不新增遥测，token/remote/命令诊断脱敏。

## TDD 与批准门

- [ ] 先写 capsule、continuation、operation binding 与一次性链 contract。
- [ ] 覆盖 claim、replay、expiry、篡改、remote partial success 与 Stop retention。
- [ ] 全部 Git transaction、clone、tool-phase 与并发 state 测试通过。

Ticket 06、09 合并且本提案批准后方可实施；合并后 Ticket 10 完成。
