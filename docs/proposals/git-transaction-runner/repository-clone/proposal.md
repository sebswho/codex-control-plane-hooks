# Git repository 与 constrained clone Module

状态：待批准
实施分支：从最新 `main` 创建 `feature/git-repository-clone`
行为基线：v0.2.6
依赖：`../runner-compatibility/proposal.md`

## 动机与目标

把受控 repository 查询和 clone reservation/provenance 提取为两个领域 Module。

## 设计

- `repository` 保持 scope、remote identity、branch、OID、object format/database 验证。
- `clone` 保持 constrained/full candidate、唯一 destination、reservation、provenance 与后续 mutation binding。
- Git 查询使用受控 subprocess Adapter；helper/local/insecure/rewrite/ambiguous/drift 继续 fail closed。

## 改动清单

- 新增 repository、clone 两个 Module，并让旧入口通过兼容调用使用。
- 增加真实临时仓库或既有可信 fake 的响应/state/artifact contract。

## 兼容性、可观测性与非目标

不迁移 authorization/ledger；schema、允许操作与 clone 默认开关不变。不新增遥测，remote/path 诊断脱敏。

## TDD 与批准门

- [ ] 先固定 repository scope 与 clone reservation/provenance contract。
- [ ] 覆盖 helper、rewrite、多目标、drift 与 checkout mutation 拒绝。
- [ ] 全部 Git/clone 协议测试通过。

Ticket 08 合并且本提案批准后方可实施；合并后 Ticket 09 完成。
