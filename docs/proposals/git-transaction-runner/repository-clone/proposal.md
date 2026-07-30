# Git repository 与 constrained clone Module

状态：待批准
实施分支：从最新 `main` 创建 `feature/git-repository-clone`
行为基线：上游 v0.2.8 `b6f86a49d8f2adca146d8eb99d0847b465e543d6` + 本地 parity merge `3b5fa54598a80d1fbed6683ff3d48b71e0146cb5`
依赖：`../runner-compatibility/proposal.md`

## 动机与目标

把受控 repository 查询和 clone reservation/provenance 提取为两个领域 Module，同时保留 v0.2.8 的事件预算、缓存与 runner 安全复核边界。

## 设计

- `repository` 保持 scope、remote identity、branch、OID、object format/database 验证。
- `clone` 保持 constrained/full candidate、唯一 destination、reservation、provenance 与后续 mutation binding。
- Hook 分类查询共享事件六秒预算和事件级缓存；成功、拒绝与异常路径都清理缓存。
- runner 执行前的 remote/branch/OID 安全复核不得使用事件缓存，必须重新读取真实仓库状态。
- helper/local/insecure/rewrite/ambiguous/drift 继续 fail closed。

## 改动清单

- 新增 repository、clone 与 Git query Adapter，并让 façade 通过兼容调用使用。
- 增加挂起查询预算、缓存隔离、uncached runner recheck 和真实临时仓库 contract。

## 兼容性、可观测性与非目标

不迁移 authorization/ledger；schema、允许操作与 clone 默认开关不变。不新增遥测，remote/path 诊断脱敏。

## TDD 与批准门

- [ ] 先固定 repository scope、clone reservation/provenance、预算与缓存 contract。
- [ ] 覆盖 helper、rewrite、多目标、drift、checkout mutation 和 runner 前 uncached recheck。
- [ ] 全部 Git/clone 协议测试通过。

Ticket 08 合并且本提案批准后方可实施；合并后 Ticket 09 完成。
