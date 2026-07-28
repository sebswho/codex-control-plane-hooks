# Hook 入口拆分提案索引

状态：已拆分为四个领域套件及其模块边界子提案，等待逐项批准
Git 分支基线：每个实施分支均从 fork 当时最新 `main` 创建
行为回归基线：v0.2.6 的 Hook 协议与安全测试
前置条件：Windows runtime isolation 已完成自动化与 Windows 10 Desktop 验收

原提案同时覆盖 8 个入口、十余个 Module、manifest、launcher、测试与 CI，超过仓库对复杂提案的拆分阈值。它不再作为可实施 proposal，仅作为依赖索引。

## 子提案

1. [Core extraction 套件](../core-extraction/proposal.md)：拆分 bootstrap/protocol、policy/state 和 `UserPromptSubmit` tracer bullet。
2. [Policy engines 套件](../policy-engines/proposal.md)：拆分 command/sensitive、tool adapters 与独立并行的 lifecycle 链。
3. [Git transaction and runner 套件](../git-transaction-runner/proposal.md)：拆分 runner CLI、compatibility、repository/clone 与 authorization/ledger。
4. [Event adapters and manifest 套件](../event-adapters-manifest/proposal.md)：拆分 manifest/launcher 切换与旧入口收缩/App 验收。

## 共同约束

- 不改变 Hook payload、响应 shape、policy/state/runner schema、默认开关、matcher 或 timeout。
- 每个可实施子提案单独审批、单独 feature 分支、单独 PR；领域索引不可直接实施，前序未合并不得开始被阻塞提案。
- 测试不仅比较响应 JSON，还必须比较 plugin-data 前后状态、reservation/claim/receipt 和一次性 runner artifacts。
- 不允许 8 个新入口重新汇聚到旧 `dispatch()`；兼容 Adapter 只能暂时转发，不承载业务规则。
- 任何行为、schema 或安全语义变化必须先更新对应子提案并重新审核。
