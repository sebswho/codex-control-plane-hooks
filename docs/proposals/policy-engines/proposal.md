# Policy engines proposal 套件索引

状态：已拆分，等待各实施子提案批准
依赖：`../core-extraction/user-prompt-entrypoint/proposal.md`
对应票据：Ticket 05、06、07

## 动机与并行边界

Tool policy、PostTool effects 与 Agent lifecycle 是不同变更原因，必须分别交付。本文件仅作为索引，不可直接实施。Ticket 04 完成后，Ticket 05 与 Ticket 07 可并行；Ticket 06 只依赖 Ticket 05，不阻塞 lifecycle。

## 实施子提案

Tool 链：

1. [Command 与 sensitive policy](command-sensitive-policy/proposal.md)：两个纯领域 Module。
2. [PreToolUse 与 PermissionRequest](pretool-permission/proposal.md)：两个独立 gate Adapter；完成 Ticket 05。
3. [PostToolUse effects](posttool-effects/proposal.md)：receipt、pending、clone provenance 与输出检查；完成 Ticket 06。

Lifecycle 链（可与 Tool 链并行）：

1. [Lifecycle ledger](lifecycle-ledger/proposal.md)：Agent ledger、checkpoint 与 Stop reconciliation 领域 Module。
2. [Subagent adapters](subagent-adapters/proposal.md)：SubagentStart/Stop 两个 Adapter。
3. [PreCompact 与 Stop adapters](session-closure-adapters/proposal.md)：两个 session-closure Adapter；完成 Ticket 07。

## 共同约束

- matcher、timeout、默认开关、policy/state schema 与 Git transaction 语义不变。
- 外部 contract 同时断言响应、session state 和 pending/reservation/receipt/provenance artifacts。
- 旧内部测试只在相同风险路径有等价外部 contract 后删除。
- 每个子提案独立批准、分支和 PR；本地 Hook 不新增网络遥测，只保留脱敏错误与测试 artifacts。

## 改动清单

- 新增六个模块边界受控的实施子提案。
- 恢复 Ticket 04 后 Ticket 05/07 的并行 frontier，并保留 Ticket 05 → 06 的依赖。
