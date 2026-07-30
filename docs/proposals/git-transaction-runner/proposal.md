# Git transaction 与 runner proposal 套件索引

状态：已按 v0.2.8 runner/cleanup 契约调整，等待各实施子提案批准
依赖：Phase 1: split protocol test and documentation ownership
对应票据：Ticket 08、09、10
行为基线：上游 v0.2.8 `b6f86a49d8f2adca146d8eb99d0847b465e543d6` + 本地 parity merge `3b5fa54598a80d1fbed6683ff3d48b71e0146cb5`

## 动机与边界

Runner/cleanup、repository/clone 与 authorization ledger 属于不同模块和风险边界。本文件仅作为索引，不可直接实施。

## 实施子提案

1. [Private Git runner Module 与 cleanup worker](runner-interface-cli/proposal.md)：提取既有 `--run-approved-git` runner，并封装 v0.2.8 私有 cleanup worker。
2. [Runner CLI compatibility contract](runner-compatibility/proposal.md)：固定旧 CLI shape、cleanup 参数和失败隔离；完成 Ticket 08。
3. [Repository 与 clone](repository-clone/proposal.md)：受事件预算约束、带事件级缓存的分类查询，以及 runner 前不使用缓存的安全复核；完成 Ticket 09。
4. [Authorization 与 transaction ledger](authorization-ledger/proposal.md)：最后接入 tool 事件链并完成 Ticket 10。

依赖顺序：v0.2.8 baseline → Phase 1 → Ticket 08 → Ticket 09 → Ticket 10。最终 authorization 集成还依赖 Ticket 05、06。

## 共同约束

- 公开兼容参数 `--run-approved-git <token> <data-dir>` 原样保留；不引入替代 ticket shape。
- 私有 `--cleanup-orphans <absolute-data-dir>` 只由已批准 runner best-effort 调度，普通 Hook decision 路径永不执行或调度 cleanup。
- runner/push 活跃 lease 阻止 cleanup 删除在用目录；cleanup 的锁、cursor、64/2/500ms/1s 上限与失败隔离保持不变。
- policy/state/ticket/receipt、TTL、lease 和 cleanup artifact 的序列化兼容不变。
- contract 覆盖响应、state、request/running/status、claim、replay、expiry、篡改、receipt 与 Stop retention。

## 改动清单

- 重写 runner 提取边界，不再计划双 CLI shape 迁移。
- 明确 Ticket 08/09/10 的串行与交叉依赖，以及 cleanup 对 decision/exit code/receipt 的零影响。
