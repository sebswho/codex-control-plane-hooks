# Git transaction 与 runner proposal 套件索引

状态：已拆分，等待各实施子提案批准
依赖：`../core-extraction/user-prompt-entrypoint/proposal.md`
对应票据：Ticket 08、09、10

## 动机与边界

Runner CLI、legacy compatibility、repository/clone 与 authorization ledger 属于不同模块和风险边界。本文件仅作为索引，不可直接实施。

## 实施子提案

1. [Runner Interface 与专用 CLI](runner-interface-cli/proposal.md)：先 expand 新私有执行入口。
2. [Legacy runner compatibility](runner-compatibility/proposal.md)：严格双形状识别与在途 ticket 兼容；完成 Ticket 08。
3. [Repository 与 clone](repository-clone/proposal.md)：受控 Git 查询、clone reservation 与 provenance；完成 Ticket 09。
4. [Authorization 与 transaction ledger](authorization-ledger/proposal.md)：接入 tool 事件链并完成 Ticket 10。

依赖顺序：Ticket 04 → runner Interface/CLI → compatibility → repository/clone → authorization/ledger。最终 authorization 集成还依赖 Ticket 05、06。

## 共同约束

- 先接受严格 legacy/new 两种固定 shape，再生成 new shape；旧入口至少保留整个重构发布周期。
- policy/state/ticket/receipt schema、TTL、默认开关和允许操作集合不变。
- contract 覆盖响应、state、request/running/status、claim、replay、expiry、篡改和 Stop retention。
- 每个子提案独立批准、分支和 PR；不新增网络日志、指标或 tracing，诊断保持脱敏。

## 改动清单

- 新增四个模块边界受控的实施子提案。
- 保留原子 compatibility 窗口，并明确 Ticket 08/09/10 的串行与交叉依赖。
