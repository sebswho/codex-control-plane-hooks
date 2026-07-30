# Policy engines proposal 套件索引

状态：已按 v0.2.8 基线调整，等待各实施子提案批准
依赖：Phase 1: split protocol test and documentation ownership
对应票据：Ticket 05、06、07
行为基线：上游 v0.2.8 `b6f86a49d8f2adca146d8eb99d0847b465e543d6` + 本地 parity merge `3b5fa54598a80d1fbed6683ff3d48b71e0146cb5`

## 动机与并行边界

Tool policy、PostTool effects 与 lifecycle Adapter 是不同变更原因，必须分别交付。本文件仅作为索引，不可直接实施。Phase 1 完成后，Ticket 05 与 Ticket 07 可并行；Ticket 06 只依赖 Ticket 05，不阻塞 lifecycle。

## 实施子提案

Tool 链：

1. [Command 与 sensitive policy](command-sensitive-policy/proposal.md)：纯领域 Module，保留事件快照、字段范围与重定向保护。
2. [PreToolUse 与 PermissionRequest](pretool-permission/proposal.md)：由单一公开 façade 路由到两个独立 Adapter；完成 Ticket 05。
3. [PostToolUse effects](posttool-effects/proposal.md)：receipt、pending、clone provenance 与既有来源范围内的输出检查；完成 Ticket 06。

Lifecycle 链（可与 Tool 链并行）：

1. [Lifecycle ledger](lifecycle-ledger/proposal.md)：SessionStart、SubagentStop 与 Stop 使用的共享领域 Module。
2. [SubagentStop adapter](subagent-adapters/proposal.md)：提取 SubagentStop 路径并保留 façade fallback。
3. [SessionStart 与 Stop adapters](session-closure-adapters/proposal.md)：完成 lifecycle 纵向切片；完成 Ticket 07。

## 共同约束

- 六秒事件预算、事件级 Git 分类缓存、每事件一次 policy/data-directory 快照必须无损传递；缓存不得跨请求或异常泄漏。
- command 规则只读取真实 command 字段，destination 规则只读取真实 destination/path 字段；受保护输出重定向继续 fail closed，合法只读引用不误报。
- matcher、timeout、默认开关、policy/state schema、错误输出与 Git transaction 语义不变。
- 外部 contract 同时断言响应、session state 和 pending/reservation/receipt/provenance artifacts。
- `hooks.json` 继续调用 `control_plane_hook.py`；内部 handler/entrypoint 只是测试和模块边界，不扩展为多个公开 manifest 命令。

## 改动清单

- 调整六个模块边界受控的实施子提案，使其服从 v0.2.8 façade 与事件快照契约。
- 固定 Phase 1 后 Ticket 05/07 的并行 frontier，并保留 Ticket 05 → 06 的依赖。
