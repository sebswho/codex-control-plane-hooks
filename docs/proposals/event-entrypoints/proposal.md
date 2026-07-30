# Hook 入口拆分提案索引

状态：已按 v0.2.8 单一 façade 路线修订，等待逐项批准
Git 分支基线：每个实施分支均从 fork 当时最新 `main` 创建
行为回归基线：上游 v0.2.8 `b6f86a49d8f2adca146d8eb99d0847b465e543d6` + 本地 parity merge `3b5fa54598a80d1fbed6683ff3d48b71e0146cb5` 的 Hook 协议与安全测试
前置条件：v0.2.8 baseline Issue 与 Phase 1: split protocol test and documentation ownership 完成

原提案同时覆盖多个入口、十余个 Module、manifest、launcher、测试与 CI，超过仓库对复杂提案的拆分阈值。它不再作为可实施 proposal，仅作为依赖索引。

## 子提案

1. [Core extraction 套件](../core-extraction/proposal.md)：既有 bootstrap/protocol、policy/state 和 `UserPromptSubmit` tracer bullet。
2. [Policy engines 套件](../policy-engines/proposal.md)：command/sensitive、tool adapters 与 lifecycle 链。
3. [Git transaction and runner 套件](../git-transaction-runner/proposal.md)：runner/cleanup、repository/clone 与 authorization/ledger。
4. [Event adapters and manifest 套件](../event-adapters-manifest/proposal.md)：单一 façade 路由、实现收缩与 App 验收。

## 共同约束

- 不改变 Hook payload、响应 shape、policy/state/runner schema、默认开关、matcher、timeout、statusMessage 或旧 CLI shape。
- `hooks.json` 继续指向 `control_plane_hook.py`；内部入口只作为测试或模块边界，不成为多个公开命令。
- POSIX 保持 `python3 -I -S`；Windows 保持 pinned Python 3.12 runtime 且不回退 PATH。
- 测试不仅比较响应 JSON，还必须比较 plugin-data 前后状态、reservation/claim/receipt、lease、cleanup artifacts 和一次性 runner artifacts。
- v0.2.8 的事件预算、事件快照、字段范围、重定向保护、cleanup 隔离与序列化兼容是所有后续提取的不可变 contract。
