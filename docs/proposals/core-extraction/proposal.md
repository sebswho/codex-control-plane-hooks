# Core extraction proposal 套件索引

状态：已拆分，等待各实施子提案批准
依赖：`../runtime-isolation/proposal.md`
对应票据：Ticket 04

## 动机与边界

Ticket 04 同时触及 bootstrap、protocol、policy、state、handler 与 entrypoint，超过单一 proposal 的模块上限。本文件仅维护依赖与共同约束，不可直接实施。

## 实施子提案

1. [安全 bootstrap 与 protocol](bootstrap-protocol/proposal.md)：固定 package root、isolated-mode 启动和通用 Hook protocol。
2. [Policy 与 state 基础 Interface](policy-state/proposal.md)：封装 policy view、session state、锁与原子替换。
3. [UserPromptSubmit tracer bullet](user-prompt-entrypoint/proposal.md)：用独立 handler/entrypoint 验证前两项 Interface。

依赖顺序：runtime isolation → bootstrap/protocol → policy/state → UserPromptSubmit。三个子提案均完成后 Ticket 04 才完成。

## 共同约束

- 响应 JSON、policy/state schema、退出行为与 v0.2.6 行为基线不变。
- 新旧入口的 contract 同时比较响应和 plugin-data 前后状态；新入口不得调用旧字符串 `dispatch()`。
- 每个子提案从当时最新 `main` 建独立 feature 分支并创建独立 PR。
- 本地 Hook 不新增网络日志、指标或 tracing；只使用既有 fail-closed stderr/退出码和测试 artifacts，避免泄露 payload 与个人路径。

## 改动清单

- 新增三个模块边界受控的实施子提案及其测试、文档和分支门禁。
- Ticket 04 的验收保持不变，不扩大 Hook 行为或 schema。
