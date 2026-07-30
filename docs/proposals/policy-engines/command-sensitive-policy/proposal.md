# Command 与 sensitive policy Module

状态：待批准
实施分支：从最新 `main` 创建 `feature/command-sensitive-policy`
行为基线：上游 v0.2.8 `b6f86a49d8f2adca146d8eb99d0847b465e543d6` + 本地 parity merge `3b5fa54598a80d1fbed6683ff3d48b71e0146cb5`
依赖：`../../core-extraction/user-prompt-entrypoint/proposal.md`

## 动机与目标

先把 tool gate 的纯判定与敏感数据规则从 monolith 提取为两个无副作用领域 Module，不迁移事件 Adapter。

## 设计

- `command_rules` 返回 validation、findings 与 digest，不执行命令或写 state。
- `sensitive_data` 封装 secret scan、configured terms、redaction exception、external/durable 判定与 disclosure grants。

## 改动清单

- 新增两个领域 Module，并让旧入口通过兼容调用使用它们。
- 保留并扩展 command/sensitive 的表驱动回归测试。

## 兼容性、可观测性与非目标

不改 matcher、默认开关、policy/state schema 或事件响应；不新增网络遥测，测试与诊断不得输出命中的敏感值。

## TDD 与批准门

- [ ] 先固定 validation/findings/digest 与 sensitive findings contract。
- [ ] 证明 Module 不启动 subprocess、不写 state。
- [ ] 全部 command/sensitive 既有测试通过。

Ticket 04 合并且本提案批准后方可实施。
