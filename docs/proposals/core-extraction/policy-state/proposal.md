# Policy 与 state 基础 Interface

状态：已批准并实施（2026-07-29，待 PR/CI）
实施分支：从当时最新 `main` 创建 `feature/core-policy-state`
行为基线：v0.2.6
依赖：`../bootstrap-protocol/proposal.md`

## 动机与目标

把文件边界和并发状态细节封装成两个可复用 Module，使事件 handler 不直接操作路径、锁和 schema。

## 设计

- `policy` 暴露经验证的不可变 view，隐藏路径、大小、ownership/mode/reparse 与严格 boolean 规则。
- `state` 暴露快照读取与锁内变更，隐藏 session hash、锁 sentinel、原子替换、过期、schema 验证和 Stop 清理原语。
- 两个 Module 不 import events/entrypoints；所有持久化格式保持原样。

## 改动清单

- 新增 policy、state 两个 Module。
- 将旧入口改为调用新 Interface，并保留全部现有并发、损坏和权限测试。

## 兼容性、可观测性与非目标

policy/state schema、TTL、锁 inode 和错误映射不变；不新增事件入口、业务规则或遥测。诊断继续脱敏且不记录 state 内容。

## TDD 与批准门

- [x] 先锁定 policy/state 的外部 contract、损坏文件、reparse、并发与原子替换行为。
- [x] 用最小 Interface 让旧入口测试转绿。
- [x] 运行全部 state 并发/损坏和协议测试。

bootstrap/protocol 合并且本提案批准后方可实施。

批准门已满足：本提案已获批准，bootstrap/protocol 已合并。
