# Manifest 与 Windows launcher 切换

状态：待批准
实施分支：从最新 `main` 创建 `feature/manifest-launcher-switch`
行为基线：v0.2.6
依赖：Ticket 06、07、10

## 动机与目标

在 8 个 entrypoint 已分别通过 contract 后，将 manifest 一一接线，并让共享 Windows launcher 只接受固定事件 allowlist。

## 设计

- POSIX manifest 为 8 类事件分别指向既有 entrypoint。
- Windows manifest 调用共享 launcher 并传固定事件名；launcher 只接受编译式 allowlist，不接受路径或未知事件。
- matcher、timeout 与 statusMessage 保持不变。

## 改动清单

- 修改 manifest 与 Windows launcher 两个边界。
- 增加一一映射、错配、未知事件、路径穿越与 poisoned cwd/PATH/PYTHONPATH smoke。
- 在同一 PR 更新 `CHANGELOG.md` 与兼容性矩阵，披露 manifest trust identity 变化和重新接受 trust 的要求。

## 兼容性、可观测性与非目标

不删除旧业务入口；payload、响应与 schema 不变。不新增遥测，diagnostics 保持脱敏。Manifest trust identity 预计变化，但 launcher/cache identity 不作未验证断言。

## TDD 与批准门

- [ ] 切换前 8 个入口 response/state/artifact contract 全部通过。
- [ ] 先写 manifest mapping 与 allowlist 失败测试，再改接线。
- [ ] 协议、state、runner、release、host smoke、Ruff 与 validator 全部通过。

Ticket 06、07、10 合并且本提案批准后方可实施。
