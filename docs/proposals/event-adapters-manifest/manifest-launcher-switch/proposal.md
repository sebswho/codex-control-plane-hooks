# Façade 路由与 launcher 验证

状态：待批准
实施分支：从最新 `main` 创建 `feature/manifest-launcher-switch`
行为基线：上游 v0.2.8 `b6f86a49d8f2adca146d8eb99d0847b465e543d6` + 本地 parity merge `3b5fa54598a80d1fbed6683ff3d48b71e0146cb5`
依赖：Phase 1.5 Codex App canary（Issue #20）与 Ticket 06、07、10

## 动机与目标

在内部 Adapter 分别通过 contract 后，完成 `control_plane_hook.py` 的模块路由并验证跨平台 launcher；不改变 manifest 的单一公开入口。

## 设计

- POSIX manifest 对所有事件继续调用 `python3 -I -S "$PLUGIN_ROOT/scripts/control_plane_hook.py"`。
- Windows manifest 继续调用 pinned runtime launcher，始终使用固定 Python 3.12，不回退 PATH。
- façade 根据协议事件路由到内部 Adapter，并保留兼容 fallback、stderr 与退出码。
- matcher、timeout 与 statusMessage 保持不变；内部入口只作为测试或模块边界。

## 改动清单

- 完成 façade 路由与 fallback contract，不把 8 类事件切成 8 个公开命令。
- 增加错配/未知事件、hostile cwd/PYTHONPATH、Windows pinned runtime 和 packaged smoke。
- 在同一 PR 更新 `CHANGELOG.md` 与兼容性矩阵，并重放 Issue #20 的 launcher/trust/cache canary；因 manifest 命令不变，不宣称新的 trust identity。

## 兼容性、可观测性与非目标

不删除 façade 或 runner compatibility；payload、响应、schema、公开 CLI 不变。不新增遥测，diagnostics 保持脱敏。

## TDD 与批准门

- [ ] 切换前所有 Adapter response/state/artifact contract 全部通过。
- [ ] 先写 façade routing/fallback 失败测试，再改内部接线。
- [ ] 协议、state、runner、release、host smoke、Ruff 与 validator 全部通过。
- [ ] 重放 Issue #20 中与 façade、launcher、runtime 和 trust/cache 边界相关的真实 App 场景。

Issue #20 完成、Ticket 06、07、10 合并且本提案批准后方可实施。
