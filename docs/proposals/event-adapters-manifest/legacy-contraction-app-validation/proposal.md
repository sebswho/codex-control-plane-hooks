# Façade 收缩与 Windows App 验收

状态：待批准
实施分支：从最新 `main` 创建 `feature/legacy-contraction-app-validation`
行为基线：上游 v0.2.8 `b6f86a49d8f2adca146d8eb99d0847b465e543d6` + 本地 parity merge `3b5fa54598a80d1fbed6683ff3d48b71e0146cb5`
依赖：`../manifest-launcher-switch/proposal.md`

## 动机与目标

在 façade 已稳定路由到内部 Adapter 后，只收缩已被外部 contract 覆盖的内部业务，并完成 Windows 10 Codex Desktop 的 trust/cache 实测和发布文档；单一 façade 继续保留。

## 设计

- 仅删除已有等价外部 contract 覆盖的 façade 内部业务；保留 façade fallback、runner compatibility 与 cleanup 私有参数。
- 使用 plugin cachebuster helper 与本地 marketplace 重装，在新任务和 App 重启后验证实际加载版本。
- 记录 App、PowerShell、Python 版本和 trust/cache 结果，不提交个人路径或敏感配置。

## 改动清单

- 收缩已替代的 façade 内部实现并清理等价内部测试；不删除 `control_plane_hook.py`。
- 更新 Windows smoke、README、hook contract、configuration、`CHANGELOG.md` 与兼容性矩阵。

## 兼容性、可观测性与非目标

不改变策略、schema、matcher、timeout、statusMessage、manifest 命令或旧 CLI shape；不声称未实测的 host 行为。不新增遥测，App 证据必须脱敏。

## TDD 与批准门

- [ ] 先证明每段待删除逻辑已有 response/state/artifact contract 与 façade fallback 覆盖。
- [ ] 完整自动化与 packaged smoke 通过后再收缩。
- [ ] Windows 10 App Happy Path、拒绝路径、重启、trust/cache 留下脱敏证据。

Façade routing proposal 合并且本提案批准后方可实施；合并后 Ticket 11 完成。
