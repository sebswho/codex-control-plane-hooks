# Event adapters 与 manifest contract proposal 套件索引

状态：已按单一 façade 决策调整，等待实施子提案批准
依赖：Ticket 06、07、10
对应票据：Ticket 11
行为基线：上游 v0.2.8 `b6f86a49d8f2adca146d8eb99d0847b465e543d6` + 本地 parity merge `3b5fa54598a80d1fbed6683ff3d48b71e0146cb5`

## 动机与边界

前序提案逐步提取内部 handler/Adapter；最终阶段负责完成 façade 路由、收缩已替代实现并做真实 App 验证。`hooks.json` 继续指向 `control_plane_hook.py`，不再计划切换为多个公开入口。

## 实施子提案

1. [Façade 路由与 launcher 验证](manifest-launcher-switch/proposal.md)：验证单一公开入口对内部 Adapter 的路由、fallback 和 packaged smoke。
2. [Façade 收缩与 App 验收](legacy-contraction-app-validation/proposal.md)：只移除已有 contract 覆盖的 façade 内部业务，完成 cache/trust 实测与文档。

## 共同约束

- matcher、timeout、statusMessage、payload、响应、policy/state/runner schema 与旧 CLI shape 不变。
- POSIX 继续使用 `python3 -I -S`；Windows 继续使用 pinned Python 3.12 runtime，不恢复 PATH fallback。
- 内部入口可作为测试或模块边界，但不成为多个公开 manifest 命令。
- façade fallback 与错误输出契约保留；contract 同时覆盖 response JSON、plugin-data state 和 runner artifacts。

## 改动清单

- 将原“8 个公开入口切换”改为单一 façade 路由验证。
- 更新 façade、测试、Windows smoke、README、相关 contract 文档、`CHANGELOG.md` 与兼容性矩阵。
