# Event adapters 与 manifest contract proposal 套件索引

状态：已拆分，等待各实施子提案批准
依赖：Ticket 06、07、10
对应票据：Ticket 11

## 动机与边界

前序提案已经逐步交付 8 个 handler/entrypoint；最终阶段只负责接线与收缩。Manifest/launcher 切换和旧入口收缩/App 验收是两个可独立回滚的风险边界，本文件仅作索引，不可直接实施。

## 实施子提案

1. [Manifest 与 Windows launcher 切换](manifest-launcher-switch/proposal.md)：一一映射 8 个既有 entrypoint，并加入固定事件 allowlist。
2. [旧入口收缩与 App 验收](legacy-contraction-app-validation/proposal.md)：移除已被 contract 覆盖的非 runner 业务，完成 cache/trust 实测与文档。

## 共同约束

- matcher、timeout、statusMessage、payload、响应、policy/state/runner schema 不变。
- 新入口不汇聚到旧 `dispatch()`；legacy runner compatibility Adapter 按批准窗口保留。
- contract 同时覆盖 response JSON、plugin-data state 和 runner artifacts；未知/错配事件 fail closed。
- 每个子提案独立批准、分支和 PR；不新增网络遥测，App 证据必须脱敏。

## 改动清单

- 新增两个模块边界受控的实施子提案。
- 更新 manifest/launcher、旧入口、测试、Windows smoke、README、相关 contract 文档、`CHANGELOG.md` 与兼容性矩阵。
