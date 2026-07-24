# 旧入口收缩与 Windows App 验收

状态：待批准
实施分支：从最新 `main` 创建 `feature/legacy-contraction-app-validation`
行为基线：v0.2.6
依赖：`../manifest-launcher-switch/proposal.md`

## 动机与目标

在 manifest 已稳定使用新入口后，收缩旧 monolith 的非 runner 业务，并完成 Windows 10 Codex Desktop 的 trust/cache 实测和发布文档。

## 设计

- 仅删除已有等价外部 contract 覆盖的旧业务；保留批准窗口内的 runner compatibility Adapter。
- 使用 plugin cachebuster helper 与本地 marketplace 重装，在新任务和 App 重启后验证实际加载版本。
- 记录 App、PowerShell、Python 版本和 trust/cache 结果，不提交个人路径或敏感配置。

## 改动清单

- 收缩旧入口并清理已替代内部测试。
- 更新 Windows smoke、README、hook contract、configuration、`CHANGELOG.md` 与兼容性矩阵。

## 兼容性、可观测性与非目标

不改变策略、schema、matcher 或 timeout；不声称未实测的 host 行为。不新增遥测，App 证据必须脱敏。

## TDD 与批准门

- [ ] 先证明每段待删除逻辑已有 response/state/artifact contract。
- [ ] 完整自动化与 packaged smoke 通过后再收缩。
- [ ] Windows 10 App Happy Path、拒绝路径、重启、trust/cache 留下脱敏证据。

Manifest/launcher proposal 合并且本提案批准后方可实施；合并后 Ticket 11 完成。
