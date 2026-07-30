# Private Git runner Module 与 cleanup worker

状态：待批准
实施分支：从最新 `main` 创建 `feature/git-runner-interface-cli`
行为基线：上游 v0.2.8 `b6f86a49d8f2adca146d8eb99d0847b465e543d6` + 本地 parity merge `3b5fa54598a80d1fbed6683ff3d48b71e0146cb5`
依赖：Phase 1: split protocol test and documentation ownership

## 动机与目标

从 façade 实现中提取既有私有 Git runner 和 cleanup worker，不改变已经发布的 runner CLI shape。

## 设计

- runner Interface 处理 ticket claim、isolated config/bare repo、immutable OID push、活跃 lease 与 receipt。
- 公开兼容参数继续是 `--run-approved-git <token> <data-dir>`；POSIX/PowerShell invocation 保持精确 quoting、退出码和一次 claim 语义。
- 私有 `--cleanup-orphans <absolute-data-dir>` 只可由已批准 runner best-effort 启动独立 worker；普通 Hook dispatch 和 runner 准备阶段不得调度 cleanup。
- cleanup 使用非阻塞 single-flight lock、持久化 cursor，最多扫描 64 项、尝试删除 2 项、单次删除子进程 500ms、枚举后总预算 1 秒。
- cleanup 尊重 runner/push lease；启动、锁、枚举或删除失败不得改变 decision、runner exit code 或 receipt。

## 改动清单

- 新增 runner Module 与 cleanup worker Module，façade 仅保留兼容路由。
- 增加 lease、single-flight、cursor、上限和全失败模式 contract。

## 兼容性、可观测性与非目标

不切换 ticket shape、不删除 `--run-approved-git`；ticket/receipt/state schema 与允许操作不变。不新增遥测，诊断不输出 token 或命令。

## TDD 与批准门

- [ ] 先为 runner/cleanup Module 写失败/成功 contract。
- [ ] 验证普通 Hook 永不 cleanup、只有已批准 runner 调度、活跃 lease 阻止删除。
- [ ] 验证 64/2/500ms/1s 上限和所有 cleanup 失败均不影响 runner/receipt。
- [ ] 全部现有 runner 测试保持绿色。

Phase 1 完成且本提案批准后方可实施。
