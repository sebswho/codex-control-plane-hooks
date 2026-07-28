# 安全 bootstrap 与 Hook protocol

状态：待批准
实施分支：从当时最新 `main` 创建 `feature/core-bootstrap-protocol`
行为基线：v0.2.6
依赖：`../../runtime-isolation/proposal.md`

## 动机与目标

建立只信任插件打包目录的 Python package bootstrap，并提取统一的 Hook protocol；不同时迁移 policy、state 或业务事件。

## 设计

- `control_plane` package 层级均有 `__init__.py`。
- bootstrap 仅由 entrypoint 的 `__file__` 推导固定 `scripts` root，验证 root、package marker 与目标为普通非 reparse 文件后注入 `sys.path`。
- 不读取 cwd、`PYTHONPATH` 或用户 site；Windows 使用固定 runtime 的 `-I -S`。
- `protocol.run_hook(expected_event, handler)` 负责严格 UTF-8/JSON、事件名匹配、ASCII-safe 输出和既有 fail-closed 映射。

## 改动清单

- 新增 bootstrap 与 protocol 两个 Module 及 poisoned cwd/package smoke。
- 增加 malformed UTF-8/JSON、未知/错配事件和退出码 contract。

## 兼容性、可观测性与非目标

响应 JSON 和退出行为不变；不修改 policy/state schema、manifest 或业务 handler。不新增网络遥测，失败只使用既有脱敏 stderr/退出码。

## TDD 与批准门

- [ ] 先写 `-I -S`、仓库外 cwd、毒化 cwd/`PYTHONPATH` 与同名 package 失败测试。
- [ ] 先写 protocol malformed/错配 contract，再实现最小 Module。
- [ ] PowerShell 5.1/7 与 POSIX package smoke 通过。

本提案批准且 runtime isolation 合并后方可实施。
