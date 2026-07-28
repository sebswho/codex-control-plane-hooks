# Runner Interface 与专用私有 CLI

状态：待批准
实施分支：从最新 `main` 创建 `feature/git-runner-interface-cli`
行为基线：v0.2.6
依赖：`../../core-extraction/user-prompt-entrypoint/proposal.md`

## 动机与目标

先 expand 独立 runner Module 和私有 CLI，使后续迁移不依赖 monolith 的 `--run-approved-git` 业务实现。

## 设计

- runner Interface 处理 ticket claim、isolated config/bare repo、immutable OID push 与 receipt。
- dedicated CLI 使用固定解释器、`-I -S`、一次性 token 和绝对 plugin-data 参数。
- POSIX/PowerShell invocation 保持精确 quoting、退出码和一次 claim 语义。

## 改动清单

- 新增 runner Module 与 dedicated CLI entrypoint。
- 增加 claim、replay、expiry、mismatch、receipt 与 shell contract。

## 兼容性、可观测性与非目标

本提案不切换新 ticket shape、不删除 legacy CLI；ticket/receipt schema 与允许操作不变。不新增遥测，诊断不输出 token 或命令。

## TDD 与批准门

- [ ] 先为 dedicated CLI 写失败/成功 contract。
- [ ] 验证固定解释器、isolated mode、绝对 plugin-data 与 token binding。
- [ ] 全部现有 runner 测试保持绿色。

Ticket 04 合并且本提案批准后方可实施。
