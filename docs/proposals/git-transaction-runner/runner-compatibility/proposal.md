# Legacy runner compatibility 与双 shape 迁移

状态：待批准
实施分支：从最新 `main` 创建 `feature/git-runner-compatibility`
行为基线：v0.2.6
依赖：`../runner-interface-cli/proposal.md`

## 动机与目标

在新 reservation 生成 dedicated CLI shape 前，先让严格 recognizer 同时接受 legacy/new 两种固定形状，并保住在途 ticket。

## 设计

- legacy `--run-approved-git` 入口作为 Adapter 转发到同一 runner Interface，至少保留整个重构发布周期。
- shape recognizer 只接受两种固定脚本/argv 形状，不接受任意路径、宽松 argv 或 shell override。
- 在途 request/running/status 不改写 digest、token 或 transaction binding。

## 改动清单

- 新增 legacy compatibility Adapter 与双 shape recognizer。
- recognizer contract 通过后才切换新 reservation 的生成 shape。

## 兼容性、可观测性与非目标

不迁移 repository/clone/authorization；schema、TTL 和安全语义不变。不新增遥测，失败诊断不泄露 token。

## TDD 与批准门

- [ ] 先写 legacy/new shape、篡改、retry 与在途 ticket contract。
- [ ] 先扩 recognizer，再切生成 shape。
- [ ] POSIX/PowerShell runner 全量测试通过。

Runner Interface/CLI 合并且本提案批准后方可实施；合并后 Ticket 08 完成。
