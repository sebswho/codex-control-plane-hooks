# Runner CLI compatibility contract

状态：待批准
实施分支：从最新 `main` 创建 `feature/git-runner-compatibility`
行为基线：上游 v0.2.8 `b6f86a49d8f2adca146d8eb99d0847b465e543d6` + 本地 parity merge `3b5fa54598a80d1fbed6683ff3d48b71e0146cb5`
依赖：`../runner-interface-cli/proposal.md`

## 动机与目标

固定 v0.2.8 已发布的 runner 与 cleanup 参数形状，确保模块提取不破坏在途 ticket、receipt 或失败隔离。

## 设计

- `--run-approved-git <token> <data-dir>` 继续转发到同一 runner Interface，不新增替代 shape。
- `--cleanup-orphans <absolute-data-dir>` 保持私有、绝对路径校验和 best-effort 语义。
- recognizer 不接受任意脚本路径、宽松 argv、shell override 或篡改后的 runner-shaped retry。
- 在途 request/running/status 不改写 digest、token 或 transaction binding。

## 改动清单

- 增加旧 runner shape、私有 cleanup 参数、篡改和在途 ticket contract。
- 删除“先双 shape、再切换生成 shape”的 roadmap 要求。

## 兼容性、可观测性与非目标

不迁移 repository/clone/authorization；schema、TTL 和安全语义不变。不新增遥测，失败诊断不泄露 token。

## TDD 与批准门

- [ ] 先写旧 runner shape、cleanup shape、篡改、retry 与在途 ticket contract。
- [ ] 证明 cleanup 失败不改变 runner exit code 或 receipt。
- [ ] POSIX/PowerShell runner 全量测试通过。

Runner/cleanup Module 合并且本提案批准后方可实施；合并后 Ticket 08 完成。
