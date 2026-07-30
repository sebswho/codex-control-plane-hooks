# 04 – 建立安全 package bootstrap 和首个事件入口

**What to build:** 在保留旧入口的同时，建立不依赖 cwd、`PYTHONPATH` 或用户 site 的 isolated-mode package bootstrap，并让 UserPromptSubmit 通过新的 protocol、policy、state Interface 独立运行。

**Blocked by:** 03 – 让 Windows Hook 只使用已发布 runtime.

**Status:** implementation-complete; pending final PR/CI

- [x] 所有 package 层级都有明确 marker，entrypoint 只从自身固定位置注入受信 scripts root。
- [x] 仓库外 cwd、毒化 cwd、毒化 `PYTHONPATH` 和同名 package 均不能劫持导入。
- [x] protocol 保持严格 UTF-8/JSON、事件名匹配、ASCII-safe 输出和现有 fail-closed 映射。
- [x] policy/state 隐藏文件验证、锁、原子替换、过期和 schema 细节，外部 schema 不变。
- [x] UserPromptSubmit 新旧入口的响应、turn/grant/sensitive state 前后 contract 一致。
- [x] 新入口不调用旧字符串 `dispatch()`；旧入口仍保持绿色。
- [x] PowerShell 5.1/7、本地 package smoke 和全部既有 state 并发/损坏测试通过；POSIX 由最终 PR CI 复验。
