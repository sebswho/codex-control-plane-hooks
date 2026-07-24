# 11 – 切换全部 manifest 入口并收缩旧脚本

**What to build:** 在所有新 Module 通过外部 contract 后，将 8 类 Hook 映射到 8 个独立 Adapter，启用 Windows 事件 allowlist，收缩旧业务脚本，并在真实 Windows 10 Codex App 中验证安装、信任和缓存刷新。

**Blocked by:** 06 – 迁移 PostToolUse 消费与输出检查; 07 – 迁移 Agent lifecycle 事件; 10 – 迁移 Git authorization 与 transaction ledger.

**Status:** ready-for-agent

- [ ] 8 类 manifest 事件各指向不同 Python entrypoint，matcher、timeout 和 statusMessage 不变。
- [ ] Windows launcher 只接受固定事件 allowlist，不接受相对路径、路径穿越或未知事件。
- [ ] 所有 entrypoint 使用安全 isolated bootstrap，且不汇聚到旧 `dispatch()`。
- [ ] 旧脚本只保留经批准的 runner compatibility Adapter；其余业务逻辑仅在等价 contract 存在后移除。
- [ ] 8 个入口分别通过响应、state 和相关 runner artifact contract。
- [ ] packaged smoke 在仓库外 cwd 与毒化 PATH/PYTHONPATH 下通过 PowerShell 5.1/7 和 POSIX。
- [ ] 全部协议、并发 state、Git runner、release、host smoke、Ruff 与 plugin validator 通过。
- [ ] 使用 cachebuster helper 与本地 marketplace 重装，在新 Codex 任务和 App 重启后确认未加载旧缓存。
- [ ] Windows 10 App 的 trust 提示、Happy Path 与拒绝路径均留下脱敏证据并形成独立 PR。
