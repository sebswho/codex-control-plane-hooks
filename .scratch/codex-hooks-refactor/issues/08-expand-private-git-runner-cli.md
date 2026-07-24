# 08 – 为 Git runner 增加专用私有 CLI

**What to build:** 新增专用一次性 Git runner 入口，同时保留旧私有 CLI 作为 compatibility Adapter，使升级时的新 ticket 使用新命令形状、在途旧 ticket 仍能安全完成或按原规则撤销。

**Blocked by:** 04 – 建立安全 package bootstrap 和首个事件入口.

**Status:** ready-for-agent

- [ ] dedicated runner 使用固定解释器、isolated mode、一次性 token 和绝对 plugin-data 参数。
- [ ] legacy runner CLI 转发到同一 runner Interface，整个重构发布周期内保持可用。
- [ ] shape validation 先扩展为严格接受 legacy/new 两种固定形状，再切换新 ticket 的生成形状。
- [ ] 任意脚本路径、宽松 argv、shell override 和篡改后的 runner-shaped retry 均被拒绝。
- [ ] 在途 legacy request/running/status artifacts 不被改写 digest、token 或 transaction binding。
- [ ] 双形状的 claim、replay、expiry、mismatch、receipt contract 全部通过。
- [ ] POSIX 与 PowerShell quoting、退出码和一次 claim 行为保持不变。
