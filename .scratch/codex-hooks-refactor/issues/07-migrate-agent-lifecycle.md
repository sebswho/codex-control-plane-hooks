# 07 – 迁移 Agent lifecycle 事件

**What to build:** 让 SubagentStart、SubagentStop、PreCompact 和 Stop 通过独立 Adapter 使用共享 lifecycle Module，保护并发 Agent ledger 与 unfinished transaction retention。

**Blocked by:** 04 – 建立安全 package bootstrap 和首个事件入口.

**Status:** ready-for-agent

- [ ] 四类 lifecycle 事件各有独立 handler，不通过字符串 dispatch 重新汇聚。
- [ ] nested delegation、Agent start/stop 和 PreCompact checkpoint 的响应与 state 变化保持一致。
- [ ] 并发 Agent 更新和 Stop 不丢 ledger entry，不切换锁 inode。
- [ ] Stop 保留 unfinished transaction 与 pending reservation；无 active Agent 时按原规则清理 session state。
- [ ] contract 同时断言响应、state 前后内容、lock sentinel 和 retention artifacts。
- [ ] policy/state schema、超时和默认行为不变。
- [ ] lifecycle 全量测试可与 Ticket 05、08 的实现并行保持绿色。
