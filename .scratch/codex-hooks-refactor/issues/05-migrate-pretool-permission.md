# 05 – 迁移 PreToolUse 与 PermissionRequest 策略链

**What to build:** 让命令与敏感数据策略通过独立 PreToolUse、PermissionRequest Adapter 工作，并保持危险命令授权、reservation、claim 和 replay 保护的可观察行为不变。

**Blocked by:** 04 – 建立安全 package bootstrap 和首个事件入口.

**Status:** ready-for-agent

- [ ] command rules 是不执行命令、不写 state 的纯判定 Interface。
- [ ] sensitive policy 集中处理 secret、configured terms、redaction、external/durable 和 disclosure grants。
- [ ] PreToolUse 与 PermissionRequest 保持不同响应 shape 和时序，不重新合并为事件字符串分支。
- [ ] contract 覆盖 reservation 创建、重复 PreTool 幂等、matching claim、missing/mismatch/replay 拒绝。
- [ ] 每个 contract 同时断言响应 JSON、session state 和 pending artifacts。
- [ ] 默认关闭的实验开关、matcher、timeout、policy/state schema 和授权语义不变。
- [ ] 旧内部测试仅在等价外部 contract 存在后删除。
