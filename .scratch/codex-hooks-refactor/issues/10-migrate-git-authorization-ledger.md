# 10 – 迁移 Git authorization 与 transaction ledger

**What to build:** 让授权 capsule、跨 turn continuation、operation binding 和 runner receipt 完整穿过新的 PreToolUse、PermissionRequest、PostToolUse 事件链，并保持隔离 push 的所有安全保证。

**Blocked by:** 05 – 迁移 PreToolUse 与 PermissionRequest 策略链; 06 – 迁移 PostToolUse 消费与输出检查; 08 – 为 Git runner 增加专用私有 CLI; 09 – 提取 Git repository 与 constrained clone 行为.

**Status:** ready-for-agent

- [ ] authorization capsule、positive clause、安全排除、scope mapping 和 continuation TTL 语义不变。
- [ ] operation reservation、permission claim、runner execution、PostTool receipt 形成一次性完整链。
- [ ] isolated bare repository、冻结 system/global config、禁止 local hooks/rewrite 和 immutable OID push 保持不变。
- [ ] remote success 与 upstream metadata write 独立记录，远端已成功时不会危险重试。
- [ ] contract 覆盖 state ledger、request/running/status artifacts、claim、replay、expiry、篡改和 Stop retention。
- [ ] legacy/new runner shape 在兼容窗口内均按绑定工作。
- [ ] policy/state/ticket/receipt schema、允许操作集合、TTL 和默认关闭状态不变。
- [ ] 全部 Git transaction、clone、tool-phase 和并发 state 测试通过。
