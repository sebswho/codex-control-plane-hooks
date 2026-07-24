# 06 – 迁移 PostToolUse 消费与输出检查

**What to build:** 让独立 PostToolUse Adapter 正确消费或撤销 tool-phase 状态，记录 clone provenance，并保持敏感输出保护与一次性 artifact 生命周期不变。

**Blocked by:** 05 – 迁移 PreToolUse 与 PermissionRequest 策略链.

**Status:** ready-for-agent

- [ ] contract 覆盖成功、失败、缺失和不匹配 receipt 的消费或撤销行为。
- [ ] pending permission 在正确 PostToolUse 后清理，错误 tool identity 或 response 不会误消费。
- [ ] constrained/full clone provenance 只在匹配的成功调用后记录。
- [ ] secret 和 configured sensitive output 保持现有 fail-closed/context 行为。
- [ ] 每个测试同时断言响应、session state、receipt/status 和 clone artifacts。
- [ ] replay、expiry、remote success 与后续本地 metadata 失败的语义不变。
- [ ] 全部既有 tool protocol 与 Git transaction 回归测试保持绿色。
