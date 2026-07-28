# 09 – 提取 Git repository 与 constrained clone 行为

**What to build:** 将仓库身份、remote/branch/OID 查询和 clone reservation/provenance 放入独立 Module，同时让现有 Hook 流程继续执行相同的安全判定。

**Blocked by:** 08 – 为 Git runner 增加专用私有 CLI.

**Status:** ready-for-agent

- [ ] repository Interface 保持 scope、remote identity、branch、OID、object format/database 的现有验证语义。
- [ ] helper、local、insecure、rewrite、ambiguous multi-target 和 remote drift 继续 fail closed。
- [ ] constrained/full clone candidate、唯一 destination、reservation 和 provenance 行为不变。
- [ ] checkout mutation 仍需要精确预授权或后续独立授权。
- [ ] 测试同时断言响应、state、clone reservation 和 provenance artifacts。
- [ ] Git 查询使用受控 subprocess Adapter，测试使用真实临时仓库或既有可信 fake。
- [ ] 每次提取后完整 Git/clone 协议测试保持绿色。
