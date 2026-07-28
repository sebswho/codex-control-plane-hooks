# Windows 固定运行时发布验证

## 依赖

依赖 `03a-windows-pinned-runtime-launcher` 的启动器契约。

## 动机

清单驱动启动器要求 Windows 冒烟环境先创建专用运行时；旧 CI 和发布检查仍假设启动器可以从 `PATH` 发现 Python。

## 目标

- 在 Windows PowerShell 5.1、PowerShell 7 和真实 Codex Host 冒烟前运行 `setup_runtime.ps1`。
- Python 3.9 作业继续验证通用协议和缺失/无效配置，但只在 Python 3.12 作业创建并运行专用运行时。
- 更新发布边界测试和简体中文运维说明。

## 非目标

- 不改变 Hook 事件、业务策略、序列化状态或插件版本。
- 不改变 POSIX 冒烟流程。

## 改动清单

- [x] 更新发布布局测试，禁止重新引入 PATH 探测。
- [x] 更新 PowerShell 5.1/7 清单冒烟的运行时准备步骤。
- [x] 更新真实 Codex Host Windows 冒烟的运行时准备步骤。
- [x] 将完整 Windows 启动器冒烟限定到 Python 3.12 矩阵项。
- [x] 更新 README、配置、Hook 契约、贡献指南和变更记录。
- [x] 运行完整测试、Ruff、插件校验和发布检查。
- [x] 在 Windows 10 `10.0.19044` 上完成 PowerShell 5.1 与 PowerShell 7.6.4 打包 Hook 手工门禁。
- [x] 在隔离 `CODEX_HOME` 中完成 Codex CLI 0.145.0 Host discovery、untrusted→trusted 写入/重读与 Hook 运行时门禁。
- [ ] 单独验证 Windows 10 Codex Desktop 的 Hook trust/cache 行为；当前仅记录为未验证，不作为已完成声明。
- [x] 完成规格与工程规范双审查并修复全部可行动发现。

## 兼容性影响

CI 的 Python 3.9 Windows 作业不再重复执行必然失败的 Python 3.12 专用运行时冒烟；Python 3.12 Windows 作业仍覆盖两种 PowerShell 和真实宿主路径。
