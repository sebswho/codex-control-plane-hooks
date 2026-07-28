# Windows 固定运行时启动器

## 动机

现有 Windows 启动器会从 `PATH` 查找并探测 `py.exe`/`python.exe`。这会让 Hook 的解释器选择受当前工作目录、用户环境和 Python Manager 行为影响，也会为一次 Hook 调用创建多个探测进程。

## 目标

- 只读取宿主提供的 `PLUGIN_DATA/runtime.json`，不再发现或回退到 `PATH`。
- 只接受 `setup_runtime.ps1` 发布的 Python 3.12 固定运行时布局。
- 在同一个 Python 子进程中验证 Python 3.12 并执行 Hook。
- 继承 stdin/stdout/stderr，并原样返回 Hook 的退出码。
- 缺少配置返回 `127`；配置无效、路径不可信、启动失败或版本错误返回 `126`。

## 非目标

- 不修改 `.cmd` 兼容入口、Hook 清单或业务策略逻辑。
- 不下载 Python，不增加第三方运行时依赖。
- 不开始 Ticket 04。

## 改动清单

- [x] 先写缺失、损坏和不受信任清单的失败测试。
- [x] 严格校验 UTF-8、大小、schema、字段集合、字段类型和值域。
- [x] 使用 Windows Profile API 固定运行时根目录和解释器布局。
- [x] 对已观察目录、清单和解释器加句柄锁并拒绝 reparse point。
- [x] 删除 `where.exe`、`py.exe`、`python.exe` 探测和回退逻辑。
- [x] 用单个 `python.exe -I -S -c` 子进程验证版本并执行 Hook。
- [x] 透传标准流和 Hook 退出码，并区分启动器保留错误码。

## 兼容性影响

Windows 用户升级后必须先运行 `setup_runtime.ps1`。未配置时不再尝试系统 Python，而是稳定返回 `127`。已配置用户继续使用 PowerShell 5.1/7 和原有 `.cmd` 入口；POSIX 启动路径不变。

## 可观测性

启动器只输出固定、不含本地路径的错误类别。Hook 自身输出保持原样，不添加遥测或网络请求。
