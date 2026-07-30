# Windows Codex App 专用运行时隔离

状态：已批准（2026-07-24）
Git 分支基线：实施时从 fork 的最新 `main` 新建分支；本次规格修订基于 `0ffc0e3732599bbd668e150070495264e2b0f913`
行为回归基线：上游 v0.2.8 `b6f86a49d8f2adca146d8eb99d0847b465e543d6` + 本地 parity merge `3b5fa54598a80d1fbed6683ff3d48b71e0146cb5`
实施分支：批准后从当时最新 `main` 新建 `feature/windows-app-runtime`
依赖：无
后续：`../event-entrypoints/proposal.md`

## 动机

当前 Windows Hook 每次触发都会从 `PATH` 中定位并探测 `py.exe`、`python.exe`。在同步上游 v0.2.8 基线前，这条路径即使已限制为显式 `PATH`、共享截止时间并清理超时进程树，这条路径仍有三个问题：

1. 每次 Hook 都支付解释器发现和版本探测成本。
2. Codex App 实际执行的 Python 会随用户 `PATH`、Python Launcher 和安装状态变化。
3. 开发测试覆盖 Windows Server 2022，但没有 Windows 10 Codex Desktop 的安装、信任和缓存刷新证据。

本提案先稳定 Windows 运行时，不改 Hook 事件业务逻辑。事件入口拆分在后续独立提案中完成。

## 目标

- Windows 正式执行只使用 Codex 专用 Python 3.12 虚拟环境。
- Hook 热路径不再调用 `where.exe`，不再探测 `py.exe` 或 `python.exe`。
- 运行时安装是显式、可重复、可诊断的操作，不由 Hook 自动下载或安装 Python。
- 保持现有 Hook 输入输出、policy、session state、runner ticket 和 Git transaction 序列化格式不变。
- 在 Windows 10 Codex Desktop 上完成一次真实安装、重载、信任和事件 smoke。

## 非目标

- 不在本提案中拆分 `control_plane_hook.py`。
- 不改变自然语言审批、Git transaction、clone 或敏感披露的默认开关。
- 不改变 macOS/Linux 的 Python 发现方式。
- 不尝试绕过 Codex App 的 Hook trust 或审批机制。
- 不把运行时、`.venv` 或个人 marketplace 配置提交到仓库。

## 设计

### 1. 固定运行时位置

Windows 正式运行时固定在：

```text
%USERPROFILE%\.codex\runtimes\codex-control-plane-hooks\
```

解释器位于固定 root 下的版本化目录：

```text
%USERPROFILE%\.codex\runtimes\codex-control-plane-hooks\versions\<runtime-id>\Scripts\python.exe
```

该位置与插件缓存分离，插件升级或 cachebuster 变化不会隐式删除运行时。升级先创建新的 `runtime-id`，再通过原子替换清单切换；已有 Hook 进程可继续使用旧版本，避免原地覆盖 Windows 正在使用的文件。

### 2. 运行时清单

`PLUGIN_DATA\runtime.json` 是 Windows launcher 热路径的唯一解释器发现 Interface。首次 setup 不假设普通终端继承了 host 的 `PLUGIN_DATA`；setup 使用下文的确定性发现规则定位该目录。初始 schema：

```json
{
  "schema_version": 1,
  "interpreter": "C:\\Profile\\.codex\\runtimes\\codex-control-plane-hooks\\versions\\<runtime-id>\\Scripts\\python.exe",
  "python_version": "3.12.x",
  "runtime_root": "C:\\Profile\\.codex\\runtimes\\codex-control-plane-hooks",
  "configured_at": "RFC-3339 UTC timestamp"
}
```

launcher 必须验证：

- `PLUGIN_DATA`、`runtime_root` 和 `interpreter` 均为绝对路径；
- `schema_version` 受支持；
- `runtime_root` 等于通过 Windows 用户 profile API 取得的固定位置，不信任可任意改写的 `%USERPROFILE%` 文本；
- `interpreter` 精确匹配该 root 下 `versions\<safe-runtime-id>\Scripts\python.exe` 的形状；
- 已观察路径不包含 symlink 或 Windows reparse point；
- 解释器存在；setup 已验证其为 Python 3.12，launcher 用单个子进程完成版本断言和 Hook 执行，不另起兼容性 probe；
- JSON 缺失、损坏、类型错误或路径漂移时失败，不回退系统 Python。

`runtime.json` 原子写入。它不保存凭据、环境变量快照或用户命令。

### 3. 显式安装 Module

新增 `plugins/codex-control-plane-hooks/scripts/setup_runtime.ps1`。最小 Interface 为：

```powershell
./setup_runtime.ps1 `
  -PythonPath C:\absolute\path\to\python.exe
```

约束：

- `-PythonPath` 必须是绝对路径，并精确验证为 Python 3.12；
- plugin-data 按确定性优先级选择：显式绝对 `-PluginDataPath`；否则当前进程中绝对的 `PLUGIN_DATA`；否则在显式 `-CodexHome` 或 Windows 用户 profile API 得到的默认 Codex home 下搜索；
- Codex home 发现规则与 host smoke 等价：只接受 `plugins\data` 下名称等于插件名或以插件名加连字符开头的目录，并且候选必须恰好一个；零个或多个候选均失败并只输出候选数量和安全诊断；
- 显式路径和自动发现路径都必须通过绝对路径、目录、固定父目录与 reparse point 检查；
- 不自动安装 Python，不在多个命令之间静默 fallback；
- 在固定 runtime root 的新版本目录中创建专用 venv；
- 完成创建和 smoke 后，以原子清单切换发布新 runtime；默认永不删除旧 runtime；
- 旧 runtime 只能通过显式 `-PruneOldRuntime` 清理，默认 `-Keep 2`，且永不删除清单当前指向的版本；清理前检查候选解释器是否仍有活跃进程，无法可靠检查或删除时跳过该候选并报告，不把清理失败转化为新 runtime 发布失败；
- 成功验证后才原子更新 `PLUGIN_DATA\runtime.json`；
- 重跑是幂等的；失败保留上一个可用 runtime 和清晰 stderr；
- 不安装第三方运行时依赖，当前 Hook 继续只用标准库。

开发环境与 App runtime 分离。实施和测试使用主工作树 Python 3.12 的 `.venv` 软链接，绝不直接调用系统级 Python。

### 4. 瘦 Windows launcher

`run_control_plane_hook.ps1` 只承担以下职责：

1. 严格读取并验证 `PLUGIN_DATA\runtime.json`；
2. 用固定解释器的 `-I -S` 模式在单个子进程中断言 Python 3.12 并启动已打包 Hook；
3. 原样转发 stdin/stdout/stderr；
4. 保留子进程退出码。

删除热路径中的 `where.exe`、Python Launcher 探测、候选循环和探测进程树管理。`.cmd` compatibility shim 保留，但插件 manifest 继续直接使用 PowerShell launcher。

建议退出码：

- `127`：runtime 尚未配置；
- `126`：runtime 清单或解释器不可信/不可执行；
- 其他：保留 Hook 子进程退出码。

stdout 必须继续只包含 Hook JSON；诊断写 stderr。

### 5. 可观测性取舍

- setup 与 launcher 只输出有界、脱敏的 stderr 诊断和退出码；不得记录用户路径、命令、环境快照或 payload。
- 本地 Hook 没有稳定的指标或 tracing sink，本提案不新增网络遥测。自动化以退出码、原子清单和脱敏 smoke 记录作为可观测证据。

### 6. 安全与兼容性

- 安全模型不再信任每次触发时的 `PATH`，改为信任一次显式配置且受固定 root 约束的解释器。
- 不声称抵御已被攻陷的 Windows 用户账户、Codex 二进制、插件缓存或 runtime 目录。
- `policy.json`、session state、lock、runner request/receipt 的 schema 均不改变。
- Hook manifest 在本提案中不改变，但 launcher 内容是否参与 Codex App trust/cache identity 尚无公开契约证据；“不会触发新 trust 提示”只能作为假设，必须在 Windows 10 App 实测并记录结果。
- Windows 用户升级后必须先运行 setup；未配置时明确失败。Codex host 在 Hook 启动失败时是否 fail-open 仍属于 host 契约，文档必须继续披露。
- 核心 Python 代码继续兼容 CI 的 Python 3.9/3.12；仅 Windows App 正式 runtime 固定为 3.12。

## 改动清单

- 新增 `plugins/codex-control-plane-hooks/scripts/setup_runtime.ps1`。
- 重写 `plugins/codex-control-plane-hooks/scripts/run_control_plane_hook.ps1` 为清单驱动 launcher。
- 保留 `run_control_plane_hook.cmd` compatibility shim。
- 调整 Windows launcher 与 release-layout 测试。
- 增加 runtime setup/损坏清单/路径漂移/reparse point/退出码测试。
- 更新 README、configuration、hook-contract、CONTRIBUTING 和 Windows smoke 文档。
- 更新 `CHANGELOG.md` 与 README 中的 Windows 兼容性矩阵，明确 setup 前置条件、Python 3.12 runtime 和回滚边界。
- CI 的 Windows 单测继续覆盖 PowerShell 5.1 与 PowerShell 7；新增 runtime bootstrap fixture。

## TDD 实施顺序

- [ ] 建立/链接主工作树 Python 3.12 `.venv`，记录版本证据。
- [ ] 先写缺失和损坏 `runtime.json` 均不 fallback 的失败测试。
- [ ] 先写解释器越出固定 root、错误版本、reparse point 被拒绝的失败测试。
- [ ] 先写 setup 幂等、原子替换、失败保留旧 runtime 的测试。
- [ ] 先写 plugin-data 唯一候选、零候选、多候选和显式 override 的失败/成功测试。
- [ ] 先写默认不清理、显式 prune 保留数量、当前版本保护和活跃进程保护测试。
- [ ] 实现 `setup_runtime.ps1` 的最小可用版本。
- [ ] 将 launcher 改为只读 `runtime.json`，让测试转绿。
- [ ] 删除已失效的 PATH probe 测试，替换为新 Interface 的行为测试。
- [ ] 运行全部新旧单测、manifest smoke、release checker、Ruff 和插件 validator。
- [ ] 在 Windows 10 Codex Desktop 完成手动 Happy Path。
- [ ] 更新文档并创建 PR；PR 合并后再启动事件入口提案。

## 验收标准

自动化：

- 仓库中 Windows Hook 热路径不再包含 `where.exe`、`py.exe` 或 `python.exe` 候选发现逻辑。
- runtime 未配置、清单损坏、路径漂移和 Python 非 3.12 时均不会执行系统 Python。
- setup 重跑不会破坏可用 runtime，失败不会发布半成品清单。
- 普通 Windows 终端无需预先拥有 `PLUGIN_DATA` 即可在唯一候选场景完成 setup；零候选或多候选绝不猜测。
- 没有显式 prune 时旧 runtime 保持不变；显式 prune 仍保护当前版本、保留数量和活跃进程。
- Windows PowerShell 5.1、PowerShell 7、Python 3.9/3.12 的适用 CI 全部通过。
- 插件结构校验、release boundary 和现有协议测试通过。

Windows 10 Codex Desktop 手动验收：

- 用显式 Python 3.12 路径创建 runtime；
- 通过已配置的本地 marketplace 安装/重装插件；
- 在新 Codex 任务中触发安全命令与拒绝路径，确认 JSON/退出码正确；
- 重启 App 后 runtime 仍稳定，不受 App 启动时 `PATH` 差异影响；
- 记录 App 版本、PowerShell 版本、Python 版本、信任提示和缓存刷新结果，不提交个人路径或敏感配置。

## 备选方案与取舍

1. **继续优化每次 PATH probe**：改动小，但无法消除启动成本和环境漂移，拒绝。
2. **把 Python 打包进插件**：运行最稳定，但显著增加发布体积、补丁责任和供应链面，当前阶段拒绝。
3. **Hook 缺 runtime 时 fallback 系统 Python**：迁移平滑，但正式模式又回到不确定解释器，拒绝。
4. **首次 Hook 自动创建 venv**：用户体验简单，但把写入、安装和超时风险放进安全关键热路径，拒绝。

## 风险与回滚

- 最大兼容性风险是已有用户未先执行 setup。通过明确的 `127`、安装文档和升级说明处理。
- 最大安全风险是 `runtime.json` 被改写为任意可执行文件。通过固定 root、精确相对位置和 reparse 检查缩小风险。
- Python venv 仍依赖创建它的 Python 3.12 基础安装；本提案提供稳定选择与隔离，不声称提供完全自包含的 Python 分发。
- 回滚只恢复旧 launcher；不自动删除 runtime 或 `runtime.json`，避免破坏用户环境。旧 launcher 不读取该文件。

## 批准门

批准本提案后才实施 runtime 隔离。实施中若需要改变 runtime root、清单 schema、Python 版本或 fallback 策略，先更新本提案并重新审核。
