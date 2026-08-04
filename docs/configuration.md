# Configuration

This page covers installation and configuration inputs. The authoritative behavioral contract for events, responses, approvals, state, runner artifacts, and cleanup is [`hook-contract.md`](hook-contract.md).

## Policy location

On macOS and Linux, the Hook resolves policy in this order:

1. An absolute `CONTROL_PLANE_POLICY` path, when explicitly set.
2. `policy.json` inside the host-provided `PLUGIN_DATA` directory.

On Windows, `PLUGIN_DATA` is required and policy must remain at `PLUGIN_DATA/policy.json`. External policy paths fail closed because this dependency-free Hook cannot independently validate arbitrary NTFS DACLs. If the default policy does not exist, organization-specific detection and all natural-language approvals remain disabled.

## Windows 运行时准备

Windows 启动器只使用 `scripts/setup_runtime.ps1` 创建的 `PLUGIN_DATA/runtime.json`。准备脚本要求 Python 3.12 解释器的绝对路径，而且不会下载 Python：

```powershell
.\scripts\setup_runtime.ps1 -PythonPath "C:\absolute\path\to\python.exe"
```

该仓库根级脚本只转发到插件发布目录中的规范实现，避免维护两份安全敏感的 runtime setup 逻辑。安装插件后，仍使用插件目录内的 `scripts/setup_runtime.ps1`。

插件数据目录按以下顺序选择：绝对 `-PluginDataPath`、宿主提供的绝对 `PLUGIN_DATA`，最后是在绝对 `-CodexHome` 或 Windows 用户 Profile 默认 `.codex` 目录下的唯一插件候选。位于 `plugins\data` 之外的路径、相对路径、零个或多个候选以及观察到的 reparse point 都会关闭失败。

Codex CLI 0.146 为 selector `codex-control-plane-hooks@codex-control-plane-hooks` 提供的活动目录名是 `codex-control-plane-hooks-codex-control-plane-hooks`。安装或重钉 SHA 时应显式创建该目录，并将其作为 `-PluginDataPath`；无后缀 `codex-control-plane-hooks` 目录仅作为保留的 legacy 数据，不能代替活动目录，也不得在未设计 copy-only 迁移前删除或覆盖。

运行时版本位于 `%USERPROFILE%\.codex\runtimes\codex-control-plane-hooks\versions`。脚本先创建并冒烟验证 staging venv，再原子发布 `runtime.json`；失败不会破坏原有清单。重复执行是幂等的。默认保留旧版本；`-PruneOldRuntime -Keep N` 要求 `N >= 2`，保护当前版本，并跳过正在使用或无法检查的候选。venv 依赖基础 Python 3.12 安装，不是自包含发行版。

启动器不读取 `PATH`，也不调用 `where.exe`、`py.exe` 或其他 Python 发现机制。它严格校验清单 schema、UTF-8、字段、Windows Profile API 返回的固定根目录、解释器布局和 reparse point，并在一个 `python.exe -I -S -c` 子进程中验证 Python 3.12 后执行 Hook。缺少 `PLUGIN_DATA` 或 `runtime.json` 返回 `127`；其余配置、信任、启动或版本错误返回 `126`；Hook 自身退出码原样返回。

Directory and policy resolution are stable for one dispatched event and are refreshed for the next event. See [Failure behavior](hook-contract.md#failure-behavior) for the authoritative snapshot and teardown contract.

## Policy fields

| Field | Type | Default | Meaning |
|---|---|---|---|
| `sensitive_markers` | list of strings | `[]` | Organization or project markers required for sensitive context. |
| `sensitive_terms` | list of strings | `[]` | Data-class terms used for concrete-value checks. |
| `durable_destination_markers` | list of strings | `[]` | Private local path or workflow markers that should count as durable destinations. |
| `enable_natural_language_approvals` | boolean | `false` | Enables experimental one-shot command and local Git approval parsing. |
| `enable_scoped_git_transactions` | boolean | `false` | Enables experimental, explicitly mapped, one-shot Git/GitHub transaction grants. Requires natural-language approvals. |
| `enable_constrained_github_clone` | boolean | `false` | Enables the experimental constrained GitHub HTTPS clone lane and post-clone provenance gate. |
| `enable_sensitive_disclosure_approvals` | boolean | `false` | Enables experimental one-shot disclosure grants. |

The policy file is capped at 64 KiB. Each string list is capped at 100 entries. A present policy that is malformed, oversized, symlinked, reparse-point, non-regular, or POSIX-owned by another user causes the current Hook event to fail closed. An explicitly configured POSIX policy also fails closed when any group or other permission bit is set; use mode `0600` or a stricter owner-only mode. A missing default policy keeps private detection, natural-language approvals, scoped transactions, constrained clone, and disclosure approvals disabled; a missing explicitly configured POSIX policy fails closed. Boolean options activate only for the JSON value `true`.

The experimental approval flags are independent opt-ins. Scoped transactions also require natural-language approvals; constrained clone and sensitive-disclosure approvals remain separately gated. Exact command binding, cross-turn continuation, ticket/receipt handling, Windows runner shell restrictions, clone provenance, disclosure matching, and local-redaction behavior are defined in [Approval binding](hook-contract.md#approval-binding) and [Local redaction](hook-contract.md#local-redaction). Add installation-specific durable path or workflow markers to the private policy instead of hard-coding them in public source.

## Private release-boundary markers

`scripts/check_release.py` always applies generic path and credential checks. On macOS or Linux, add installation-specific literal checks with a repository-external UTF-8 file containing one marker per line:

```bash
chmod 600 /absolute/path/outside/repository/private-patterns
python3 scripts/check_release.py \
  --private-patterns-file /absolute/path/outside/repository/private-patterns
```

Blank lines and lines beginning with `#` are ignored. The file must be a current-user-owned regular file, no larger than 64 KiB, with no group or other permissions. `RELEASE_PRIVATE_PATTERNS_FILE` is also supported for controlled POSIX CI environments. Findings identify the private rule by number and never print its value. Windows rejects this optional input because owner and DACL validation would otherwise be incomplete.

For Python source, an assignment-like credential match is suppressed only when AST parsing proves that a lowercase credential-shaped target receives a call expression with no string or bytes literal of 16 or more characters. Quoted assignments, ambiguous or malformed source, non-Python files, and every provider-specific credential pattern remain findings.

## State

The host-provided plugin-data directory is preferred. On macOS and Linux, the fallback is:

- `$XDG_STATE_HOME/codex-control-plane-hooks`, or
- `~/.local/state/codex-control-plane-hooks`.

Windows requires an absolute host-provided `PLUGIN_DATA` path. The Hook rejects observed symlinks and Windows reparse points. On POSIX it checks ownership and enforces mode `0700` for the directory and `0600` for files. Windows relies on the host directory's inherited DACL and does not independently audit every ACE. Session identifiers are hashed before they become filenames.

State uses a private schema-4 store with bounded cross-process locking, rolling compatibility for supported older schemas, and fail-closed validation. Runner tickets, receipts, leases, isolated push repositories, and detached cleanup are private artifacts governed by the same contract. See [Failure behavior](hook-contract.md#failure-behavior) and [Approval binding](hook-contract.md#approval-binding) for the authoritative lifecycle, deadline, compatibility, and cleanup rules.

## Config and Rules examples

`examples/config.toml`, `examples/AGENTS.md.example`, and `examples/rules/default.rules` are inert references. Merge only fields you understand. A broad Rules allowlist can weaken the approval boundary when the Hook is disabled, untrusted, timed out, or incompatible.
