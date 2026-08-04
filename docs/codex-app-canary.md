# Codex App Canary

This checklist is the release gate for Phase 1.5 and for every later ticket that changes the plugin. Phase 1.5 validates the exact code and selector-derived data directory loaded by a real Codex App without changing Hook events, matchers, payloads, responses, policy/state/configuration schemas, approval semantics, or experimental defaults.

## Invariants

- Operate only on the authorized fork, `sebswho/codex-control-plane-hooks`.
- Install exactly one target marketplace named `codex-control-plane-hooks` and exactly one target plugin selector, `codex-control-plane-hooks@codex-control-plane-hooks`. Unrelated App-managed marketplaces such as `openai-api-curated` do not count as a second target instance.
- Pin every marketplace installation to a full 40-character commit SHA. Never use `main`, a feature branch, a floating tag, or unattended marketplace upgrades for a development canary.
- Keep newly introduced experimental behavior disabled unless the current ticket explicitly tests that behavior.
- For selector `codex-control-plane-hooks@codex-control-plane-hooks`, the active Windows data directory is `%CODEX_HOME%\plugins\data\codex-control-plane-hooks-codex-control-plane-hooks`. Never substitute the legacy unsuffixed directory.
- Never remove an active or legacy plugin data directory, `runtime.json`, or `session-*.json` during a reinstall or rollback.
- Do not record private policy, trust, configuration, credential, state, prompt, or tool-payload contents in evidence.

The Codex CLI 0.146 command `plugin marketplace upgrade` only refreshes the currently configured snapshot. It is suitable for repairing the cache of an already pinned SHA, not for advancing the development installation to another commit. Repinning uses an explicit remove and add transaction.

## 1. Prepare an immutable candidate

Use an isolated feature worktree and the project Python 3.12 virtual environment. Complete the automated gates before installing the candidate into the App.

```powershell
$Python = '<project-root>\.venv\Scripts\python.exe'
$AppCodex = '<absolute-path-to-the-accessible-App-bundled-codex.exe>'
$ExternalCodex = (Get-Command codex -ErrorAction Stop).Source
$ExpectedCheckout = '<feature-worktree>'
$ExpectedCommit = git -C $ExpectedCheckout rev-parse HEAD

if ($ExpectedCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'Expected a full commit SHA'
}
if (git -C $ExpectedCheckout status --porcelain) {
    throw 'The canary checkout must be clean'
}
if ((git -C $ExpectedCheckout remote get-url origin) -notmatch 'sebswho/codex-control-plane-hooks(?:\.git)?$') {
    throw 'The canary checkout is not attached to the authorized fork'
}
```

Record the App version from the App diagnostics or About surface. Resolve an accessible App-bundled CLI copy from the App diagnostics/plugin app-server environment; do not try to bypass WindowsApps execution restrictions. Verify `& $AppCodex --version` and `& $ExternalCodex --version` separately. The collector uses `$AppCodex` for App inventory and `hooks/list`, and discovers the external CLI from `PATH` only for a version cross-check.

## 2. Establish the single-instance baseline

```powershell
& $AppCodex plugin marketplace list --json
& $AppCodex plugin list --json
```

Stop if more than one marketplace named `codex-control-plane-hooks` or more than one installed `codex-control-plane-hooks` plugin is present, if the selector is ambiguous, or if an unrelated installation would be removed. Record unrelated App-managed marketplaces/plugins, but do not remove them and do not count them as a duplicate target instance. The intended development steady state has one target marketplace and one target plugin. A formal and a development copy must not be active together.

Before repinning, identify both the selector-derived active directory and any preserved legacy directory. Record only counts, hashes, and file metadata for `runtime.json` and existing `session-*.json`; do not copy their contents into repository evidence.

```powershell
$CodexHome = Join-Path $env:USERPROFILE '.codex'
$ActivePluginData = Join-Path $CodexHome 'plugins\data\codex-control-plane-hooks-codex-control-plane-hooks'
$LegacyPluginData = Join-Path $CodexHome 'plugins\data\codex-control-plane-hooks'
```

Codex CLI 0.146 passes the selector-derived suffixed path to the active Hook. An unsuffixed directory can remain as an inactive backup, but a `runtime.json` stored only there does not configure the active launcher. If a legacy directory contains `session-*.json`, policy, or other operational state, stop the live canary and design a copy-only migration in an isolated `CODEX_HOME` before proceeding. Do not delete or overwrite the legacy directory.

## 3. Repin to the exact feature SHA with the App closed

Codex App keeps an in-memory configuration snapshot and can atomically rewrite `config.toml`. A plugin installed by an external process while the App is running can therefore disappear from the next App snapshot. Fully exit the App before any remove/add operation, and confirm no Codex App process remains. Do not forcibly terminate it while a task is writing state.

```powershell
if (Get-Process -Name Codex -ErrorAction SilentlyContinue) {
    throw 'Fully exit Codex App before changing marketplace/plugin registration'
}
```

If the target selector is already installed, remove only its installed configuration and cache. Do not delete the plugin data directory. Use the App-bundled CLI for the entire registration transaction so the exact host being tested owns the resulting inventory.

```powershell
& $AppCodex plugin remove 'codex-control-plane-hooks@codex-control-plane-hooks' --json
& $AppCodex plugin marketplace remove 'codex-control-plane-hooks' --json
& $AppCodex plugin marketplace add 'sebswho/codex-control-plane-hooks' --ref $ExpectedCommit --json
& $AppCodex plugin add 'codex-control-plane-hooks@codex-control-plane-hooks' --json

& $AppCodex plugin marketplace list --json
& $AppCodex plugin list --json
```

If the marketplace or plugin does not already exist, omit only the corresponding remove command. Treat any source other than the authorized fork, any non-SHA ref, or any duplicate instance as a failed canary.

On Windows, create the selector-derived active directory explicitly and pass it to the runtime setup script. This is not a second active plugin instance; it is the data directory Codex 0.146 supplies for the single installed selector. Keep any unsuffixed legacy directory untouched.

```powershell
New-Item -ItemType Directory -Force -Path $ActivePluginData | Out-Null
& (Join-Path $ExpectedCheckout 'scripts\setup_runtime.ps1') `
  -PythonPath $Python `
  -PluginDataPath $ActivePluginData
```

Verify that `$ActivePluginData\runtime.json` now exists. A launcher error, missing/invalid runtime manifest, native sandbox rejection, or filesystem permission failure is not a Hook deny and fails the canary.

## 4. Trust and behavior scenarios

Reopen the App only after the closed-App inventory and active `runtime.json` are correct. Review the installed `hooks.json`, PowerShell launcher, and Python façade, then verify the App reports the target Hook as enabled and trusted. Do not automate, bypass, or infer the trust decision from a shell exit code.

Run these scenarios in the real App and record only `passed`, `failed`, `not_run`, or `not_recorded`:

1. `untrusted_to_trusted`: Hook discovery is initially untrusted and becomes trusted only after explicit review.
2. `safe_allow`: a deterministic safe command is allowed.
3. `dangerous_deny`: a deterministic dangerous command is denied before shell entry with an explicit `Command blocked by PreToolUse hook:` result containing `git_non_read_only`. Native `rejected: blocked by policy`, filesystem permission errors, sandbox failures, or a nonzero shell exit do not satisfy this scenario.
4. `cross_turn_resume`: a bounded publication transaction resumes in another turn without broadening its grant.
5. `new_task_same_sha`: a new task loads the same installed artifacts.
6. `app_restart_same_sha`: an App restart loads the same installed artifacts.
7. `same_sha_reinstall_state_preserved`: reinstalling the same SHA preserves `runtime.json` and state metadata.
8. `experiments_default_off`: no experimental behavior is active unless the ticket explicitly opted in.

The single-instance assertion also requires that one App event produces no duplicate Hook decision or duplicate state transition.

## 5. Capture sanitized feature evidence

After all feature scenarios pass, run the read-only collector. It does not install plugins, change trust, or read private configuration/state contents.

```powershell
& $Python -B scripts\capture_codex_app_canary.py `
  --codex $AppCodex `
  --expected-checkout $ExpectedCheckout `
  --expected-commit $ExpectedCommit `
  --marketplace 'codex-control-plane-hooks' `
  --plugin 'codex-control-plane-hooks' `
  --output '<evidence-directory>\feature-canary.json' `
  --phase feature `
  --app-version '<app-version>' `
  --bundled-cli-version '<bundled-cli-version>' `
  --scenario untrusted_to_trusted=passed `
  --scenario safe_allow=passed `
  --scenario dangerous_deny=passed `
  --scenario cross_turn_resume=passed `
  --scenario new_task_same_sha=passed `
  --scenario app_restart_same_sha=passed `
  --scenario same_sha_reinstall_state_preserved=passed `
  --scenario experiments_default_off=passed
```

The collector fails closed unless the checkout is clean, `origin` is the authorized fork, the App-bundled CLI marketplace/plugin inventory identifies that fork, App-bundled `hooks/list` exposes the exact expected target event counts with every target Hook enabled and trusted, HEAD exactly matches the requested SHA, one plugin instance is enabled, the Python 3.12 runtime uses the launcher's trusted root and versioned interpreter layout, and the installed cache hashes match the checkout. On Windows it locks the trusted runtime directory chain and interpreter against replacement, rejects reparse points through the held handles, and reads the executable `FileVersionInfo`; it never executes that runtime interpreter. Codex CLI 0.146 reports the Git source but not the pinned marketplace commit, so the evidence records that limitation and proves the commit through the authorized checkout plus the four required installed-artifact SHA-256 comparisons. Evidence also records path-free metadata for the active selector-derived data directory and any preserved legacy candidates (counts plus runtime/state-file presence only). It uses placeholders for private absolute paths, redacts sensitive fields, and rejects any remaining absolute path or credential-like value before writing the JSON file.

Do not commit a local evidence file unless it contains no private paths or operational data and the ticket explicitly calls for a sanitized fixture. A concise result summary in the fork Issue or PR is normally sufficient.

## 6. Merge-SHA repin

Create a pull request only from `sebswho:feature/...` to `sebswho:main`. A ready PR remains forbidden if App-bundled `hooks/list` is empty, the target Hooks are untrusted, or the dangerous case is blocked only by native policy/sandbox behavior. After the fork PR is merged, obtain the full merge SHA and repeat the remove/add/install transaction with that SHA. Keep the development plugin installed at the merge SHA.

The merged-phase minimum scenarios are:

- `safe_allow=passed`
- `dangerous_deny=passed`
- `new_task_same_sha=passed`
- `app_restart_same_sha=passed`
- `experiments_default_off=passed`
- `merge_sha_repin=passed`

Capture a second evidence file with `--phase merged`. Update the README compatibility table and close the Phase 1.5 Issue only after this merged evidence is ready.

## 7. Failure and rollback

On any App canary failure:

1. Stop opening new tasks that could exercise the failed installation.
2. Remove the installed plugin selector without deleting either the active selector-derived data directory or any legacy data directory.
3. Recreate the marketplace at the last known-good full SHA if provenance is ambiguous.
4. Reinstall the selector and re-run installed-artifact hashes, `safe_allow`, and `dangerous_deny`.
5. If plugin removal changed or removed `runtime.json` or state metadata, stop the live canary and reproduce the behavior in an isolated `CODEX_HOME` before changing the design.

## Later-ticket gate

Every later ticket starts from the most recent merge SHA that passed this real-App canary. The required flow is:

1. isolated worktree;
2. TDD and automated gates;
3. feature-SHA App delta canary;
4. fork-only pull request;
5. merge-SHA repin and minimum App canary.

A behavior-parity refactor does not need an artificial feature flag. New or unstable behavior must be opt-in, default off, reversible, backward-compatible, and explicitly represented in the canary evidence.
