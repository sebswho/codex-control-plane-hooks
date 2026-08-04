# Codex App Canary

This checklist is the release gate for Phase 1.5 and for every later ticket that changes the plugin. It validates the exact code loaded by a real Codex App without changing the Hook event, matcher, response, policy, state, or configuration contracts.

## Invariants

- Operate only on the authorized fork, `sebswho/codex-control-plane-hooks`.
- Install exactly one marketplace named `codex-control-plane-hooks` and exactly one plugin selector, `codex-control-plane-hooks@codex-control-plane-hooks`.
- Pin every marketplace installation to a full 40-character commit SHA. Never use `main`, a feature branch, a floating tag, or unattended marketplace upgrades for a development canary.
- Keep newly introduced experimental behavior disabled unless the current ticket explicitly tests that behavior.
- Never remove `PLUGIN_DATA`, `runtime.json`, or `session-*.json` during a reinstall or rollback.
- Do not record private policy, trust, configuration, credential, state, prompt, or tool-payload contents in evidence.

The Codex CLI 0.146 command `plugin marketplace upgrade` only refreshes the currently configured snapshot. It is suitable for repairing the cache of an already pinned SHA, not for advancing the development installation to another commit. Repinning uses an explicit remove and add transaction.

## 1. Prepare an immutable candidate

Use an isolated feature worktree and the project Python 3.12 virtual environment. Complete the automated gates before installing the candidate into the App.

```powershell
$Python = '<project-root>\.venv\Scripts\python.exe'
$Codex = (Get-Command codex -ErrorAction Stop).Source
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

Record the App version from the App diagnostics or About surface. Record the bundled CLI version from a terminal launched by the App; do not try to bypass WindowsApps execution restrictions. Also record the external `codex --version`, PowerShell version, and project Python version.

## 2. Establish the single-instance baseline

```powershell
& $Codex plugin marketplace list --json
& $Codex plugin list --json
```

Stop if more than one marketplace or installed plugin is present, if the selector is ambiguous, or if an unrelated installation would be removed. The intended development steady state has one marketplace and one installed plugin. A formal and a development copy must not be active together.

Before repinning, record only hashes and file metadata for `runtime.json` and any existing `session-*.json`. Do not copy their contents into repository evidence.

## 3. Repin to the exact feature SHA

If the target selector is already installed, remove only its installed configuration and cache. Do not delete the plugin data directory.

```powershell
& $Codex plugin remove 'codex-control-plane-hooks@codex-control-plane-hooks' --json
& $Codex plugin marketplace remove 'codex-control-plane-hooks' --json
& $Codex plugin marketplace add 'sebswho/codex-control-plane-hooks' --ref $ExpectedCommit --json
& $Codex plugin add 'codex-control-plane-hooks@codex-control-plane-hooks' --json

& $Codex plugin marketplace list --json
& $Codex plugin list --json
```

If the marketplace or plugin does not already exist, omit only the corresponding remove command. Treat any source other than the authorized fork, any non-SHA ref, or any duplicate instance as a failed canary.

On Windows, prepare the dedicated Python 3.12 runtime with the plugin's `setup_runtime.ps1` procedure documented in the main README. Reuse the existing `PLUGIN_DATA`; do not create a second data directory just for an upgrade.

## 4. Trust and behavior scenarios

Review the installed `hooks.json`, PowerShell launcher, and Python façade before accepting Hook trust in the App. Do not automate or bypass the trust decision.

Run these scenarios in the real App and record only `passed`, `failed`, `not_run`, or `not_recorded`:

1. `untrusted_to_trusted`: Hook discovery is initially untrusted and becomes trusted only after explicit review.
2. `safe_allow`: a deterministic safe command is allowed.
3. `dangerous_deny`: a deterministic dangerous command is denied without executing it.
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
  --codex $Codex `
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

The collector fails closed unless the checkout is clean, `origin` is the authorized fork, both CLI marketplace-source records identify that fork, HEAD exactly matches the requested SHA, one plugin instance is enabled, the Python 3.12 runtime uses the launcher's trusted root and versioned interpreter layout, and the installed cache hashes match the checkout. On Windows it locks the trusted runtime directory chain and interpreter against replacement, rejects reparse points through the held handles, and reads the executable `FileVersionInfo`; it never executes that runtime interpreter. Codex CLI 0.146 reports the Git source but not the pinned marketplace commit, so the evidence records that limitation and proves the commit through the authorized checkout plus the four required installed-artifact SHA-256 comparisons. Evidence uses placeholders for private absolute paths, redacts sensitive fields, and rejects any remaining absolute path or credential-like value before writing the JSON file.

Do not commit a local evidence file unless it contains no private paths or operational data and the ticket explicitly calls for a sanitized fixture. A concise result summary in the fork Issue or PR is normally sufficient.

## 6. Merge-SHA repin

Create a pull request only from `sebswho:feature/...` to `sebswho:main`. After the fork PR is merged, obtain the full merge SHA and repeat the remove/add/install transaction with that SHA. Keep the development plugin installed at the merge SHA.

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
2. Remove the installed plugin selector without deleting plugin data.
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
