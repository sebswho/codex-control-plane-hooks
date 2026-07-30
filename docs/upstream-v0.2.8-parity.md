# Upstream v0.2.8 parity baseline

This document records the auditable baseline used by the local fork. The behavioral source of truth remains [hook-contract.md](hook-contract.md).

## Baseline and ancestry

- Upstream repository: `le-soleil-se-couche/codex-control-plane-hooks`
- Upstream release: `v0.2.8`
- Upstream baseline commit: `b6f86a49d8f2adca146d8eb99d0847b465e543d6`
- Local parity merge commit: `3b5fa54598a80d1fbed6683ff3d48b71e0146cb5`
- Merge parents: local semantic-port tip `6e6d01733e2a129fe6b31f31ebd39191b2aa8c1e` and upstream v0.2.8 baseline `b6f86a49d8f2adca146d8eb99d0847b465e543d6`

The parity merge is a real non-fast-forward merge. The upstream v0.2.8 commit is therefore an ancestor, not an `ours`-strategy placeholder. Future upstream reviews can start after v0.2.8.

## Semantic-port commits

- `d7d8141` — port v0.2.7 event hardening: one shared six-second budget, event-local Git query cache, one-event policy/data-directory snapshots, strict command/destination field scopes, protected redirection checks, and POSIX `python3 -I -S` validation.
- `6e6d017` — port v0.2.8 cleanup isolation: private `--cleanup-orphans` compatibility CLI, approved-runner-only detached cleanup, live leases, nonblocking single-flight, persisted cursor, and bounded 64/2/500 ms/1 s work.
- `d9febbe` — preserve the fork's Windows pinned-runtime lifecycle and profile-boundary lock behavior before the parity ports.

## Intentional fork differences

The following differences from the upstream v0.2.8 tree are intentional and compatible:

1. The public Hook manifest continues to route all events through `scripts/control_plane_hook.py`. The façade delegates into the local `control_plane` package instead of reverting to the upstream monolithic implementation.
2. Windows uses `PLUGIN_DATA/runtime.json` and a pinned Python 3.12 interpreter created by `scripts/setup_runtime.ps1`. It does not probe or fall back to `PATH`, `where.exe`, `py.exe`, or arbitrary Python installations.
3. Windows launcher, setup, release, smoke, and protocol tests retain the fork's existing runtime trust, path, reparse-point, process, exit-code, and compatibility checks. Upstream tests that require PATH-based interpreter fallback are intentionally not imported.
4. Existing local modularization proposals, protocol/state tests, and compatibility behavior remain present. No public configuration schema, state schema, ticket, receipt, CLI, manifest response, matcher, timeout, or status-message contract is intentionally changed by the sync.
5. CI runs the pinned-runtime Windows manifest smoke on Python 3.12 while the protocol/release matrix still covers Python 3.9 and 3.12 on Ubuntu, macOS, and Windows.

## Verification receipt

Verified on July 30, 2026 with the project main-worktree virtual environment:

- `python -m unittest discover -s tests -p 'test_*.py'`: 358 tests passed, 23 platform/fixture skips.
- PowerShell 7 and Windows PowerShell 5.1 packaged manifest smoke: passed.
- `scripts/check_release.py`: passed, 89 release files scanned.
- Ruff full-repository check: passed.
- Codex-bundled plugin validator: passed.
- `git merge-base --is-ancestor b6f86a49d8f2adca146d8eb99d0847b465e543d6 3b5fa54598a80d1fbed6683ff3d48b71e0146cb5`: passed.
