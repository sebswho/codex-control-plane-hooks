# Test ownership

`docs/hook-contract.md` is the single source of truth for Hook behavior. This file assigns regression ownership only; it must not restate protocol semantics.

| Contract surface | Owning test module |
|---|---|
| Response JSON, entrypoint/bootstrap isolation, event deadline, event-local cache, and policy/data-directory snapshot lifecycle | `test_core_protocol.py` |
| Policy path resolution, validation, defaults, and immutable policy views | `test_policy_store.py` |
| State serialization, schema compatibility, locking, atomic replacement, runner leases, and detached cleanup artifacts | `test_state_store.py` |
| Ticket/reservation/claim/receipt behavior and end-to-end policy/tool/lifecycle integration | `test_control_plane_hook.py` |
| Windows runtime setup, runtime manifest publication, and runtime pruning | `test_setup_runtime.py` |
| Public Windows launcher behavior and façade exit-code compatibility | `test_control_plane_hook.py` until the façade/launcher extraction ticket moves that boundary |
| Release candidate layout, manifest coverage, CI gates, and release checker behavior | `test_release_layout.py` |
| Read-only Codex App canary inventory, App-bundled `hooks/list`, provenance, runtime, artifact hashes, and evidence redaction | `test_capture_codex_app_canary.py` |
| Clean-profile host-smoke interpretation, including explicit Hook denial versus native policy denial | `test_smoke_codex_host.py` |
| Dedicated `UserPromptSubmit` entrypoint equivalence | `test_user_prompt_entrypoint.py` |

Shared protocol fixtures live in `protocol_test_fixtures.py`. They own the subprocess harness and reusable fixtures for the six-second event budget, event-cache teardown, policy/data-directory snapshots, and legacy serialized state. Focused modules should add regressions to their owning file rather than growing `test_control_plane_hook.py` unless the scenario crosses multiple contract surfaces.
