from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "smoke_codex_host.py"
SPEC = importlib.util.spec_from_file_location("smoke_codex_host", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
HOST_SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST_SMOKE)


class HostSmokeTests(unittest.TestCase):
    def test_only_explicit_pretool_hook_denial_satisfies_dangerous_gate(self) -> None:
        hook_output = (
            "Command blocked by PreToolUse hook: "
            "Command requires explicit approval: git_non_read_only."
        )
        self.assertTrue(HOST_SMOKE.is_pretool_hook_denial(hook_output))
        self.assertFalse(HOST_SMOKE.is_pretool_hook_denial("rejected: blocked by policy"))
        self.assertFalse(HOST_SMOKE.is_pretool_hook_denial("Permission denied"))

    def test_host_smoke_prepares_the_selector_derived_plugin_data_directory(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory)
            legacy = codex_home / "plugins" / "data" / "codex-control-plane-hooks"
            legacy.mkdir(parents=True)
            (legacy / "runtime.json").write_text("legacy", encoding="utf-8")

            actual = HOST_SMOKE.installed_plugin_data(codex_home)

            self.assertEqual(
                codex_home
                / "plugins"
                / "data"
                / "codex-control-plane-hooks-codex-control-plane-hooks",
                actual,
            )
            self.assertTrue(actual.is_dir())
            self.assertEqual("legacy", (legacy / "runtime.json").read_text(encoding="utf-8"))

    def test_dangerous_probe_bypasses_native_sandbox_so_hook_is_observable(self) -> None:
        self.assertEqual("read-only", HOST_SMOKE.runtime_case_sandbox("safe"))
        self.assertEqual("danger-full-access", HOST_SMOKE.runtime_case_sandbox("dangerous"))


if __name__ == "__main__":
    unittest.main()
