from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from protocol_test_fixtures import HookProtocolTestCase

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "codex-control-plane-hooks" / "scripts"
PACKAGE = SCRIPTS / "control_plane"


class CoreProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.packaged_scripts = self.root / "plugin" / "scripts"
        self.packaged_scripts.mkdir(parents=True)
        shutil.copytree(PACKAGE, self.packaged_scripts / "control_plane")

    def make_entrypoint(self) -> Path:
        entrypoint = self.packaged_scripts / "control_plane" / "entrypoints" / "probe.py"
        entrypoint.write_text(
            """from pathlib import Path
import runpy

bootstrap_path = Path(__file__).parent.parent / "bootstrap.py"
configure_package = runpy.run_path(str(bootstrap_path))["configure_package"]
configure_package(__file__)

from control_plane.protocol import run_hook


def handler(event):
    return {"systemMessage": "trusted package"}


raise SystemExit(run_hook("UserPromptSubmit", handler))
""",
            encoding="utf-8",
        )
        return entrypoint

    def make_recording_entrypoint(self, expected_event: str) -> Path:
        entrypoint = (
            self.packaged_scripts / "control_plane" / "entrypoints" / "record.py"
        )
        entrypoint.write_text(
            f"""from pathlib import Path
import os
import runpy

bootstrap_path = Path(__file__).parent.parent / "bootstrap.py"
configure_package = runpy.run_path(str(bootstrap_path))["configure_package"]
configure_package(__file__)

from control_plane.protocol import run_hook


def handler(event):
    Path(os.environ["HANDLER_MARKER"]).write_text("called", encoding="utf-8")
    return {{"systemMessage": "handler called"}}


raise SystemExit(run_hook({expected_event!r}, handler))
""",
            encoding="utf-8",
        )
        return entrypoint

    def test_isolated_entrypoint_ignores_poisoned_cwd_and_pythonpath(self) -> None:
        entrypoint = self.make_entrypoint()
        poisoned = self.root / "poisoned"
        poisoned_package = poisoned / "control_plane"
        poisoned_package.mkdir(parents=True)
        (poisoned_package / "__init__.py").write_text(
            "raise RuntimeError('poisoned package imported')\n",
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(poisoned)
        payload = json.dumps(
            {"hook_event_name": "UserPromptSubmit", "prompt": "hello"}
        )

        completed = subprocess.run(
            [sys.executable, "-I", "-S", str(entrypoint)],
            cwd=poisoned,
            env=environment,
            input=payload,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("", completed.stderr)
        self.assertEqual(
            '{"systemMessage":"trusted package"}\n',
            completed.stdout,
        )

    @unittest.skipUnless(os.name == "nt", "PowerShell package smoke is Windows-only")
    def test_powershell_5_and_7_preserve_the_package_protocol(self) -> None:
        entrypoint = self.make_entrypoint()
        wrapper = self.root / "run-package-smoke.ps1"
        wrapper.write_text(
            """param(
    [Parameter(Mandatory = $true)][string]$PythonPath,
    [Parameter(Mandatory = $true)][string]$EntrypointPath
)

& $PythonPath -I -S $EntrypointPath
exit $LASTEXITCODE
""",
            encoding="utf-8",
        )
        payload = b'{"hook_event_name":"UserPromptSubmit"}'

        for executable in ("powershell.exe", "pwsh.exe"):
            with self.subTest(executable=executable):
                shell = shutil.which(executable)
                self.assertIsNotNone(shell, f"required shell is unavailable: {executable}")
                completed = subprocess.run(
                    [
                        shell,
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(wrapper),
                        "-PythonPath",
                        sys.executable,
                        "-EntrypointPath",
                        str(entrypoint),
                    ],
                    cwd=self.root,
                    input=payload,
                    capture_output=True,
                    check=False,
                )

                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertEqual(b"", completed.stderr)
                self.assertEqual(
                    b'{"systemMessage":"trusted package"}\n', completed.stdout
                )

    def test_legacy_entrypoint_can_bootstrap_the_sibling_package(self) -> None:
        entrypoint = self.packaged_scripts / "control_plane_hook.py"
        entrypoint.write_text(
            """from pathlib import Path
import runpy

bootstrap_path = Path(__file__).parent / "control_plane" / "bootstrap.py"
configure_package = runpy.run_path(str(bootstrap_path))["configure_package"]
configure_package(__file__)

from control_plane.policy import PolicyView

print(PolicyView().enable_scoped_git_transactions)
""",
            encoding="utf-8",
        )

        completed = subprocess.run(
            [sys.executable, "-I", "-S", str(entrypoint)],
            cwd=self.root,
            capture_output=True,
            check=False,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(b"False\n", completed.stdout.replace(b"\r\n", b"\n"))
        self.assertEqual(b"", completed.stderr)

    def test_unknown_expected_event_is_blocked_without_calling_handler(self) -> None:
        entrypoint = self.make_recording_entrypoint("UnexpectedEvent")
        marker = self.root / "handler-called"
        environment = os.environ.copy()
        environment["HANDLER_MARKER"] = str(marker)

        completed = subprocess.run(
            [sys.executable, "-I", "-S", str(entrypoint)],
            cwd=self.root,
            env=environment,
            input=b'{"hook_event_name":"UnexpectedEvent"}',
            capture_output=True,
            check=False,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(b"", completed.stderr)
        self.assertEqual(
            b'{"decision":"block","reason":"Control-plane internal validation '
            b'failed; the action is blocked."}\n',
            completed.stdout,
        )
        self.assertFalse(marker.exists())

    def test_malformed_input_is_blocked_without_calling_handler(self) -> None:
        entrypoint = self.make_recording_entrypoint("UserPromptSubmit")
        malformed_payloads = {
            "invalid UTF-8": b"\xff",
            "truncated JSON": b'{"hook_event_name":',
            "non-standard JSON constant": (
                b'{"hook_event_name":"UserPromptSubmit","value":NaN}'
            ),
            "duplicate object key": (
                b'{"hook_event_name":"PostToolUse",'
                b'"hook_event_name":"UserPromptSubmit"}'
            ),
            "excessive nesting": b"[" * 2000 + b"0" + b"]" * 2000,
        }

        for label, payload in malformed_payloads.items():
            with self.subTest(label=label):
                marker = self.root / f"handler-called-{label.replace(' ', '-')}"
                environment = os.environ.copy()
                environment["HANDLER_MARKER"] = str(marker)

                completed = subprocess.run(
                    [sys.executable, "-I", "-S", str(entrypoint)],
                    cwd=self.root,
                    env=environment,
                    input=payload,
                    capture_output=True,
                    check=False,
                )

                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertEqual(b"", completed.stderr)
                self.assertEqual(
                    b'{"decision":"block","reason":"Control-plane input could '
                    b'not be parsed; the action is blocked."}\n',
                    completed.stdout,
                )
                self.assertFalse(marker.exists())

    def test_unserializable_handler_output_is_mapped_to_internal_block(self) -> None:
        invalid_responses = {
            "unsupported type": '{"invalid": {"not", "JSON"}}',
            "non-standard number": '{"invalid": float("nan")}',
        }

        for index, (label, response_source) in enumerate(invalid_responses.items()):
            with self.subTest(label=label):
                entrypoint = (
                    self.packaged_scripts
                    / "control_plane"
                    / "entrypoints"
                    / f"invalid_{index}.py"
                )
                entrypoint.write_text(
                    f"""from pathlib import Path
import runpy

bootstrap_path = Path(__file__).parent.parent / "bootstrap.py"
configure_package = runpy.run_path(str(bootstrap_path))["configure_package"]
configure_package(__file__)

from control_plane.protocol import run_hook


def handler(event):
    return {response_source}


raise SystemExit(run_hook("UserPromptSubmit", handler))
""",
                    encoding="utf-8",
                )

                completed = subprocess.run(
                    [sys.executable, "-I", "-S", str(entrypoint)],
                    cwd=self.root,
                    input=b'{"hook_event_name":"UserPromptSubmit"}',
                    capture_output=True,
                    check=False,
                )

                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertEqual(b"", completed.stderr)
                self.assertEqual(
                    b'{"decision":"block","reason":"Control-plane internal '
                    b'validation failed; the action is blocked."}\n',
                    completed.stdout,
                )

    def test_mismatched_event_is_blocked_without_calling_handler(self) -> None:
        entrypoint = self.make_recording_entrypoint("UserPromptSubmit")
        marker = self.root / "handler-called-on-mismatch"
        environment = os.environ.copy()
        environment["HANDLER_MARKER"] = str(marker)

        completed = subprocess.run(
            [sys.executable, "-I", "-S", str(entrypoint)],
            cwd=self.root,
            env=environment,
            input=b'{"hook_event_name":"PostToolUse"}',
            capture_output=True,
            check=False,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(b"", completed.stderr)
        self.assertEqual(
            b'{"decision":"block","reason":"Control-plane internal validation '
            b'failed; the action is blocked."}\n',
            completed.stdout,
        )
        self.assertFalse(marker.exists())

    def test_parse_failures_preserve_the_legacy_generic_block_shape(self) -> None:
        for event_name in ("PreToolUse", "PermissionRequest"):
            with self.subTest(event_name=event_name):
                entrypoint = self.make_recording_entrypoint(event_name)
                marker = self.root / f"handler-called-{event_name}"
                environment = os.environ.copy()
                environment["HANDLER_MARKER"] = str(marker)

                completed = subprocess.run(
                    [sys.executable, "-I", "-S", str(entrypoint)],
                    cwd=self.root,
                    env=environment,
                    input=b"not JSON",
                    capture_output=True,
                    check=False,
                )

                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertEqual(b"", completed.stderr)
                self.assertEqual(
                    b'{"decision":"block","reason":"Control-plane input could '
                    b'not be parsed; the action is blocked."}\n',
                    completed.stdout,
                )
                self.assertFalse(marker.exists())

    def test_success_output_is_ascii_safe_json(self) -> None:
        entrypoint = (
            self.packaged_scripts / "control_plane" / "entrypoints" / "unicode.py"
        )
        entrypoint.write_text(
            """from pathlib import Path
import runpy

bootstrap_path = Path(__file__).parent.parent / "bootstrap.py"
configure_package = runpy.run_path(str(bootstrap_path))["configure_package"]
configure_package(__file__)

from control_plane.protocol import run_hook


def handler(event):
    return {"systemMessage": "中文"}


raise SystemExit(run_hook("UserPromptSubmit", handler))
""",
            encoding="utf-8",
        )

        completed = subprocess.run(
            [sys.executable, "-I", "-S", str(entrypoint)],
            cwd=self.root,
            input=b'{"hook_event_name":"UserPromptSubmit"}',
            capture_output=True,
            check=False,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(b"", completed.stderr)
        self.assertEqual(
            b'{"systemMessage":"\\u4e2d\\u6587"}\n', completed.stdout
        )

    def test_missing_package_marker_fails_with_sanitized_exit_contract(self) -> None:
        entrypoint = self.make_recording_entrypoint("UserPromptSubmit")
        marker = self.root / "handler-called-without-package-marker"
        package_marker = self.packaged_scripts / "control_plane" / "__init__.py"
        package_marker.unlink()
        environment = os.environ.copy()
        environment["HANDLER_MARKER"] = str(marker)

        completed = subprocess.run(
            [sys.executable, "-I", "-S", str(entrypoint)],
            cwd=self.root,
            env=environment,
            input=b'{"hook_event_name":"UserPromptSubmit"}',
            capture_output=True,
            check=False,
        )

        self.assertEqual(126, completed.returncode)
        self.assertEqual(b"", completed.stdout)
        self.assertEqual(
            b"codex-control-plane-hooks: package bootstrap failed\n",
            completed.stderr.replace(b"\r\n", b"\n"),
        )
        self.assertNotIn(str(self.root).encode(), completed.stderr)
        self.assertFalse(marker.exists())

    def test_nonregular_protocol_target_fails_before_module_import(self) -> None:
        entrypoint = self.make_recording_entrypoint("UserPromptSubmit")
        protocol_target = self.packaged_scripts / "control_plane" / "protocol.py"
        protocol_target.unlink()
        protocol_target.mkdir()
        marker = self.root / "handler-called-with-invalid-protocol"
        environment = os.environ.copy()
        environment["HANDLER_MARKER"] = str(marker)

        completed = subprocess.run(
            [sys.executable, "-I", "-S", str(entrypoint)],
            cwd=self.root,
            env=environment,
            input=b'{"hook_event_name":"UserPromptSubmit"}',
            capture_output=True,
            check=False,
        )

        self.assertEqual(126, completed.returncode)
        self.assertEqual(b"", completed.stdout)
        self.assertEqual(
            b"codex-control-plane-hooks: package bootstrap failed\n",
            completed.stderr.replace(b"\r\n", b"\n"),
        )
        self.assertFalse(marker.exists())

    def test_nonregular_store_target_fails_before_module_import(self) -> None:
        entrypoint = self.make_recording_entrypoint("UserPromptSubmit")

        for module_name in ("policy.py", "state.py"):
            with self.subTest(module_name=module_name):
                module_target = (
                    self.packaged_scripts / "control_plane" / module_name
                )
                original = module_target.read_bytes()
                module_target.unlink()
                module_target.mkdir()
                marker = self.root / f"handler-called-with-invalid-{module_name}"
                environment = os.environ.copy()
                environment["HANDLER_MARKER"] = str(marker)

                completed = subprocess.run(
                    [sys.executable, "-I", "-S", str(entrypoint)],
                    cwd=self.root,
                    env=environment,
                    input=b'{"hook_event_name":"UserPromptSubmit"}',
                    capture_output=True,
                    check=False,
                )

                self.assertEqual(126, completed.returncode)
                self.assertEqual(b"", completed.stdout)
                self.assertEqual(
                    b"codex-control-plane-hooks: package bootstrap failed\n",
                    completed.stderr.replace(b"\r\n", b"\n"),
                )
                self.assertFalse(marker.exists())

                module_target.rmdir()
                module_target.write_bytes(original)

    def test_reparse_package_is_rejected_before_handler_import(self) -> None:
        entrypoint = self.make_recording_entrypoint("UserPromptSubmit")
        package = self.packaged_scripts / "control_plane"
        real_package = self.root / "real-control-plane"
        shutil.move(str(package), str(real_package))

        if os.name == "nt":
            comspec = os.environ.get("COMSPEC", "cmd.exe")
            linked = subprocess.run(
                [comspec, "/d", "/c", "mklink", "/J", str(package), str(real_package)],
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, linked.returncode, linked.stdout + linked.stderr)
        else:
            package.symlink_to(real_package, target_is_directory=True)

        marker = self.root / "handler-called-through-reparse"
        environment = os.environ.copy()
        environment["HANDLER_MARKER"] = str(marker)
        completed = subprocess.run(
            [sys.executable, "-I", "-S", str(entrypoint)],
            cwd=self.root,
            env=environment,
            input=b'{"hook_event_name":"UserPromptSubmit"}',
            capture_output=True,
            check=False,
        )

        self.assertEqual(126, completed.returncode)
        self.assertEqual(b"", completed.stdout)
        self.assertEqual(
            b"codex-control-plane-hooks: package bootstrap failed\n",
            completed.stderr.replace(b"\r\n", b"\n"),
        )
        self.assertFalse(marker.exists())


class EventContextRegressionTests(HookProtocolTestCase):
    def test_event_budget_bounds_hanging_git_children_and_fails_closed(self) -> None:
        module = __import__("control_plane_hook")
        self.assert_default_event_budget(module)
        repositories = [self.seed_remote_repository(f"budget-repo-{index}") for index in range(4)]
        real_run = module.subprocess.run
        spawned: list[tuple[str, ...]] = []

        def hanging(command, **kwargs):
            spawned.append(tuple(command))
            sleep_for = float(kwargs.get("timeout") or 1.0) + 5.0
            return real_run(
                [sys.executable, "-c", f"import time; time.sleep({sleep_for})"],
                **kwargs,
            )

        event = self.push_authorization_event(repositories)
        with (
            self.event_budget(module, seconds=1.0),
            mock.patch.object(module.subprocess, "run", side_effect=hanging),
        ):
            started = time.monotonic()
            module.dispatch(event)
            elapsed = time.monotonic() - started

        # Unbounded per-child timeouts would have taken far longer than the
        # host's ten-second hook timeout, which is a fail-open path.
        self.assertTrue(spawned)
        self.assertLess(elapsed, 4.0)
        self.assertLess(len(spawned), 4 * len(repositories))
        state = json.loads(module.state_store._state_path(self.session).read_text(encoding="utf-8"))
        self.assertIsNone(state["local_git_grant"])

    def test_git_classification_reads_are_memoized_within_one_event(self) -> None:
        module = __import__("control_plane_hook")
        repo = self.seed_remote_repository("memoized-remote")
        self.seed_git_branch(repo)
        real_run = module.subprocess.run
        observed: list[tuple[tuple[str, ...], str | None]] = []

        def counting(command, **kwargs):
            observed.append((tuple(command), kwargs.get("cwd")))
            return real_run(command, **kwargs)

        with mock.patch.object(module.subprocess, "run", side_effect=counting):
            module.dispatch(self.push_authorization_event([repo]))

        self.assertTrue(observed)
        self.assertEqual(len(observed), len(set(observed)))

    def test_memoized_reads_do_not_leak_across_events(self) -> None:
        module = __import__("control_plane_hook")
        repo = self.seed_remote_repository("recheck-remote")
        self.seed_git_branch(repo)
        event = self.push_authorization_event([repo])
        module.dispatch(event)
        real_run = module.subprocess.run
        observed: list[tuple[str, ...]] = []

        def counting(command, **kwargs):
            observed.append(tuple(command))
            return real_run(command, **kwargs)

        with mock.patch.object(module.subprocess, "run", side_effect=counting):
            module.dispatch(event)

        self.assertTrue(
            any("get-url" in command for command in observed),
            msg="a later event must re-read the remote instead of reusing a cache",
        )

    def test_event_budget_globals_clear_after_success_and_exception(self) -> None:
        module = __import__("control_plane_hook")

        def successful_handler(_event: dict[str, object]) -> dict[str, object]:
            self.assertIsNotNone(module._EVENT_DEADLINE)
            module._GIT_QUERY_CACHE[("fixture",)] = "cached"
            return {}

        with mock.patch.object(module, "_handle_tool_gate", side_effect=successful_handler):
            self.assertEqual({}, module.dispatch({"hook_event_name": "PreToolUse"}))
        self.assert_event_cache_cleared(module)

        def failing_handler(_event: dict[str, object]) -> dict[str, object]:
            self.assertIsNotNone(module._EVENT_DEADLINE)
            module._GIT_QUERY_CACHE[("fixture",)] = "cached"
            raise RuntimeError("simulated failure")

        with mock.patch.object(module, "_handle_tool_gate", side_effect=failing_handler):
            with self.assertRaises(RuntimeError):
                module.dispatch({"hook_event_name": "PreToolUse"})
        self.assert_event_cache_cleared(module)

    def test_dispatch_snapshots_policy_and_data_directory_per_event(self) -> None:
        module = __import__("control_plane_hook")
        first_policy_path = Path(self.data_dir) / "policy.json"
        observations: list[object] = []
        with self.policy_data_directory(["Second Capital"]) as second_data_dir:

            def first_handler(_event: dict[str, object]) -> dict[str, object]:
                first_data = module._data_dir()
                first_policy = module._policy()
                first_policy_path.write_text(
                    json.dumps({"sensitive_markers": ["Changed Capital"]}),
                    encoding="utf-8",
                )
                os.environ["PLUGIN_DATA"] = second_data_dir
                observations.extend(
                    [
                        first_data,
                        module._data_dir(),
                        first_policy,
                        module._policy(),
                    ]
                )
                return {}

            def second_handler(_event: dict[str, object]) -> dict[str, object]:
                observations.extend([module._data_dir(), module._policy()])
                return {}

            with (
                mock.patch.dict(os.environ, {"PLUGIN_DATA": self.data_dir}, clear=False),
                mock.patch.object(module, "_private_directory", wraps=module._private_directory) as private_directory,
                mock.patch.object(module.json, "loads", wraps=module.json.loads) as json_loads,
            ):
                with mock.patch.object(module, "_handle_tool_gate", side_effect=first_handler):
                    self.assertEqual({}, module.dispatch({"hook_event_name": "PreToolUse"}))
                with mock.patch.object(module, "_handle_tool_gate", side_effect=second_handler):
                    self.assertEqual({}, module.dispatch({"hook_event_name": "PreToolUse"}))

        self.assertEqual(Path(self.data_dir), observations[0])
        self.assertEqual(observations[0], observations[1])
        self.assertIs(observations[2], observations[3])
        self.assertEqual(["Example Capital"], observations[2]["markers"])
        self.assertEqual(Path(second_data_dir), observations[4])
        self.assertEqual(["Second Capital"], observations[5]["markers"])
        self.assertEqual(2, private_directory.call_count)
        self.assertEqual(2, json_loads.call_count)
        self.assert_event_snapshot_cleared(module)
        with mock.patch.object(module, "_handle_tool_gate", side_effect=RuntimeError("simulated failure")):
            with self.assertRaises(RuntimeError):
                module.dispatch({"hook_event_name": "PreToolUse"})
        self.assert_event_snapshot_cleared(module)


if __name__ == "__main__":
    unittest.main()
