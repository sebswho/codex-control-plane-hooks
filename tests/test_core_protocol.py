from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
