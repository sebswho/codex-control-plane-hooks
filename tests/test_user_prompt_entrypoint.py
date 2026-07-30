from __future__ import annotations

import ast
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
LEGACY_ENTRYPOINT = SCRIPTS / "control_plane_hook.py"
USER_PROMPT_ENTRYPOINT = (
    SCRIPTS / "control_plane" / "entrypoints" / "user_prompt_submit.py"
)


class UserPromptEntrypointContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.legacy_data = self.root / "legacy-data"
        self.new_data = self.root / "new-data"
        policy = {
            "sensitive_markers": ["Example Capital"],
            "sensitive_terms": ["position", "account", "client", "NAV"],
            "durable_destination_markers": ["/tmp/private-notes/"],
            "enable_natural_language_approvals": True,
            "enable_sensitive_disclosure_approvals": True,
            "enable_scoped_git_transactions": True,
            "enable_constrained_github_clone": True,
        }
        for data_dir in (self.legacy_data, self.new_data):
            data_dir.mkdir()
            (data_dir / "policy.json").write_text(
                json.dumps(policy), encoding="utf-8"
            )

    def run_entrypoint(self, entrypoint: Path, data_dir: Path, payload: dict) -> bytes:
        environment = os.environ.copy()
        environment["PLUGIN_DATA"] = str(data_dir)
        completed = subprocess.run(
            [sys.executable, "-I", "-S", str(entrypoint)],
            input=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            capture_output=True,
            env=environment,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(b"", completed.stderr)
        return completed.stdout

    def read_state(self, data_dir: Path) -> dict:
        state_files = list(data_dir.glob("session-*.json"))
        self.assertEqual(1, len(state_files))
        state = json.loads(state_files[0].read_text(encoding="utf-8"))
        self.assertIsInstance(state.pop("updated_at"), int)
        grant = state.get("local_git_grant")
        if isinstance(grant, dict):
            self.assertIsInstance(grant.pop("issued_at"), (int, float))
        return state

    def test_legacy_and_new_entrypoints_use_the_shared_handler(self) -> None:
        packaged_scripts = self.root / "packaged" / "scripts"
        shutil.copytree(SCRIPTS, packaged_scripts)
        handler = (
            packaged_scripts
            / "control_plane"
            / "handlers"
            / "user_prompt_submit.py"
        )
        handler.write_text(
            "def handle(event):\n"
            "    return {'systemMessage': 'shared handler'}\n",
            encoding="utf-8",
        )
        payload = {
            "hook_event_name": "UserPromptSubmit",
            "session_id": "shared-handler-session",
            "turn_id": "shared-handler-turn",
            "cwd": tempfile.gettempdir(),
            "permission_mode": "default",
            "prompt": "Review the implementation.",
        }

        legacy_response = self.run_entrypoint(
            packaged_scripts / "control_plane_hook.py", self.legacy_data, payload
        )
        new_response = self.run_entrypoint(
            packaged_scripts
            / "control_plane"
            / "entrypoints"
            / "user_prompt_submit.py",
            self.new_data,
            payload,
        )

        self.assertEqual(b'{"systemMessage":"shared handler"}\n', new_response)
        self.assertEqual(new_response, legacy_response)

    def test_missing_handler_package_marker_fails_closed(self) -> None:
        packaged_scripts = self.root / "missing-handler-marker" / "scripts"
        shutil.copytree(SCRIPTS, packaged_scripts)
        (
            packaged_scripts / "control_plane" / "handlers" / "__init__.py"
        ).unlink()
        environment = os.environ.copy()
        environment["PLUGIN_DATA"] = str(self.new_data)
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                str(
                    packaged_scripts
                    / "control_plane"
                    / "entrypoints"
                    / "user_prompt_submit.py"
                ),
            ],
            input=b'{"hook_event_name":"UserPromptSubmit"}',
            capture_output=True,
            env=environment,
            check=False,
        )

        self.assertEqual(126, completed.returncode)
        self.assertEqual(b"", completed.stdout)
        self.assertEqual(
            b"codex-control-plane-hooks: package bootstrap failed"
            + os.linesep.encode("ascii"),
            completed.stderr,
        )

    def test_nonregular_core_target_fails_during_bootstrap(self) -> None:
        packaged_scripts = self.root / "nonregular-core-target" / "scripts"
        shutil.copytree(SCRIPTS, packaged_scripts)
        core_target = packaged_scripts / "control_plane" / "core.py"
        core_target.unlink()
        core_target.mkdir()
        environment = os.environ.copy()
        environment["PLUGIN_DATA"] = str(self.new_data)
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                str(
                    packaged_scripts
                    / "control_plane"
                    / "entrypoints"
                    / "user_prompt_submit.py"
                ),
            ],
            input=b'{"hook_event_name":"UserPromptSubmit"}',
            capture_output=True,
            env=environment,
            check=False,
        )

        self.assertEqual(126, completed.returncode)
        self.assertEqual(b"", completed.stdout)
        self.assertEqual(
            b"codex-control-plane-hooks: package bootstrap failed"
            + os.linesep.encode("ascii"),
            completed.stderr,
        )

    def test_routine_prompt_matches_legacy_response_and_state(self) -> None:
        payload = {
            "hook_event_name": "UserPromptSubmit",
            "session_id": "entrypoint-contract-session",
            "turn_id": "entrypoint-contract-turn",
            "cwd": tempfile.gettempdir(),
            "permission_mode": "default",
            "prompt": "请启动 5 个 Agent 审计五个独立模块。",
        }
        before = (self.legacy_data / "policy.json").read_bytes()
        self.assertEqual(before, (self.new_data / "policy.json").read_bytes())

        legacy_response = self.run_entrypoint(
            LEGACY_ENTRYPOINT, self.legacy_data, payload
        )
        new_response = self.run_entrypoint(
            USER_PROMPT_ENTRYPOINT, self.new_data, payload
        )

        self.assertEqual(b"{}\n", legacy_response)
        self.assertEqual(legacy_response, new_response)
        self.assertEqual(before, (self.legacy_data / "policy.json").read_bytes())
        self.assertEqual(before, (self.new_data / "policy.json").read_bytes())
        legacy_state = self.read_state(self.legacy_data)
        self.assertEqual(legacy_state, self.read_state(self.new_data))
        self.assertEqual("entrypoint-contract-turn", legacy_state["current_turn_id"])
        self.assertTrue(legacy_state["explicit_expand"])
        self.assertFalse(legacy_state["nested_allowed"])

    def test_git_grant_matches_legacy_response_and_state(self) -> None:
        payload = {
            "hook_event_name": "UserPromptSubmit",
            "session_id": "entrypoint-grant-session",
            "turn_id": "entrypoint-grant-turn",
            "cwd": "/tmp/example-repo",
            "permission_mode": "default",
            "prompt": (
                "批准你在 /tmp/example-repo 执行上述 git add 和 git commit。"
            ),
        }

        legacy_response = self.run_entrypoint(
            LEGACY_ENTRYPOINT, self.legacy_data, payload
        )
        new_response = self.run_entrypoint(
            USER_PROMPT_ENTRYPOINT, self.new_data, payload
        )

        self.assertEqual(b"{}\n", legacy_response)
        self.assertEqual(legacy_response, new_response)
        legacy_state = self.read_state(self.legacy_data)
        self.assertEqual(legacy_state, self.read_state(self.new_data))
        self.assertEqual("entrypoint-grant-turn", legacy_state["current_turn_id"])
        self.assertIsInstance(legacy_state["local_git_grant"], dict)
        self.assertEqual(
            ["add", "commit"],
            legacy_state["local_git_grant"]["operations"],
        )

    def test_sensitive_prompt_matches_legacy_response_and_state(self) -> None:
        payload = {
            "hook_event_name": "UserPromptSubmit",
            "session_id": "entrypoint-sensitive-session",
            "turn_id": "entrypoint-sensitive-turn",
            "cwd": tempfile.gettempdir(),
            "permission_mode": "default",
            "prompt": (
                "Process Example Capital position data locally and minimize it first."
            ),
        }

        legacy_response = self.run_entrypoint(
            LEGACY_ENTRYPOINT, self.legacy_data, payload
        )
        new_response = self.run_entrypoint(
            USER_PROMPT_ENTRYPOINT, self.new_data, payload
        )

        self.assertEqual(legacy_response, new_response)
        response = json.loads(new_response.decode("ascii"))
        context = response["hookSpecificOutput"]["additionalContext"]
        self.assertIn("Configured sensitive-business context", context)
        legacy_state = self.read_state(self.legacy_data)
        self.assertEqual(legacy_state, self.read_state(self.new_data))
        self.assertEqual(
            "entrypoint-sensitive-turn", legacy_state["current_turn_id"]
        )
        self.assertTrue(legacy_state["sensitive_context"])

    def test_mismatched_event_is_blocked_before_state_mutation(self) -> None:
        payload = {
            "hook_event_name": "PostToolUse",
            "session_id": "entrypoint-mismatch-session",
            "turn_id": "entrypoint-mismatch-turn",
            "cwd": tempfile.gettempdir(),
            "permission_mode": "default",
        }

        response = self.run_entrypoint(
            USER_PROMPT_ENTRYPOINT, self.new_data, payload
        )

        self.assertEqual(
            b'{"decision":"block","reason":"Control-plane internal '
            b'validation failed; the action is blocked."}\n',
            response,
        )
        self.assertEqual([], list(self.new_data.glob("session-*.json")))

    def test_dedicated_entrypoint_ignores_poisoned_import_paths(self) -> None:
        poisoned = self.root / "poisoned"
        poisoned_package = poisoned / "control_plane"
        poisoned_package.mkdir(parents=True)
        (poisoned_package / "__init__.py").write_text(
            "raise RuntimeError('poisoned package imported')\n",
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment["PLUGIN_DATA"] = str(self.new_data)
        environment["PYTHONPATH"] = str(poisoned)
        payload = {
            "hook_event_name": "UserPromptSubmit",
            "session_id": "entrypoint-poison-session",
            "turn_id": "entrypoint-poison-turn",
            "cwd": str(poisoned),
            "permission_mode": "default",
            "prompt": "Review the implementation.",
        }

        completed = subprocess.run(
            [sys.executable, "-I", "-S", str(USER_PROMPT_ENTRYPOINT)],
            cwd=poisoned,
            env=environment,
            input=json.dumps(payload).encode("utf-8"),
            capture_output=True,
            check=False,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(b"", completed.stderr)
        self.assertEqual(b"{}\n", completed.stdout)

    def test_dedicated_entrypoint_does_not_import_the_legacy_module(self) -> None:
        packaged_scripts = self.root / "without-legacy-module" / "scripts"
        shutil.copytree(SCRIPTS, packaged_scripts)
        (packaged_scripts / "control_plane_hook.py").unlink()
        payload = {
            "hook_event_name": "UserPromptSubmit",
            "session_id": "entrypoint-no-dispatch-session",
            "turn_id": "entrypoint-no-dispatch-turn",
            "cwd": tempfile.gettempdir(),
            "permission_mode": "default",
            "prompt": "Review the implementation.",
        }

        response = self.run_entrypoint(
            packaged_scripts
            / "control_plane"
            / "entrypoints"
            / "user_prompt_submit.py",
            self.new_data,
            payload,
        )

        self.assertEqual(b"{}\n", response)

    def test_core_module_does_not_own_other_event_handlers(self) -> None:
        core = SCRIPTS / "control_plane" / "core.py"
        tree = ast.parse(core.read_text(encoding="utf-8"))
        functions = {
            node.name
            for node in tree.body
            if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef))
        }

        self.assertIn("handle_user_prompt_submit", functions)
        self.assertTrue(
            functions.isdisjoint(
                {
                    "dispatch",
                    "_handle_tool_gate",
                    "_handle_post_tool",
                    "_handle_subagent_start",
                    "_handle_subagent_stop",
                    "_handle_precompact",
                    "_handle_stop",
                }
            )
        )

        legacy = ast.parse(LEGACY_ENTRYPOINT.read_text(encoding="utf-8"))
        legacy_functions = {
            node.name
            for node in legacy.body
            if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef))
        }
        self.assertNotIn("_handle_user_prompt", legacy_functions)

    @unittest.skipUnless(os.name == "nt", "PowerShell smoke is Windows-only")
    def test_powershell_5_and_7_run_the_dedicated_entrypoint(self) -> None:
        wrapper = self.root / "run-user-prompt-entrypoint.ps1"
        wrapper.write_text(
            "param(\n"
            "    [Parameter(Mandatory = $true)][string]$PythonPath,\n"
            "    [Parameter(Mandatory = $true)][string]$EntrypointPath\n"
            ")\n"
            "& $PythonPath -I -S $EntrypointPath\n"
            "exit $LASTEXITCODE\n",
            encoding="utf-8",
        )
        payload = json.dumps(
            {
                "hook_event_name": "UserPromptSubmit",
                "session_id": "powershell-entrypoint-session",
                "turn_id": "powershell-entrypoint-turn",
                "cwd": tempfile.gettempdir(),
                "permission_mode": "default",
                "prompt": "Review.",
            }
        ).encode("utf-8")
        environment = os.environ.copy()
        environment["PLUGIN_DATA"] = str(self.new_data)

        for executable in ("powershell.exe", "pwsh.exe"):
            with self.subTest(executable=executable):
                shell = shutil.which(executable)
                self.assertIsNotNone(
                    shell, f"required shell is unavailable: {executable}"
                )
                completed = subprocess.run(
                    [
                        str(shell),
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
                        str(USER_PROMPT_ENTRYPOINT),
                    ],
                    cwd=self.root,
                    env=environment,
                    input=payload,
                    capture_output=True,
                    check=False,
                )

                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertEqual(b"", completed.stderr)
                self.assertEqual(b"{}\n", completed.stdout)


if __name__ == "__main__":
    unittest.main()
