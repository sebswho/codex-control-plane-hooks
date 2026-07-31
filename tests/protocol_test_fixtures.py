from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Callable
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "codex-control-plane-hooks" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
SCRIPT = SCRIPTS / "control_plane_hook.py"
DEFAULT_CWD = tempfile.gettempdir()
EVENT_BUDGET_SECONDS = 6.0

from control_plane import state as state_store  # noqa: E402


class HookProtocolTestCase(unittest.TestCase):
    @staticmethod
    def cleanup_owned_runtime_version(path: Path, marker: Path, token: str) -> None:
        versions_root = Path.home() / ".codex" / "runtimes" / "codex-control-plane-hooks" / "versions"
        runtime_id = path.name
        safe_id = (
            runtime_id.startswith("py312-")
            and len(runtime_id) == 22
            and all(character in "0123456789abcdef" for character in runtime_id[6:])
        )
        try:
            owned = marker.is_file() and marker.read_text(encoding="ascii") == token
        except OSError:
            owned = False
        if path.parent != versions_root or not safe_id or not owned:
            return
        is_junction = getattr(path, "is_junction", None)
        if (callable(is_junction) and is_junction()) or path.is_symlink():
            os.rmdir(path)
        else:
            shutil.rmtree(path, True)

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data_dir = self.temp.name
        previous_plugin_data = os.environ.get("PLUGIN_DATA")
        os.environ["PLUGIN_DATA"] = self.data_dir
        self.addCleanup(
            lambda: (
                os.environ.__setitem__("PLUGIN_DATA", previous_plugin_data)
                if previous_plugin_data is not None
                else os.environ.pop("PLUGIN_DATA", None)
            )
        )
        Path(self.data_dir, "policy.json").write_text(
            json.dumps(
                {
                    "sensitive_markers": ["Example Capital"],
                    "sensitive_terms": ["position", "account", "client", "NAV"],
                    "durable_destination_markers": ["/tmp/private-notes/"],
                    "enable_natural_language_approvals": True,
                    "enable_sensitive_disclosure_approvals": True,
                    "enable_scoped_git_transactions": True,
                    "enable_constrained_github_clone": True,
                }
            ),
            encoding="utf-8",
        )
        self.session = "test-session"
        self.turn = "test-turn"
        self.tool_sequence = 0

    def run_raw(self, payload: str, *, data_dir: str | None = None) -> tuple[subprocess.CompletedProcess[str], dict]:
        env = os.environ.copy()
        env["PLUGIN_DATA"] = data_dir or self.data_dir
        completed = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=payload,
            text=True,
            capture_output=True,
            env=env,
            check=True,
        )
        self.assertEqual("", completed.stderr)
        return completed, json.loads(completed.stdout)

    def run_bytes(
        self, payload: bytes, *, data_dir: str | None = None
    ) -> tuple[subprocess.CompletedProcess[bytes], dict]:
        env = os.environ.copy()
        env["PLUGIN_DATA"] = data_dir or self.data_dir
        completed = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=payload,
            capture_output=True,
            env=env,
            check=True,
        )
        self.assertEqual(b"", completed.stderr)
        return completed, json.loads(completed.stdout.decode("ascii"))

    def run_hook(self, event: dict, *, data_dir: str | None = None) -> dict:
        payload = {
            "session_id": self.session,
            "turn_id": self.turn,
            "cwd": DEFAULT_CWD,
            "permission_mode": "default",
            **event,
        }
        tool_events = {"PreToolUse", "PermissionRequest", "PostToolUse"}
        if payload.get("hook_event_name") in tool_events and "tool_use_id" not in payload:
            self.tool_sequence += 1
            payload["tool_use_id"] = f"tool-{self.tool_sequence}"
        return self.run_raw(json.dumps(payload), data_dir=data_dir)[1]

    def run_windows_launcher_fixture(
        self,
        *,
        manifest_text: str | None,
        manifest_bytes: bytes | None = None,
        hook_source: str = "raise SystemExit(37)\n",
        payload: str | None = None,
        configure_runtime: bool = False,
        before_launch: Callable[[Path], None] | None = None,
        launcher_shell: str | Path | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        system32 = Path(os.environ["SystemRoot"]) / "System32"
        powershell = system32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        root = Path(tempfile.mkdtemp(prefix="launcher-", dir=self.temp.name))
        plugin_root = root / "plugin with spaces"
        plugin_data = root / "codex home with spaces" / "plugins" / "data" / "codex-control-plane-hooks"
        plugin_root.mkdir()
        plugin_data.mkdir(parents=True)
        launcher = plugin_root / "run_control_plane_hook.ps1"
        shutil.copyfile(SCRIPTS / launcher.name, launcher)
        (plugin_root / "control_plane_hook.py").write_text(hook_source, encoding="utf-8")
        if manifest_text is not None:
            (plugin_data / "runtime.json").write_text(manifest_text, encoding="utf-8")
        if manifest_bytes is not None:
            self.assertIsNone(manifest_text)
            (plugin_data / "runtime.json").write_bytes(manifest_bytes)
        if configure_runtime:
            self.assertIsNone(manifest_text)
            source_runtime = root / "source runtime"
            source_setup = subprocess.run(
                [sys.executable, "-I", "-S", "-m", "venv", str(source_runtime)],
                text=True,
                capture_output=True,
                timeout=90,
                check=False,
            )
            self.assertEqual(0, source_setup.returncode, source_setup.stderr)
            source_python = source_runtime / "Scripts" / "python.exe"
            runtime_root = Path.home() / ".codex" / "runtimes" / "codex-control-plane-hooks" / "versions"
            runtime_root.mkdir(parents=True, exist_ok=True)
            setup = subprocess.run(
                [
                    str(powershell),
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(SCRIPTS / "setup_runtime.ps1"),
                    "-PythonPath",
                    str(source_python),
                    "-PluginDataPath",
                    str(plugin_data),
                ],
                text=True,
                capture_output=True,
                timeout=90,
                check=False,
            )
            self.assertEqual(0, setup.returncode, setup.stderr)
            manifest = json.loads((plugin_data / "runtime.json").read_text(encoding="utf-8"))
            created = Path(manifest["interpreter"]).parents[1]
            self.assertEqual(runtime_root, created.parent)
            ownership_token = os.urandom(16).hex()
            ownership_marker = created / ".codex-test-owner"
            with ownership_marker.open("x", encoding="ascii") as marker_file:
                marker_file.write(ownership_token)
            self.addCleanup(
                self.cleanup_owned_runtime_version,
                created,
                ownership_marker,
                ownership_token,
            )
        if before_launch is not None:
            before_launch(plugin_data)
        environment = os.environ.copy()
        environment["PLUGIN_DATA"] = str(plugin_data)
        environment["PATH"] = os.pathsep.join([str(system32)])
        completed = subprocess.run(
            [
                str(launcher_shell or powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(launcher),
            ],
            input=payload,
            text=True,
            capture_output=True,
            timeout=10,
            env=environment,
            check=False,
        )
        return completed, plugin_data

    def windows_launcher_shells(self) -> list[tuple[str, str | Path | None]]:
        shells: list[tuple[str, str | Path | None]] = [("powershell-5.1", None)]
        pwsh = shutil.which("pwsh")
        if pwsh is not None:
            shells.append(("powershell-7", pwsh))
        return shells

    def prompt(self, text: str, *, cwd: str = DEFAULT_CWD) -> dict:
        return self.run_hook({"hook_event_name": "UserPromptSubmit", "prompt": text, "cwd": cwd})

    def seed_git_branch(self, repo: Path, branch: str = "main") -> str:
        (repo / "README.md").write_text("runner fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "-c",
                "user.name=Control Plane Tests",
                "-c",
                "user.email=tests@example.invalid",
                "commit",
                "-q",
                "-m",
                "test: seed push source",
            ],
            check=True,
        )
        subprocess.run(["git", "-C", str(repo), "branch", "-M", branch], check=True)
        return subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()

    def update_policy(self, **updates: object) -> None:
        path = Path(self.data_dir, "policy.json")
        policy = json.loads(path.read_text(encoding="utf-8"))
        policy.update(updates)
        path.write_text(json.dumps(policy), encoding="utf-8")

    def prepare_publication_grant(self, name: str) -> tuple[Path, Path, str, Path]:
        root = Path(self.data_dir) / f"publication-{name}"
        repo = root / name
        repo.mkdir(parents=True)
        target = f"fixture-owner/{name}"
        subprocess.run(
            ["git", "init", "-q", "-b", "main", str(repo)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["git", "-C", str(repo), "remote", "add", "origin", f"https://github.com/{target}.git"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.prompt(
            f"允许在 {repo} 执行 git init/add/commit，并在 fixture-owner 下创建 {name} private repository，推送 main。",
            cwd=str(root),
        )
        digest = hashlib.sha256(self.session.encode("utf-8")).hexdigest()[:24]
        state_path = Path(self.data_dir) / f"session-{digest}.json"
        return root, repo, target, state_path

    def bash(self, command: str, *, cwd: str = DEFAULT_CWD) -> dict:
        return self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "cwd": cwd,
            }
        )

    def probe_transaction_command(
        self,
        command: str,
        *,
        cwd: str,
        tool_name: str = "Bash",
    ) -> dict:
        self.tool_sequence += 1
        tool_use_id = f"transaction-probe-{self.tool_sequence}"
        tool_input = {"cmd": command, "workdir": cwd} if tool_name == "exec_command" else {"command": command}
        result = self.run_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": tool_name,
                "tool_use_id": tool_use_id,
                "tool_input": tool_input,
                "cwd": cwd,
            }
        )
        output = result.get("hookSpecificOutput") or {}
        if output.get("permissionDecision") == "deny":
            return result
        state_path = next(Path(self.data_dir).glob("session-*.json"))
        state = json.loads(state_path.read_text(encoding="utf-8"))
        permission = state["pending_permission_authorizations"].get(tool_use_id)
        if not isinstance(permission, dict) or not permission.get("transaction_id"):
            return result
        runner_id = str(permission.get("runner_token") or "")
        module = __import__("control_plane_hook")

        def complete_probe(current: dict) -> None:
            pending = current.get("pending_permission_authorizations") or {}
            current_permission = pending.pop(tool_use_id, None)
            current["pending_permission_authorizations"] = pending
            grant = current.get("local_git_grant")
            if not isinstance(current_permission, dict) or not isinstance(grant, dict):
                raise AssertionError("transaction probe lost its reservation")
            module._consume_git_grant(
                grant,
                {
                    "scope_hash": current_permission["scope_hash"],
                    "operation": current_permission["operation"],
                },
            )
            current["local_git_grant"] = (
                grant if module._git_grant_usable(grant, str(current.get("session_hash") or "")) else None
            )

        state_store.mutate_session(self.session, complete_probe)
        if runner_id:
            module._unlink_owned_regular(Path(self.data_dir) / f".git-runner-request-{runner_id}.json")
        return result

    def run_transaction_command(
        self,
        event: dict,
        *,
        expected_returncode: int = 0,
    ) -> tuple[dict, subprocess.CompletedProcess[str], dict, str]:
        pretool = self.run_hook({"hook_event_name": "PreToolUse", **event})
        output = pretool.get("hookSpecificOutput") or {}
        self.assertNotEqual("deny", output.get("permissionDecision"), pretool)
        runner_command = str((output.get("updatedInput") or {}).get("command") or "")
        self.assertTrue(runner_command, pretool)

        rewritten_event = dict(event)
        rewritten_input = dict(event.get("tool_input") or {})
        command_key = "cmd" if "cmd" in rewritten_input else "command"
        rewritten_input[command_key] = runner_command
        rewritten_event["tool_input"] = rewritten_input
        permission = self.run_hook({"hook_event_name": "PermissionRequest", **rewritten_event})
        self.assertNotEqual(
            "deny",
            permission["hookSpecificOutput"]["decision"].get("behavior"),
            permission,
        )

        state_path = next(Path(self.data_dir).glob("session-*.json"))
        state = json.loads(state_path.read_text(encoding="utf-8"))
        pending = state["pending_permission_authorizations"][event["tool_use_id"]]
        token = str(pending.get("runner_token") or "")
        self.assertRegex(token, r"^[0-9a-f]{32}$")
        environment = os.environ.copy()
        environment.pop("PLUGIN_DATA", None)
        if os.name == "nt":
            shell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
            self.assertTrue(shell, "PowerShell is required for the Windows runner test")
            runner_argv = [
                str(shell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                runner_command,
            ]
        else:
            runner_argv = ["/bin/sh", "-c", runner_command]
        completed = subprocess.run(
            runner_argv,
            cwd=str(event.get("cwd") or DEFAULT_CWD),
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )
        self.assertEqual(expected_returncode, completed.returncode, completed.stderr)
        posttool = self.run_hook(
            {
                "hook_event_name": "PostToolUse",
                **rewritten_event,
                "tool_response": completed.stdout + completed.stderr,
            }
        )
        return pretool, completed, posttool, token

    def exec_command(
        self,
        command: str,
        *,
        cwd: str = DEFAULT_CWD,
        tool_use_id: str | None = None,
        **options: object,
    ) -> dict:
        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": "exec_command",
            "tool_input": {"cmd": command, "workdir": cwd, **options},
            "cwd": cwd,
        }
        if tool_use_id is not None:
            event["tool_use_id"] = tool_use_id
        return self.run_hook(event)

    def post_tool(
        self,
        output: str,
        *,
        tool_name: str = "Read",
        tool_input: dict | None = None,
        cwd: str = DEFAULT_CWD,
    ) -> dict:
        return self.run_hook(
            {
                "hook_event_name": "PostToolUse",
                "tool_name": tool_name,
                "tool_input": tool_input or {"file_path": str(SCRIPT)},
                "tool_response": {"output": output},
                "cwd": cwd,
            }
        )

    def seed_remote_repository(self, name: str) -> Path:
        repo = Path(self.data_dir) / name
        repo.mkdir()
        subprocess.run(
            ["git", "init", "-q", "-b", "main", str(repo)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "remote",
                "add",
                "origin",
                f"https://github.com/fixture-owner/{name}.git",
            ],
            check=True,
        )
        return repo

    def push_authorization_event(self, repositories: list[Path]) -> dict:
        commands = "\n".join(f"`git -C {repo} push origin main`" for repo in repositories)
        return {
            "hook_event_name": "UserPromptSubmit",
            "session_id": self.session,
            "turn_id": self.turn,
            "cwd": self.data_dir,
            "prompt": f"本轮批准你依次执行以下字面命令：\n{commands}\n推送 main。",
        }

    def assert_default_event_budget(self, module) -> None:
        self.assertEqual(EVENT_BUDGET_SECONDS, module._EVENT_BUDGET_SECONDS)

    @contextmanager
    def event_budget(self, module, *, seconds: float = EVENT_BUDGET_SECONDS) -> Iterator[None]:
        with mock.patch.object(module, "_EVENT_BUDGET_SECONDS", seconds):
            yield

    def assert_event_cache_cleared(self, module) -> None:
        self.assertIsNone(module._EVENT_DEADLINE)
        self.assertEqual({}, module._GIT_QUERY_CACHE)

    def assert_event_snapshot_cleared(self, module) -> None:
        self.assertFalse(module._EVENT_SNAPSHOT_ACTIVE)
        self.assertIsNone(module._EVENT_DATA_DIR)
        self.assertIsNone(module._EVENT_POLICY)

    @contextmanager
    def policy_data_directory(self, markers: list[str]) -> Iterator[str]:
        with tempfile.TemporaryDirectory() as data_dir:
            Path(data_dir, "policy.json").write_text(
                json.dumps({"sensitive_markers": markers}),
                encoding="utf-8",
            )
            yield data_dir

    def write_legacy_state(self, schema_version: int, *, session: str) -> Path:
        digest = hashlib.sha256(session.encode("utf-8")).hexdigest()[:24]
        state_path = Path(self.data_dir) / f"session-{digest}.json"
        state_path.write_text(
            json.dumps(
                {
                    "schema_version": schema_version,
                    "active_agents": {},
                    "updated_at": int(time.time()),
                }
            ),
            encoding="utf-8",
        )
        return state_path
