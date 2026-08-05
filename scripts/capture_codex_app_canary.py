#!/usr/bin/env python3
"""Capture sanitized, read-only evidence for a real Codex App plugin canary."""

from __future__ import annotations

import argparse
import collections
import contextlib
import hashlib
import json
import os
import queue
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

AUTHORIZED_REPOSITORY = "sebswho/codex-control-plane-hooks"
PLUGIN_NAME = "codex-control-plane-hooks"
CLI_BASE = ["--disable", "remote_plugin", "--disable", "plugin_sharing"]
ARTIFACT_PATHS = (
    Path(".codex-plugin/plugin.json"),
    Path("hooks/hooks.json"),
    Path("scripts/run_control_plane_hook.ps1"),
    Path("scripts/control_plane_hook.py"),
)
REQUIRED_SCENARIOS = (
    "untrusted_to_trusted",
    "safe_allow",
    "dangerous_deny",
    "cross_turn_resume",
    "new_task_same_sha",
    "app_restart_same_sha",
    "same_sha_reinstall_state_preserved",
    "experiments_default_off",
    "merge_sha_repin",
)
FEATURE_REQUIRED_SCENARIOS = REQUIRED_SCENARIOS[:-1]
MERGED_REQUIRED_SCENARIOS = (
    "safe_allow",
    "dangerous_deny",
    "new_task_same_sha",
    "app_restart_same_sha",
    "experiments_default_off",
    "merge_sha_repin",
)
SCENARIO_STATUSES = {"passed", "failed", "not_run", "not_recorded"}
SENSITIVE_KEY = re.compile(
    r"(?:^|_)(?:token|password|secret|credential|private_key|config|trust|policy)(?:_|$)",
    re.IGNORECASE,
)
CREDENTIAL_NAME = re.compile(
    r"(?:^|_)(?:ACCESS_KEY|API_KEY|AUTH|CREDENTIALS?|PASSWORD|PRIVATE_KEY|SECRET|TOKEN)(?:_|$)"
)
ABSOLUTE_PATH_PATTERNS = (
    re.compile(r"[A-Za-z]:[\\/]", re.IGNORECASE),
    re.compile(r"\\\\[^\\\s]+\\[^\\\s]+", re.IGNORECASE),
    re.compile(re.escape("/") + r"(?:Users|home)/[^/\s]+/", re.IGNORECASE),
    re.compile(
        re.escape("/m" + "nt/") + r"[a-z]/" + "Users" + r"/[^/\s]+/",
        re.IGNORECASE,
    ),
)

CREDENTIAL_VALUE = re.compile(
    r"(?:\b(?:Authorization\s*:\s*)?Bearer\s+\S+|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b|"
    r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b|"
    r"\b(?:api[_-]?key|token|secret|password|client[_-]?secret|access[_-]?key)"
    r"\s*[:=]\s*['\"]?[A-Za-z0-9_./+=:-]{16,}|"
    r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16})\b|"
    r"https?://[^/\s:@]+:[^/\s@]+@)",
    re.IGNORECASE,
)


class CanaryError(RuntimeError):
    """Raised when evidence cannot prove the requested canary invariant."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CanaryError(message)


def command_argv(executable: Path, arguments: list[str]) -> list[str]:
    if os.name == "nt" and executable.suffix.lower() == ".ps1":
        return ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(executable), *arguments]
    if os.name == "nt" and executable.suffix.lower() in {".bat", ".cmd"}:
        return [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", str(executable), *arguments]
    return [str(executable), *arguments]


def child_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if CREDENTIAL_NAME.search(name.upper()) or name.upper() == "SSH_AUTH_SOCK":
            environment.pop(name)
    environment.update(NO_COLOR="1")
    return environment


def run_command(executable: Path, arguments: list[str], cwd: Path | None = None) -> str:
    completed = subprocess.run(
        command_argv(executable, arguments),
        cwd=cwd,
        env=child_environment(),
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=90,
        check=False,
    )
    if completed.returncode:
        raise CanaryError(
            f"read-only command failed ({completed.returncode}): {executable.name} {' '.join(arguments)}\n"
            f"stderr: {completed.stderr[-1200:].strip()}"
        )
    return completed.stdout.strip()


class AppServer:
    EOF = object()

    def __init__(self, codex: Path, environment: dict[str, str], cwd: Path) -> None:
        self.process = subprocess.Popen(
            command_argv(codex, [*CLI_BASE, "app-server", "--listen", "stdio://"]),
            cwd=cwd,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        require(self.process.stdin is not None, "app-server stdin is unavailable")
        require(self.process.stdout is not None, "app-server stdout is unavailable")
        require(self.process.stderr is not None, "app-server stderr is unavailable")
        self.stdin = self.process.stdin
        self.stdout = self.process.stdout
        self.stderr = self.process.stderr
        self.messages: queue.Queue[object] = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.next_id = 1

    def _read(self) -> None:
        for line in self.stdout:
            self.messages.put(line)
        self.messages.put(self.EOF)

    def _send(self, value: dict[str, Any]) -> None:
        self.stdin.write(json.dumps(value, separators=(",", ":")) + "\n")
        self.stdin.flush()

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        request_id = self.next_id
        self.next_id += 1
        self._send({"id": request_id, "method": method, "params": params})
        deadline = time.monotonic() + 30
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CanaryError(f"app-server request timed out: {method}")
            try:
                line = self.messages.get(timeout=remaining)
            except queue.Empty as exc:
                raise CanaryError(f"app-server request timed out: {method}") from exc
            require(line is not self.EOF, f"app-server exited during {method}")
            require(isinstance(line, str), "app-server stdout queue contained a non-string")
            try:
                message = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CanaryError("app-server emitted non-JSON stdout") from exc
            if message.get("id") != request_id:
                continue
            require("error" not in message, f"app-server {method} returned an error")
            result = message.get("result")
            require(isinstance(result, dict), f"app-server {method} result is not an object")
            return result

    def initialize(self, codex_home: Path) -> None:
        result = self.request(
            "initialize",
            {
                "clientInfo": {
                    "name": "codex-control-plane-hooks-app-canary",
                    "version": "1.0.0",
                },
                "capabilities": {"experimentalApi": False},
            },
        )
        require(
            Path(str(result.get("codexHome") or "")).resolve() == codex_home,
            "app-server CODEX_HOME mismatch",
        )
        self._send({"method": "initialized"})

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.reader.join(timeout=2)
        self.stdout.close()
        self.stderr.close()


def parse_json_output(output: str, label: str) -> Any:
    candidates = [output]
    first_object = output.find("{")
    last_object = output.rfind("}")
    if first_object >= 0 and last_object > first_object:
        candidates.append(output[first_object : last_object + 1])
    candidates.extend(reversed(output.splitlines()))
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    raise CanaryError(f"{label} did not return JSON")


def _list_field(payload: Any, field: str, label: str) -> list[Any]:
    require(isinstance(payload, dict), f"{label} JSON must be an object")
    rows = payload.get(field)
    require(isinstance(rows, list), f"{label} JSON must contain a {field} list")
    return rows


def validate_app_hook_inventory(
    payload: Any,
    *,
    cwd: Path,
    manifest: dict[str, Any],
    selector: str,
) -> dict[str, Any]:
    require(isinstance(payload, dict), "hooks/list result must be an object")
    entries = payload.get("data")
    require(isinstance(entries, list) and len(entries) == 1, "hooks/list returned an unexpected cwd set")
    entry = entries[0]
    require(isinstance(entry, dict), "hooks/list cwd entry must be an object")
    require(Path(str(entry.get("cwd") or "")).resolve() == cwd.resolve(), "hooks/list cwd mismatch")
    require(entry.get("warnings") == [], "hooks/list returned warnings")
    require(entry.get("errors") == [], "hooks/list returned errors")
    rows = entry.get("hooks")
    require(isinstance(rows, list), "hooks/list hooks must be an array")

    expected: collections.Counter[str] = collections.Counter()
    hook_groups = manifest.get("hooks") if isinstance(manifest, dict) else None
    require(isinstance(hook_groups, dict), "installed hooks manifest is invalid")
    for event_name, groups in hook_groups.items():
        require(isinstance(groups, list), "installed hooks manifest event groups are invalid")
        for group in groups:
            handlers = group.get("hooks") if isinstance(group, dict) else None
            require(isinstance(handlers, list), "installed hooks manifest handlers are invalid")
            expected[event_name[:1].lower() + event_name[1:]] += sum(
                isinstance(handler, dict) and handler.get("type") == "command" for handler in handlers
            )

    target = [row for row in rows if isinstance(row, dict) and row.get("pluginId") == selector]
    actual = collections.Counter(str(row.get("eventName") or "") for row in target)
    require(actual == expected, f"App bundled hooks/list target events mismatch: {dict(actual)}")
    require(all(row.get("source") == "plugin" for row in target), "target Hook source is not plugin")
    require(all(row.get("handlerType") == "command" for row in target), "target Hook handler type changed")
    require(all(row.get("enabled") is True for row in target), "target Hook is disabled")
    trust_counts = collections.Counter(str(row.get("trustStatus") or "missing") for row in target)
    require(trust_counts == {"trusted": len(target)}, "target Hooks are not all trusted")
    require(
        all(re.fullmatch(r"sha256:[0-9a-f]{64}", str(row.get("currentHash") or "")) for row in target),
        "target Hook currentHash is invalid",
    )
    return {
        "hook_count": len(target),
        "host_total_hook_count": len(rows),
        "event_counts": dict(sorted(actual.items())),
        "trust_status_counts": dict(sorted(trust_counts.items())),
        "all_enabled": True,
        "all_trusted": True,
        "hash_algorithm": "sha256",
    }


def collect_app_hook_inventory(
    codex: Path,
    *,
    codex_home: Path,
    cwd: Path,
    manifest: dict[str, Any],
    selector: str,
) -> dict[str, Any]:
    with contextlib.closing(AppServer(codex, child_environment(), cwd)) as server:
        server.initialize(codex_home)
        payload = server.request("hooks/list", {"cwds": [str(cwd)]})
    return validate_app_hook_inventory(payload, cwd=cwd, manifest=manifest, selector=selector)


def validate_inventory(
    marketplace_payload: Any,
    plugin_payload: Any,
    *,
    marketplace: str,
    plugin: str,
) -> dict[str, Any]:
    require(marketplace == PLUGIN_NAME, "marketplace name is not the fixed canary name")
    require(plugin == PLUGIN_NAME, "plugin name is not the fixed canary name")
    marketplaces = _list_field(marketplace_payload, "marketplaces", "marketplace list")
    require(all(isinstance(row, dict) for row in marketplaces), "marketplace row must be an object")
    matching_marketplaces = [row for row in marketplaces if row.get("name") == marketplace]
    require(
        len(matching_marketplaces) == 1,
        f"Codex must expose exactly one marketplace named {marketplace} during the canary",
    )
    marketplace_row = matching_marketplaces[0]

    installed = _list_field(plugin_payload, "installed", "plugin list")
    require(all(isinstance(row, dict) for row in installed), "installed plugin row must be an object")
    selector = f"{plugin}@{marketplace}"
    matching_plugins = [
        row for row in installed if row.get("name") == plugin or row.get("pluginId") == selector
    ]
    require(
        len(matching_plugins) == 1,
        f"Codex must expose exactly one installed plugin instance named {plugin} during the canary",
    )
    plugin_row = matching_plugins[0]
    require(plugin_row.get("pluginId") == selector, "the installed plugin selector does not match")
    require(plugin_row.get("name") == plugin, "the installed plugin name does not match")
    require(plugin_row.get("marketplaceName") == marketplace, "the plugin marketplace does not match")
    require(plugin_row.get("installed") is True, "the target plugin is not installed")
    require(plugin_row.get("enabled") is True, "the target plugin is not enabled")
    version = plugin_row.get("version")
    require(isinstance(version, str) and bool(version), "the installed plugin version is missing")
    marketplace_source_repository = validate_marketplace_source(
        marketplace_row.get("marketplaceSource"),
        "marketplace",
    )
    plugin_source_repository = validate_marketplace_source(
        plugin_row.get("marketplaceSource"),
        "installed plugin",
    )
    require(
        marketplace_source_repository == plugin_source_repository,
        "marketplace and plugin sources do not match",
    )
    return {
        "marketplace": marketplace,
        "marketplace_count": len(matching_marketplaces),
        "marketplace_total_count": len(marketplaces),
        "plugin": plugin,
        "plugin_count": len(matching_plugins),
        "installed_plugin_total_count": len(installed),
        "selector": selector,
        "version": version,
        "enabled": True,
        "installed": True,
        "marketplace_source_type": "git",
        "marketplace_source_repository": marketplace_source_repository,
    }


def _repository_slug(origin: str) -> str | None:
    text = origin.strip().replace("\\", "/")
    patterns = (
        r"^(?P<slug>[^/:]+/[^/]+?)(?:\.git)?$",
        r"^https?://github\.com/(?P<slug>[^/]+/[^/]+?)(?:\.git)?/?$",
        r"^ssh://git@github\.com/(?P<slug>[^/]+/[^/]+?)(?:\.git)?/?$",
        r"^git@github\.com:(?P<slug>[^/]+/[^/]+?)(?:\.git)?$",
    )
    for pattern in patterns:
        match = re.fullmatch(pattern, text, re.IGNORECASE)
        if match:
            return match.group("slug").lower()
    return None


def validate_marketplace_source(source: Any, label: str) -> str:
    require(isinstance(source, dict), f"{label} source metadata is missing")
    require(source.get("sourceType") == "git", f"{label} source type is not git")
    source_value = source.get("source")
    require(isinstance(source_value, str) and bool(source_value.strip()), f"{label} source is missing")
    repository = _repository_slug(source_value)
    require(repository == AUTHORIZED_REPOSITORY, f"{label} source is not the authorized fork")
    return repository


def validate_checkout_metadata(
    *,
    expected_commit: str,
    actual_commit: str,
    origin: str,
    status: str,
) -> dict[str, str]:
    expected = expected_commit.strip().lower()
    actual = actual_commit.strip().lower()
    require(bool(re.fullmatch(r"[0-9a-f]{40}", expected)), "expected commit must be a full 40-character SHA")
    require(actual == expected, "checkout HEAD does not match the expected commit")
    repository = _repository_slug(origin)
    require(repository == AUTHORIZED_REPOSITORY, "checkout origin is not the authorized fork")
    require(not status.strip(), "expected checkout is not clean")
    return {
        "repository": repository,
        "expected_commit": expected,
        "checkout_commit": actual,
    }


def checkout_metadata(checkout: Path, expected_commit: str) -> dict[str, str]:
    git = Path("git")
    actual = run_command(git, ["-C", str(checkout), "rev-parse", "HEAD"])
    origin = run_command(git, ["-C", str(checkout), "remote", "get-url", "origin"])
    status = run_command(git, ["-C", str(checkout), "status", "--porcelain"])
    return validate_checkout_metadata(
        expected_commit=expected_commit,
        actual_commit=actual,
        origin=origin,
        status=status,
    )


def _normalized_path(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def trusted_user_profile() -> Path:
    if os.name != "nt":
        return Path.home().resolve()
    import ctypes

    buffer = ctypes.create_unicode_buffer(32768)
    result = ctypes.windll.shell32.SHGetFolderPathW(None, 40, None, 0, buffer)
    require(result == 0 and bool(buffer.value), "Windows user profile is unavailable")
    profile = Path(buffer.value)
    require(profile.is_absolute(), "Windows user profile is not absolute")
    return profile


def _is_reparse_point(path: Path) -> bool:
    if os.name != "nt":
        return path.is_symlink()
    attributes = getattr(os.lstat(path), "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def require_no_reparse_points(path: Path, trusted_root: Path) -> None:
    candidate = _normalized_path(path)
    root = _normalized_path(trusted_root)
    try:
        common = os.path.commonpath((root, candidate))
    except ValueError as exc:
        raise CanaryError("runtime path is outside the trusted root") from exc
    require(common == root, "runtime path is outside the trusted root")
    current = Path(trusted_root)
    relative_parts = Path(os.path.relpath(candidate, root)).parts
    for part in (".", *relative_parts):
        if part != ".":
            current /= part
        require(os.path.lexists(current), "runtime path component is missing")
        require(not _is_reparse_point(current), "runtime path contains a reparse point")


@contextmanager
def lock_non_reparse_path(path: Path, trusted_root: Path) -> Iterator[None]:
    """Hold delete locks on a Windows path chain while it is inspected by name."""
    candidate = _normalized_path(path)
    root = _normalized_path(trusted_root)
    try:
        common = os.path.commonpath((root, candidate))
    except ValueError as exc:
        raise CanaryError("runtime path is outside the trusted root") from exc
    require(common == root, "runtime path is outside the trusted root")
    if os.name != "nt":
        require_no_reparse_points(path, trusted_root)
        yield
        return

    import ctypes
    from ctypes import wintypes

    class FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [("file_attributes", wintypes.DWORD), ("reparse_tag", wintypes.DWORD)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    get_information = kernel32.GetFileInformationByHandleEx
    get_information.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    get_information.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    open_existing = 3
    share_read = 0x00000001
    share_write = 0x00000002
    open_reparse_point = 0x00200000
    backup_semantics = 0x02000000
    attribute_directory = 0x00000010
    attribute_reparse_point = 0x00000400
    invalid_handle = ctypes.c_void_p(-1).value

    components = [Path(root)]
    current = components[0]
    relative_parts = Path(os.path.relpath(candidate, root)).parts
    for part in relative_parts:
        if part == ".":
            continue
        current /= part
        components.append(current)

    handles: list[int] = []
    try:
        for index, component in enumerate(components):
            is_file = index == len(components) - 1
            share_mode = share_read if is_file else share_read | share_write
            flags = open_reparse_point if is_file else open_reparse_point | backup_semantics
            handle = create_file(
                str(component),
                0,
                share_mode,
                None,
                open_existing,
                flags,
                None,
            )
            if handle in (None, invalid_handle):
                error = ctypes.get_last_error()
                profile_is_trust_anchor = (
                    index == 0
                    and root == _normalized_path(trusted_user_profile())
                    and error == 5
                )
                if profile_is_trust_anchor:
                    require(
                        not _is_reparse_point(component),
                        "Windows user profile contains a reparse point",
                    )
                    continue
                raise CanaryError(
                    f"unable to lock runtime path component against replacement (WinError {error})"
                )
            handles.append(handle)
            information = FileAttributeTagInfo()
            if not get_information(
                handle,
                9,
                ctypes.byref(information),
                ctypes.sizeof(information),
            ):
                error = ctypes.get_last_error()
                raise CanaryError(f"unable to inspect runtime path component (WinError {error})")
            require(
                not information.file_attributes & attribute_reparse_point,
                "runtime path contains a reparse point",
            )
            if is_file:
                require(
                    not information.file_attributes & attribute_directory,
                    "runtime interpreter is not a regular file",
                )
            else:
                require(
                    bool(information.file_attributes & attribute_directory),
                    "runtime path component is not a directory",
                )
        yield
    finally:
        for handle in reversed(handles):
            close_handle(handle)


def probe_windows_file_version(interpreter: Path, cwd: Path) -> str:
    require(os.name == "nt", "Windows file-version probing requires Windows")
    command = (
        "$info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($args[0]); "
        "if ([string]::IsNullOrWhiteSpace($info.FileVersion)) { exit 2 }; "
        "$info.FileVersion"
    )
    return run_command(
        Path("pwsh"),
        ["-NoProfile", "-NonInteractive", "-CommandWithArgs", command, str(interpreter)],
        cwd=cwd,
    )


def validate_runtime_manifest(
    manifest_path: Path,
    *,
    expected_runtime_root: Path,
    trusted_root: Path,
    version_probe: Callable[[Path], str] | None = None,
) -> dict[str, Any]:
    require(manifest_path.is_file(), "plugin runtime.json is missing")
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CanaryError("plugin runtime.json is not valid UTF-8 JSON") from exc
    require(isinstance(payload, dict), "plugin runtime.json must contain an object")
    required_fields = {"schema_version", "interpreter", "python_version", "runtime_root", "configured_at"}
    require(set(payload) == required_fields, "plugin runtime.json fields do not match schema version 1")
    require(payload.get("schema_version") == 1, "plugin runtime.json schema version is not 1")
    python_version = payload.get("python_version")
    require(
        isinstance(python_version, str) and bool(re.fullmatch(r"3\.12\.\d+", python_version)),
        "plugin runtime must use Python 3.12",
    )
    interpreter_text = payload.get("interpreter")
    runtime_root_text = payload.get("runtime_root")
    require(
        isinstance(interpreter_text, str) and Path(interpreter_text).is_absolute(),
        "runtime interpreter must be absolute",
    )
    require(
        isinstance(runtime_root_text, str) and Path(runtime_root_text).is_absolute(),
        "runtime root must be absolute",
    )
    runtime_root = Path(runtime_root_text)
    require(
        _normalized_path(runtime_root) == _normalized_path(expected_runtime_root),
        "runtime root is not the trusted plugin runtime root",
    )
    interpreter = Path(interpreter_text)
    require(interpreter.name.lower() == "python.exe", "runtime interpreter filename is invalid")
    require(interpreter.parent.name.lower() == "scripts", "runtime interpreter layout is invalid")
    runtime_id = interpreter.parent.parent.name
    require(bool(re.fullmatch(r"py312-[0-9a-f]{16}", runtime_id)), "runtime identifier is invalid")
    expected_interpreter = expected_runtime_root / "versions" / runtime_id / "Scripts" / "python.exe"
    require(
        _normalized_path(interpreter) == _normalized_path(expected_interpreter),
        "runtime interpreter is not in the trusted runtime layout",
    )
    with lock_non_reparse_path(interpreter, trusted_root):
        require(interpreter.is_file(), "runtime interpreter does not exist")
        if version_probe is not None:
            actual_version = version_probe(interpreter).strip()
            require(actual_version == python_version, "runtime interpreter version does not match runtime.json")
    configured_at = payload.get("configured_at")
    require(isinstance(configured_at, str) and configured_at.endswith("Z"), "runtime configured_at is invalid")
    try:
        configured = datetime.fromisoformat(configured_at.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise CanaryError("runtime configured_at is invalid") from exc
    require(configured.utcoffset() == UTC.utcoffset(configured), "runtime configured_at is invalid")
    return {
        "schema_version": 1,
        "python_version": python_version,
        "runtime_id": runtime_id,
        "trusted_layout": True,
        "interpreter_exists": True,
        "configured": True,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def compare_artifact_hashes(expected_root: Path, installed_root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for relative in ARTIFACT_PATHS:
        expected = expected_root / relative
        installed = installed_root / relative
        require(expected.is_file(), f"expected artifact is missing: {relative.as_posix()}")
        require(installed.is_file(), f"installed artifact is missing: {relative.as_posix()}")
        expected_hash = _sha256(expected)
        installed_hash = _sha256(installed)
        require(expected_hash == installed_hash, f"artifact hash mismatch: {relative.as_posix()}")
        result[relative.as_posix()] = {
            "expected_sha256": expected_hash,
            "installed_sha256": installed_hash,
            "matches": True,
        }
    return result


def discover_installed_root(codex_home: Path, marketplace: str, plugin: str, version: str) -> Path:
    version_root = codex_home / "plugins" / "cache" / marketplace / plugin / version
    require(version_root.is_dir(), "installed plugin cache directory is missing")
    return version_root


def discover_plugin_data(codex_home: Path, plugin: str, marketplace: str) -> Path:
    expected_name = f"{plugin}-{marketplace}"
    expected = codex_home / "plugins" / "data" / expected_name
    configured = os.environ.get("PLUGIN_DATA")
    if configured:
        candidate = Path(configured).expanduser()
        require(candidate.is_absolute(), "PLUGIN_DATA must be absolute")
        require(candidate.is_dir(), "PLUGIN_DATA directory is missing")
        require(
            candidate.resolve() == expected.resolve(),
            "PLUGIN_DATA does not match the active plugin selector path",
        )
        return candidate
    require(expected.parent.is_dir(), "plugin data directory is missing")
    require(expected.is_dir(), "active plugin data directory is missing")
    return expected


def plugin_data_inventory(codex_home: Path, plugin: str, marketplace: str) -> dict[str, Any]:
    root = codex_home / "plugins" / "data"
    require(root.is_dir(), "plugin data directory is missing")
    active_name = f"{plugin}-{marketplace}"
    active = root / active_name
    require(active.is_dir(), "active plugin data directory is missing")

    legacy_candidates = [
        candidate
        for candidate in root.iterdir()
        if candidate.name != active_name
        and (candidate.name == plugin or candidate.name.startswith(f"{plugin}-"))
        and candidate.is_dir()
        and not _is_reparse_point(candidate)
    ]
    return {
        "active_directory_name": active_name,
        "active_runtime_manifest_exists": (active / "runtime.json").is_file(),
        "active_state_file_count": sum(1 for _path in active.glob("session-*.json")),
        "legacy_candidate_count": len(legacy_candidates),
        "legacy_runtime_manifest_count": sum(
            1 for candidate in legacy_candidates if (candidate / "runtime.json").is_file()
        ),
        "legacy_state_file_count": sum(
            1 for candidate in legacy_candidates for _path in candidate.glob("session-*.json")
        ),
    }


def sanitize_evidence(value: Any, path_replacements: dict[str, str]) -> tuple[Any, int]:
    replacements = 0
    ordered_paths = sorted(
        ((path, replacement) for path, replacement in path_replacements.items() if path),
        key=lambda row: len(row[0]),
        reverse=True,
    )

    def sanitize(item: Any, key: str | None = None) -> Any:
        nonlocal replacements
        if key is not None and SENSITIVE_KEY.search(key):
            replacements += 1
            return "<redacted-sensitive>"
        if isinstance(item, dict):
            return {str(child_key): sanitize(child, str(child_key)) for child_key, child in item.items()}
        if isinstance(item, list):
            return [sanitize(child) for child in item]
        if isinstance(item, str):
            text = item
            for path, replacement in ordered_paths:
                text, count = re.subn(re.escape(path), lambda _match: replacement, text, flags=re.IGNORECASE)
                replacements += count
            return text
        return item

    return sanitize(value), replacements


def find_sensitive_residuals(value: Any) -> list[str]:
    findings: set[str] = set()

    def inspect(item: Any, key: str | None = None) -> None:
        if key is not None and SENSITIVE_KEY.search(key) and item != "<redacted-sensitive>":
            findings.add("sensitive field")
        if isinstance(item, dict):
            for child_key, child in item.items():
                inspect(child, str(child_key))
        elif isinstance(item, list):
            for child in item:
                inspect(child)
        elif isinstance(item, str):
            if any(pattern.search(item) for pattern in ABSOLUTE_PATH_PATTERNS):
                findings.add("absolute path")
            if CREDENTIAL_VALUE.search(item):
                findings.add("credential-like value")

    inspect(value)
    return sorted(findings)


def parse_scenarios(values: list[str]) -> dict[str, str]:
    scenarios = {name: "not_recorded" for name in REQUIRED_SCENARIOS}
    for item in values:
        name, separator, status = item.partition("=")
        require(bool(separator) and bool(re.fullmatch(r"[a-z][a-z0-9_]*", name)), "scenario must use name=status")
        require(name in scenarios, f"unknown canary scenario: {name}")
        require(status in SCENARIO_STATUSES, f"invalid canary scenario status: {status}")
        require(scenarios[name] == "not_recorded", f"duplicate canary scenario: {name}")
        scenarios[name] = status
    return scenarios


def safe_allow_attribution(
    hook_response: str | None,
    host_approval_mode: str | None,
    scenarios: dict[str, str],
) -> dict[str, str] | None:
    provided = (hook_response is not None, host_approval_mode is not None)
    require(provided[0] == provided[1], "safe Hook response and host approval mode must be provided together")
    if not any(provided):
        return None
    require(scenarios.get("safe_allow") == "passed", "safe attribution requires safe_allow=passed")
    require(hook_response == "no_decision", "safe Hook response must be no_decision")
    require(bool(host_approval_mode and host_approval_mode.strip()), "host approval mode must not be blank")
    return {
        "hook_response": hook_response,
        "host_approval_mode": host_approval_mode,
    }


def evidence_ready(app_version: str, bundled_cli_version: str, scenarios: dict[str, str], phase: str) -> bool:
    required = FEATURE_REQUIRED_SCENARIOS if phase == "feature" else MERGED_REQUIRED_SCENARIOS
    return (
        app_version != "not_recorded"
        and bundled_cli_version != "not_recorded"
        and all(scenarios.get(name) == "passed" for name in required)
    )


def _codex_json(codex: Path, arguments: list[str], label: str, cwd: Path) -> Any:
    return parse_json_output(run_command(codex, [*CLI_BASE, *arguments], cwd=cwd), label)


def _tool_versions(codex: Path, checkout: Path) -> dict[str, str]:
    pwsh = Path("pwsh")
    powershell_version = run_command(
        pwsh,
        ["-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.ToString()"],
        cwd=checkout,
    )
    external = shutil.which("codex")
    external_version = (
        run_command(Path(external), ["--version"], cwd=checkout)
        if external is not None
        else "not_available"
    )
    return {
        "app_bundled_cli": run_command(codex, ["--version"], cwd=checkout),
        "external_codex_cli": external_version,
        "powershell": powershell_version,
        "collector_python": ".".join(str(part) for part in sys.version_info[:3]),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", required=True, type=Path, help="Absolute Codex App bundled CLI path")
    parser.add_argument("--expected-checkout", required=True, type=Path, help="Clean checkout used for hash comparison")
    parser.add_argument("--expected-commit", required=True, help="Full 40-character commit SHA")
    parser.add_argument(
        "--marketplace", required=True, choices=(PLUGIN_NAME,), help="Expected single marketplace name"
    )
    parser.add_argument("--plugin", required=True, choices=(PLUGIN_NAME,), help="Expected single plugin name")
    parser.add_argument("--output", required=True, type=Path, help="JSON evidence output path")
    parser.add_argument("--phase", choices=("feature", "merged"), default="feature")
    parser.add_argument("--app-version", default="not_recorded", help="Version reported by the Codex App")
    parser.add_argument(
        "--bundled-cli-version",
        default="not_recorded",
        help="CLI version reported inside the Codex App",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        default=[],
        metavar="NAME=STATUS",
        help="Record a canary scenario as passed, failed, not_run, or not_recorded",
    )
    parser.add_argument(
        "--safe-hook-response",
        choices=("no_decision",),
        help="Optional protocol result for the safe_allow probe",
    )
    parser.add_argument(
        "--host-approval-mode",
        help="Optional Codex App approval mode used for the safe_allow probe",
    )
    return parser


def collect_evidence(args: argparse.Namespace) -> dict[str, Any]:
    codex = args.codex.expanduser()
    checkout = args.expected_checkout.expanduser().resolve()
    output = args.output.expanduser().resolve()
    require(codex.is_absolute(), "--codex must be an absolute path")
    require(codex.is_file(), "--codex does not identify a file")
    require(checkout.is_dir(), "--expected-checkout does not identify a directory")

    checkout_summary = checkout_metadata(checkout, args.expected_commit)
    marketplace_payload = _codex_json(
        codex,
        ["plugin", "marketplace", "list", "--json"],
        "plugin marketplace list",
        checkout,
    )
    plugin_payload = _codex_json(codex, ["plugin", "list", "--json"], "plugin list", checkout)
    inventory = validate_inventory(
        marketplace_payload,
        plugin_payload,
        marketplace=args.marketplace,
        plugin=args.plugin,
    )

    codex_home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))).expanduser().resolve()
    installed_root = discover_installed_root(
        codex_home,
        args.marketplace,
        args.plugin,
        inventory["version"],
    )
    plugin_data = discover_plugin_data(codex_home, args.plugin, args.marketplace)
    user_profile = trusted_user_profile()
    runtime = validate_runtime_manifest(
        plugin_data / "runtime.json",
        expected_runtime_root=user_profile / ".codex" / "runtimes" / args.plugin,
        trusted_root=user_profile,
        version_probe=lambda interpreter: probe_windows_file_version(interpreter, checkout),
    )
    expected_plugin_root = checkout / "plugins" / args.plugin
    artifacts = compare_artifact_hashes(expected_plugin_root, installed_root)
    installed_manifest = json.loads((installed_root / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    app_hooks = collect_app_hook_inventory(
        codex,
        codex_home=codex_home,
        cwd=checkout,
        manifest=installed_manifest,
        selector=inventory["selector"],
    )
    scenarios = parse_scenarios(args.scenario)
    safe_attribution = safe_allow_attribution(
        args.safe_hook_response,
        args.host_approval_mode,
        scenarios,
    )
    versions = _tool_versions(codex, checkout)
    if args.bundled_cli_version != "not_recorded":
        require(
            args.bundled_cli_version in versions["app_bundled_cli"],
            "recorded bundled CLI version does not match the App bundled executable",
        )

    evidence: dict[str, Any] = {
        "schema_version": 1,
        "captured_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "phase": args.phase,
        "authorized_source": {
            **checkout_summary,
            "marketplace_ref_visibility": "not_reported_by_codex_cli_0.146",
            "verification_method": "marketplace_source+checkout_sha+installed_artifact_sha256",
        },
        "versions": {
            "codex_app": args.app_version,
            **versions,
            "plugin_runtime_python": runtime["python_version"],
        },
        "inventory": inventory,
        "app_hooks": app_hooks,
        "plugin_data": plugin_data_inventory(codex_home, args.plugin, args.marketplace),
        "runtime": runtime,
        "artifacts": artifacts,
        "scenarios": scenarios,
        "ready": evidence_ready(
            args.app_version,
            versions["app_bundled_cli"],
            scenarios,
            args.phase,
        ),
    }
    if safe_attribution is not None:
        evidence["safe_allow_attribution"] = safe_attribution
    sanitized, replacements = sanitize_evidence(
        evidence,
        {
            str(plugin_data): "<PLUGIN_DATA>",
            str(installed_root): "<PLUGIN_CACHE>",
            str(codex_home): "<CODEX_HOME>",
            str(checkout): "<WORKSPACE>",
            str(Path.home()): "<USER_HOME>",
        },
    )
    require(isinstance(sanitized, dict), "sanitized evidence must remain an object")
    residuals = find_sensitive_residuals(sanitized)
    require(not residuals, f"evidence contains sensitive residuals: {', '.join(residuals)}")
    sanitized["redaction"] = {
        "passed": True,
        "replacement_count": replacements,
        "residual_scan": "passed",
    }
    serialized = json.dumps(sanitized, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    for raw_path in (str(plugin_data), str(installed_root), str(codex_home), str(checkout), str(Path.home())):
        require(raw_path.lower() not in serialized.lower(), "evidence still contains a private absolute path")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(serialized, encoding="utf-8")
    return sanitized


def main() -> int:
    args = build_parser().parse_args()
    try:
        evidence = collect_evidence(args)
    except CanaryError as exc:
        print(f"Codex App canary evidence failed: {exc}", file=sys.stderr)
        return 1
    print(f"Codex App canary evidence captured; ready={str(evidence['ready']).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
