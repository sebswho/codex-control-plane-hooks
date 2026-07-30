#!/usr/bin/env python3
"""Deterministic, local-first lifecycle guardrails for Codex plugins."""

from __future__ import annotations

import ast
import hashlib
import importlib
import json
import os
import re
import runpy
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import types
from collections.abc import Sequence
from pathlib import Path
from typing import Any

_BOOTSTRAP_PATH = Path(__file__).parent / "control_plane" / "bootstrap.py"
_configure_package = runpy.run_path(str(_BOOTSTRAP_PATH))["configure_package"]
_configure_package(__file__)

_core_module = importlib.import_module("control_plane.core")

# Compatibility exports for callers of the legacy internal module.
from control_plane.core import (  # noqa: E402, F401
    _ABSOLUTE_PATH_RE,
    _ASSIGNMENT_RE,
    _AUTH_GIT_CONTINUATION_RE,
    _AUTH_NEGATED_RE,
    _AUTH_SEGMENT_SPLIT_RE,
    _AUTHORIZATION_REVOCATION_RE,
    _AUTHORIZED_TRANSACTION_CONTINUATION_RE,
    _CHINESE_GIT_OPERATION_LIST_RE,
    _CHINESE_GIT_OPERATION_MAP,
    _COMMAND_EXECUTABLES,
    _COMMAND_NEGATION_RE,
    _COMMAND_START_RE,
    _CONSTRAINED_CLONE_BOOLEAN_OPTIONS,
    _CONSTRAINED_CLONE_DESTINATION_META,
    _CONSTRAINED_CLONE_POSIX_BROAD_ROOTS,
    _CONSTRAINED_CLONE_POSIX_SYSTEM_ROOTS,
    _CONSTRAINED_CLONE_SENSITIVE_COMPONENTS,
    _CONTROL_TOKENS,
    _CURRENT_EXPANSION_AUTH_RE,
    _CURRENT_EXPANSION_RE,
    _CURRENT_REPO_RE,
    _DANGEROUS_APPROVAL_RE,
    _EXACT_PUSH_BOOLEAN_OPTIONS,
    _EXACT_PUSH_OPTIONAL_VALUE_PREFIXES,
    _EXACT_PUSH_VALUE_OPTIONS,
    _EXACT_PUSH_VALUE_PREFIXES,
    _EXPANSION_NEGATED_RE,
    _EXTERNAL_TARGET_PATTERNS,
    _GIT_GLOBAL_FLAGS,
    _GIT_GLOBAL_VALUE_FLAGS,
    _GIT_NETWORK_SUBCOMMANDS,
    _GIT_OPERATION_LIST_RE,
    _GIT_SCOPE_FLAGS,
    _GITHUB_CREATE_COMMAND_RE,
    _GITHUB_CREATE_INTENT_RE,
    _GITHUB_OWNER_CONTEXT_RE,
    _GITHUB_REPO_NAME_RE,
    _INTERPRETER_EVAL_FLAGS,
    _LOCAL_GIT_APPROVAL_RE,
    _MCP_TARGET_CANDIDATE_RE,
    _MCP_TARGET_TOKEN_RE,
    _MCP_TARGET_TRAILING_PUNCTUATION,
    _NEGATED_AUTH_COMMENT_RE,
    _NEGATED_GIT_OPERATION_RE,
    _NESTED_AUTH_RE,
    _PACKAGE_INSTALL_SUBCOMMANDS,
    _PACKAGE_RUNNER_SUBCOMMANDS,
    _PACKAGE_VALUE_OPTIONS,
    _PENDING_COMMAND_REFERENCE_RE,
    _PENDING_GIT_TTL_SECONDS,
    _POWERSHELL_ENVIRONMENT_OPTIONS,
    _POWERSHELL_READ_ONLY_COMMANDS,
    _POWERSHELL_SAFE_SWITCHES,
    _POWERSHELL_TERMINAL_SWITCHES,
    _POWERSHELL_VALUE_OPTIONS,
    _PRIVILEGE_WRAPPERS,
    _PROMPT_EXTERNAL_TARGET_PATTERNS,
    _PROMPT_TARGET_TERMINAL_PUNCTUATION,
    _QUOTED_ABSOLUTE_PATH_RE,
    _QUOTED_WINDOWS_EXECUTABLE_RE,
    _READ_ONLY_COMMANDS,
    _READ_ONLY_GIT_CONFIG_QUERIES,
    _READ_ONLY_GIT_CONFIG_SCOPES,
    _READ_ONLY_GIT_SUBCOMMANDS,
    _SCOPED_GIT_OPERATIONS,
    _SCOPED_GIT_TRANSACTION_TTL_SECONDS,
    _SCOPED_PUSH_OPTIONS,
    _SCOPED_TRANSACTION_OPERATIONS,
    _SECRET_PATTERNS,
    _SENSITIVE_ENV_NAMES,
    _SENSITIVE_EXPLICIT_AUTH_RE,
    _SENSITIVE_EXTERNAL_VERB_RE,
    _SENSITIVE_NEGATION_RE,
    _SHELL_CONTROL_RE,
    _SHELL_EVAL,
    _SYSTEM_PACKAGE_ACTIONS,
    _SYSTEM_PACKAGE_VALUE_OPTIONS,
    _TERM_NEGATION_POSTFIX_RE,
    _TERM_NEGATION_SUFFIX_RE,
    _TRUSTED_MCP_MULTIPLEXER_TARGET_PREFIXES,
    _TRUSTED_MCP_SERVER_TARGETS,
    _URI_SPAN_RE,
    _WINDOWS_ABSOLUTE_PATH_RE,
    _WINDOWS_ENV_EXPANSION_RE,
    _WINDOWS_INLINE_GIT_GLOBAL_VALUE_RE,
    SEVERITY_ORDER,
    _authorization_clauses,
    _authorization_command_candidates,
    _authorization_prose,
    _authorized_git_command_scopes,
    _before_option_terminator,
    _bounded_term_source,
    _branch_short_options_mutate,
    _clone_destination_allowed,
    _clone_parent_access_mode,
    _clone_path_has_sensitive_component,
    _clone_path_is_system_sensitive,
    _clone_workspace_root,
    _command_hash,
    _command_path_candidates,
    _command_uses_untrusted_clone,
    _constrained_github_clone_candidate,
    _context,
    _continued_git_grant_from_prompt,
    _dangerous_authorization_hashes,
    _dangerous_codes,
    _dedupe_findings,
    _exact_github_clone_candidate,
    _exact_push_remote,
    _executable_name,
    _explicit_expand,
    _explicit_git_operation_list,
    _external_target_scope_from_prompt,
    _external_targets_from_tool_name,
    _fallback_scan_text,
    _finding,
    _git_authorization_text,
    _git_command,
    _git_config_values,
    _git_grant_effective_operations,
    _git_grant_usable,
    _git_is_read_only,
    _git_push_url_identity,
    _git_remote_command,
    _git_remote_identities,
    _git_remote_targets,
    _git_remote_urls,
    _git_repo_root,
    _git_scope_and_args,
    _git_transaction_continuation_commands_safe,
    _git_transaction_resume_requested,
    _git_uses_network,
    _github_https_clone_target,
    _github_target_from_remote,
    _has_option_before_terminator,
    _has_shell_indirection,
    _has_short_flag,
    _has_unquoted_shell_comment,
    _is_literal_powershell_call_target,
    _is_literal_powershell_script_target,
    _is_reparse_info,
    _is_repository_identity_config_command,
    _is_shell_eval_flag,
    _is_strict_identity_amend_command,
    _is_strictly_read_only_command,
    _local_git_grant_from_prompt,
    _looks_like_git_clone,
    _looks_like_windows_command,
    _matches_eval_flag,
    _matches_policy_values,
    _matching_grant_term_hashes,
    _nested_allowed,
    _normalize_git_global_arg,
    _normalized_cwd,
    _ordered_unique,
    _parse_github_create_candidate,
    _path_within,
    _pending_git_usable,
    _policy_value_hash,
    _powershell_launcher_findings,
    _powershell_option,
    _powershell_runas_requested,
    _prompt_absolute_paths,
    _prompt_clone_candidates,
    _prompt_command_scopes,
    _prompt_git_operation_digests,
    _prompt_git_operations,
    _prompt_git_scopes,
    _prompt_github_create_candidate,
    _prompt_github_mappings,
    _prompt_github_targets,
    _prompt_has_unresolved_git_scope_override,
    _prompt_init_branch,
    _prompt_push_target,
    _prompt_target_match_is_delimited,
    _prompt_target_start_is_delimited,
    _pure_authorization_command_candidates,
    _safe_branch_name,
    _safe_clone_branch,
    _safe_git_push_url,
    _safe_push_target,
    _scan_text,
    _scope_hash,
    _scope_identity,
    _scoped_git_candidate,
    _secret_found,
    _sed_command_body,
    _sed_delimited_end,
    _sed_is_strictly_read_only,
    _sed_script_is_strictly_read_only,
    _sed_substitution_is_read_only,
    _segment_findings,
    _sensitive_context,
    _sensitive_disclosure_grant,
    _session_id,
    _shell_tokens,
    _skip_options,
    _split_shell_commands,
    _strip_token_quotes,
    _structured_command_findings,
    _subcommand_after_options,
    _tokens_before_separator,
    _tracked_clone_roots,
    _transaction_operation_from_command,
    _trusted_executable_token,
    _unwrap_command,
    _windows_segment_findings,
    policy_store,
    state_store,
)

_CORE_SHARED_EXPORTS = frozenset(
    name
    for name, value in vars(_core_module).items()
    if name in globals() and globals()[name] is value
)


class _LegacyModule(types.ModuleType):
    """Keep legacy monkey-patching compatible with functions moved to core."""

    def __setattr__(self, name: str, value: Any) -> None:
        super().__setattr__(name, value)
        if name in _CORE_SHARED_EXPORTS:
            setattr(_core_module, name, value)


sys.modules[__name__].__class__ = _LegacyModule

user_prompt_submit_handler = importlib.import_module(
    "control_plane.handlers.user_prompt_submit"
)


MAX_SCAN_CHARS = 500_000
MAX_POLICY_BYTES = 64_000
_PYTHON_SOURCE_SUFFIXES = {".py", ".pyi"}
_LOCAL_SOURCE_READ_EXECUTABLES = {"nl", "rg", "sed"}

_CREDENTIAL_ASSIGNMENT_DETAIL_RE = re.compile(
    r"(?i)\b(?P<label>api[_-]?key|token|secret|password|client[_-]?secret|access[_-]?key)"
    r"\s*(?P<separator>[:=])\s*(?P<quote>['\"]?)(?P<value>[A-Za-z0-9_./+=:-]{16,})"
)
_REDACTION_PLACEHOLDER_RE = re.compile(
    r"(?i)\{\{[ \t]*(?:redacted|removed|masked|omitted)[ \t]*\}\}"
)
_GENERIC_ASSIGNMENT_RE = re.compile(
    r"(?:^|[,，;；|{\[])[ \t]*"
    r"(?P<quote>[\"']?)(?P<label>(?!\d)\w(?:[\w .-]{0,62}\w)?)(?P=quote)"
    r"[ \t\r\n]*[:：=]",
    re.MULTILINE,
)
_EXTERNAL_TOOL_RE = re.compile(
    r"(?i)(gmail|google|drive|notion|slack|teams|outlook|canva|github|browser|chrome|web|upload|send|post|publish|share)"
)
_EXTERNAL_COMMAND_RE = re.compile(
    r"(?i)\b(curl|wget|scp|sftp|ssh|rsync|rclone|aws|gcloud|gsutil|az|azcopy|gh|"
    r"nc|netcat|ncat|socat|lftp|ftp|aria2c|open|osascript|invoke-webrequest|"
    r"invoke-restmethod|start-bitstransfer|bitsadmin)\b|"
    r"\bcertutil\b[^\r\n]*\s-urlcache\b|\bgit\s+push\b"
)
_DURABLE_DESTINATION_RE = re.compile(
    r"(?i)([\\/]\.codex[\\/](?:memories|skills)|[\\/]\.claude[\\/].*[\\/]memory|"
    r"marketplace|public|publish)"
)
_GIT_RUNNER_TTL_SECONDS = 5 * 60
_GIT_RUNNER_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
_EMPTY_GIT_URL_REWRITE_SNAPSHOT = hashlib.sha256(b"[]").hexdigest()
_SCOPED_PUSH_UPSTREAM_OPTIONS = frozenset({"-u", "--set-upstream"})
_TRUSTED_EXEC_COMMAND_SHELLS = {"/bin/bash", "/bin/sh", "/bin/zsh"}
_TRUSTED_WINDOWS_EXEC_COMMAND_SHELLS = {"bash", "cmd", "powershell", "pwsh", "sh"}
_EXEC_COMMAND_ALLOWED_FIELDS = frozenset(
    "cmd command justification login max_output_tokens sandbox_permissions shell tty "
    "workdir yield_time_ms".split()
)


def _trusted_exec_command_shell(shell: str) -> bool:
    if shell in _TRUSTED_EXEC_COMMAND_SHELLS:
        return True
    if os.name != "nt" or _executable_name(shell) not in _TRUSTED_WINDOWS_EXEC_COMMAND_SHELLS:
        return False
    if not any(separator in shell for separator in ("/", "\\")):
        return True
    resolved = shutil.which(_executable_name(shell)) or shutil.which(
        f"{_executable_name(shell)}.exe"
    )
    return bool(
        resolved
        and os.path.normcase(os.path.realpath(shell))
        == os.path.normcase(os.path.realpath(resolved))
    )


def _tool_family(tool_name: str) -> str:
    lowered = tool_name.casefold()
    if lowered == "bash":
        return "bash"
    if lowered == "exec_command" or lowered.endswith("__exec_command"):
        return "exec_command"
    return lowered


def _is_exec_command_tool(tool_name: str) -> bool:
    lowered = tool_name.casefold()
    return lowered == "exec_command" or lowered.endswith("__exec_command")


def _exec_command_validation_error(tool_name: str, tool_input: Any) -> str:
    if not _is_exec_command_tool(tool_name):
        return ""
    if not isinstance(tool_input, dict):
        return "exec_command input must be an object"
    if "prefix_rule" in tool_input:
        return "exec_command prefix_rule is not accepted by the hook"
    unknown = sorted(set(tool_input) - _EXEC_COMMAND_ALLOWED_FIELDS)
    if unknown:
        return "exec_command contains unknown fields: " + ", ".join(unknown)
    command_fields = [key for key in ("cmd", "command") if key in tool_input]
    if len(command_fields) != 1 or not isinstance(tool_input.get(command_fields[0]), str):
        return "exec_command requires exactly one string command field"
    if "shell" in tool_input:
        shell = tool_input.get("shell")
        if not isinstance(shell, str) or not _trusted_exec_command_shell(shell):
            return "exec_command shell override is not trusted"
    if "login" in tool_input and not isinstance(tool_input.get("login"), bool):
        return "exec_command login must be boolean"
    if "tty" in tool_input and not isinstance(tool_input.get("tty"), bool):
        return "exec_command tty must be boolean"
    if "workdir" in tool_input and (
        not isinstance(tool_input.get("workdir"), str) or not tool_input.get("workdir")
    ):
        return "exec_command workdir must be a nonempty string"
    if "justification" in tool_input and not isinstance(tool_input.get("justification"), str):
        return "exec_command justification must be a string"
    for key in ("max_output_tokens", "yield_time_ms"):
        if key in tool_input and (
            not isinstance(tool_input.get(key), int)
            or isinstance(tool_input.get(key), bool)
            or int(tool_input[key]) < 0
        ):
            return f"exec_command {key} must be a nonnegative integer"
    sandbox = tool_input.get("sandbox_permissions", "use_default")
    if sandbox not in {"use_default", "require_escalated"}:
        return "exec_command sandbox_permissions is invalid"
    return ""


def _execution_options_digest(tool_name: str, tool_input: Any) -> str:
    if not _is_exec_command_tool(tool_name):
        return hashlib.sha256(b"{}").hexdigest()
    if not isinstance(tool_input, dict):
        return ""
    options = {
        "login_present": "login" in tool_input,
        "login": tool_input.get("login", True),
        "sandbox_permissions_present": "sandbox_permissions" in tool_input,
        "sandbox_permissions": tool_input.get("sandbox_permissions", "use_default"),
        "shell_present": "shell" in tool_input,
        "shell": tool_input.get("shell") or "",
        "tty_present": "tty" in tool_input,
        "tty": tool_input.get("tty", False),
        "workdir_present": "workdir" in tool_input,
        "workdir": _normalized_cwd(str(tool_input.get("workdir") or ".")),
    }
    encoded = json.dumps(options, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _python_source_path(value: str, cwd: str) -> Path | None:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path(cwd) / path
    try:
        info = path.lstat()
        if (
            path.is_symlink()
            or _is_reparse_info(info)
            or path.suffix.casefold() not in _PYTHON_SOURCE_SUFFIXES
            or not stat.S_ISREG(info.st_mode)
        ):
            return None
        return path.resolve(strict=True)
    except OSError:
        return None


def _source_reader_operands(executable: str, args: list[str]) -> list[str] | None:
    if executable == "nl":
        operands = args[1:] if args[:1] == ["-ba"] else args
        return operands if len(operands) == 1 and not operands[0].startswith("-") else None
    if executable in {"sed", "rg"}:
        flags = {"-n", "--quiet", "--silent"} if executable == "sed" else {"-n", "--line-number"}
        operands = args[1:] if args[:1] and args[0] in flags else args
        return operands[1:] if len(operands) == 2 and not operands[0].startswith("-") else None
    return None


def _local_python_source_read_path(event: dict[str, Any]) -> Path | None:
    tool_name = str(event.get("tool_name") or "")
    tool_input = event.get("tool_input") or {}
    cwd = (
        str(tool_input.get("workdir") or event.get("cwd") or ".")
        if isinstance(tool_input, dict)
        else str(event.get("cwd") or ".")
    )
    if tool_name == "Read" and isinstance(tool_input, dict):
        path = str(tool_input.get("file_path") or tool_input.get("path") or "")
        return _python_source_path(path, cwd) if path else None
    if _tool_family(tool_name) not in {"bash", "exec_command"} or not isinstance(tool_input, dict):
        return None
    command = str(tool_input.get("command") or tool_input.get("cmd") or "")
    commands, operators = _split_shell_commands(
        _shell_tokens(command), windows_style=_looks_like_windows_command(command)
    )
    if len(commands) != 1 or operators:
        return None
    executable, args, wrappers = _unwrap_command(commands[0])
    if wrappers or executable not in _LOCAL_SOURCE_READ_EXECUTABLES:
        return None
    operands = _source_reader_operands(executable, args)
    if operands is None or len(operands) != 1:
        return None
    return _python_source_path(operands[0], cwd)


def _python_callable_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _python_callable_name(node.value)
        return f"{parent}.{node.attr}" if parent else ""
    return ""


def _source_contains_call_line(source_path: Path, source_line: str) -> bool:
    try:
        with source_path.open("r", encoding="utf-8", errors="replace") as handle:
            return any(source_line in line for line in handle)
    except OSError:
        return False


def _credential_assignment_is_code_call(
    text: str,
    match: re.Match[str],
    source_path: Path,
) -> bool:
    detail = _CREDENTIAL_ASSIGNMENT_DETAIL_RE.search(match.group(0))
    if (
        not detail
        or detail.group("separator") != "="
        or detail.group("quote")
        or not detail.group("label").islower()
    ):
        return False
    value = detail.group("value")
    callable_identifier = re.fullmatch(
        r"_?[a-z][a-z0-9]*(?:_[a-z0-9]+)+(?:\._?[a-z][a-z0-9]*(?:_[a-z0-9]+)+)*",
        value,
    )
    tail = text[match.end() : match.end() + 16]
    if not callable_identifier or not re.match(r"[ \t]*\(", tail):
        return False
    line_end = text.find("\n", match.end())
    source_line = text[match.start() : len(text) if line_end < 0 else line_end].strip()
    if not _source_contains_call_line(source_path, source_line):
        return False
    try:
        parsed = ast.parse(source_line)
    except SyntaxError:
        return False
    for statement in parsed.body:
        if not isinstance(statement, ast.Assign) or not isinstance(statement.value, ast.Call):
            continue
        if any(
            isinstance(node, ast.Constant)
            and isinstance(node.value, (str, bytes))
            and len(node.value) >= 16
            for node in ast.walk(statement.value)
        ):
            continue
        targets = [target.id for target in statement.targets if isinstance(target, ast.Name)]
        if detail.group("label") in targets and _python_callable_name(statement.value.func) == value:
            return True
    return False


def _scan_tool_output(
    event: dict[str, Any], text: str, *, source: str
) -> list[dict[str, str]]:
    """Suppress generic assignment noise only for AST-proven local Python call sites."""
    source_path = _local_python_source_read_path(event)
    if source_path is None:
        return _scan_text(text, source=source)
    generic_pattern = dict(_SECRET_PATTERNS)["credential_assignment"]

    def mask_code_call(match: re.Match[str]) -> str:
        if not _credential_assignment_is_code_call(text, match, source_path):
            return match.group(0)
        detail = _CREDENTIAL_ASSIGNMENT_DETAIL_RE.search(match.group(0))
        if detail is None:
            return match.group(0)
        start, end = detail.span("label")
        return match.group(0)[:start] + (" " * (end - start)) + match.group(0)[end:]

    return _scan_text(generic_pattern.sub(mask_code_call, text), source=source)


def _fallback_scan_command(command: str) -> list[dict[str, str]]:
    findings = _fallback_scan_text(command)
    findings.extend(_structured_command_findings(command))
    return _dedupe_findings(findings)


def _scan_command(command: str, *, source: str) -> list[dict[str, str]]:
    del source
    return _fallback_scan_command(command)


def _private_directory(path: Path) -> Path:
    path = path.expanduser()
    if path.exists() and path.is_symlink():
        raise RuntimeError(f"refusing symlinked state directory: {path}")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = os.stat(path, follow_symlinks=False)
    if _is_reparse_info(info):
        raise RuntimeError(f"refusing reparse-point state directory: {path}")
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"state path is not a directory: {path}")
    if os.name != "nt" and hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise PermissionError(f"state directory is owned by another user: {path}")
    if os.name != "nt" and info.st_mode & 0o077:
        path.chmod(0o700)
    return path


def _existing_private_directory(path: Path) -> Path:
    path = path.expanduser()
    if not path.is_absolute() or path.is_symlink():
        raise RuntimeError(f"runner data directory is not a safe absolute path: {path}")
    info = os.stat(path, follow_symlinks=False)
    if _is_reparse_info(info) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"runner data path is not a regular directory: {path}")
    if os.name != "nt" and hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise PermissionError(f"runner data directory is owned by another user: {path}")
    if os.name != "nt" and info.st_mode & 0o077:
        raise PermissionError(f"runner data directory permissions are too broad: {path}")
    return path


def _absolute_configured_path(value: str, name: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise RuntimeError(f"{name} must be an absolute path")
    return path


def _data_dir() -> Path:
    configured = os.environ.get("PLUGIN_DATA")
    if configured:
        return _private_directory(_absolute_configured_path(configured, "PLUGIN_DATA"))
    if os.name == "nt":
        raise RuntimeError("PLUGIN_DATA is required on Windows")
    state_home = os.environ.get("XDG_STATE_HOME")
    base = (
        _absolute_configured_path(state_home, "XDG_STATE_HOME")
        if state_home
        else Path.home() / ".local" / "state"
    )
    return _private_directory(base / "codex-control-plane-hooks")


def _configure_runner_data_dir(value: str) -> None:
    path = _existing_private_directory(_absolute_configured_path(value, "runner data directory"))
    os.environ["PLUGIN_DATA"] = str(path)


def _open_private(path: Path, flags: int, mode: int = 0o600):
    if path.exists() and path.is_symlink():
        raise RuntimeError(f"refusing symlinked state file: {path}")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags | nofollow | cloexec, mode)
    info = os.fstat(descriptor)
    if _is_reparse_info(info) or not stat.S_ISREG(info.st_mode):
        os.close(descriptor)
        raise RuntimeError(f"state file is not a regular non-reparse file: {path}")
    if os.name != "nt" and hasattr(os, "getuid") and info.st_uid != os.getuid():
        os.close(descriptor)
        raise PermissionError(f"state file is owned by another user: {path}")
    if os.name != "nt":
        os.fchmod(descriptor, mode)
    writable = bool(flags & (os.O_WRONLY | os.O_RDWR))
    stream_mode = "r+" if writable else "r"
    return os.fdopen(descriptor, stream_mode, encoding="utf-8")


def _unlink_owned_regular(candidate: Path) -> None:
    try:
        info = os.stat(candidate, follow_symlinks=False)
    except FileNotFoundError:
        return
    owned = os.name == "nt" or not hasattr(os, "getuid") or info.st_uid == os.getuid()
    if stat.S_ISREG(info.st_mode) and not _is_reparse_info(info) and owned:
        candidate.unlink()


def _git_runner_path(kind: str, token: str) -> Path:
    if kind not in {"request", "running", "status"} or not _GIT_RUNNER_TOKEN_RE.fullmatch(token):
        raise ValueError("invalid Git runner path")
    return _data_dir() / f".git-runner-{kind}-{token}.json"


def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
    temp = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    try:
        with _open_private(temp, os.O_RDWR | os.O_CREAT | os.O_EXCL) as stream:
            stream.write(
                json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
                + "\n"
            )
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        _unlink_owned_regular(temp)


def _read_private_json(path: Path) -> dict[str, Any]:
    info = os.stat(path, follow_symlinks=False)
    if _is_reparse_info(info) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError("Git runner record must be a regular non-reparse file")
    if info.st_size <= 0 or info.st_size > MAX_POLICY_BYTES:
        raise RuntimeError("Git runner record has an invalid size")
    with _open_private(path, os.O_RDONLY) as stream:
        payload = json.load(stream)
    if not isinstance(payload, dict):
        raise RuntimeError("Git runner record must contain an object")
    return payload


def _cleanup_stale_git_runner_records() -> None:
    cutoff = time.time() - _GIT_RUNNER_TTL_SECONDS
    for pattern in (".git-runner-request-*.json", ".git-runner-running-*.json", ".git-runner-status-*.json"):
        for candidate in _data_dir().glob(pattern):
            try:
                info = os.stat(candidate, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if info.st_mtime < cutoff:
                _unlink_owned_regular(candidate)


def _powershell_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _git_runner_shell_kind(tool_name: str, tool_input: Any) -> str:
    if os.name != "nt":
        return "posix"
    shell = ""
    if _is_exec_command_tool(tool_name) and isinstance(tool_input, dict):
        shell = str(tool_input.get("shell") or "")
    shell_name = _executable_name(shell) if shell else "powershell"
    if shell_name not in {"powershell", "pwsh"}:
        raise RuntimeError("Windows Git transaction runner requires PowerShell or pwsh")
    return "powershell"


def _render_git_runner_command(argv: list[str], shell_kind: str) -> str:
    if shell_kind == "powershell":
        return "& " + " ".join(_powershell_quote(item) for item in argv)
    if shell_kind == "posix":
        return shlex.join(argv)
    raise ValueError("unsupported Git runner shell")


def _git_runner_command(
    token: str,
    data_dir: str,
    *,
    tool_name: str,
    tool_input: Any,
) -> str:
    if not _GIT_RUNNER_TOKEN_RE.fullmatch(token):
        raise ValueError("invalid Git runner token")
    argv = [
        str(Path(sys.executable).resolve()),
        "-I",
        "-S",
        str(Path(__file__).resolve()),
        "--run-approved-git",
        token,
        data_dir,
    ]
    return _render_git_runner_command(
        argv,
        _git_runner_shell_kind(tool_name, tool_input),
    )


def _git_runner_invocation_shape(command: str) -> bool:
    tokens = _shell_tokens(command)
    if tokens[:1] == ["&"]:
        tokens = tokens[1:]
    return bool(
        len(tokens) == 7
        and tokens[1:3] == ["-I", "-S"]
        and tokens[4] == "--run-approved-git"
    )


def _matching_git_runner_permission(
    state: dict[str, Any],
    *,
    tool_use_id: str,
    tool_name: str,
    turn_id: str,
    command_digest: str,
    base_event_cwd: str,
    effective_cwd: str,
    execution_options_digest: str,
    original: bool = False,
) -> dict[str, Any] | None:
    pending = state.get("pending_permission_authorizations")
    permission = pending.get(tool_use_id) if isinstance(pending, dict) else None
    if not isinstance(permission, dict) or not permission.get("transaction_id"):
        return None
    token = str(permission.get("runner_token") or "")
    expected_digest = str(
        permission.get("original_digest" if original else "digest") or ""
    )
    return permission if (
        _GIT_RUNNER_TOKEN_RE.fullmatch(token)
        and command_digest == expected_digest
        and _git_runner_request_matches_permission(permission)
        and str(permission.get("session_hash") or "") == str(state.get("session_hash") or "")
        and str(permission.get("turn_id") or "") == turn_id
        and str(permission.get("tool_use_id") or "") == tool_use_id
        and str(permission.get("tool_name") or "") == tool_name
        and str(permission.get("base_event_cwd") or "") == _normalized_cwd(base_event_cwd)
        and str(permission.get("effective_cwd") or "") == _normalized_cwd(effective_cwd)
        and str(permission.get("execution_options_digest") or "") == execution_options_digest
    ) else None


def _git_runner_request_matches_permission(permission: dict[str, Any]) -> bool:
    token = str(permission.get("runner_token") or "")
    if not _GIT_RUNNER_TOKEN_RE.fullmatch(token) or permission.get("runner_claimed_at"):
        return False
    try:
        request = _read_private_json(_git_runner_path("request", token))
    except Exception:
        return False
    if not str(permission.get("runner_request_digest") or "") or str(
        permission.get("runner_request_digest") or ""
    ) != _git_runner_request_digest(request):
        return False
    expected = {
        "base_event_cwd": str(permission.get("base_event_cwd") or ""),
        "effective_cwd": str(permission.get("effective_cwd") or ""),
        "execution_options_digest": str(permission.get("execution_options_digest") or ""),
        "operation": str(permission.get("operation") or ""),
        "original_digest": str(permission.get("original_digest") or ""),
        "runner_digest": str(permission.get("digest") or ""),
        "scope_hash": str(permission.get("scope_hash") or ""),
        "session_hash": str(permission.get("session_hash") or ""),
        "tool_name": str(permission.get("tool_name") or ""),
        "tool_use_id": str(permission.get("tool_use_id") or ""),
        "transaction_id": str(permission.get("transaction_id") or ""),
        "turn_id": str(permission.get("turn_id") or ""),
    }
    return all(str(request.get(key) or "") == value for key, value in expected.items())


def _git_runner_request_digest(request: dict[str, Any]) -> str:
    encoded = json.dumps(
        request,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _git_runner_candidate_binding(candidate: dict[str, Any]) -> dict[str, Any]:
    binding: dict[str, Any] = {}
    for key in (
        "branch",
        "digest",
        "operation",
        "pathspecs",
        "refspec",
        "remote",
        "remote_identities",
        "remote_targets",
        "scope_hash",
        "target",
        "visibility",
    ):
        if key not in candidate:
            continue
        value = candidate[key]
        binding[key] = list(value) if isinstance(value, tuple) else value
    return binding


def _prepare_git_runner(
    session_id: str,
    *,
    tool_use_id: str,
    tool_name: str,
    tool_input: Any,
    original_command: str,
    original_digest: str,
    effective_cwd: str,
) -> str:
    _cleanup_stale_git_runner_records()
    state = state_store.read_session(session_id)
    pending = state.get("pending_permission_authorizations")
    permission = pending.get(tool_use_id) if isinstance(pending, dict) else None
    if not isinstance(permission, dict) or not permission.get("transaction_id"):
        raise RuntimeError("Git runner requires a reserved transaction operation")
    if str(permission.get("digest") or "") != original_digest:
        raise RuntimeError("Git runner reservation digest changed")

    existing_token = str(permission.get("runner_token") or "")
    if existing_token:
        command = str(permission.get("runner_command") or "")
        if (
            _GIT_RUNNER_TOKEN_RE.fullmatch(existing_token)
            and command
            and _git_runner_path("request", existing_token).exists()
        ):
            return command
        raise RuntimeError("Git runner reservation is no longer reusable")

    argv = _shell_tokens(original_command)
    executable, _, wrappers = _unwrap_command(argv)
    operation = str(permission.get("operation") or "")
    if (
        wrappers
        or executable not in {"git", "gh"}
        or operation not in _SCOPED_TRANSACTION_OPERATIONS
    ):
        raise RuntimeError("Git runner received an unsupported command")

    dangerous = _dangerous_codes(_structured_command_findings(original_command))
    candidate = _scoped_git_candidate(original_command, effective_cwd, dangerous)
    if candidate is None:
        candidate = _scoped_github_create_candidate(
            original_command, effective_cwd, dangerous
        )
    if (
        not isinstance(candidate, dict)
        or str(candidate.get("digest") or "") != original_digest
        or str(candidate.get("operation") or "") != operation
        or str(candidate.get("scope_hash") or "")
        != str(permission.get("scope_hash") or "")
    ):
        raise RuntimeError("Git runner candidate changed before binding")

    token = os.urandom(16).hex()
    runner_command = _git_runner_command(
        token,
        str(_data_dir()),
        tool_name=tool_name,
        tool_input=tool_input,
    )
    runner_digest = _command_hash(runner_command, effective_cwd)
    request = {
        "argv": argv,
        "base_event_cwd": str(permission.get("base_event_cwd") or ""),
        "candidate_binding": _git_runner_candidate_binding(candidate),
        "created_at": time.time(),
        "effective_cwd": _normalized_cwd(effective_cwd),
        "execution_options_digest": str(permission.get("execution_options_digest") or ""),
        "operation": operation,
        "original_digest": original_digest,
        "runner_digest": runner_digest,
        "scope_hash": str(permission.get("scope_hash") or ""),
        "session_id": session_id,
        "session_hash": str(permission.get("session_hash") or ""),
        "tool_name": tool_name,
        "tool_use_id": tool_use_id,
        "transaction_id": str(permission.get("transaction_id") or ""),
        "turn_id": str(permission.get("turn_id") or ""),
    }
    if operation == "push":
        remote_urls = tuple(candidate.get("remote_urls") or ())
        remote_identities = tuple(candidate.get("remote_identities") or ())
        if (
            len(remote_urls) != 1
            or len(remote_identities) != 1
            or _safe_git_push_url(str(remote_urls[0])) != remote_urls[0]
            or _git_push_url_identity(str(remote_urls[0])) != remote_identities[0]
        ):
            raise RuntimeError("Git runner push URL is not uniquely safe")
        request["pinned_push_url"] = remote_urls[0]
        environment = _git_runner_base_environment()
        source_branch, source_oid, object_dir, object_format = (
            _git_push_source_snapshot(candidate, environment)
        )
        request["push_source"] = {
            "branch": source_branch,
            "object_dir": str(object_dir),
            "object_format": object_format,
            "oid": source_oid,
        }
        rewrite_snapshot = _git_url_rewrite_snapshot(
            str(candidate.get("scope") or ""),
            str(remote_urls[0]),
            environment,
        )
        if rewrite_snapshot != _EMPTY_GIT_URL_REWRITE_SNAPSHOT:
            raise RuntimeError("Git runner push URL is subject to Git URL rewriting")
        request["url_rewrite_snapshot"] = rewrite_snapshot
    request_path = _git_runner_path("request", token)
    _write_private_json(request_path, request)

    def bind_runner(current: dict[str, Any]) -> None:
        current_pending = current.get("pending_permission_authorizations")
        current_permission = (
            current_pending.get(tool_use_id) if isinstance(current_pending, dict) else None
        )
        same_transaction = [
            item_id
            for item_id, item in (
                current_pending.items() if isinstance(current_pending, dict) else ()
            )
            if isinstance(item, dict)
            and str(item.get("transaction_id") or "") == request["transaction_id"]
        ]
        if (
            not isinstance(current_permission, dict)
            or same_transaction != [tool_use_id]
            or str(current_permission.get("digest") or "") != original_digest
            or str(current_permission.get("transaction_id") or "") != request["transaction_id"]
            or current_permission.get("runner_claimed_at")
        ):
            raise RuntimeError("Git runner reservation changed before binding")
        current_permission.update(
            {
                "digest": runner_digest,
                "original_digest": original_digest,
                "runner_command": runner_command,
                "runner_request_digest": _git_runner_request_digest(request),
                "runner_token": token,
            }
        )

    try:
        state_store.mutate_session(session_id, bind_runner)
    except Exception:
        _unlink_owned_regular(request_path)
        raise
    return runner_command


def _clear_git_transaction_state(state: dict[str, Any], transaction_id: str) -> None:
    grant = state.get("local_git_grant")
    if (
        isinstance(grant, dict)
        and str(grant.get("transaction_id") or "") == transaction_id
    ):
        state["local_git_grant"] = None
    pending = state.get("pending_permission_authorizations")
    if isinstance(pending, dict):
        state["pending_permission_authorizations"] = {
            item_id: item
            for item_id, item in pending.items()
            if not (
                isinstance(item, dict)
                and str(item.get("transaction_id") or "") == transaction_id
            )
        }


def _cleanup_git_runner_transaction_records(transaction_id: str) -> None:
    if not transaction_id:
        return
    for pattern in (
        ".git-runner-request-*.json",
        ".git-runner-running-*.json",
        ".git-runner-status-*.json",
    ):
        for candidate in _data_dir().glob(pattern):
            try:
                payload = _read_private_json(candidate)
            except Exception:
                continue
            if str(payload.get("transaction_id") or "") == transaction_id:
                _unlink_owned_regular(candidate)


def _revoke_git_transaction(session_id: str, transaction_id: str) -> None:
    if not session_id or not transaction_id:
        return
    try:
        state_store.mutate_session(
            session_id,
            lambda state: _clear_git_transaction_state(state, transaction_id),
        )
    finally:
        _cleanup_git_runner_transaction_records(transaction_id)


def _validate_git_runner_request(
    request: dict[str, Any],
) -> tuple[list[str], str, dict[str, Any]]:
    argv = request.get("argv")
    cwd = str(request.get("effective_cwd") or "")
    created_at = request.get("created_at")
    operation = str(request.get("operation") or "")
    original_digest = str(request.get("original_digest") or "")
    runner_digest = str(request.get("runner_digest") or "")
    session_id = str(request.get("session_id") or "")
    session_hash = str(request.get("session_hash") or "")
    if (
        not isinstance(argv, list)
        or not argv
        or len(argv) > 200
        or not all(isinstance(item, str) and item and "\x00" not in item for item in argv)
        or not os.path.isabs(cwd)
        or not isinstance(created_at, (int, float))
        or isinstance(created_at, bool)
        or not 0 <= time.time() - float(created_at) <= _GIT_RUNNER_TTL_SECONDS
        or operation not in _SCOPED_TRANSACTION_OPERATIONS
        or not original_digest
        or not runner_digest
        or not session_id
        or len(session_id) > 512
        or hashlib.sha256(session_id.encode("utf-8", errors="replace")).hexdigest()[:16]
        != session_hash
    ):
        raise RuntimeError("Git runner request validation failed")
    executable, _, wrappers = _unwrap_command(argv)
    if wrappers or executable not in {"git", "gh"}:
        raise RuntimeError("Git runner executable validation failed")
    command = shlex.join(argv)
    dangerous = _dangerous_codes(_structured_command_findings(command))
    candidate = _scoped_git_candidate(command, cwd, dangerous)
    if candidate is None:
        candidate = _scoped_github_create_candidate(command, cwd, dangerous)
    if (
        not isinstance(candidate, dict)
        or str(candidate.get("digest") or "") != original_digest
        or str(candidate.get("operation") or "") != operation
        or str(candidate.get("scope_hash") or "") != str(request.get("scope_hash") or "")
        or _git_runner_candidate_binding(candidate)
        != request.get("candidate_binding")
    ):
        raise RuntimeError("Git runner candidate validation failed")
    pinned_push_url = str(request.get("pinned_push_url") or "")
    if operation == "push":
        if (
            _safe_git_push_url(pinned_push_url) != pinned_push_url
            or tuple(candidate.get("remote_urls") or ()) != (pinned_push_url,)
            or tuple(candidate.get("remote_identities") or ())
            != (_git_push_url_identity(pinned_push_url),)
        ):
            raise RuntimeError("Git runner pinned push URL validation failed")
    elif pinned_push_url:
        raise RuntimeError("Git runner request has an unexpected push URL")
    return argv, cwd, candidate


def _git_runner_environment(
    request: dict[str, Any], candidate: dict[str, Any]
) -> dict[str, str]:
    environment = _git_runner_base_environment()
    if str(candidate.get("operation") or "") != "push":
        return environment
    pinned_push_url = str(request.get("pinned_push_url") or "")
    if (
        candidate.get("remote") != "origin"
        or _safe_git_push_url(pinned_push_url) != pinned_push_url
        or tuple(candidate.get("remote_urls") or ()) != (pinned_push_url,)
    ):
        raise RuntimeError("Git runner cannot pin the approved push destination")
    return environment


def _git_runner_base_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["GIT_TERMINAL_PROMPT"] = "0"
    for key in tuple(environment):
        if (
            key == "GIT_CONFIG_PARAMETERS"
            or key.startswith("GIT_CONFIG_")
            or key
            in {
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                "GIT_CEILING_DIRECTORIES",
                "GIT_COMMON_DIR",
                "GIT_DIR",
                "GIT_DISCOVERY_ACROSS_FILESYSTEM",
                "GIT_INDEX_FILE",
                "GIT_NAMESPACE",
                "GIT_OBJECT_DIRECTORY",
                "GIT_SHALLOW_FILE",
                "GIT_WORK_TREE",
            }
        ):
            environment.pop(key, None)
    return environment


def _git_url_rewrite_snapshot(
    scope: str,
    pinned_push_url: str,
    environment: dict[str, str],
) -> str:
    if not scope or _safe_git_push_url(pinned_push_url) != pinned_push_url:
        return ""
    try:
        completed = subprocess.run(
            ["git", "-C", scope, "config", "--get-regexp", r"^url\..*\."],
            env=environment,
            text=True,
            capture_output=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if completed.returncode not in {0, 1}:
        return ""

    matching: list[str] = []
    for line in completed.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key, prefix = parts
        match = re.fullmatch(
            r"url\.(?P<replacement>.+)\.(?P<kind>insteadof|pushinsteadof)",
            key,
            re.IGNORECASE,
        )
        if match and prefix and pinned_push_url.startswith(prefix):
            matching.append(
                hashlib.sha256(
                    (match.group("kind").casefold() + "\0" + key + "\0" + prefix).encode(
                        "utf-8", errors="replace"
                    )
                ).hexdigest()
            )
    encoded = json.dumps(sorted(matching), separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _pinned_git_push_argv(
    argv: list[str],
    request: dict[str, Any],
    candidate: dict[str, Any],
    *,
    git_dir: Path,
    source_oid: str,
    branch: str,
) -> tuple[list[str], bool]:
    pinned_push_url = str(request.get("pinned_push_url") or "")
    executable, args, wrappers = _unwrap_command(argv)
    subcommand, git_args, dynamic_config = _git_command(args)
    global_arg_count = len(args) - len(git_args) - 1
    if (
        wrappers
        or executable != "git"
        or subcommand != "push"
        or dynamic_config
        or global_arg_count < 0
        or candidate.get("remote") != "origin"
        or _safe_git_push_url(pinned_push_url) != pinned_push_url
        or tuple(candidate.get("remote_urls") or ()) != (pinned_push_url,)
    ):
        raise RuntimeError("Git runner cannot construct a pinned push")

    push_options: list[str] = []
    positionals = 0
    options_done = False
    set_upstream = False
    for token in git_args:
        if not options_done and token == "--":
            options_done = True
            continue
        if not options_done and token in _SCOPED_PUSH_OPTIONS:
            if token in _SCOPED_PUSH_UPSTREAM_OPTIONS:
                set_upstream = True
            else:
                push_options.append(token)
            continue
        if token.startswith("-"):
            raise RuntimeError("Git runner received an unsupported push option")
        if positionals == 0:
            if token != "origin":
                raise RuntimeError("Git runner push remote changed")
        elif positionals == 1:
            if _safe_branch_name(token) != str(candidate.get("refspec") or ""):
                raise RuntimeError("Git runner push branch changed")
        else:
            raise RuntimeError("Git runner received multiple push targets")
        positionals += 1
    if positionals != 2:
        raise RuntimeError("Git runner push target is incomplete")

    if (
        not git_dir.is_absolute()
        or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source_oid)
        or _safe_branch_name(branch) != branch
        or branch == "HEAD"
    ):
        raise RuntimeError("Git runner push source is not immutable")
    return [
        "git",
        "--no-replace-objects",
        f"--git-dir={git_dir}",
        "push",
        *push_options,
        "--",
        pinned_push_url,
        f"{source_oid}:refs/heads/{branch}",
    ], set_upstream


def _git_push_source_snapshot(
    candidate: dict[str, Any], environment: dict[str, str]
) -> tuple[str, str, Path, str]:
    scope = str(candidate.get("scope") or "")
    branch = _safe_branch_name(str(candidate.get("refspec") or ""))
    if not scope or not branch:
        raise RuntimeError("Git runner push source is invalid")
    if branch == "HEAD":
        resolved = subprocess.run(
            ["git", "-C", scope, "symbolic-ref", "--quiet", "--short", "HEAD"],
            env=environment,
            text=True,
            capture_output=True,
            timeout=3,
            check=False,
        )
        branch = _safe_branch_name(resolved.stdout.strip())
        if resolved.returncode != 0 or not branch or branch == "HEAD":
            raise RuntimeError("Git runner cannot resolve detached HEAD")

    source = subprocess.run(
        [
            "git",
            "-C",
            scope,
            "rev-parse",
            "--verify",
            "--quiet",
            f"refs/heads/{branch}^{{commit}}",
        ],
        env=environment,
        text=True,
        capture_output=True,
        timeout=3,
        check=False,
    )
    source_oid = source.stdout.strip().casefold()
    if (
        source.returncode != 0
        or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source_oid)
    ):
        raise RuntimeError("Git runner push source branch is unavailable")

    common = subprocess.run(
        ["git", "-C", scope, "rev-parse", "--git-common-dir"],
        env=environment,
        text=True,
        capture_output=True,
        timeout=3,
        check=False,
    )
    common_value = common.stdout.strip()
    if common.returncode != 0 or not common_value:
        raise RuntimeError("Git runner cannot resolve the object database")
    common_dir = Path(common_value)
    if not common_dir.is_absolute():
        common_dir = Path(scope) / common_dir
    object_dir = Path(os.path.realpath(common_dir / "objects"))
    if not object_dir.is_dir():
        raise RuntimeError("Git runner object database is unavailable")
    object_format = "sha1" if len(source_oid) == 40 else "sha256"
    return branch, source_oid, object_dir, object_format


def _git_isolated_config_records(
    environment: dict[str, str],
) -> list[tuple[str, str]]:
    records: list[tuple[str, str]] = []
    for scope in ("--system", "--global"):
        completed = subprocess.run(
            ["git", "config", scope, "--includes", "--null", "--list"],
            env=environment,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            capture_output=True,
            timeout=3,
            check=False,
        )
        if completed.returncode != 0:
            if not completed.stdout:
                continue
            raise RuntimeError("Git runner cannot snapshot trusted Git config")
        for record in completed.stdout.split("\0"):
            if not record:
                continue
            key, separator, value = record.partition("\n")
            normalized = key.casefold()
            if (
                not separator
                or not normalized.startswith(("credential.", "http."))
                or "\0" in value
            ):
                continue
            records.append((key, value))
    return records


def _write_isolated_git_config(
    path: Path,
    records: list[tuple[str, str]],
    environment: dict[str, str],
) -> None:
    with _open_private(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL):
        pass
    for key, value in records:
        configured = subprocess.run(
            ["git", "config", "--file", str(path), "--add", key, value],
            env=environment,
            text=True,
            capture_output=True,
            timeout=3,
            check=False,
        )
        if configured.returncode != 0:
            raise RuntimeError("Git runner cannot build isolated Git config")
    os.chmod(path, 0o600)


def _prepare_isolated_git_push(
    object_dir: Path, object_format: str, environment: dict[str, str]
) -> tuple[Path, dict[str, str]]:
    git_dir = Path(tempfile.mkdtemp(prefix=".git-push-", dir=str(_data_dir())))
    try:
        config_records = _git_isolated_config_records(environment)
        empty_template = git_dir / "empty-template"
        empty_template.mkdir(mode=0o700)
        isolated_environment = environment.copy()
        isolated_environment["GIT_CONFIG_NOSYSTEM"] = "1"
        isolated_environment["GIT_CONFIG_GLOBAL"] = os.devnull
        isolated_environment["GIT_DEFAULT_HASH"] = object_format
        init_args = [
            "git",
            "init",
            "--bare",
            "--quiet",
            f"--template={empty_template}",
        ]
        if object_format == "sha256":
            init_args.append("--object-format=sha256")
        elif object_format != "sha1":
            raise RuntimeError("Git runner object format is unsupported")
        init_args.append(str(git_dir))
        initialized = subprocess.run(
            init_args,
            cwd=str(_data_dir()),
            env=isolated_environment,
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
        if initialized.returncode != 0:
            raise RuntimeError("Git runner cannot create an isolated push repository")
        hooks_dir = git_dir / "disabled-hooks"
        hooks_dir.mkdir(mode=0o700)
        configured = subprocess.run(
            [
                "git",
                f"--git-dir={git_dir}",
                "config",
                "--local",
                "core.hooksPath",
                str(hooks_dir),
            ],
            cwd=str(_data_dir()),
            env=isolated_environment,
            text=True,
            capture_output=True,
            timeout=3,
            check=False,
        )
        if configured.returncode != 0:
            raise RuntimeError("Git runner cannot disable push hooks")
        trusted_config = git_dir / "trusted-user.gitconfig"
        _write_isolated_git_config(
            trusted_config, config_records, isolated_environment
        )
    except Exception:
        shutil.rmtree(git_dir, ignore_errors=True)
        raise
    push_environment = isolated_environment.copy()
    push_environment["GIT_CONFIG_GLOBAL"] = str(trusted_config)
    push_environment["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = str(object_dir)
    return git_dir, push_environment


def _set_git_push_upstream(
    candidate: dict[str, Any],
    pinned_push_url: str,
    environment: dict[str, str],
    branch: str,
) -> bool:
    scope = str(candidate.get("scope") or "")
    branch = _safe_branch_name(branch)
    current_urls = _git_remote_urls(scope, "origin", environment=environment)
    if not scope or not branch or current_urls != (pinned_push_url,):
        return False
    current_identities = _git_remote_identities(
        scope,
        "origin",
        urls=current_urls,
        environment=environment,
    )
    if current_identities != (_git_push_url_identity(pinned_push_url),):
        return False
    local_branch = subprocess.run(
        [
            "git",
            "-C",
            scope,
            "show-ref",
            "--verify",
            "--quiet",
            f"refs/heads/{branch}",
        ],
        env=environment,
        check=False,
    )
    if local_branch.returncode != 0:
        return False
    for key, value in (
        (f"branch.{branch}.remote", "origin"),
        (f"branch.{branch}.merge", f"refs/heads/{branch}"),
    ):
        completed = subprocess.run(
            ["git", "-C", scope, "config", "--local", "--replace-all", key, value],
            env=environment,
            check=False,
        )
        if completed.returncode != 0:
            return False
    return True


def _claim_git_runner_request(
    token: str,
    request: dict[str, Any],
    candidate: dict[str, Any],
) -> None:
    session_id = str(request.get("session_id") or "")
    transaction_id = str(request.get("transaction_id") or "")
    tool_use_id = str(request.get("tool_use_id") or "")

    def claim(state: dict[str, Any]) -> None:
        pending = state.get("pending_permission_authorizations")
        permission = pending.get(tool_use_id) if isinstance(pending, dict) else None
        grant = state.get("local_git_grant")
        same_transaction = [
            item_id
            for item_id, item in (pending.items() if isinstance(pending, dict) else ())
            if isinstance(item, dict)
            and str(item.get("transaction_id") or "") == transaction_id
        ]
        if (
            not transaction_id
            or same_transaction != [tool_use_id]
            or not isinstance(permission, dict)
            or str(permission.get("runner_token") or "") != token
            or str(permission.get("digest") or "")
            != str(request.get("runner_digest") or "")
            or str(permission.get("original_digest") or "")
            != str(request.get("original_digest") or "")
            or str(permission.get("runner_request_digest") or "")
            != _git_runner_request_digest(request)
            or str(permission.get("transaction_id") or "") != transaction_id
            or str(permission.get("scope_hash") or "")
            != str(request.get("scope_hash") or "")
            or str(permission.get("operation") or "")
            != str(request.get("operation") or "")
            or str(permission.get("session_hash") or "")
            != str(request.get("session_hash") or "")
            or str(permission.get("turn_id") or "")
            != str(request.get("turn_id") or "")
            or str(permission.get("execution_options_digest") or "")
            != str(request.get("execution_options_digest") or "")
            or permission.get("runner_claimed_at")
            or not isinstance(grant, dict)
            or str(grant.get("transaction_id") or "") != transaction_id
            or not _git_grant_matches(
                grant,
                candidate,
                str(request.get("turn_id") or ""),
                str(request.get("session_hash") or ""),
            )
        ):
            raise RuntimeError("Git runner state claim failed")
        permission["runner_claimed_at"] = time.time()

    state_store.mutate_session(session_id, claim)


def _run_approved_git(token: str) -> int:
    if not _GIT_RUNNER_TOKEN_RE.fullmatch(token):
        return 126
    _cleanup_stale_git_runner_records()
    request_path = _git_runner_path("request", token)
    running_path = _git_runner_path("running", token)
    status_path = _git_runner_path("status", token)
    request: dict[str, Any] = {}
    try:
        os.replace(request_path, running_path)
        request = _read_private_json(running_path)
        argv, cwd, candidate = _validate_git_runner_request(request)
        _claim_git_runner_request(token, request, candidate)
    except Exception:
        _unlink_owned_regular(running_path)
        try:
            _revoke_git_transaction(
                str(request.get("session_id") or ""),
                str(request.get("transaction_id") or ""),
            )
        except Exception:
            pass
        return 126

    isolated_git_dir: Path | None = None
    remote_succeeded = False
    try:
        environment = _git_runner_environment(request, candidate)
        child_environment = environment
        child_cwd = cwd
        child_argv = argv
        set_upstream = False
        source_branch = ""
        if str(candidate.get("operation") or "") == "push":
            rewrite_snapshot = str(request.get("url_rewrite_snapshot") or "")
            if (
                rewrite_snapshot != _EMPTY_GIT_URL_REWRITE_SNAPSHOT
                or _git_url_rewrite_snapshot(
                    str(candidate.get("scope") or ""),
                    str(request.get("pinned_push_url") or ""),
                    environment,
                )
                != rewrite_snapshot
            ):
                raise RuntimeError("Git runner push URL rewrite configuration changed")
            source_branch, source_oid, object_dir, object_format = (
                _git_push_source_snapshot(candidate, environment)
            )
            push_source = request.get("push_source")
            if push_source != {
                "branch": source_branch,
                "object_dir": str(object_dir),
                "object_format": object_format,
                "oid": source_oid,
            }:
                raise RuntimeError("Git runner push source changed after ticket binding")
            isolated_git_dir, child_environment = _prepare_isolated_git_push(
                object_dir, object_format, environment
            )
            child_argv, set_upstream = _pinned_git_push_argv(
                argv,
                request,
                candidate,
                git_dir=isolated_git_dir,
                source_oid=source_oid,
                branch=source_branch,
            )
            child_cwd = str(_data_dir())
        completed = subprocess.run(
            child_argv, cwd=child_cwd, env=child_environment, check=False
        )
        exit_code = int(completed.returncode)
        remote_succeeded = bool(
            str(candidate.get("operation") or "") == "push" and exit_code == 0
        )
        if exit_code == 0 and set_upstream and not _set_git_push_upstream(
            candidate,
            str(request.get("pinned_push_url") or ""),
            environment,
            source_branch,
        ):
            exit_code = 126
    except (OSError, RuntimeError):
        exit_code = 126
    finally:
        if isolated_git_dir is not None:
            shutil.rmtree(isolated_git_dir, ignore_errors=True)
    status = {
        "completed_at": time.time(),
        "execution_options_digest": str(request.get("execution_options_digest") or ""),
        "exit_code": exit_code,
        "operation": str(request.get("operation") or ""),
        "original_digest": str(request.get("original_digest") or ""),
        "remote_succeeded": remote_succeeded,
        "scope_hash": str(request.get("scope_hash") or ""),
        "session_hash": str(request.get("session_hash") or ""),
        "tool_use_id": str(request.get("tool_use_id") or ""),
        "transaction_id": str(request.get("transaction_id") or ""),
        "turn_id": str(request.get("turn_id") or ""),
    }
    try:
        _write_private_json(status_path, status)
    except Exception:
        _unlink_owned_regular(running_path)
        try:
            _revoke_git_transaction(
                str(request.get("session_id") or ""),
                str(request.get("transaction_id") or ""),
            )
        except Exception:
            pass
        return 126 if exit_code == 0 else exit_code
    _unlink_owned_regular(running_path)
    return exit_code


def _consume_git_runner_status(permission: dict[str, Any]) -> str:
    token = str(permission.get("runner_token") or "")
    if not _GIT_RUNNER_TOKEN_RE.fullmatch(token):
        return "unknown"
    status_path = _git_runner_path("status", token)
    try:
        status = _read_private_json(status_path)
    except Exception:
        return "unknown"
    finally:
        _unlink_owned_regular(status_path)
    expected = {
        "execution_options_digest": str(permission.get("execution_options_digest") or ""),
        "operation": str(permission.get("operation") or ""),
        "original_digest": str(permission.get("original_digest") or ""),
        "scope_hash": str(permission.get("scope_hash") or ""),
        "session_hash": str(permission.get("session_hash") or ""),
        "tool_use_id": str(permission.get("tool_use_id") or ""),
        "transaction_id": str(permission.get("transaction_id") or ""),
        "turn_id": str(permission.get("turn_id") or ""),
    }
    if any(str(status.get(key) or "") != value for key, value in expected.items()):
        return "unknown"
    completed_at = status.get("completed_at")
    exit_code = status.get("exit_code")
    if (
        not isinstance(completed_at, (int, float))
        or isinstance(completed_at, bool)
        or not 0 <= time.time() - float(completed_at) <= _GIT_RUNNER_TTL_SECONDS
        or not isinstance(exit_code, int)
        or isinstance(exit_code, bool)
    ):
        return "unknown"
    if expected["operation"] == "push":
        remote_succeeded = status.get("remote_succeeded")
        if not isinstance(remote_succeeded, bool):
            return "unknown"
        return "success" if remote_succeeded else "failure"
    return "success" if exit_code == 0 else "failure"


def _stop_state(session_id: str) -> int:
    active_count = 0

    def remove_if_inactive(state: dict[str, Any]) -> bool:
        nonlocal active_count
        active_count = len(state.get("active_agents") or {})
        resumable_git = _git_grant_usable(
            state.get("local_git_grant"),
            str(state.get("session_hash") or ""),
        ) or _pending_git_usable(state.get("pending_local_git"))
        pending_permissions = state.get("pending_permission_authorizations")
        if isinstance(pending_permissions, dict):
            resumable_git = resumable_git or any(
                isinstance(item, dict) and item.get("transaction_id")
                for item in pending_permissions.values()
            )
        return not active_count and not resumable_git

    state_store.cleanup_session(session_id, remove_if_inactive)
    return active_count


def _flatten_text(value: Any, *, limit: int = MAX_SCAN_CHARS) -> str:
    parts: list[str] = []
    size = 0

    def visit(item: Any) -> None:
        nonlocal size
        if size >= limit:
            return
        if isinstance(item, str):
            chunk = item[: limit - size]
            parts.append(chunk)
            size += len(chunk)
        elif isinstance(item, dict):
            for key, child in item.items():
                visit(str(key))
                visit(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                visit(child)
        elif item is not None:
            visit(str(item))

    visit(value)
    return "\n".join(parts)


def _flatten_sensitive_fields(value: Any, *, limit: int = MAX_SCAN_CHARS) -> str:
    parts: list[str] = []
    size = 0

    def has_content(item: Any) -> bool:
        if isinstance(item, dict):
            return any(has_content(child) for child in item.values())
        if isinstance(item, (list, tuple)):
            return any(has_content(child) for child in item)
        return item is not None and bool(str(item).strip())

    def append(item: Any) -> None:
        nonlocal size
        if item is None or size >= limit:
            return
        chunk = str(item)[: limit - size]
        parts.append(chunk)
        size += len(chunk)

    def visit(item: Any) -> None:
        if size >= limit:
            return
        if isinstance(item, dict):
            for key, child in item.items():
                if isinstance(child, (str, int, float, bool)):
                    append(f"{key}: {child}")
                elif has_content(child):
                    append(f"{key}: [structured]")
                    visit(child)
                else:
                    append(key)
        elif isinstance(item, (list, tuple)):
            for child in item:
                visit(child)
        else:
            append(item)

    visit(value)
    return "\n".join(parts)


def _local_redaction_surfaces(tool_name: str, tool_input: Any) -> tuple[str, str]:
    """Return removed and newly persisted text for narrowly supported local edits."""
    if tool_name == "apply_patch":
        patch = tool_input if isinstance(tool_input, str) else _flatten_text(tool_input)
        removed = [
            line[1:]
            for line in patch.splitlines()
            if line.startswith("-") and not line.startswith("---")
        ]
        added = [
            line[1:]
            for line in patch.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        ]
        return "\n".join(removed), "\n".join(added)
    if tool_name == "Edit" and isinstance(tool_input, dict):
        return str(tool_input.get("old_string") or ""), str(tool_input.get("new_string") or "")
    return "", ""


def _clone_reservation_metadata(
    candidate: dict[str, str],
    *,
    session_hash: str,
    turn_id: str,
    tool_name: str,
    tool_use_id: str,
    digest: str,
    base_event_cwd: str,
    effective_cwd: str,
    execution_options_digest: str,
) -> dict[str, Any]:
    return {
        **candidate,
        "session_hash": session_hash,
        "turn_id": turn_id,
        "tool_name": tool_name,
        "tool_use_id": tool_use_id,
        "digest": digest,
        "base_event_cwd": _normalized_cwd(base_event_cwd),
        "effective_cwd": _normalized_cwd(effective_cwd),
        "execution_options_digest": execution_options_digest,
    }


def _clone_reservation_matches(record: Any, expected: dict[str, Any]) -> bool:
    return bool(
        isinstance(record, dict)
        and set(record) == set(expected) | {"created_at"}
        and all(record.get(key) == value for key, value in expected.items())
    )


def _reserve_clone(state: dict[str, Any], tool_use_id: str, metadata: dict[str, Any]) -> bool:
    pending = state.get("pending_constrained_clones")
    if not isinstance(pending, dict):
        pending = {}
    existing = pending.get(tool_use_id)
    if existing is not None:
        return _clone_reservation_matches(existing, metadata)
    pending[tool_use_id] = {**metadata, "created_at": time.time()}
    state["pending_constrained_clones"] = pending
    return True


def _contains_clone_invocation(command: str, *, depth: int = 0) -> bool:
    tokens = _shell_tokens(command)
    commands, _ = _split_shell_commands(
        tokens, windows_style=_looks_like_windows_command(command)
    )
    for segment in commands:
        executable, args, _ = _unwrap_command(segment)
        if executable == "git":
            _, args = _git_scope_and_args(args, ".")
            subcommand, _, dynamic_config = _git_command(args)
            if subcommand == "clone" or dynamic_config:
                return True
        if executable == "gh" and args[:2] == ["repo", "clone"]:
            return True
        if executable in _SHELL_EVAL and depth < 4:
            for index, token in enumerate(args):
                if _is_shell_eval_flag(token) and index + 1 < len(args):
                    if _contains_clone_invocation(
                        args[index + 1], depth=depth + 1
                    ):
                        return True
                    break
        if executable in {"powershell", "pwsh"} and depth < 4:
            for index, token in enumerate(args):
                name, inline_value = _powershell_option(token)
                if name in {"c", "command"}:
                    payload = ([inline_value] if inline_value is not None else []) + args[
                        index + 1 :
                    ]
                    if payload and _contains_clone_invocation(" ".join(payload), depth=depth + 1):
                        return True
                    break
        if executable == "cmd" and depth < 4:
            for index, token in enumerate(args):
                lowered = token.casefold()
                if lowered in {"/c", "-c"} and index + 1 < len(args):
                    if _contains_clone_invocation(
                        " ".join(args[index + 1 :]), depth=depth + 1
                    ):
                        return True
                    break
    return False


def _scoped_github_create_candidate(
    command: str, cwd: str, dangerous: set[str]
) -> dict[str, Any] | None:
    parsed = _parse_github_create_candidate(command, cwd, dangerous)
    if not parsed:
        return None
    candidate, executable_token = parsed
    return candidate if _trusted_executable_token(executable_token, "gh") else None


def _git_grant_matches(
    grant: dict[str, Any],
    candidate: dict[str, Any],
    event_turn: str,
    expected_session_hash: str = "",
) -> bool:
    if not _git_grant_usable(grant, expected_session_hash):
        return False
    if str(grant.get("turn_id") or "") != event_turn:
        return False
    operation = str(candidate.get("operation") or "")
    scope_hash = str(candidate.get("scope_hash") or "")
    bindings = grant.get("bindings")
    if not isinstance(bindings, dict) or not isinstance(bindings.get(scope_hash), dict):
        return False
    binding = bindings[scope_hash]
    if operation not in _git_grant_effective_operations(grant, scope_hash):
        return False
    pending_digest = str(grant.get("pending_digest") or "")
    if pending_digest and str(candidate.get("digest") or "") != pending_digest:
        return False
    consumed = grant.get("consumed_operations") or {}
    if operation in set(consumed.get(scope_hash) or []):
        return False
    operation_digests = binding.get("operation_digests") or {}
    if not isinstance(operation_digests, dict):
        return False
    expected_digest = str(operation_digests.get(operation) or "")
    if expected_digest and str(candidate.get("digest") or "") != expected_digest:
        return False
    if "downloaded_code_execution" in set(candidate.get("codes") or ()) and not expected_digest:
        return False
    if operation == "init":
        return bool(
            binding.get("init_branch")
            and candidate.get("branch") == binding.get("init_branch")
        )
    if operation == "push":
        if not (
            binding.get("remote") == "origin"
            and candidate.get("remote") == "origin"
            and binding.get("push_branch")
            and candidate.get("refspec") == binding.get("push_branch")
        ):
            return False
        target = str(binding.get("target") or "")
        if not target or tuple(candidate.get("remote_targets") or ()) != (target,):
            return False
        remote_identity = str(binding.get("remote_identity") or "")
        return bool(
            not remote_identity
            or tuple(candidate.get("remote_identities") or ()) == (remote_identity,)
        )
    if operation == "repo_create":
        return bool(
            candidate.get("visibility") == "private"
            and candidate.get("remote") == "origin"
            and binding.get("target")
            and candidate.get("target") == binding.get("target")
        )
    return True


def _consume_git_grant(grant: dict[str, Any], candidate: dict[str, Any]) -> None:
    scope_hash = str(candidate.get("scope_hash") or "")
    consumed = grant.get("consumed_operations")
    if not isinstance(consumed, dict):
        consumed = {}
    operations = set(consumed.get(scope_hash) or [])
    operations.add(str(candidate.get("operation") or ""))
    consumed[scope_hash] = sorted(operations)
    grant["consumed_operations"] = consumed


def _configured_term_pattern(terms: Sequence[str]) -> re.Pattern[str] | None:
    alternatives = "|".join(
        re.escape(term)
        for term in sorted(set(terms), key=lambda item: (-len(item), item.casefold()))
    )
    if not alternatives:
        return None
    return re.compile(
        rf"(?<![A-Za-z0-9_])(?P<term>{alternatives})(?![A-Za-z0-9_])",
        re.IGNORECASE,
    )


def _matching_concrete_term_hashes(text: str) -> set[str]:
    pattern = _configured_term_pattern(policy_store.load_policy().terms)
    if pattern is None:
        return set()
    concrete: set[str] = set()

    def record(term: str, value_start: int, value_end: int) -> None:
        value = _REDACTION_PLACEHOLDER_RE.sub("", text[value_start:value_end])
        if value.strip(" \t\r\n,，;；|"):
            concrete.add(_policy_value_hash(term))

    events: list[tuple[int, int, str | None, int]] = []
    for mention in pattern.finditer(text):
        cursor = mention.end()
        if (
            cursor < len(text)
            and text[cursor] in "\"'"
            and mention.start()
            and text[mention.start() - 1] == text[cursor]
        ):
            cursor += 1
        while cursor < len(text) and text[cursor] in " \t\r\n":
            cursor += 1
        if cursor == len(text) or text[cursor] not in ":：=":
            continue
        events.append((mention.start(), 1, mention.group("term"), cursor + 1))
    for assignment in _GENERIC_ASSIGNMENT_RE.finditer(text):
        label = assignment.group("label")
        if label.casefold() in {"http", "https"} and text[assignment.end() :].startswith("//"):
            continue
        events.append((assignment.start("label"), 0, None, assignment.end()))

    previous: tuple[str, int] | None = None
    for start, _, term, value_start in sorted(events):
        if previous is not None:
            record(previous[0], previous[1], start)
        previous = (term, value_start) if term is not None else None
    if previous is not None:
        record(previous[0], previous[1], len(text))
    return concrete


def _contains_concrete_sensitive_term(text: str) -> bool:
    return bool(_matching_concrete_term_hashes(text))


def _sensitive_concrete(text: str) -> bool:
    return bool(_sensitive_context(text) and _contains_concrete_sensitive_term(text))


def _is_external_tool(tool_name: str, text: str) -> bool:
    return bool(
        tool_name.startswith("mcp__")
        or _EXTERNAL_TOOL_RE.search(tool_name)
        or _EXTERNAL_COMMAND_RE.search(text)
    )


def _is_durable_destination(text: str) -> bool:
    return bool(
        _DURABLE_DESTINATION_RE.search(text)
        or _matches_policy_values(text, policy_store.load_policy().durable_markers)
    )


def _deny_pretool(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _deny_permission(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "deny", "message": reason},
        }
    }


def _allow_permission() -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "allow"},
        }
    }


def _handle_tool_gate(event: dict[str, Any]) -> dict[str, Any]:
    event_name = str(event.get("hook_event_name") or "")
    tool_name = str(event.get("tool_name") or "")
    tool_input = event.get("tool_input") or {}
    validation_error = _exec_command_validation_error(tool_name, tool_input)
    if validation_error:
        reason = "Execution tool input rejected: " + validation_error + "."
        return _deny_pretool(reason) if event_name == "PreToolUse" else _deny_permission(reason)
    text = _flatten_text(tool_input)
    sensitive_text = _flatten_sensitive_fields(tool_input)
    command = ""
    if isinstance(tool_input, dict) and _tool_family(tool_name) in {"bash", "exec_command"}:
        command = str(tool_input.get("command") or tool_input.get("cmd") or "")
    findings = (
        _scan_command(command, source=f"{event_name}:{tool_name}")
        if command
        else _scan_text(text, source=f"{event_name}:{tool_name}")
    )
    removed_text, persisted_text = _local_redaction_surfaces(tool_name, tool_input)
    secret_redaction = bool(
        removed_text
        and _secret_found(_scan_text(removed_text, source=f"{event_name}:{tool_name}:removed"))
        and not _secret_found(_scan_text(persisted_text, source=f"{event_name}:{tool_name}:persisted"))
    )

    if _secret_found(findings) and not secret_redaction:
        reason = "Potential credential detected in tool input. Redact it before execution."
        return _deny_pretool(reason) if event_name == "PreToolUse" else _deny_permission(reason)

    session_id = _session_id(event)
    event_turn = str(event.get("turn_id") or "")
    tool_use_id = str(event.get("tool_use_id") or "")
    base_event_cwd = str(event.get("cwd") or ".")
    event_cwd = base_event_cwd
    if isinstance(tool_input, dict) and tool_input.get("workdir"):
        event_cwd = str(tool_input["workdir"])
    state_snapshot = state_store.read_session(session_id)
    policy = policy_store.load_policy()
    clone_enabled = policy.enable_constrained_github_clone
    transaction_enabled = policy.enable_scoped_git_transactions
    execution_options_digest = _execution_options_digest(tool_name, tool_input)
    command_digest = _command_hash(command or text, event_cwd)
    runner_permission = _matching_git_runner_permission(
        state_snapshot,
        tool_use_id=tool_use_id,
        tool_name=tool_name,
        turn_id=event_turn,
        command_digest=command_digest,
        base_event_cwd=base_event_cwd,
        effective_cwd=event_cwd,
        execution_options_digest=execution_options_digest,
    )
    original_runner_permission = _matching_git_runner_permission(
        state_snapshot,
        tool_use_id=tool_use_id,
        tool_name=tool_name,
        turn_id=event_turn,
        command_digest=command_digest,
        base_event_cwd=base_event_cwd,
        effective_cwd=event_cwd,
        execution_options_digest=execution_options_digest,
        original=True,
    )
    pending_snapshot = state_snapshot.get("pending_permission_authorizations")
    stored_runner_permission = (
        pending_snapshot.get(tool_use_id)
        if isinstance(pending_snapshot, dict) and tool_use_id
        else None
    )
    stale_runner_permission = bool(
        isinstance(stored_runner_permission, dict)
        and stored_runner_permission.get("transaction_id")
        and stored_runner_permission.get("runner_token")
        and (
            command_digest
            in {
                str(stored_runner_permission.get("digest") or ""),
                str(stored_runner_permission.get("original_digest") or ""),
            }
            or _git_runner_invocation_shape(command)
        )
        and runner_permission is None
        and original_runner_permission is None
    )
    if stale_runner_permission:
        _revoke_git_transaction(
            session_id,
            str(stored_runner_permission.get("transaction_id") or ""),
        )
        reason = "The Git transaction runner ticket is missing, invalid, or already claimed."
        return _deny_pretool(reason) if event_name == "PreToolUse" else _deny_permission(reason)
    if original_runner_permission is not None:
        if event_name == "PermissionRequest":
            return _deny_permission(
                "The approved Git transaction must execute through its bound runner."
            )
        output = _context(
            "PreToolUse",
            "The scoped authorization remains active for this exact transaction step.",
        )
        output["hookSpecificOutput"].update(
            {
                "permissionDecision": "allow",
                "updatedInput": {
                    "command": str(original_runner_permission.get("runner_command") or "")
                },
            }
        )
        return output
    if runner_permission is not None:
        return _allow_permission() if event_name == "PermissionRequest" else {}
    clone_invocation = bool(command and _contains_clone_invocation(command))
    sandbox = (
        tool_input.get("sandbox_permissions", "use_default")
        if isinstance(tool_input, dict)
        else ""
    )
    constrained_clone_candidate = (
        _constrained_github_clone_candidate(
            command,
            effective_cwd=event_cwd,
            workspace_cwd=base_event_cwd,
        )
        if clone_enabled and command
        else None
    )
    exact_clone_candidate = (
        _exact_github_clone_candidate(
            command,
            effective_cwd=event_cwd,
            workspace_cwd=base_event_cwd,
        )
        if clone_enabled and command and constrained_clone_candidate is None
        else None
    )
    parsed_clone_candidate = constrained_clone_candidate or exact_clone_candidate
    clone_candidate = (
        parsed_clone_candidate
        if (
            parsed_clone_candidate
            and tool_name == "exec_command"
            and tool_use_id
            and sandbox == "use_default"
        )
        else None
    )
    if parsed_clone_candidate and clone_candidate is None:
        reason = (
            "The constrained clone lane requires exact exec_command, a nonempty tool_use_id, "
            "and the default sandbox."
        )
        return _deny_pretool(reason) if event_name == "PreToolUse" else _deny_permission(reason)
    if clone_enabled and clone_invocation and clone_candidate is None:
        reason = (
            "Clone-capable Git commands, including dynamic Git configuration, must use a directly "
            "parseable invocation with an explicit absolute destination so provenance can be "
            "tracked. For a read-only GitHub audit, use: "
            "git clone --depth 1 --no-checkout "
            "https://github.com/OWNER/REPO.git /ABSOLUTE/NEW/DESTINATION."
        )
        return _deny_pretool(reason) if event_name == "PreToolUse" else _deny_permission(reason)
    if clone_enabled and command and _command_uses_untrusted_clone(
        command, event_cwd, _tracked_clone_roots(state_snapshot)
    ):
        findings.append(_finding("downloaded_code_execution", "medium"))
    dangerous = _dangerous_codes(_dedupe_findings(findings))
    digest = command_digest
    clone_reservation = (
        _clone_reservation_metadata(
            clone_candidate,
            session_hash=str(state_snapshot.get("session_hash") or ""),
            turn_id=event_turn,
            tool_name=tool_name,
            tool_use_id=tool_use_id,
            digest=digest,
            base_event_cwd=base_event_cwd,
            effective_cwd=event_cwd,
            execution_options_digest=execution_options_digest,
        )
        if clone_candidate
        else None
    )
    if clone_reservation:
        reservation_result = {"ready": False}

        if event_name == "PreToolUse":
            def reserve_clone(state: dict[str, Any]) -> None:
                reservation_result["ready"] = _reserve_clone(
                    state, tool_use_id, clone_reservation
                )

            state_snapshot = state_store.mutate_session(session_id, reserve_clone)
        else:
            pending_clones = state_snapshot.get("pending_constrained_clones")
            reservation_result["ready"] = bool(
                isinstance(pending_clones, dict)
                and _clone_reservation_matches(
                    pending_clones.get(tool_use_id), clone_reservation
                )
            )
        if not reservation_result["ready"]:
            reason = "Constrained clone provenance reservation did not match exactly."
            return _deny_pretool(reason) if event_name == "PreToolUse" else _deny_permission(reason)
        if constrained_clone_candidate:
            # Native Codex policy remains responsible for this read-only audit lane.
            dangerous -= {"git_network", "git_non_read_only"}
    scoped_operation = None
    if command:
        scoped_operation = _scoped_git_candidate(command, event_cwd, dangerous)
        if scoped_operation is None:
            scoped_operation = _scoped_github_create_candidate(command, event_cwd, dangerous)
    current_grant = state_snapshot.get("local_git_grant")
    if (
        os.name == "nt"
        and event_name == "PreToolUse"
        and transaction_enabled
        and scoped_operation
        and isinstance(current_grant, dict)
        and _git_grant_matches(
            current_grant,
            scoped_operation,
            event_turn,
            str(state_snapshot.get("session_hash") or ""),
        )
    ):
        try:
            _git_runner_shell_kind(tool_name, tool_input)
        except RuntimeError as error:
            return _deny_pretool(str(error))
    authorization_result: dict[str, Any] = {
        "unauthorized": sorted(dangerous),
        "permission_accepted": False,
    }

    def mutate_authorization(state: dict[str, Any]) -> None:
        current_turn = str(state.get("current_turn_id") or "")
        turn_matches = bool(current_turn and event_turn and current_turn == event_turn)
        authorized = state.get("dangerous_authorization_hashes") or {}
        pending_permissions = state.get("pending_permission_authorizations")
        if not isinstance(pending_permissions, dict):
            pending_permissions = {}

        if event_name == "PermissionRequest":
            pending = pending_permissions.get(tool_use_id) if tool_use_id else None
            pending_matches = bool(
                dangerous
                and digest
                and turn_matches
                and isinstance(pending, dict)
                and str(pending.get("session_hash") or "")
                == str(state.get("session_hash") or "")
                and str(pending.get("turn_id") or "") == event_turn
                and str(pending.get("tool_use_id") or "") == tool_use_id
                and str(pending.get("tool_name") or "") == tool_name
                and str(pending.get("digest") or "") == digest
                and str(pending.get("base_event_cwd") or "")
                == _normalized_cwd(base_event_cwd)
                and str(pending.get("effective_cwd") or "")
                == _normalized_cwd(event_cwd)
                and str(pending.get("execution_options_digest") or "")
                == execution_options_digest
                and set(pending.get("codes") or []) == dangerous
            )
            if pending_matches and pending.get("transaction_id"):
                grant = state.get("local_git_grant")
                pending_matches = bool(
                    isinstance(grant, dict)
                    and scoped_operation
                    and pending.get("transaction_id") == grant.get("transaction_id")
                    and pending.get("scope_hash") == scoped_operation.get("scope_hash")
                    and pending.get("operation") == scoped_operation.get("operation")
                    and _git_grant_matches(
                        grant,
                        scoped_operation,
                        event_turn,
                        str(state.get("session_hash") or ""),
                    )
                )
            if pending_matches:
                if not pending.get("transaction_id"):
                    pending_permissions.pop(tool_use_id, None)
            authorization_result["unauthorized"] = [] if pending_matches else sorted(dangerous)
            authorization_result["permission_accepted"] = pending_matches
            state["pending_permission_authorizations"] = pending_permissions
            return

        pending = pending_permissions.get(tool_use_id) if tool_use_id else None
        pending_matches = bool(
            dangerous
            and digest
            and turn_matches
            and isinstance(pending, dict)
            and str(pending.get("session_hash") or "")
            == str(state.get("session_hash") or "")
            and str(pending.get("turn_id") or "") == event_turn
            and str(pending.get("tool_use_id") or "") == tool_use_id
            and str(pending.get("digest") or "") == digest
            and str(pending.get("tool_name") or "") == tool_name
            and str(pending.get("base_event_cwd") or "")
            == _normalized_cwd(base_event_cwd)
            and str(pending.get("effective_cwd") or "")
            == _normalized_cwd(event_cwd)
            and str(pending.get("execution_options_digest") or "")
            == execution_options_digest
            and set(pending.get("codes") or []) == dangerous
        )
        if pending_matches:
            authorization_result["unauthorized"] = []
            state["pending_permission_authorizations"] = pending_permissions
            return

        exact_codes = {
            code for code in dangerous if turn_matches and digest and digest in set(authorized.get(code) or [])
        }
        grant_codes: set[str] = set()
        grant = state.get("local_git_grant")
        transaction_reserved = False
        if (
            transaction_enabled
            and scoped_operation
            and isinstance(grant, dict)
            and turn_matches
        ):
            if _git_grant_matches(
                grant,
                scoped_operation,
                event_turn,
                str(state.get("session_hash") or ""),
            ):
                transaction_reserved = any(
                    isinstance(item, dict)
                    and item.get("transaction_id") == grant.get("transaction_id")
                    for item in pending_permissions.values()
                )
                if not transaction_reserved:
                    grant_codes.update(scoped_operation.get("codes") or [])

        allowed_codes = exact_codes | grant_codes
        unauthorized = sorted(code for code in dangerous if code not in allowed_codes)
        if dangerous and (not tool_use_id or not digest or not turn_matches):
            unauthorized = sorted(dangerous)
        authorization_result["unauthorized"] = unauthorized

        if not unauthorized and dangerous:
            for code in exact_codes:
                remaining_hashes = [item for item in authorized.get(code, []) if item != digest]
                if remaining_hashes:
                    authorized[code] = remaining_hashes
                else:
                    authorized.pop(code, None)
            state["dangerous_authorization_hashes"] = authorized
            state["dangerous_authorizations"] = sorted(authorized)

            permission_record = {
                "session_hash": str(state.get("session_hash") or ""),
                "turn_id": event_turn,
                "tool_use_id": tool_use_id,
                "tool_name": tool_name,
                "digest": digest,
                "codes": sorted(dangerous),
                "base_event_cwd": _normalized_cwd(base_event_cwd),
                "effective_cwd": _normalized_cwd(event_cwd),
                "execution_options_digest": execution_options_digest,
            }
            if grant_codes and isinstance(grant, dict) and scoped_operation:
                permission_record.update(
                    {
                        "transaction_id": str(grant.get("transaction_id") or ""),
                        "scope_hash": str(scoped_operation.get("scope_hash") or ""),
                        "operation": str(scoped_operation.get("operation") or ""),
                        "scope": str(scoped_operation.get("scope") or ""),
                    }
                )
                for key in (
                    "branch",
                    "pathspecs",
                    "refspec",
                    "target",
                ):
                    if key in scoped_operation:
                        permission_record[key] = scoped_operation[key]
            pending_permissions[tool_use_id] = permission_record
            state["pending_permission_authorizations"] = pending_permissions

        if unauthorized and event_name == "PreToolUse" and scoped_operation:
            pending = state.get("pending_local_git")
            if not pending or pending.get("digest") == scoped_operation.get("digest"):
                state["pending_local_git"] = {
                    **scoped_operation,
                    "created_at": time.time(),
                    "source_turn_id": event_turn,
                }
            else:
                state["pending_local_git"] = {
                    "ambiguous": True,
                    "created_at": time.time(),
                    "source_turn_id": event_turn,
                }
        elif not unauthorized and scoped_operation:
            pending = state.get("pending_local_git")
            if isinstance(pending, dict) and pending.get("digest") == scoped_operation.get("digest"):
                state["pending_local_git"] = None

    state = state_store.mutate_session(session_id, mutate_authorization)
    unauthorized = authorization_result["unauthorized"]
    if unauthorized:
        if "downloaded_code_execution" in unauthorized:
            reason = (
                "Execution or mutation inside a freshly cloned codebase requires one exact "
                "current-turn authorization for this command. Read-only inspection with Read, "
                "rg, cat, git show, git status, and git diff remains available. Blocked for: "
                + ", ".join(unauthorized)
                + "."
            )
        elif scoped_operation and event_name == "PreToolUse":
            reason = (
                "A scoped Git/GitHub operation is pending approval: "
                + str(scoped_operation["operation"])
                + ". One explicit transaction grant may cover all predeclared "
                "init/add/commit/private repo create/push steps; do not request them "
                "separately. Blocked for: "
                + ", ".join(unauthorized)
                + "."
            )
        else:
            reason = (
                "High-risk command blocked because this turn lacks explicit authorization for: "
                + ", ".join(unauthorized)
                + ". Use a reversible alternative or ask the user to authorize the exact command and scope."
            )
        return _deny_pretool(reason) if event_name == "PreToolUse" else _deny_permission(reason)

    session_sensitive = bool(state.get("sensitive_context"))
    sensitive = _sensitive_context(sensitive_text) or session_sensitive
    concrete = _sensitive_concrete(sensitive_text) or bool(
        session_sensitive and _contains_concrete_sensitive_term(sensitive_text)
    )
    removed_sensitive = _sensitive_concrete(removed_text) or bool(
        session_sensitive and _contains_concrete_sensitive_term(removed_text)
    )
    persisted_sensitive = _sensitive_concrete(persisted_text) or bool(
        session_sensitive and _contains_concrete_sensitive_term(persisted_text)
    )
    sensitive_redaction = bool(removed_text and removed_sensitive and not persisted_sensitive)
    targets = _external_targets_from_tool_name(tool_name)
    external = bool(targets) or _is_external_tool(tool_name, text)
    local_persistence = tool_name in {"Write", "Edit", "apply_patch"}
    durable = local_persistence or _is_durable_destination(text)
    grant = state.get("sensitive_disclosure_grant")
    concrete_terms = _matching_concrete_term_hashes(sensitive_text)
    grant_terms = set(grant.get("term_hashes") or []) if isinstance(grant, dict) else set()
    grant_tool_hash = str(grant.get("tool_name_hash") or "") if isinstance(grant, dict) else ""
    disclosure = bool(
        isinstance(grant, dict)
        and str(grant.get("turn_id") or "") == event_turn
        and len(targets) == 1
        and str(grant.get("target") or "") == next(iter(targets))
        and (not grant_tool_hash or grant_tool_hash == _policy_value_hash(tool_name))
        and concrete_terms
        and concrete_terms.issubset(grant_terms)
    )
    if sensitive and concrete and (external or durable) and not disclosure and not sensitive_redaction:
        reason = (
            "Concrete configured sensitive-business data is blocked from external or durable use. "
            "Aggregate or redact it, or obtain explicit disclosure authorization for this turn."
        )
        return _deny_pretool(reason) if event_name == "PreToolUse" else _deny_permission(reason)

    if disclosure and concrete and (external or durable):
        def consume_disclosure(current: dict[str, Any]) -> None:
            if current.get("sensitive_disclosure_grant") == grant:
                current["sensitive_disclosure_grant"] = None

        state = state_store.mutate_session(session_id, consume_disclosure)

    if event_name == "PermissionRequest" and authorization_result["permission_accepted"]:
        return _allow_permission()

    if event_name == "PreToolUse" and (
        dangerous
        or sensitive
        or secret_redaction
        or sensitive_redaction
        or (state.get("sensitive_context") and external)
    ):
        notes: list[str] = []
        if dangerous:
            notes.append(
                "The scoped authorization was accepted for this turn; "
                "do not request the same authorization again."
            )
        if secret_redaction or sensitive_redaction:
            notes.append(
                "Local redaction accepted because newly persisted content no longer contains "
                "the detected sensitive value."
            )
        if sensitive or (state.get("sensitive_context") and external):
            notes.append(
                "Keep configured sensitive-business data aggregated or redacted; "
                "do not disclose concrete values."
            )
        output = _context("PreToolUse", " ".join(notes))
        pending_permissions = state.get("pending_permission_authorizations")
        permission = (
            pending_permissions.get(tool_use_id)
            if isinstance(pending_permissions, dict)
            else None
        )
        if dangerous and isinstance(permission, dict) and permission.get("transaction_id"):
            try:
                runner_command = _prepare_git_runner(
                    session_id,
                    tool_use_id=tool_use_id,
                    tool_name=tool_name,
                    tool_input=tool_input,
                    original_command=command,
                    original_digest=digest,
                    effective_cwd=event_cwd,
                )
            except Exception:
                transaction_id = str(permission.get("transaction_id") or "")
                _revoke_git_transaction(session_id, transaction_id)
                raise
            output["hookSpecificOutput"].update(
                {
                    "permissionDecision": "allow",
                    "updatedInput": {"command": runner_command},
                }
            )
        return output
    return {}


def _tool_response_status(response: Any) -> str:
    if not isinstance(response, dict):
        return "unknown"
    if response.get("isError") is True or response.get("is_error") is True:
        return "failure"
    statuses: list[int] = []
    for key in ("exit_code", "returncode"):
        value = response.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            statuses.append(value)
    if any(value != 0 for value in statuses):
        return "failure"
    return "success" if statuses else "unknown"


def _handle_post_tool(event: dict[str, Any]) -> dict[str, Any]:
    tool_name = str(event.get("tool_name") or "")
    session_id = _session_id(event)
    event_turn = str(event.get("turn_id") or "")
    tool_use_id = str(event.get("tool_use_id") or "")
    tool_input = event.get("tool_input") or {}
    validation_error = _exec_command_validation_error(tool_name, tool_input)
    command = ""
    if isinstance(tool_input, dict) and _tool_family(tool_name) in {"bash", "exec_command"}:
        command = str(tool_input.get("command") or tool_input.get("cmd") or "")
    base_event_cwd = str(event.get("cwd") or ".")
    event_cwd = base_event_cwd
    if isinstance(tool_input, dict) and tool_input.get("workdir"):
        event_cwd = str(tool_input["workdir"])
    digest = _command_hash(command, event_cwd) if command else ""
    execution_options_digest = _execution_options_digest(tool_name, tool_input)
    clone_enabled = policy_store.load_policy().enable_constrained_github_clone
    tool_status = _tool_response_status(event.get("tool_response"))

    def clear_pending(state: dict[str, Any]) -> None:
        pending = state.get("pending_permission_authorizations")
        permission = pending.get(tool_use_id) if isinstance(pending, dict) else None
        permission_matches = bool(
            isinstance(permission, dict)
            and not validation_error
            and digest
            and str(permission.get("session_hash") or "")
            == str(state.get("session_hash") or "")
            and str(permission.get("turn_id") or "") == event_turn
            and str(permission.get("tool_use_id") or "") == tool_use_id
            and str(permission.get("tool_name") or "") == tool_name
            and digest == str(permission.get("digest") or "")
            and str(permission.get("base_event_cwd") or "")
            == _normalized_cwd(base_event_cwd)
            and str(permission.get("effective_cwd") or "")
            == _normalized_cwd(event_cwd)
            and str(permission.get("execution_options_digest") or "")
            == execution_options_digest
        )
        if isinstance(pending, dict) and permission_matches:
            pending.pop(tool_use_id, None)
            state["pending_permission_authorizations"] = pending
            transaction_id = str(permission.get("transaction_id") or "")
            grant = state.get("local_git_grant")
            if (
                transaction_id
                and isinstance(grant, dict)
                and str(grant.get("transaction_id") or "") == transaction_id
            ):
                operation_succeeded = (
                    _consume_git_runner_status(permission) == "success"
                    if permission.get("runner_token")
                    else tool_status == "success"
                )
                if operation_succeeded:
                    _consume_git_grant(
                        grant,
                        {
                            "scope_hash": str(permission.get("scope_hash") or ""),
                            "operation": str(permission.get("operation") or ""),
                        },
                    )
                    state["local_git_grant"] = (
                        grant
                        if _git_grant_usable(
                            grant, str(state.get("session_hash") or "")
                        )
                        else None
                    )
                else:
                    _clear_git_transaction_state(state, transaction_id)
                    _cleanup_git_runner_transaction_records(transaction_id)
        pending_clones = state.get("pending_constrained_clones")
        if not isinstance(pending_clones, dict):
            pending_clones = {}
        clone = pending_clones.get(tool_use_id) if tool_use_id else None
        clone_matches = False
        if (
            isinstance(clone, dict)
            and not validation_error
            and tool_name == "exec_command"
            and digest
        ):
            expected = _clone_reservation_metadata(
                {
                    "source": str(clone.get("source") or ""),
                    "target": str(clone.get("target") or ""),
                    "destination": str(clone.get("destination") or ""),
                },
                session_hash=str(state.get("session_hash") or ""),
                turn_id=event_turn,
                tool_name=tool_name,
                tool_use_id=tool_use_id,
                digest=digest,
                base_event_cwd=base_event_cwd,
                effective_cwd=event_cwd,
                execution_options_digest=execution_options_digest,
            )
            clone_matches = _clone_reservation_matches(clone, expected)
        clone = pending_clones.pop(tool_use_id, None) if clone_matches else None
        state["pending_constrained_clones"] = pending_clones
        if not clone_enabled or not isinstance(clone, dict):
            return
        raw_destination = str(clone.get("destination") or "")
        if not raw_destination:
            return
        destination = _normalized_cwd(raw_destination)
        if not _looks_like_git_clone(destination):
            return
        roots = state.get("untrusted_clone_roots")
        if not isinstance(roots, dict):
            roots = {}
        roots[destination] = {
            "source": str(clone.get("source") or ""),
            "target": str(clone.get("target") or ""),
            "created_at": int(time.time()),
        }
        state["untrusted_clone_roots"] = roots

    state = state_store.mutate_session(session_id, clear_pending)
    response_text = _flatten_sensitive_fields(event.get("tool_response"))
    findings = _scan_tool_output(event, response_text, source=f"PostToolUse:{tool_name}")
    if _secret_found(findings):
        return {
            "decision": "block",
            "reason": "Potential credential detected in tool output. Do not repeat, persist, or externalize it.",
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": (
                    "Treat the original tool output as sensitive and continue only with "
                    "a redacted summary."
                ),
            },
        }
    concrete_sensitive = _sensitive_concrete(response_text) or bool(
        state.get("sensitive_context") and _contains_concrete_sensitive_term(response_text)
    )
    if concrete_sensitive:
        return _context(
            "PostToolUse",
            "The tool returned configured sensitive-business data. Use it only for the authorized local task "
            "and redact or aggregate it before durable notes, logs, public docs, or external services.",
        )
    return {}


def _handle_subagent_start(event: dict[str, Any]) -> dict[str, Any]:
    session_id = _session_id(event)
    agent_id = str(event.get("agent_id") or f"unknown-{time.time_ns()}")
    agent_type = str(event.get("agent_type") or "default")

    def mutate(state: dict[str, Any]) -> None:
        active = state.setdefault("active_agents", {})
        active[agent_id] = {"agent_type": agent_type, "started_at": int(time.time())}

    state = state_store.mutate_session(session_id, mutate)
    nested = bool(state.get("nested_allowed"))
    if nested:
        message = "Nested delegation is authorized for this turn. Stay within the parent's explicit child budget."
    else:
        message = "Nested delegation is not authorized for this turn. Do not spawn subagents."
    return _context("SubagentStart", message)


def _handle_subagent_stop(event: dict[str, Any]) -> dict[str, Any]:
    session_id = _session_id(event)
    agent_id = str(event.get("agent_id") or "")

    def mutate(state: dict[str, Any]) -> None:
        state.setdefault("active_agents", {}).pop(agent_id, None)

    state_store.mutate_session(session_id, mutate)
    return {}


def _handle_precompact(event: dict[str, Any]) -> dict[str, Any]:
    session_id = _session_id(event)

    def mutate(state: dict[str, Any]) -> None:
        state["compaction_count"] = int(state.get("compaction_count", 0)) + 1

    state = state_store.mutate_session(session_id, mutate)
    active_count = len(state.get("active_agents") or {})
    if not active_count:
        return {}
    return {
        "systemMessage": (
            f"Control-plane state checkpoint recorded before compaction. {active_count} Agent(s) remain active; "
            "reconcile them before claiming completion."
        )
    }


def _handle_stop(event: dict[str, Any]) -> dict[str, Any]:
    if bool(event.get("stop_hook_active")):
        return {}
    session_id = _session_id(event)
    active_count = _stop_state(session_id)
    if active_count:
        return {
            "decision": "block",
            "reason": (
                f"{active_count} Agent(s) are still active. Wait for or close them, "
                "then reconcile their results."
            ),
        }
    return {}


def dispatch(event: dict[str, Any]) -> dict[str, Any]:
    event_name = str(event.get("hook_event_name") or "")
    if event_name == "UserPromptSubmit":
        return user_prompt_submit_handler.handle(event)
    if event_name in {"PreToolUse", "PermissionRequest"}:
        return _handle_tool_gate(event)
    if event_name == "PostToolUse":
        return _handle_post_tool(event)
    if event_name == "SubagentStart":
        return _handle_subagent_start(event)
    if event_name == "SubagentStop":
        return _handle_subagent_stop(event)
    if event_name == "PreCompact":
        return _handle_precompact(event)
    if event_name == "Stop":
        return _handle_stop(event)
    return {}


def _internal_error_response(event: dict[str, Any], *, parse_error: bool = False) -> dict[str, Any]:
    event_name = str(event.get("hook_event_name") or "")
    reason = (
        "Control-plane input could not be parsed; the action is blocked."
        if parse_error
        else "Control-plane internal validation failed; the action is blocked."
    )
    if event_name == "PreToolUse":
        return _deny_pretool(reason)
    if event_name == "PermissionRequest":
        return _deny_permission(reason)
    return {"decision": "block", "reason": reason}


def main() -> int:
    if len(sys.argv) == 4 and sys.argv[1] == "--run-approved-git":
        try:
            _configure_runner_data_dir(sys.argv[3])
        except Exception:
            return 126
        return _run_approved_git(sys.argv[2])
    if len(sys.argv) != 1:
        return 64
    event: dict[str, Any] = {}
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8", errors="strict"))
        if not isinstance(payload, dict):
            response = _internal_error_response({}, parse_error=True)
        else:
            event = payload
            response = dispatch(event)
    except Exception:
        response = _internal_error_response(event, parse_error=not event)
    encoded = (json.dumps(response, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
