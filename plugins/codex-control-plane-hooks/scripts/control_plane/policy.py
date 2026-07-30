"""Validated immutable policy view for control-plane handlers."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import event_context

MAX_POLICY_BYTES = 64_000


@dataclass(frozen=True)
class PolicyView:
    """The complete policy Interface consumed by hook handlers."""

    markers: tuple[str, ...] = ()
    terms: tuple[str, ...] = ()
    durable_markers: tuple[str, ...] = ()
    enable_natural_language_approvals: bool = False
    enable_sensitive_disclosure_approvals: bool = False
    enable_scoped_git_transactions: bool = False
    enable_constrained_github_clone: bool = False


def _is_reparse_point(info: os.stat_result) -> bool:
    attributes = int(getattr(info, "st_file_attributes", 0))
    marker = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    return bool(marker and attributes & marker)


def _absolute_path(value: str, name: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise RuntimeError(f"{name} must be an absolute path")
    return path


def _resolve_private_data_dir() -> Path:
    configured = os.environ.get("PLUGIN_DATA")
    if configured:
        path = _absolute_path(configured, "PLUGIN_DATA")
    else:
        if os.name == "nt":
            raise RuntimeError("PLUGIN_DATA is required on Windows")
        state_home = os.environ.get("XDG_STATE_HOME")
        base = _absolute_path(state_home, "XDG_STATE_HOME") if state_home else Path.home() / ".local" / "state"
        path = base / "codex-control-plane-hooks"

    if path.exists() and path.is_symlink():
        raise RuntimeError("refusing symlinked policy data directory")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = os.stat(path, follow_symlinks=False)
    if _is_reparse_point(info) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError("policy data path is not a regular directory")
    if os.name != "nt" and hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise PermissionError("policy data directory is owned by another user")
    if os.name != "nt" and info.st_mode & 0o077:
        path.chmod(0o700)
    return path


def _private_data_dir() -> Path:
    return event_context.data_dir(_resolve_private_data_dir)


def _policy_path() -> Path:
    configured = os.environ.get("CONTROL_PLANE_POLICY")
    if configured and os.name == "nt":
        raise RuntimeError("Windows policy must use PLUGIN_DATA/policy.json")
    return _absolute_path(configured, "CONTROL_PLANE_POLICY") if configured else _private_data_dir() / "policy.json"


def _values(raw: dict[str, Any], key: str) -> tuple[str, ...]:
    values = raw.get(key, [])
    if not isinstance(values, list):
        return ()
    return tuple(item.strip() for item in values[:100] if isinstance(item, str) and item.strip())


def _load_policy_uncached() -> PolicyView:
    """Load the configured policy or return the immutable default policy."""

    path = _policy_path()
    explicitly_configured = bool(os.environ.get("CONTROL_PLANE_POLICY"))
    try:
        info = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        if explicitly_configured:
            raise RuntimeError("configured policy file is unavailable") from None
        return PolicyView()

    if path.is_symlink() or _is_reparse_point(info) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError("policy path must be a regular non-symlink file")
    if info.st_size > MAX_POLICY_BYTES:
        raise RuntimeError("policy file exceeds the size limit")
    if os.name != "nt" and hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise PermissionError("policy file is owned by another user")
    if explicitly_configured and os.name != "nt" and info.st_mode & 0o077:
        raise PermissionError("external policy file must not be accessible by group or others")

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError("policy file is invalid") from exc
    if not isinstance(raw, dict):
        raise RuntimeError("policy file must contain a JSON object")

    return PolicyView(
        markers=_values(raw, "sensitive_markers"),
        terms=_values(raw, "sensitive_terms"),
        durable_markers=_values(raw, "durable_destination_markers"),
        enable_natural_language_approvals=(raw.get("enable_natural_language_approvals") is True),
        enable_sensitive_disclosure_approvals=(raw.get("enable_sensitive_disclosure_approvals") is True),
        enable_scoped_git_transactions=(raw.get("enable_scoped_git_transactions") is True),
        enable_constrained_github_clone=(raw.get("enable_constrained_github_clone") is True),
    )


def load_policy() -> PolicyView:
    """Load at most one immutable policy view per dispatched event."""

    return event_context.policy(_load_policy_uncached)
