"""Private session persistence exposed through snapshot-oriented operations."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Any, Callable

from . import event_context

try:
    import fcntl
except ImportError:  # pragma: no cover - unavailable on native Windows.
    fcntl = None

try:
    import msvcrt
except ImportError:  # pragma: no cover - unavailable on macOS/Linux.
    msvcrt = None


__all__ = ["cleanup_session", "mutate_session", "read_session"]

_STATE_SCHEMA_VERSION = 4
_STATE_TTL_SECONDS = 7 * 24 * 60 * 60

_SessionSnapshot = dict[str, Any]
_SessionMutator = Callable[[_SessionSnapshot], None]
_RemovePredicate = Callable[[_SessionSnapshot], bool]


def read_session(session_id: str) -> _SessionSnapshot:
    """Return the current session snapshot, refreshing its persisted timestamp."""

    return mutate_session(session_id, lambda state: None)


def mutate_session(session_id: str, mutator: _SessionMutator) -> _SessionSnapshot:
    """Apply ``mutator`` to a session and return the persisted snapshot."""

    path = _state_path(session_id)
    lock_path = path.with_suffix(".lock")
    with _open_private(lock_path, os.O_RDWR | os.O_CREAT, binary=True) as lock:
        lock_backend = _lock_state(lock)
        try:
            state = _load(path, session_id)
            mutator(state)
            state["schema_version"] = _STATE_SCHEMA_VERSION
            state["updated_at"] = int(time.time())
            _write_atomic(path, state)
            return state
        finally:
            _unlock_state(lock, lock_backend)


def cleanup_session(session_id: str, remove_predicate: _RemovePredicate) -> _SessionSnapshot:
    """Return a snapshot and remove its file only when the predicate returns true.

    The predicate is evaluated while holding the session lock. Returning ``False``
    retains the state; returning ``True`` removes it.
    """

    path = _state_path(session_id)
    lock_path = path.with_suffix(".lock")
    with _open_private(lock_path, os.O_RDWR | os.O_CREAT, binary=True) as lock:
        lock_backend = _lock_state(lock)
        try:
            state = _load(path, session_id)
            if remove_predicate(state):
                _unlink_owned_regular(path)
            return state
        finally:
            _unlock_state(lock, lock_backend)


def _resolve_data_dir() -> Path:
    configured = os.environ.get("PLUGIN_DATA")
    if configured:
        return _private_directory(_absolute_configured_path(configured, "PLUGIN_DATA"))
    if os.name == "nt":
        raise RuntimeError("PLUGIN_DATA is required on Windows")
    state_home = os.environ.get("XDG_STATE_HOME")
    base = _absolute_configured_path(state_home, "XDG_STATE_HOME") if state_home else Path.home() / ".local" / "state"
    return _private_directory(base / "codex-control-plane-hooks")


def _data_dir() -> Path:
    return event_context.data_dir(_resolve_data_dir)


def _absolute_configured_path(value: str, name: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise RuntimeError(f"{name} must be an absolute path")
    return path


def _is_reparse_info(info: os.stat_result) -> bool:
    attributes = int(getattr(info, "st_file_attributes", 0))
    marker = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    return bool(marker and attributes & marker)


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


def _state_path(session_id: str) -> Path:
    if not session_id.strip():
        raise ValueError("session_id is required")
    digest = hashlib.sha256(session_id.encode("utf-8", errors="replace")).hexdigest()[:24]
    return _data_dir() / f"session-{digest}.json"


def _load(path: Path, session_id: str) -> _SessionSnapshot:
    try:
        with _open_private(path, os.O_RDONLY) as stream:
            raw = stream.read()
    except FileNotFoundError:
        return _default_state(session_id)
    try:
        state = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("state file contains invalid JSON") from exc
    if not isinstance(state, dict):
        raise RuntimeError("state file must contain a JSON object")
    schema_version = state.get("schema_version")
    updated_at = state.get("updated_at")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or not isinstance(updated_at, int)
        or isinstance(updated_at, bool)
    ):
        raise RuntimeError("state file metadata is invalid")
    if schema_version not in {1, 2, 3, _STATE_SCHEMA_VERSION}:
        raise RuntimeError("state file schema is unsupported")
    if updated_at <= 0:
        raise RuntimeError("state file timestamp is invalid")
    if int(time.time()) - updated_at > _STATE_TTL_SECONDS:
        return _default_state(session_id)

    _validate_state_fields(state)
    normalized = _default_state(session_id)
    for key in normalized:
        if key in state:
            normalized[key] = state[key]
    normalized["schema_version"] = _STATE_SCHEMA_VERSION
    normalized["session_hash"] = _default_state(session_id)["session_hash"]
    return normalized


def _open_private(path: Path, flags: int, mode: int = 0o600, *, binary: bool = False):
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
    if binary:
        stream_mode = "r+b" if writable else "rb"
        return os.fdopen(descriptor, stream_mode, buffering=0)
    stream_mode = "r+" if writable else "r"
    return os.fdopen(descriptor, stream_mode, encoding="utf-8")


def _lock_state(stream) -> str:
    timeout = event_context.remaining_seconds(5.0)
    if timeout <= 0:
        raise TimeoutError("event budget exhausted before acquiring the state lock")
    deadline = time.monotonic() + timeout
    if fcntl is not None:
        while True:
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return "fcntl"
            except (BlockingIOError, OSError):
                if time.monotonic() >= deadline:
                    raise TimeoutError("timed out acquiring the POSIX state lock")
                time.sleep(0.05)
    if msvcrt is None:
        raise RuntimeError("no supported state-lock backend is available")
    while True:
        stream.seek(0, os.SEEK_END)
        if stream.tell() > 0:
            break
        try:
            stream.write(b"0")
            os.fsync(stream.fileno())
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise TimeoutError("timed out initializing the Windows state lock")
            time.sleep(0.05)
    while True:
        stream.seek(0)
        try:
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            return "msvcrt"
        except OSError:
            if time.monotonic() >= deadline:
                raise TimeoutError("timed out acquiring the Windows state lock")
            time.sleep(0.05)


def _unlock_state(stream, backend: str) -> None:
    if backend == "fcntl":
        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        return
    if backend == "msvcrt":
        stream.seek(0)
        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        return
    raise RuntimeError(f"unknown state-lock backend: {backend}")


def _try_lock_state(stream) -> str | None:
    """Try one state-style lock without waiting; None leaves ownership unknown."""
    if fcntl is not None:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return "fcntl"
        except (BlockingIOError, OSError):
            return None
    if msvcrt is None:
        return None
    stream.seek(0, os.SEEK_END)
    if stream.tell() == 0:
        return None
    stream.seek(0)
    try:
        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        return "msvcrt"
    except OSError:
        return None


def _write_atomic(path: Path, state: _SessionSnapshot) -> None:
    temp = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    try:
        with _open_private(temp, os.O_RDWR | os.O_CREAT | os.O_EXCL) as stream:
            stream.write(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        _unlink_owned_regular(temp)


def _unlink_owned_regular(candidate: Path) -> None:
    try:
        info = os.stat(candidate, follow_symlinks=False)
    except FileNotFoundError:
        return
    owned = os.name == "nt" or not hasattr(os, "getuid") or info.st_uid == os.getuid()
    if stat.S_ISREG(info.st_mode) and not _is_reparse_info(info) and owned:
        candidate.unlink()


def _validate_state_fields(state: _SessionSnapshot) -> None:
    scalar_types = {
        "session_hash": str,
        "current_turn_id": str,
        "explicit_expand": bool,
        "nested_allowed": bool,
        "sensitive_context": bool,
    }
    for key, expected_type in scalar_types.items():
        if key in state and type(state[key]) is not expected_type:
            raise RuntimeError(f"state field has invalid type: {key}")

    active_agents = state.get("active_agents", {})
    if not isinstance(active_agents, dict) or not all(
        isinstance(agent_id, str) and isinstance(metadata, dict) for agent_id, metadata in active_agents.items()
    ):
        raise RuntimeError("state field has invalid type: active_agents")

    dangerous_authorizations = state.get("dangerous_authorizations", [])
    if not isinstance(dangerous_authorizations, list) or not all(
        isinstance(item, str) for item in dangerous_authorizations
    ):
        raise RuntimeError("state field has invalid type: dangerous_authorizations")

    dangerous_hashes = state.get("dangerous_authorization_hashes", {})
    if not isinstance(dangerous_hashes, dict) or not all(
        isinstance(code, str) and isinstance(digests, list) and all(isinstance(digest, str) for digest in digests)
        for code, digests in dangerous_hashes.items()
    ):
        raise RuntimeError("state field has invalid type: dangerous_authorization_hashes")

    pending_permissions = state.get("pending_permission_authorizations", {})
    if not isinstance(pending_permissions, dict) or not all(
        isinstance(tool_id, str) and isinstance(metadata, dict) for tool_id, metadata in pending_permissions.items()
    ):
        raise RuntimeError("state field has invalid type: pending_permission_authorizations")

    for key in ("pending_constrained_clones", "untrusted_clone_roots"):
        records = state.get(key, {})
        if not isinstance(records, dict) or not all(
            isinstance(record_id, str) and isinstance(metadata, dict) for record_id, metadata in records.items()
        ):
            raise RuntimeError(f"state field has invalid type: {key}")

    for key in ("sensitive_disclosure_grant", "local_git_grant", "pending_local_git"):
        if key in state and state[key] is not None and not isinstance(state[key], dict):
            raise RuntimeError(f"state field has invalid type: {key}")

    compaction_count = state.get("compaction_count", 0)
    if not isinstance(compaction_count, int) or isinstance(compaction_count, bool) or compaction_count < 0:
        raise RuntimeError("state field has invalid type: compaction_count")


def _default_state(session_id: str) -> _SessionSnapshot:
    return {
        "schema_version": _STATE_SCHEMA_VERSION,
        "session_hash": hashlib.sha256(session_id.encode("utf-8", errors="replace")).hexdigest()[:16],
        "current_turn_id": "",
        "active_agents": {},
        "explicit_expand": False,
        "nested_allowed": False,
        "sensitive_context": False,
        "sensitive_disclosure_grant": None,
        "dangerous_authorizations": [],
        "dangerous_authorization_hashes": {},
        "pending_permission_authorizations": {},
        "local_git_grant": None,
        "pending_local_git": None,
        "pending_constrained_clones": {},
        "untrusted_clone_roots": {},
        "compaction_count": 0,
        "updated_at": int(time.time()),
    }
