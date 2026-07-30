"""Event-local snapshots and timing shared by modular hook handlers."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable, TypeVar

_T = TypeVar("_T")

_ACTIVE = False
_DATA_DIR: Path | None = None
_POLICY: Any = None
_DEADLINE: float | None = None
_RUNNER_MODE = False


def begin_snapshot() -> None:
    global _ACTIVE, _DATA_DIR, _POLICY
    _ACTIVE = True
    _DATA_DIR = None
    _POLICY = None


def end_snapshot() -> None:
    global _ACTIVE, _DATA_DIR, _POLICY
    _DATA_DIR = None
    _POLICY = None
    _ACTIVE = False


def data_dir(loader: Callable[[], Path]) -> Path:
    global _DATA_DIR
    if _ACTIVE and _DATA_DIR is not None:
        return _DATA_DIR
    value = loader()
    if _ACTIVE:
        _DATA_DIR = value
    return value


def policy(loader: Callable[[], _T]) -> _T:
    global _POLICY
    if _ACTIVE and _POLICY is not None:
        return _POLICY
    value = loader()
    if _ACTIVE:
        _POLICY = value
    return value


def begin_budget(seconds: float) -> float:
    global _DEADLINE
    _DEADLINE = time.monotonic() + seconds
    return _DEADLINE


def end_budget() -> None:
    global _DEADLINE
    _DEADLINE = None


def enter_runner_mode() -> None:
    global _RUNNER_MODE
    _RUNNER_MODE = True


def budget_active() -> bool:
    return _DEADLINE is not None and not _RUNNER_MODE


def remaining_seconds(ceiling: float) -> float:
    if not budget_active():
        return ceiling
    assert _DEADLINE is not None
    return min(ceiling, _DEADLINE - time.monotonic())
