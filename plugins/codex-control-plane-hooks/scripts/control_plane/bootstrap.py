"""Import-safe package bootstrap for isolated hook entrypoints."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

_WINDOWS_REPARSE_POINT = 0x0400


class BootstrapError(RuntimeError):
    """Raised when an entrypoint is not contained in a trusted package layout."""


def _lstat(path: Path, description: str) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        raise BootstrapError(f"Missing or inaccessible {description}.") from exc


def _is_reparse_point(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & _WINDOWS_REPARSE_POINT)


def _require_directory(path: Path, description: str) -> None:
    info = _lstat(path, description)
    if not stat.S_ISDIR(info.st_mode) or _is_reparse_point(info):
        raise BootstrapError(f"Invalid {description}.")


def _require_regular_file(path: Path, description: str) -> None:
    info = _lstat(path, description)
    if not stat.S_ISREG(info.st_mode) or _is_reparse_point(info):
        raise BootstrapError(f"Invalid {description}.")


def _validated_scripts_root(
    entrypoint_file: str,
    required_package_files: tuple[tuple[str, str], ...],
) -> Path:
    entrypoint = Path(entrypoint_file)
    if not entrypoint.is_absolute():
        raise BootstrapError("Entrypoint path must be absolute.")

    entrypoint = Path(os.path.abspath(str(entrypoint)))
    if entrypoint.name == "control_plane_hook.py":
        scripts_root = entrypoint.parent
        package_dir = scripts_root / "control_plane"
        entrypoints_dir = package_dir / "entrypoints"
    else:
        entrypoints_dir = entrypoint.parent
        package_dir = entrypoints_dir.parent
        scripts_root = package_dir.parent
        if entrypoints_dir.name != "entrypoints" or package_dir.name != "control_plane":
            raise BootstrapError("Entrypoint is outside the fixed package layout.")

    _require_directory(scripts_root, "scripts root")
    _require_directory(package_dir, "control_plane package")
    _require_directory(entrypoints_dir, "entrypoints package")
    handlers_dir = package_dir / "handlers"
    _require_directory(handlers_dir, "handlers package")
    _require_regular_file(package_dir / "__init__.py", "control_plane package marker")
    _require_regular_file(package_dir / "policy.py", "policy module")
    _require_regular_file(package_dir / "protocol.py", "protocol module")
    _require_regular_file(package_dir / "state.py", "state module")
    _require_regular_file(package_dir / "core.py", "core module")
    _require_regular_file(
        entrypoints_dir / "__init__.py", "entrypoints package marker"
    )
    _require_regular_file(
        handlers_dir / "__init__.py", "handlers package marker"
    )
    for relative_name, description in required_package_files:
        relative_path = Path(relative_name)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise BootstrapError("Required package file is outside the package.")
        _require_regular_file(package_dir / relative_path, description)
    _require_regular_file(entrypoint, "entrypoint")

    scripts_root_text = str(scripts_root)
    if not sys.path or sys.path[0] != scripts_root_text:
        sys.path.insert(0, scripts_root_text)
    return scripts_root


def configure_package(
    entrypoint_file: str,
    *,
    required_package_files: tuple[tuple[str, str], ...] = (),
) -> Path:
    """Validate the package layout or terminate with the bootstrap exit contract."""

    try:
        return _validated_scripts_root(entrypoint_file, required_package_files)
    except BootstrapError:
        sys.stderr.write("codex-control-plane-hooks: package bootstrap failed\n")
        raise SystemExit(126) from None
