#!/usr/bin/env python3
"""Validate release layout, privacy boundaries, credentials, and syntax."""

from __future__ import annotations

import argparse
import ast
import codecs
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "codex-control-plane-hooks"
REQUIRED = (
    ROOT / ".agents" / "plugins" / "marketplace.json",
    ROOT / "README.md",
    ROOT / "PRIVACY.md",
    ROOT / "SECURITY.md",
    ROOT / "LICENSE",
    PLUGIN / ".codex-plugin" / "plugin.json",
    PLUGIN / "hooks" / "hooks.json",
    PLUGIN / "scripts" / "control_plane_hook.py",
    ROOT / "scripts" / "smoke_hook_manifest.py",
)
MAX_SCAN_FILE_BYTES = 2_000_000
MAX_PRIVATE_PATTERNS_BYTES = 64_000
MAX_PRIVATE_PATTERNS = 100
TEXT_LIKE_SUFFIXES = {
    "",
    ".example",
    ".json",
    ".md",
    ".py",
    ".rules",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
FORBIDDEN_RELEASE_SUFFIXES = {".key", ".p12", ".pem", ".pfx"}
_WINDOWS_SEPARATOR_PATTERN = r"(?:/|\\{1,4})"
_WINDOWS_LEADING_BACKSLASH_PATTERN = r"\\{2,8}"
GENERIC_PRIVATE_PATTERNS = (
    ("absolute-macos-home", re.compile(re.escape("/") + "Users/" + r"[^/\s\"']+", re.IGNORECASE)),
    ("absolute-linux-home", re.compile(re.escape("/") + "home/" + r"[^/\s\"']+", re.IGNORECASE)),
    (
        "absolute-windows-home",
        re.compile(
            rf"(?i)(?:\b[A-Z]:{_WINDOWS_SEPARATOR_PATTERN}|/mnt/[a-z]/|"
            rf"{_WINDOWS_LEADING_BACKSLASH_PATTERN}\?{_WINDOWS_SEPARATOR_PATTERN}"
            rf"[A-Z]:{_WINDOWS_SEPARATOR_PATTERN}|"
            rf"{_WINDOWS_LEADING_BACKSLASH_PATTERN}"
            rf"(?:\?{_WINDOWS_SEPARATOR_PATTERN}UNC{_WINDOWS_SEPARATOR_PATTERN})?"
            rf"[^\\/\s\"']+{_WINDOWS_SEPARATOR_PATTERN}"
            rf"[^\\/\s\"']+{_WINDOWS_SEPARATOR_PATTERN})"
            rf"Users{_WINDOWS_SEPARATOR_PATTERN}[^\\/\s\"']+"
        ),
    ),
)
SECRET_PATTERNS = (
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("bearer-token", re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    (
        "credential-assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|token|secret|password|client[_-]?secret|access[_-]?key)"
            r"\s*[:=]\s*['\"]?[A-Za-z0-9_./+=:-]{16,}"
        ),
    ),
    ("github-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _walk_release_entries(root: Path) -> list[Path]:
    entries: list[Path] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if any(part in {".git", "__pycache__"} for part in relative.parts):
            continue
        entries.append(path)
    return sorted(entries)


def _git_toplevel(root: Path) -> Path | None:
    completed = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        return None
    try:
        return Path(os.fsdecode(completed.stdout.strip())).resolve()
    except (OSError, UnicodeError, ValueError):
        return None


def release_entries(root: Path = ROOT) -> list[Path]:
    try:
        if _git_toplevel(root) != root.resolve():
            return _walk_release_entries(root)
        completed = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ],
            capture_output=True,
            check=False,
        )
    except OSError:
        return _walk_release_entries(root)
    if completed.returncode != 0:
        return _walk_release_entries(root)

    entries: list[Path] = []
    for encoded in completed.stdout.split(b"\0"):
        if not encoded:
            continue
        relative = Path(os.fsdecode(encoded))
        if relative.is_absolute() or ".." in relative.parts:
            continue
        path = root / relative
        if path.exists() or path.is_symlink():
            entries.append(path)
    return sorted(entries)


def release_files(root: Path = ROOT) -> list[Path]:
    return [path for path in release_entries(root) if path.is_file() and not path.is_symlink()]


def _load_private_patterns(path: Path | None) -> list[tuple[str, re.Pattern[str]]]:
    if path is None:
        return []
    if os.name == "nt":
        raise ValueError("private pattern files require a POSIX host with owner and mode checks")
    candidate = path.expanduser()
    try:
        info = os.stat(candidate, follow_symlinks=False)
    except OSError as exc:
        raise ValueError("private pattern file is unavailable") from exc
    if candidate.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise ValueError("private pattern file must be a regular non-symlink file")
    if info.st_size > MAX_PRIVATE_PATTERNS_BYTES:
        raise ValueError("private pattern file exceeds the size limit")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ValueError("private pattern file must be owned by the current user")
    if os.name != "nt" and info.st_mode & 0o077:
        raise ValueError("private pattern file permissions must be 0600 or stricter")
    resolved = candidate.resolve()
    if _inside(resolved, ROOT.resolve()):
        raise ValueError("private pattern file must remain outside the repository")
    try:
        lines = resolved.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError("private pattern file must be readable UTF-8 text") from exc
    values = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    if not values:
        raise ValueError("private pattern file contains no patterns")
    if len(values) > MAX_PRIVATE_PATTERNS:
        raise ValueError("private pattern file contains too many patterns")
    if any(len(value) > 500 for value in values):
        raise ValueError("private pattern file contains an overlong pattern")
    patterns: list[tuple[str, re.Pattern[str]]] = []
    for index, value in enumerate(values, start=1):
        escaped = re.escape(value)
        if re.fullmatch(r"[A-Za-z0-9_.-]+", value):
            escaped = rf"(?<![A-Za-z0-9]){escaped}(?![A-Za-z0-9])"
        patterns.append((f"private-{index:03d}", re.compile(escaped, re.IGNORECASE)))
    return patterns


def _git_index_entries(
    root: Path = ROOT,
) -> Iterator[tuple[Path, str, bytes | None]]:
    has_git_metadata = (root / ".git").exists()
    if not has_git_metadata:
        return
    try:
        if _git_toplevel(root) != root.resolve():
            raise ValueError("Git index root does not match the release tree")
        completed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--stage", "-z"],
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise ValueError("Git index could not be inspected") from exc
    if completed.returncode != 0:
        raise ValueError("Git index could not be inspected")

    for encoded in completed.stdout.split(b"\0"):
        if not encoded:
            continue
        try:
            metadata, encoded_path = encoded.split(b"\t", 1)
            mode, object_id, stage = metadata.decode("ascii").split()
        except (UnicodeError, ValueError) as exc:
            raise ValueError("Git index metadata could not be parsed") from exc
        relative = Path(os.fsdecode(encoded_path))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Git index contains an unsafe path")
        if stage != "0":
            raise ValueError(f"Git index contains an unresolved entry: {relative}")
        blob_size = subprocess.run(
            ["git", "-C", str(root), "cat-file", "-s", object_id],
            capture_output=True,
            check=False,
        )
        if blob_size.returncode != 0:
            raise ValueError(f"Git index blob size could not be read: {relative}")
        try:
            size = int(blob_size.stdout.strip())
        except ValueError as exc:
            raise ValueError(f"Git index blob size could not be parsed: {relative}") from exc
        if size > MAX_SCAN_FILE_BYTES:
            yield relative, mode, None
            continue
        blob = subprocess.run(
            ["git", "-C", str(root), "cat-file", "blob", object_id],
            capture_output=True,
            check=False,
        )
        if blob.returncode != 0:
            raise ValueError(f"Git index blob could not be read: {relative}")
        yield relative, mode, blob.stdout


def _read_release_bytes(path: Path, errors: list[str]) -> bytes | None:
    relative = path.relative_to(ROOT)
    try:
        size = path.stat().st_size
        if size > MAX_SCAN_FILE_BYTES:
            errors.append(f"oversized release file: {relative}")
            return None
        return path.read_bytes()
    except OSError:
        errors.append(f"unreadable release file: {relative}")
        return None


def _decode_release_text(
    relative: Path,
    data: bytes,
    errors: list[str],
    *,
    source: str = "",
) -> str | None:
    display = f"{source}{relative}"
    if len(data) > MAX_SCAN_FILE_BYTES:
        errors.append(f"oversized release file: {display}")
        return None
    try:
        if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
            return data.decode("utf-16")
        if b"\x00" in data:
            errors.append(f"binary release file is not allowed: {display}")
            return None
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        kind = (
            "text-like file is not valid UTF-8/UTF-16"
            if relative.suffix.lower() in TEXT_LIKE_SUFFIXES
            else "binary release file is not allowed"
        )
        errors.append(f"{kind}: {display}")
        return None


def _read_release_text(path: Path, errors: list[str]) -> str | None:
    data = _read_release_bytes(path, errors)
    if data is None:
        return None
    return _decode_release_text(path.relative_to(ROOT), data, errors)


def _scan_release_data(
    relative: Path,
    data: bytes,
    patterns: list[tuple[str, re.Pattern[str]]],
    errors: list[str],
    *,
    source: str = "",
) -> None:
    display = f"{source}{relative}"
    relative_text = relative.as_posix()
    if relative.suffix.lower() in FORBIDDEN_RELEASE_SUFFIXES:
        errors.append(f"credential container is not allowed in release tree: {display}")
    for rule_id, pattern in patterns:
        if pattern.search(relative_text):
            errors.append(f"private marker {rule_id} in path: {display}")
    text = _decode_release_text(relative, data, errors, source=source)
    if text is None:
        return
    for rule_id, pattern in patterns:
        if pattern.search(text):
            errors.append(f"private marker {rule_id} in {display}")
    for rule_id, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            errors.append(f"credential-like literal {rule_id} in {display}")
    if relative.suffix == ".py":
        try:
            ast.parse(text, filename=str(display))
        except SyntaxError as exc:
            errors.append(f"invalid Python syntax in {display}: {exc}")


def _scan_release_files(
    private_patterns: list[tuple[str, re.Pattern[str]]],
    errors: list[str],
) -> int:
    patterns = [*GENERIC_PRIVATE_PATTERNS, *private_patterns]
    files = release_files()
    worktree_data: dict[Path, bytes] = {}
    for path in release_entries():
        relative = path.relative_to(ROOT)
        if path.is_symlink():
            errors.append(f"symlink is not allowed in release tree: {relative}")
    for path in files:
        relative = path.relative_to(ROOT)
        data = _read_release_bytes(path, errors)
        if data is None:
            continue
        worktree_data[relative] = data
        _scan_release_data(relative, data, patterns, errors)
    try:
        for relative, mode, data in _git_index_entries():
            if mode == "120000":
                errors.append(f"symlink is not allowed in staged release tree: {relative}")
            if data is None:
                errors.append(f"oversized release file: staged {relative}")
                continue
            if worktree_data.get(relative) == data:
                continue
            _scan_release_data(relative, data, patterns, errors, source="staged ")
    except (OSError, ValueError) as exc:
        errors.append(str(exc) or "Git index could not be inspected")
    return len(files)


def _validate_metadata(errors: list[str]) -> None:
    for path in REQUIRED:
        if not path.is_file():
            errors.append(f"missing required file: {path.relative_to(ROOT)}")

    manifest_path = PLUGIN / ".codex-plugin" / "plugin.json"
    marketplace_path = ROOT / ".agents" / "plugins" / "marketplace.json"
    hooks_path = PLUGIN / "hooks" / "hooks.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        marketplace = json.loads(marketplace_path.read_text(encoding="utf-8"))
        hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        errors.append(f"invalid JSON: {exc}")
        manifest = marketplace = hooks = {}

    if manifest.get("name") != "codex-control-plane-hooks":
        errors.append("plugin manifest name mismatch")
    version = manifest.get("version")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        errors.append("plugin manifest version is not semantic")
    elif f"## [{version}]" not in changelog:
        errors.append("plugin manifest version is missing from CHANGELOG.md")
    if isinstance(version, str):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        if f"--ref v{version}" not in readme:
            errors.append("README installation ref does not match the plugin manifest version")
        if "--ref main" in readme:
            errors.append("README installation must not follow the mutable main ref")
    if "hooks" in manifest:
        errors.append("plugin manifest must rely on default hooks/hooks.json discovery")
    entries = marketplace.get("plugins") if isinstance(marketplace, dict) else None
    if not isinstance(entries, list) or len(entries) != 1:
        errors.append("marketplace must contain exactly one plugin entry")
    elif entries[0].get("source", {}).get("path") != "./plugins/codex-control-plane-hooks":
        errors.append("marketplace source path mismatch")
    pretool = hooks.get("hooks", {}).get("PreToolUse", []) if isinstance(hooks, dict) else []
    matcher = pretool[0].get("matcher", "") if pretool else ""
    if "exec_command" not in matcher:
        errors.append("PreToolUse matcher does not include exec_command")
    hook_events = hooks.get("hooks", {}) if isinstance(hooks, dict) else {}
    if isinstance(hook_events, dict):
        for event_name, groups in hook_events.items():
            event_groups = groups if isinstance(groups, list) else []
            for group in event_groups:
                handlers = group.get("hooks", []) if isinstance(group, dict) else []
                for handler in handlers:
                    if not isinstance(handler, dict) or handler.get("type") != "command":
                        continue
                    posix_command = handler.get("command")
                    if not isinstance(posix_command, str) or "$PLUGIN_ROOT" not in posix_command:
                        errors.append(f"{event_name} command hook lacks a PLUGIN_ROOT-based POSIX command")
                    windows_command = handler.get("commandWindows")
                    if not isinstance(windows_command, str) or "$env:PLUGIN_ROOT" not in windows_command:
                        errors.append(f"{event_name} command hook lacks a PLUGIN_ROOT-based commandWindows")
                    timeout = handler.get("timeout")
                    if not isinstance(timeout, int) or timeout <= 5 or timeout > 10:
                        errors.append(f"{event_name} command hook timeout must be between 6 and 10 seconds")

    rules = (ROOT / "examples" / "rules" / "default.rules").read_text(encoding="utf-8")
    if any(line.lstrip().startswith("prefix_rule(") for line in rules.splitlines()):
        errors.append("example Rules file must contain no active prefix_rule")

    policy = json.loads((ROOT / "examples" / "policy.example.json").read_text(encoding="utf-8"))
    if policy.get("enable_natural_language_approvals") is not False:
        errors.append("natural-language approvals must be disabled in the example policy")
    if policy.get("enable_sensitive_disclosure_approvals") is not False:
        errors.append("sensitive-disclosure approvals must be disabled in the example policy")
    if policy.get("durable_destination_markers") != []:
        errors.append("durable destination markers must be empty in the example policy")


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--private-patterns-file",
        type=Path,
        help="Repository-external private UTF-8 file with one literal private marker per line.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    configured = args.private_patterns_file
    if configured is None and os.environ.get("RELEASE_PRIVATE_PATTERNS_FILE"):
        configured = Path(os.environ["RELEASE_PRIVATE_PATTERNS_FILE"])
    errors: list[str] = []
    try:
        private_patterns = _load_private_patterns(configured)
    except ValueError as exc:
        errors.append(str(exc))
        private_patterns = []
    _validate_metadata(errors)
    scanned = _scan_release_files(private_patterns, errors)

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"release check passed: {scanned} files scanned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
