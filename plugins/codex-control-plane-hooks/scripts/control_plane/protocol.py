"""Stable stdin/stdout protocol boundary for hook entrypoints."""

from __future__ import annotations

import json
import sys
from typing import Any, Callable

HookPayload = dict[str, Any]
HookHandler = Callable[[HookPayload], HookPayload]
SUPPORTED_EVENTS = frozenset(
    {
        "PermissionRequest",
        "PostToolUse",
        "PreCompact",
        "PreToolUse",
        "Stop",
        "SubagentStart",
        "SubagentStop",
        "UserPromptSubmit",
    }
)


def _blocked_response(event_name: str, reason: str) -> HookPayload:
    if event_name == "PreToolUse":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
    if event_name == "PermissionRequest":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {"behavior": "deny", "message": reason},
            }
        }
    return {"decision": "block", "reason": reason}


def _encode_response(response: HookPayload) -> bytes:
    return json.dumps(
        response,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")


def _write_encoded_response(encoded: bytes) -> None:
    sys.stdout.buffer.write(encoded + b"\n")
    sys.stdout.buffer.flush()


def _write_response(response: HookPayload) -> None:
    _write_encoded_response(_encode_response(response))


def _reject_non_json_constant(value: str) -> None:
    raise ValueError(f"Non-standard JSON constant: {value}")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> HookPayload:
    result: HookPayload = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key.")
        result[key] = value
    return result


def run_hook(expected_event: str, handler: HookHandler) -> int:
    """Run one hook handler through the strict process protocol."""

    parse_reason = "Control-plane input could not be parsed; the action is blocked."
    internal_reason = (
        "Control-plane internal validation failed; the action is blocked."
    )

    if expected_event not in SUPPORTED_EVENTS:
        _write_response(_blocked_response(expected_event, internal_reason))
        return 0

    try:
        payload = json.loads(
            sys.stdin.buffer.read().decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_non_json_constant,
        )
        if not isinstance(payload, dict):
            raise ValueError("Hook input must be a JSON object.")
    except Exception:
        _write_response(_blocked_response("", parse_reason))
        return 0

    try:
        if payload.get("hook_event_name") != expected_event:
            raise ValueError("Hook event does not match the entrypoint.")
        response = handler(payload)
        if not isinstance(response, dict):
            raise TypeError("Hook handler must return a JSON object.")
        encoded_response = _encode_response(response)
    except Exception:
        _write_response(_blocked_response(expected_event, internal_reason))
        return 0

    _write_encoded_response(encoded_response)
    return 0
