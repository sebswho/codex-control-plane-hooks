"""UserPromptSubmit handler boundary."""

from __future__ import annotations

from typing import Any

from control_plane.core import handle_user_prompt_submit


def handle(event: dict[str, Any]) -> dict[str, Any]:
    """Apply the existing UserPromptSubmit behavior through an explicit handler."""

    return handle_user_prompt_submit(event)
