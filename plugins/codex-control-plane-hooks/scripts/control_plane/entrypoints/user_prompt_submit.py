"""Dedicated UserPromptSubmit process entrypoint."""

from __future__ import annotations

import runpy
from pathlib import Path

bootstrap_path = Path(__file__).parent.parent / "bootstrap.py"
configure_package = runpy.run_path(str(bootstrap_path))["configure_package"]
configure_package(
    __file__,
    required_package_files=(
        ("handlers/user_prompt_submit.py", "UserPromptSubmit handler"),
    ),
)

from control_plane.handlers.user_prompt_submit import handle  # noqa: E402
from control_plane.protocol import run_hook  # noqa: E402

raise SystemExit(run_hook("UserPromptSubmit", handle))
