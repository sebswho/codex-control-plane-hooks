from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "codex-control-plane-hooks" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from control_plane import state as state_module  # noqa: E402
from control_plane.state import cleanup_session, mutate_session, read_session  # noqa: E402


class StateStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.data_dir = Path(self.temp_dir.name).resolve()
        self.environment = mock.patch.dict(os.environ, {"PLUGIN_DATA": str(self.data_dir)})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_mutation_is_available_to_later_reads(self) -> None:
        def allow_expansion(state: dict) -> None:
            state["explicit_expand"] = True

        mutated = mutate_session("session-alpha", allow_expansion)
        loaded = read_session("session-alpha")

        self.assertTrue(mutated["explicit_expand"])
        self.assertTrue(loaded["explicit_expand"])
        self.assertEqual(4, loaded["schema_version"])
        self.assertEqual(mutated["session_hash"], loaded["session_hash"])

    def test_corrupt_state_fails_without_replacing_the_file(self) -> None:
        mutate_session("session-corrupt", lambda state: None)
        state_path = next(self.data_dir.glob("session-*.json"))
        corrupt = b"{"
        state_path.write_bytes(corrupt)

        with self.assertRaisesRegex(RuntimeError, "invalid JSON"):
            read_session("session-corrupt")

        self.assertEqual(corrupt, state_path.read_bytes())

    def test_invalid_schema_v4_field_fails_without_replacement(self) -> None:
        mutate_session("session-schema", lambda state: None)
        state_path = next(self.data_dir.glob("session-*.json"))
        invalid = json.loads(state_path.read_text(encoding="utf-8"))
        invalid["active_agents"] = []
        serialized = json.dumps(invalid, sort_keys=True)
        state_path.write_text(serialized, encoding="utf-8")

        with self.assertRaisesRegex(RuntimeError, "active_agents"):
            read_session("session-schema")

        self.assertEqual(serialized, state_path.read_text(encoding="utf-8"))

    def test_cleanup_removes_state_only_when_predicate_returns_true(self) -> None:
        mutate_session(
            "session-cleanup",
            lambda state: state.__setitem__("explicit_expand", True),
        )

        retained = cleanup_session("session-cleanup", lambda snapshot: False)
        self.assertTrue(retained["explicit_expand"])
        self.assertTrue(read_session("session-cleanup")["explicit_expand"])

        removed = cleanup_session("session-cleanup", lambda snapshot: True)
        self.assertTrue(removed["explicit_expand"])
        self.assertFalse(read_session("session-cleanup")["explicit_expand"])

    def test_concurrent_mutations_do_not_lose_updates(self) -> None:
        workers = 8
        barrier = threading.Barrier(workers)

        def increment() -> None:
            barrier.wait()

            def mutate(state: dict) -> None:
                current = state["compaction_count"]
                time.sleep(0.02)
                state["compaction_count"] = current + 1

            mutate_session("session-concurrent", mutate)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            list(executor.map(lambda _: increment(), range(workers)))

        self.assertEqual(8, read_session("session-concurrent")["compaction_count"])

    def test_failed_atomic_replace_preserves_existing_state(self) -> None:
        mutate_session("session-atomic", lambda state: None)
        state_path = next(self.data_dir.glob("session-*.json"))
        original = state_path.read_bytes()

        with mock.patch.object(
            state_module.os,
            "replace",
            side_effect=OSError("simulated replace failure"),
        ):
            with self.assertRaises(OSError):
                mutate_session(
                    "session-atomic",
                    lambda state: state.__setitem__("explicit_expand", True),
                )

        self.assertEqual(original, state_path.read_bytes())
        self.assertEqual([], list(self.data_dir.glob(".*.tmp")))

    def test_expired_state_resets_to_the_v4_default(self) -> None:
        mutate_session(
            "session-expired",
            lambda state: state.__setitem__("explicit_expand", True),
        )
        state_path = next(self.data_dir.glob("session-*.json"))
        expired = json.loads(state_path.read_text(encoding="utf-8"))
        expired["updated_at"] = 1
        state_path.write_text(json.dumps(expired), encoding="utf-8")

        loaded = read_session("session-expired")

        self.assertEqual(4, loaded["schema_version"])
        self.assertFalse(loaded["explicit_expand"])


if __name__ == "__main__":
    unittest.main()
