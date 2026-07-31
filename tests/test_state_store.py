from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

try:
    import msvcrt
except ImportError:  # pragma: no cover - unavailable on macOS/Linux.
    msvcrt = None

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "codex-control-plane-hooks" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from control_plane import state as state_module  # noqa: E402
from control_plane.state import cleanup_session, mutate_session, read_session  # noqa: E402
from protocol_test_fixtures import SCRIPT, HookProtocolTestCase  # noqa: E402


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

    @unittest.skipIf(msvcrt is None, "Windows byte-range lock test")
    def test_zero_length_lock_sentinel_waits_for_initialization_contention(self) -> None:
        session_id = "session-lock-initialization"
        mutate_session(session_id, lambda state: None)
        lock_path = next(self.data_dir.glob("session-*.lock"))
        outcome: list[dict | Exception] = []

        def mutate() -> None:
            try:
                outcome.append(
                    mutate_session(
                        session_id,
                        lambda state: state.__setitem__("explicit_expand", True),
                    )
                )
            except Exception as exc:
                outcome.append(exc)

        with lock_path.open("r+b", buffering=0) as holder:
            holder.truncate(0)
            holder.seek(0)
            msvcrt.locking(holder.fileno(), msvcrt.LK_NBLCK, 1)
            worker = threading.Thread(target=mutate)
            worker.start()
            time.sleep(0.2)
            holder.seek(0)
            msvcrt.locking(holder.fileno(), msvcrt.LK_UNLCK, 1)
            worker.join(timeout=2)

        self.assertFalse(worker.is_alive())
        self.assertEqual(1, len(outcome))
        if isinstance(outcome[0], Exception):
            raise outcome[0]
        self.assertTrue(outcome[0]["explicit_expand"])

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


class LegacyStateProtocolTests(HookProtocolTestCase):
    def test_legacy_state_schemas_are_migrated_to_current_schema(self) -> None:
        for schema_version in (1, 2, 3):
            with self.subTest(schema_version=schema_version):
                session = f"{self.session}-schema-{schema_version}"
                state_path = self.write_legacy_state(schema_version, session=session)

                result = self.run_hook(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "Bash",
                        "tool_input": {"command": "pwd"},
                        "session_id": session,
                    }
                )

                self.assertEqual({}, result)
                state = json.loads(state_path.read_text(encoding="utf-8"))
                self.assertEqual(4, state["schema_version"])
                self.assertIn("pending_permission_authorizations", state)


class RuntimeArtifactCleanupTests(HookProtocolTestCase):
    def test_orphan_cleanup_worker_respects_live_runner_lease(self) -> None:
        module = __import__("control_plane_hook")
        data = Path(self.data_dir)
        stale_token, live_token, fresh_token = "0" * 32, "1" * 32, "2" * 32
        expired = time.time() - module._GIT_RUNNER_TTL_SECONDS - 60
        stale = data / f".git-push-{stale_token}-stale"
        live = data / f".git-push-{live_token}-live"
        fresh = data / f".git-push-{fresh_token}-fresh"
        for directory in (stale, live, fresh):
            directory.mkdir()
        for directory in (stale, live):
            os.utime(directory, (expired, expired))
        live_records = [
            module._git_runner_path(kind, live_token)
            for kind in ("request", "running", "status")
        ]
        for record in live_records:
            module._write_private_json(record, {"transaction_id": "live"})
            os.utime(record, (expired, expired))
        lease_path = module._git_runner_lease_path(live_token)
        lease_stream = module._open_private(
            lease_path,
            os.O_RDWR | os.O_CREAT | os.O_EXCL,
        )
        lease_backend = module._lock_state(lease_stream)

        try:
            self.assertEqual(0, module._run_orphan_cleanup_worker(self.data_dir))
            self.assertFalse(stale.exists())
            self.assertTrue(live.exists())
            self.assertTrue(all(record.exists() for record in live_records))
            self.assertTrue(fresh.exists())
        finally:
            module._unlock_state(lease_stream, lease_backend)
            lease_stream.close()

        self.assertEqual(0, module._run_orphan_cleanup_worker(self.data_dir))
        self.assertFalse(live.exists())
        self.assertFalse(any(record.exists() for record in live_records))
        self.assertTrue(fresh.exists())
        module._unlink_owned_regular(lease_path)

    def test_record_limit_does_not_starve_orphan_directory_cleanup(self) -> None:
        module = __import__("control_plane_hook")
        records = [
            module._git_runner_path("request", f"{index:032x}")
            for index in range(4)
        ]
        expired = time.time() - module._GIT_RUNNER_TTL_SECONDS - 60
        for record in records:
            module._write_private_json(record, {"transaction_id": "stale"})
            os.utime(record, (expired, expired))
        stale = Path(self.data_dir) / f".git-push-{'3' * 32}-stale"
        stale.mkdir()
        os.utime(stale, (expired, expired))

        with (
            mock.patch.object(module, "_ORPHAN_CLEANUP_RECORD_LIMIT", 2),
            mock.patch.object(module, "_ORPHAN_CLEANUP_DIRECTORY_LIMIT", 1),
        ):
            self.assertEqual(0, module._run_orphan_cleanup_worker(self.data_dir))

        self.assertEqual(2, len([record for record in records if record.exists()]))
        self.assertFalse(stale.exists())

    def test_directory_limit_counts_only_eligible_cleanup_attempts(self) -> None:
        module = __import__("control_plane_hook")
        data = Path(self.data_dir)
        fresh_one = data / f".git-push-{'4' * 32}-fresh-one"
        fresh_two = data / f".git-push-{'5' * 32}-fresh-two"
        stale = data / f".git-push-{'6' * 32}-stale"
        for directory in (fresh_one, fresh_two, stale):
            directory.mkdir()
        cutoff = time.time() - module._GIT_RUNNER_TTL_SECONDS
        expired = cutoff - 60
        os.utime(stale, (expired, expired))

        with mock.patch.object(
            Path,
            "glob",
            return_value=iter([fresh_one, fresh_two, stale]),
        ):
            module._cleanup_stale_git_push_directories(
                cutoff,
                deadline=time.monotonic() + 1.0,
                scan_limit=3,
                cleanup_limit=1,
            )

        self.assertTrue(fresh_one.exists())
        self.assertTrue(fresh_two.exists())
        self.assertFalse(stale.exists())

    def test_orphan_cleanup_worker_obeys_own_budget(self) -> None:
        module = __import__("control_plane_hook")
        record = module._git_runner_path("request", "4" * 32)
        module._write_private_json(record, {"transaction_id": "stale"})
        expired = time.time() - module._GIT_RUNNER_TTL_SECONDS - 60
        os.utime(record, (expired, expired))

        with mock.patch.object(module, "_ORPHAN_CLEANUP_BUDGET_SECONDS", 0.0):
            self.assertEqual(0, module._run_orphan_cleanup_worker(self.data_dir))

        self.assertTrue(record.exists())

    def test_orphan_cleanup_worker_uses_per_entry_timeout(self) -> None:
        module = __import__("control_plane_hook")
        token = "5" * 32
        stale = Path(self.data_dir) / f".git-push-{token}-stale"
        stale.mkdir()
        expired = time.time() - module._GIT_RUNNER_TTL_SECONDS - 60
        os.utime(stale, (expired, expired))
        observed_timeouts: list[float] = []

        def timeout_child(*_args, **kwargs):
            observed_timeouts.append(float(kwargs["timeout"]))
            raise subprocess.TimeoutExpired("cleanup", kwargs["timeout"])

        started = time.monotonic()
        with mock.patch.object(module.subprocess, "run", side_effect=timeout_child):
            self.assertEqual(0, module._run_orphan_cleanup_worker(self.data_dir))
        elapsed = time.monotonic() - started

        self.assertTrue(stale.exists())
        self.assertEqual(1, len(observed_timeouts))
        self.assertGreater(observed_timeouts[0], 0)
        self.assertLessEqual(
            observed_timeouts[0],
            module._ORPHAN_CLEANUP_ENTRY_TIMEOUT_SECONDS,
        )
        self.assertLess(elapsed, 1.0)

    def test_dispatch_does_not_schedule_cleanup_on_decision_path(self) -> None:
        module = __import__("control_plane_hook")
        expected = {"decision": "block", "reason": "fixture"}

        def handler(_event):
            self.assertIsNotNone(module._EVENT_DEADLINE)
            return expected

        with (
            mock.patch.object(module, "_handle_tool_gate", side_effect=handler),
            mock.patch.object(module, "_schedule_orphan_cleanup") as schedule,
            mock.patch.object(
                module.subprocess,
                "Popen",
                side_effect=AssertionError("dispatch must not create a cleanup process"),
            ) as popen,
        ):
            self.assertEqual(
                expected,
                module.dispatch({"hook_event_name": "PreToolUse"}),
            )

        schedule.assert_not_called()
        popen.assert_not_called()
        self.assertIsNone(module._EVENT_DEADLINE)

    def test_cleanup_scheduler_failure_is_best_effort(self) -> None:
        module = __import__("control_plane_hook")

        with mock.patch.object(
            module.subprocess,
            "Popen",
            side_effect=RuntimeError("simulated cleanup failure"),
        ):
            module._schedule_orphan_cleanup()

    def test_hung_cleanup_worker_reaper_does_not_delay_scheduler(self) -> None:
        module = __import__("control_plane_hook")
        entered = threading.Event()
        release = threading.Event()
        process = mock.Mock()

        def wait_for_release():
            entered.set()
            return release.wait(5.0)

        process.wait.side_effect = wait_for_release
        started = time.monotonic()
        try:
            with mock.patch.object(module.subprocess, "Popen", return_value=process):
                module._schedule_orphan_cleanup()
                self.assertTrue(entered.wait(0.5))
        finally:
            release.set()

        self.assertLess(time.monotonic() - started, 0.5)
        process.wait.assert_called_once_with()

    def test_cleanup_scheduler_uses_detached_isolated_worker(self) -> None:
        module = __import__("control_plane_hook")
        process = mock.Mock()

        with (
            mock.patch.object(module.subprocess, "Popen", return_value=process) as popen,
            mock.patch.object(
                module,
                "_cleanup_stale_git_runner_records",
                side_effect=AssertionError("parent process must not scan cleanup targets"),
            ),
            mock.patch.object(
                module,
                "_data_dir",
                side_effect=AssertionError("parent process must not validate PLUGIN_DATA"),
            ),
            mock.patch.object(
                module,
                "_private_directory",
                side_effect=AssertionError("parent process must not touch PLUGIN_DATA"),
            ),
        ):
            module._schedule_orphan_cleanup()

        command = popen.call_args.args[0]
        options = popen.call_args.kwargs
        self.assertEqual(sys.executable, command[0])
        self.assertEqual(["-I", "-S"], command[1:3])
        self.assertEqual("--cleanup-orphans", command[-2])
        self.assertEqual(self.data_dir, command[-1])
        self.assertEqual(subprocess.DEVNULL, options["stdin"])
        self.assertEqual(subprocess.DEVNULL, options["stdout"])
        self.assertEqual(subprocess.DEVNULL, options["stderr"])
        self.assertTrue(options["close_fds"])
        if os.name == "nt":
            self.assertIn("creationflags", options)
        else:
            self.assertTrue(options["start_new_session"])

    def test_failed_cleanup_window_advances_to_later_orphan(self) -> None:
        module = __import__("control_plane_hook")
        data = Path(self.data_dir)
        directories = [
            data / f".git-push-{index:032x}-stale"
            for index in range(3)
        ]
        for directory in directories:
            directory.mkdir()
        expired = time.time() - module._GIT_RUNNER_TTL_SECONDS - 60
        for directory in directories:
            os.utime(directory, (expired, expired))
        real_glob = Path.glob

        def ordered_glob(path, pattern):
            if pattern == f"{module._GIT_PUSH_DIR_PREFIX}*":
                return iter(directories)
            return real_glob(path, pattern)

        def remove(candidate, _deadline):
            if candidate in directories[:2]:
                return False
            shutil.rmtree(candidate)
            return True

        with (
            mock.patch.object(Path, "glob", autospec=True, side_effect=ordered_glob),
            mock.patch.object(module, "_remove_tree_with_deadline", side_effect=remove),
        ):
            self.assertEqual(0, module._run_orphan_cleanup_worker(self.data_dir))
            self.assertTrue(directories[2].exists())
            self.assertEqual(0, module._run_orphan_cleanup_worker(self.data_dir))

        self.assertTrue(directories[0].exists())
        self.assertTrue(directories[1].exists())
        self.assertFalse(directories[2].exists())

    def test_cleanup_cursor_advances_beyond_first_scan_window(self) -> None:
        module = __import__("control_plane_hook")
        data = Path(self.data_dir)
        directories = [
            data / f".git-push-{index:032x}-stale"
            for index in range(module._ORPHAN_CLEANUP_DIRECTORY_SCAN_LIMIT + 1)
        ]
        for directory in directories:
            directory.mkdir()
        expired = time.time() - module._GIT_RUNNER_TTL_SECONDS - 60
        for directory in directories:
            os.utime(directory, (expired, expired))
        final_candidate = directories[-1]

        def remove(candidate, _deadline):
            if candidate != final_candidate:
                return False
            shutil.rmtree(candidate)
            return True

        with mock.patch.object(
            module,
            "_remove_tree_with_deadline",
            side_effect=remove,
        ):
            for _index in range(
                module._ORPHAN_CLEANUP_DIRECTORY_SCAN_LIMIT // 2 + 1
            ):
                self.assertEqual(
                    0,
                    module._run_orphan_cleanup_worker(self.data_dir),
                )
                if not final_candidate.exists():
                    break

        self.assertFalse(final_candidate.exists())

    def test_orphan_cleanup_worker_is_single_flight(self) -> None:
        module = __import__("control_plane_hook")
        lock_path = module._orphan_cleanup_lock_path(Path(self.data_dir))
        self.assertFalse(str(lock_path).startswith(self.data_dir + os.sep))
        lock_stream = module._open_private(
            lock_path,
            os.O_RDWR | os.O_CREAT,
        )
        if os.name == "nt":
            lock_stream.seek(0, os.SEEK_END)
            if lock_stream.tell() == 0:
                lock_stream.write("0")
                lock_stream.flush()
                os.fsync(lock_stream.fileno())
        lock_backend = module._lock_state(lock_stream)
        try:
            with (
                mock.patch.object(module, "_configure_runner_data_dir") as configure,
                mock.patch.object(module, "_cleanup_stale_git_runner_records") as cleanup,
            ):
                self.assertEqual(0, module._run_orphan_cleanup_worker(self.data_dir))
            configure.assert_not_called()
            cleanup.assert_not_called()
        finally:
            module._unlock_state(lock_stream, lock_backend)
            lock_stream.close()

    def test_orphan_cleanup_worker_cli_is_quiet_and_bounded(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                str(SCRIPT),
                "--cleanup-orphans",
                self.data_dir,
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=3.0,
        )

        self.assertEqual(0, completed.returncode)
        self.assertEqual("", completed.stdout)
        self.assertEqual("", completed.stderr)

    def test_approved_git_runner_schedules_orphan_cleanup(self) -> None:
        module = __import__("control_plane_hook")

        with mock.patch.object(module, "_schedule_orphan_cleanup") as schedule:
            self.assertEqual(126, module._run_approved_git_with_lease("6" * 32))

        schedule.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
