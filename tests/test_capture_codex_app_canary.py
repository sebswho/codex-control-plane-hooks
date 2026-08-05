from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "capture_codex_app_canary.py"
SPEC = importlib.util.spec_from_file_location("capture_codex_app_canary", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CANARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CANARY)


class CaptureCodexAppCanaryTests(unittest.TestCase):
    def valid_marketplaces(self) -> dict[str, object]:
        return {
            "marketplaces": [
                {
                    "name": "codex-control-plane-hooks",
                    "root": r"C:\private\codex-home\plugins\marketplaces\codex-control-plane-hooks",
                    "marketplaceSource": {
                        "sourceType": "git",
                        "source": "https://github.com/sebswho/codex-control-plane-hooks.git",
                    },
                }
            ]
        }

    def valid_plugins(self) -> dict[str, object]:
        return {
            "installed": [
                {
                    "pluginId": "codex-control-plane-hooks@codex-control-plane-hooks",
                    "name": "codex-control-plane-hooks",
                    "marketplaceName": "codex-control-plane-hooks",
                    "version": "0.2.8",
                    "installed": True,
                    "enabled": True,
                    "source": {"source": "local", "path": r"C:\cache\plugin"},
                    "marketplaceSource": {
                        "sourceType": "git",
                        "source": "https://github.com/sebswho/codex-control-plane-hooks.git",
                    },
                    "installPolicy": "AVAILABLE",
                    "authPolicy": "ON_INSTALL",
                }
            ],
            "available": [],
        }

    def test_inventory_requires_exactly_one_matching_marketplace_and_plugin(self) -> None:
        summary = CANARY.validate_inventory(
            self.valid_marketplaces(),
            self.valid_plugins(),
            marketplace="codex-control-plane-hooks",
            plugin="codex-control-plane-hooks",
        )
        self.assertEqual("codex-control-plane-hooks@codex-control-plane-hooks", summary["selector"])
        self.assertEqual("0.2.8", summary["version"])
        self.assertEqual(1, summary["marketplace_count"])
        self.assertEqual(1, summary["plugin_count"])
        self.assertTrue(summary["enabled"])
        self.assertEqual("sebswho/codex-control-plane-hooks", summary["marketplace_source_repository"])

        wrong_source = self.valid_plugins()
        wrong_source["installed"][0]["marketplaceSource"]["source"] = (
            "https://github.com/le-soleil-se-couche/codex-control-plane-hooks.git"
        )
        with self.assertRaisesRegex(CANARY.CanaryError, "authorized fork"):
            CANARY.validate_inventory(
                self.valid_marketplaces(),
                wrong_source,
                marketplace="codex-control-plane-hooks",
                plugin="codex-control-plane-hooks",
            )

        missing_source_marketplaces = self.valid_marketplaces()
        del missing_source_marketplaces["marketplaces"][0]["marketplaceSource"]
        missing_source_plugins = self.valid_plugins()
        del missing_source_plugins["installed"][0]["marketplaceSource"]
        with self.assertRaisesRegex(CANARY.CanaryError, "source"):
            CANARY.validate_inventory(
                missing_source_marketplaces,
                missing_source_plugins,
                marketplace="codex-control-plane-hooks",
                plugin="codex-control-plane-hooks",
            )

        duplicate_marketplaces = self.valid_marketplaces()
        duplicate_marketplaces["marketplaces"].append(duplicate_marketplaces["marketplaces"][0].copy())
        with self.assertRaisesRegex(CANARY.CanaryError, "exactly one marketplace"):
            CANARY.validate_inventory(
                duplicate_marketplaces,
                self.valid_plugins(),
                marketplace="codex-control-plane-hooks",
                plugin="codex-control-plane-hooks",
            )

        duplicate_plugins = self.valid_plugins()
        duplicate_plugins["installed"].append(duplicate_plugins["installed"][0].copy())
        with self.assertRaisesRegex(CANARY.CanaryError, "exactly one installed plugin"):
            CANARY.validate_inventory(
                self.valid_marketplaces(),
                duplicate_plugins,
                marketplace="codex-control-plane-hooks",
                plugin="codex-control-plane-hooks",
            )

    def test_inventory_allows_unrelated_builtin_marketplaces_and_plugins(self) -> None:
        marketplaces = self.valid_marketplaces()
        marketplaces["marketplaces"].append(
            {"name": "openai-api-curated", "root": r"C:\private\codex-home\.tmp\plugins"}
        )
        plugins = self.valid_plugins()
        plugins["installed"].append(
            {
                "pluginId": "unrelated@openai-api-curated",
                "name": "unrelated",
                "marketplaceName": "openai-api-curated",
                "installed": True,
                "enabled": True,
            }
        )

        summary = CANARY.validate_inventory(
            marketplaces,
            plugins,
            marketplace="codex-control-plane-hooks",
            plugin="codex-control-plane-hooks",
        )

        self.assertEqual(1, summary["marketplace_count"])
        self.assertEqual(2, summary["marketplace_total_count"])
        self.assertEqual(1, summary["plugin_count"])
        self.assertEqual(2, summary["installed_plugin_total_count"])

    def test_app_bundled_hooks_inventory_requires_exact_trusted_plugin_hooks(self) -> None:
        manifest = json.loads(
            (ROOT / "plugins" / "codex-control-plane-hooks" / "hooks" / "hooks.json").read_text(
                encoding="utf-8"
            )
        )
        hooks = []
        for event_name, groups in manifest["hooks"].items():
            for group in groups:
                for index, handler in enumerate(group["hooks"]):
                    hooks.append(
                        {
                            "key": f"{event_name}-{index}",
                            "eventName": event_name[:1].lower() + event_name[1:],
                            "source": "plugin",
                            "pluginId": "codex-control-plane-hooks@codex-control-plane-hooks",
                            "handlerType": handler["type"],
                            "enabled": True,
                            "trustStatus": "trusted",
                            "currentHash": "sha256:" + "a" * 64,
                            "sourcePath": r"C:\private\plugin\hooks.json",
                        }
                    )
        payload = {
            "data": [
                {
                    "cwd": str(ROOT),
                    "warnings": [],
                    "errors": [],
                    "hooks": hooks,
                }
            ]
        }

        summary = CANARY.validate_app_hook_inventory(
            payload,
            cwd=ROOT,
            manifest=manifest,
            selector="codex-control-plane-hooks@codex-control-plane-hooks",
        )

        self.assertEqual(len(hooks), summary["hook_count"])
        self.assertTrue(summary["all_trusted"])
        self.assertEqual({"trusted": len(hooks)}, summary["trust_status_counts"])
        self.assertNotIn("sourcePath", json.dumps(summary))

        untrusted = json.loads(json.dumps(payload))
        untrusted["data"][0]["hooks"][0]["trustStatus"] = "untrusted"
        with self.assertRaisesRegex(CANARY.CanaryError, "trusted"):
            CANARY.validate_app_hook_inventory(
                untrusted,
                cwd=ROOT,
                manifest=manifest,
                selector="codex-control-plane-hooks@codex-control-plane-hooks",
            )

        missing = json.loads(json.dumps(payload))
        missing["data"][0]["hooks"].pop()
        with self.assertRaisesRegex(CANARY.CanaryError, "events"):
            CANARY.validate_app_hook_inventory(
                missing,
                cwd=ROOT,
                manifest=manifest,
                selector="codex-control-plane-hooks@codex-control-plane-hooks",
            )

    def test_checkout_metadata_requires_clean_exact_sha_and_authorized_fork(self) -> None:
        commit = "a" * 40
        summary = CANARY.validate_checkout_metadata(
            expected_commit=commit,
            actual_commit=commit.upper(),
            origin="git@github.com:sebswho/codex-control-plane-hooks.git",
            status="",
        )
        self.assertEqual(commit, summary["expected_commit"])
        self.assertEqual(commit, summary["checkout_commit"])
        self.assertEqual("sebswho/codex-control-plane-hooks", summary["repository"])

        with self.assertRaisesRegex(CANARY.CanaryError, "full 40-character"):
            CANARY.validate_checkout_metadata(
                expected_commit="main",
                actual_commit=commit,
                origin="https://github.com/sebswho/codex-control-plane-hooks.git",
                status="",
            )
        with self.assertRaisesRegex(CANARY.CanaryError, "does not match"):
            CANARY.validate_checkout_metadata(
                expected_commit=commit,
                actual_commit="b" * 40,
                origin="https://github.com/sebswho/codex-control-plane-hooks.git",
                status="",
            )
        with self.assertRaisesRegex(CANARY.CanaryError, "authorized fork"):
            CANARY.validate_checkout_metadata(
                expected_commit=commit,
                actual_commit=commit,
                origin="https://github.com/le-soleil-se-couche/codex-control-plane-hooks.git",
                status="",
            )
        with self.assertRaisesRegex(CANARY.CanaryError, "not clean"):
            CANARY.validate_checkout_metadata(
                expected_commit=commit,
                actual_commit=commit,
                origin="https://github.com/sebswho/codex-control-plane-hooks.git",
                status=" M README.md",
            )

    def test_plugin_data_discovery_selects_active_selector_without_deleting_legacy_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory)
            root = codex_home / "plugins" / "data"
            legacy = root / "codex-control-plane-hooks"
            active = root / "codex-control-plane-hooks-codex-control-plane-hooks"
            legacy.mkdir(parents=True)
            active.mkdir()
            (legacy / "session-legacy.json").write_text("{}", encoding="utf-8")
            (active / "runtime.json").write_text("{}", encoding="utf-8")

            selected = CANARY.discover_plugin_data(
                codex_home,
                "codex-control-plane-hooks",
                "codex-control-plane-hooks",
            )

            self.assertEqual(active, selected)
            self.assertTrue((legacy / "session-legacy.json").is_file())

    def test_plugin_data_discovery_rejects_matching_name_outside_codex_home(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            codex_home = root / "codex-home"
            active = (
                codex_home
                / "plugins"
                / "data"
                / "codex-control-plane-hooks-codex-control-plane-hooks"
            )
            outside = root / "outside" / active.name
            active.mkdir(parents=True)
            outside.mkdir(parents=True)

            with mock.patch.dict(os.environ, {"PLUGIN_DATA": str(outside)}):
                with self.assertRaisesRegex(CANARY.CanaryError, "selector path"):
                    CANARY.discover_plugin_data(
                        codex_home,
                        "codex-control-plane-hooks",
                        "codex-control-plane-hooks",
                    )

    def test_plugin_data_inventory_reports_active_and_legacy_metadata_without_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory)
            root = codex_home / "plugins" / "data"
            legacy = root / "codex-control-plane-hooks"
            active = root / "codex-control-plane-hooks-codex-control-plane-hooks"
            legacy.mkdir(parents=True)
            active.mkdir()
            (legacy / "runtime.json").write_text("{}", encoding="utf-8")
            (legacy / "session-legacy.json").write_text("{}", encoding="utf-8")
            (active / "runtime.json").write_text("{}", encoding="utf-8")
            (active / "session-current.json").write_text("{}", encoding="utf-8")

            summary = CANARY.plugin_data_inventory(
                codex_home,
                "codex-control-plane-hooks",
                "codex-control-plane-hooks",
            )

            self.assertEqual(
                "codex-control-plane-hooks-codex-control-plane-hooks",
                summary["active_directory_name"],
            )
            self.assertEqual(1, summary["active_state_file_count"])
            self.assertTrue(summary["active_runtime_manifest_exists"])
            self.assertEqual(1, summary["legacy_candidate_count"])
            self.assertEqual(1, summary["legacy_runtime_manifest_count"])
            self.assertEqual(1, summary["legacy_state_file_count"])
            self.assertNotIn(str(codex_home), json.dumps(summary))

    def test_runtime_manifest_requires_existing_python_312_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime_root = root / "runtimes" / "codex-control-plane-hooks"
            interpreter = (
                runtime_root
                / "versions"
                / "py312-0123456789abcdef"
                / "Scripts"
                / "python.exe"
            )
            interpreter.parent.mkdir(parents=True)
            interpreter.write_bytes(b"placeholder")
            manifest = root / "runtime.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "interpreter": str(interpreter),
                        "python_version": "3.12.13",
                        "runtime_root": str(runtime_root),
                        "configured_at": "2026-08-04T00:00:00Z",
                    }
                ),
                encoding="utf-8",
            )

            summary = CANARY.validate_runtime_manifest(
                manifest,
                expected_runtime_root=runtime_root,
                trusted_root=runtime_root,
                version_probe=lambda _interpreter: "3.12.13",
            )
            self.assertEqual("3.12.13", summary["python_version"])
            self.assertEqual("py312-0123456789abcdef", summary["runtime_id"])
            self.assertTrue(summary["interpreter_exists"])
            with self.assertRaisesRegex(CANARY.CanaryError, "does not match"):
                CANARY.validate_runtime_manifest(
                    manifest,
                    expected_runtime_root=runtime_root,
                    trusted_root=runtime_root,
                    version_probe=lambda _interpreter: "3.11.9",
                )

            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["python_version"] = "3.11.9"
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(CANARY.CanaryError, "Python 3.12"):
                CANARY.validate_runtime_manifest(
                    manifest, expected_runtime_root=runtime_root, trusted_root=runtime_root
                )

            payload["python_version"] = "3.12.13"
            payload["runtime_root"] = str(root / "untrusted")
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(CANARY.CanaryError, "runtime root"):
                CANARY.validate_runtime_manifest(
                    manifest, expected_runtime_root=runtime_root, trusted_root=runtime_root
                )

            payload["runtime_root"] = str(runtime_root)
            payload["interpreter"] = str(
                runtime_root / "versions" / "python-current" / "Scripts" / "python.exe"
            )
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(CANARY.CanaryError, "identifier"):
                CANARY.validate_runtime_manifest(
                    manifest, expected_runtime_root=runtime_root, trusted_root=runtime_root
                )

            manifest.unlink()
            with self.assertRaisesRegex(CANARY.CanaryError, "runtime.json"):
                CANARY.validate_runtime_manifest(
                    manifest, expected_runtime_root=runtime_root, trusted_root=runtime_root
                )

    def test_runtime_path_rejects_reparse_points(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime_root = root / "runtimes" / "codex-control-plane-hooks"
            interpreter = (
                runtime_root
                / "versions"
                / "py312-0123456789abcdef"
                / "Scripts"
                / "python.exe"
            )
            interpreter.parent.mkdir(parents=True)
            interpreter.write_bytes(b"placeholder")
            with mock.patch.object(CANARY, "_is_reparse_point", return_value=True):
                with self.assertRaisesRegex(CANARY.CanaryError, "reparse"):
                    CANARY.require_no_reparse_points(interpreter, root)

    @unittest.skipUnless(os.name == "nt", "Windows native path-lock behavior")
    def test_windows_path_lock_blocks_replacement_until_version_probe_finishes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            interpreter = root / "versions" / "py312-0123456789abcdef" / "Scripts" / "python.exe"
            interpreter.parent.mkdir(parents=True)
            interpreter.write_bytes(b"trusted")
            replacement = root / "replacement.exe"
            replacement.write_bytes(b"replacement")

            with CANARY.lock_non_reparse_path(interpreter, root):
                with self.assertRaises(OSError):
                    os.replace(replacement, interpreter)

            os.replace(replacement, interpreter)
            self.assertEqual(b"replacement", interpreter.read_bytes())

    @unittest.skipUnless(os.name == "nt", "Windows native reparse behavior")
    def test_windows_path_lock_rejects_a_real_junction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "real-codex-home"
            interpreter = (
                target
                / "runtimes"
                / "codex-control-plane-hooks"
                / "versions"
                / "py312-0123456789abcdef"
                / "Scripts"
                / "python.exe"
            )
            interpreter.parent.mkdir(parents=True)
            interpreter.write_bytes(b"placeholder")
            junction = root / ".codex"
            completed = subprocess.run(
                [
                    "pwsh",
                    "-NoProfile",
                    "-NonInteractive",
                    "-CommandWithArgs",
                    "New-Item -ItemType Junction -Path $args[0] -Target $args[1] | Out-Null",
                    str(junction),
                    str(target),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            if completed.returncode:
                self.skipTest(f"junction creation unavailable: {completed.stderr.strip()}")
            try:
                with self.assertRaisesRegex(CANARY.CanaryError, "reparse"):
                    junction_interpreter = junction / interpreter.relative_to(target)
                    with CANARY.lock_non_reparse_path(junction_interpreter, root):
                        self.fail("junction-backed interpreter should not be trusted")
            finally:
                junction.rmdir()

    @unittest.skipUnless(os.name == "nt", "Windows native version probes")
    def test_windows_profile_and_file_version_probes_use_real_apis(self) -> None:
        profile = CANARY.trusted_user_profile()
        self.assertTrue(profile.is_absolute())
        self.assertTrue(profile.is_dir())
        version = CANARY.probe_windows_file_version(Path(sys.executable), ROOT)
        self.assertRegex(version, r"^3\.12\.\d+$")

    def test_artifact_hashes_match_installed_cache(self) -> None:
        relative_paths = CANARY.ARTIFACT_PATHS
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = root / "expected"
            installed = root / "installed"
            for relative in relative_paths:
                (expected / relative).parent.mkdir(parents=True, exist_ok=True)
                (installed / relative).parent.mkdir(parents=True, exist_ok=True)
                (expected / relative).write_text(f"same:{relative.as_posix()}\n", encoding="utf-8")
                (installed / relative).write_text(f"same:{relative.as_posix()}\n", encoding="utf-8")

            hashes = CANARY.compare_artifact_hashes(expected, installed)
            self.assertEqual(set(relative_paths), {Path(name) for name in hashes})
            self.assertTrue(all(row["matches"] for row in hashes.values()))

            changed = relative_paths[-1]
            (installed / changed).write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(CANARY.CanaryError, "artifact hash mismatch"):
                CANARY.compare_artifact_hashes(expected, installed)

    @unittest.skipUnless(CANARY.os.name == "nt", "Windows wrapper behavior")
    def test_command_argv_runs_powershell_wrappers_through_pwsh(self) -> None:
        wrapper = Path(r"C:\tools\codex.ps1")
        argv = CANARY.command_argv(wrapper, ["--version"])
        self.assertEqual(
            ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(wrapper), "--version"],
            argv,
        )

    def test_json_parser_accepts_cli_noise_but_rejects_non_json(self) -> None:
        self.assertEqual(
            {"installed": []},
            CANARY.parse_json_output("notice\n{\"installed\": []}\n", "plugin list"),
        )
        with self.assertRaisesRegex(CANARY.CanaryError, "did not return JSON"):
            CANARY.parse_json_output("notice only", "plugin list")

    def test_sanitizer_redacts_paths_and_sensitive_values(self) -> None:
        raw = {
            "checkout": r"D:\private-workspace\project",
            "codex_home": r"C:\private\codex-home",
            "plugin_data": r"C:\private\codex-home\plugins\data\codex-control-plane-hooks",
            "nested": {
                "token": "super-secret-value",
                "message": r"loaded D:\private-workspace\project successfully",
            },
        }
        sanitized, replacements = CANARY.sanitize_evidence(
            raw,
            {
                r"D:\private-workspace\project": "<WORKSPACE>",
                r"C:\private\codex-home\plugins\data\codex-control-plane-hooks": "<PLUGIN_DATA>",
                r"C:\private\codex-home": "<CODEX_HOME>",
            },
        )
        serialized = json.dumps(sanitized, sort_keys=True)
        self.assertNotIn(r"D:\\private-workspace\\project", serialized)
        self.assertNotIn(r"C:\\private\\codex-home", serialized)
        self.assertNotIn("super-secret-value", serialized)
        self.assertIn("<WORKSPACE>", serialized)
        self.assertEqual("<redacted-sensitive>", sanitized["nested"]["token"])
        self.assertGreaterEqual(replacements, 3)
        self.assertEqual([], CANARY.find_sensitive_residuals(sanitized))
        self.assertIn(
            "credential-like value",
            CANARY.find_sensitive_residuals({"message": "Bearer should-not-leak"}),
        )
        self.assertIn(
            "absolute path",
            CANARY.find_sensitive_residuals({"message": r"C:\private\unmapped.txt"}),
        )
        for secret in (
            "Authorization: Bearer " + "a" * 20,
            "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12,
            "xoxb-" + "a" * 24,
            "password=" + "a" * 20,
        ):
            self.assertIn(
                "credential-like value",
                CANARY.find_sensitive_residuals({"message": secret}),
                secret,
            )
        self.assertIn(
            "absolute path",
            CANARY.find_sensitive_residuals({"message": "/m" + "nt/c/" + "Users/private/file.txt"}),
        )

    def test_readiness_uses_phase_specific_scenarios(self) -> None:
        feature = {name: "passed" for name in CANARY.REQUIRED_SCENARIOS}
        feature["merge_sha_repin"] = "not_recorded"
        self.assertTrue(CANARY.evidence_ready("26.804.1", "0.146.0", feature, "feature"))

        merged = {name: "not_recorded" for name in CANARY.REQUIRED_SCENARIOS}
        for name in CANARY.MERGED_REQUIRED_SCENARIOS:
            merged[name] = "passed"
        self.assertTrue(CANARY.evidence_ready("26.804.1", "0.146.0", merged, "merged"))
        merged["app_restart_same_sha"] = "failed"
        self.assertFalse(CANARY.evidence_ready("26.804.1", "0.146.0", merged, "merged"))

    def test_safe_allow_attribution_is_optional_and_requires_a_complete_passed_pair(self) -> None:
        scenarios = {name: "not_recorded" for name in CANARY.REQUIRED_SCENARIOS}
        self.assertIsNone(CANARY.safe_allow_attribution(None, None, scenarios))

        scenarios["safe_allow"] = "passed"
        self.assertEqual(
            {
                "hook_response": "no_decision",
                "host_approval_mode": "on-request",
            },
            CANARY.safe_allow_attribution("no_decision", "on-request", scenarios),
        )

        with self.assertRaisesRegex(CANARY.CanaryError, "provided together"):
            CANARY.safe_allow_attribution("no_decision", None, scenarios)
        with self.assertRaisesRegex(CANARY.CanaryError, "safe_allow=passed"):
            CANARY.safe_allow_attribution(
                "no_decision",
                "on-request",
                {name: "not_recorded" for name in CANARY.REQUIRED_SCENARIOS},
            )

    def test_parser_exposes_fixed_interface_and_optional_app_evidence(self) -> None:
        parser = CANARY.build_parser()
        args = parser.parse_args(
            [
                "--codex",
                r"C:\tools\codex.cmd",
                "--expected-checkout",
                r"D:\repo",
                "--expected-commit",
                "a" * 40,
                "--marketplace",
                "codex-control-plane-hooks",
                "--plugin",
                "codex-control-plane-hooks",
                "--output",
                r"D:\evidence.json",
                "--phase",
                "feature",
                "--app-version",
                "26.804.1",
                "--bundled-cli-version",
                "0.146.0",
                "--scenario",
                "safe_allow=passed",
                "--safe-hook-response",
                "no_decision",
                "--host-approval-mode",
                "on-request",
            ]
        )
        self.assertEqual("a" * 40, args.expected_commit)
        self.assertEqual(["safe_allow=passed"], args.scenario)
        self.assertEqual("no_decision", args.safe_hook_response)
        self.assertEqual("on-request", args.host_approval_mode)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "--codex",
                    r"C:\tools\codex.exe",
                    "--expected-checkout",
                    r"D:\repo",
                    "--expected-commit",
                    "a" * 40,
                    "--marketplace",
                    "another-marketplace",
                    "--plugin",
                    "codex-control-plane-hooks",
                    "--output",
                    r"D:\evidence.json",
                ]
            )


if __name__ == "__main__":
    unittest.main()
