from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SETUP_SCRIPT = ROOT / "plugins" / "codex-control-plane-hooks" / "scripts" / "setup_runtime.ps1"
PLUGIN_NAME = "codex-control-plane-hooks"


@unittest.skipUnless(os.name == "nt", "Windows runtime setup test")
class RuntimeSetupTests(unittest.TestCase):
    def setUp(self) -> None:
        system_root = Path(os.environ["SystemRoot"])
        self.powershell = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        self.runtime_root = Path(os.environ["USERPROFILE"]) / ".codex" / "runtimes" / PLUGIN_NAME
        self.versions_root = self.runtime_root / "versions"

    def make_plugin_data(self, root: Path, name: str = PLUGIN_NAME) -> Path:
        plugin_data = root / "codex-home" / "plugins" / "data" / name
        plugin_data.mkdir(parents=True)
        return plugin_data

    def require_python312(self) -> None:
        if sys.version_info[:2] != (3, 12):
            self.skipTest("runtime creation requires the Python 3.12 test job")

    def make_source_runtime(self, root: Path) -> Path:
        self.require_python312()
        source_runtime = root / "source-runtime"
        subprocess.run(
            [sys.executable, "-m", "venv", str(source_runtime)],
            text=True,
            capture_output=True,
            check=True,
        )
        return source_runtime / "Scripts" / "python.exe"

    def run_setup(
        self,
        python_path: str | Path,
        *,
        plugin_data: Path | None = None,
        codex_home: Path | None = None,
        extra: tuple[str, ...] = (),
        environment: dict[str, str] | None = None,
        shell: str | Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            str(shell or self.powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SETUP_SCRIPT),
            "-PythonPath",
            str(python_path),
        ]
        if plugin_data is not None:
            command.extend(("-PluginDataPath", str(plugin_data)))
        if codex_home is not None:
            command.extend(("-CodexHome", str(codex_home)))
        command.extend(extra)
        return subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )

    def read_manifest(self, plugin_data: Path) -> dict[str, object]:
        return json.loads((plugin_data / "runtime.json").read_text(encoding="utf-8"))

    def require_empty_versions_root(self, reason: str) -> None:
        self.versions_root.mkdir(parents=True, exist_ok=True)
        if any(self.versions_root.iterdir()):
            self.skipTest(reason)

    def register_runtime_cleanup(self, manifest: dict[str, object]) -> Path:
        interpreter = Path(str(manifest["interpreter"]))
        version_directory = interpreter.parents[1]
        self.assertEqual(self.versions_root, version_directory.parent)
        self.assertRegex(version_directory.name, r"^py312-[a-z0-9-]+$")
        self.addCleanup(shutil.rmtree, version_directory, True)
        return interpreter

    def make_junction(self, link: Path, target: Path) -> None:
        comspec = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
        completed = subprocess.run(
            [comspec, "/d", "/c", "mklink", "/J", str(link), str(target)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)

    @staticmethod
    def stop_process(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            process.kill()
        process.wait()

    def test_explicit_plugin_data_bootstraps_python312_runtime(self) -> None:
        self.require_empty_versions_root("runtime bootstrap test requires an empty root")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_python = self.make_source_runtime(root)
            plugin_data = self.make_plugin_data(root)

            completed = self.run_setup(source_python, plugin_data=plugin_data)

            self.assertEqual(0, completed.returncode, completed.stderr)
            manifest = self.read_manifest(plugin_data)
            self.assertEqual(1, manifest["schema_version"])
            self.assertRegex(str(manifest["python_version"]), r"^3\.12\.\d+$")
            self.assertEqual(self.runtime_root, Path(str(manifest["runtime_root"])))
            interpreter = self.register_runtime_cleanup(manifest)
            self.assertEqual(Path("Scripts") / "python.exe", Path(*interpreter.parts[-2:]))
            self.assertTrue(interpreter.is_file())

    def test_codex_home_discovers_one_plugin_data_candidate(self) -> None:
        self.require_empty_versions_root("Codex home test requires an empty runtime root")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_python = self.make_source_runtime(root)
            plugin_data = self.make_plugin_data(
                root,
                "codex-control-plane-hooks-cachebuster123",
            )

            completed = self.run_setup(
                source_python,
                codex_home=root / "codex-home",
            )

            self.assertEqual(0, completed.returncode, completed.stderr)
            interpreter = self.register_runtime_cleanup(self.read_manifest(plugin_data))
            self.assertTrue(interpreter.is_file())

    def test_codex_home_rejects_zero_or_multiple_plugin_data_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for count in (0, 2):
                with self.subTest(count=count):
                    codex_home = root / f"codex-home-{count}"
                    data_root = codex_home / "plugins" / "data"
                    data_root.mkdir(parents=True)
                    for index in range(count):
                        (data_root / f"{PLUGIN_NAME}-{index}").mkdir()

                    completed = self.run_setup(
                        self.powershell,
                        codex_home=codex_home,
                    )

                    self.assertNotEqual(0, completed.returncode)
                    self.assertIn(f"found {count}", completed.stderr)
                    self.assertNotIn(str(data_root), completed.stderr)

    def test_invalid_python_preserves_existing_runtime_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plugin_data = self.make_plugin_data(Path(directory))
            manifest_path = plugin_data / "runtime.json"
            original = '{"schema_version":1,"sentinel":"keep-me"}\n'
            manifest_path.write_text(original, encoding="utf-8")

            completed = self.run_setup(self.powershell, plugin_data=plugin_data)

            self.assertNotEqual(0, completed.returncode)
            self.assertEqual(original, manifest_path.read_text(encoding="utf-8"))

    def test_locked_manifest_preserves_previous_runtime_and_redacts_paths(self) -> None:
        self.require_empty_versions_root("manifest replace test requires an empty root")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_python = self.make_source_runtime(root)
            plugin_data = self.make_plugin_data(root)
            first = self.run_setup(source_python, plugin_data=plugin_data)
            self.assertEqual(0, first.returncode, first.stderr)
            self.register_runtime_cleanup(self.read_manifest(plugin_data))
            manifest_path = plugin_data / "runtime.json"
            original = manifest_path.read_text(encoding="utf-8")

            create_file = ctypes.windll.kernel32.CreateFileW
            create_file.argtypes = (
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            )
            create_file.restype = wintypes.HANDLE
            handle = create_file(
                str(manifest_path),
                0x80000000,
                0,
                None,
                3,
                0x80,
                None,
            )
            self.assertNotEqual(wintypes.HANDLE(-1).value, handle)
            try:
                second = self.run_setup(source_python, plugin_data=plugin_data)
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)

            self.assertNotEqual(0, second.returncode)
            self.assertEqual(original, manifest_path.read_text(encoding="utf-8"))
            self.assertIn("runtime setup failed", second.stderr)
            self.assertNotIn(str(plugin_data), second.stderr)

    def test_manifest_publication_is_bound_to_the_temporary_file_handle(self) -> None:
        source = SETUP_SCRIPT.read_text(encoding="utf-8")

        self.assertIn("OpenFileForRename", source)
        self.assertIn("RenameByHandle", source)
        self.assertNotIn("[System.IO.File]::Replace", source)
        self.assertNotIn("[System.IO.File]::Move($temporaryManifest", source)

    def test_prune_gates_the_quarantined_interpreter_before_deletion(self) -> None:
        source = SETUP_SCRIPT.read_text(encoding="utf-8")

        self.assertIn("Remove-RuntimeTreeByHandle", source)
        self.assertIn("OpenPruneGate", source)
        self.assertIn("$quarantineGate", source)
        self.assertIn("$quarantinedInterpreter", source)
        self.assertNotIn(
            "Remove-Item -LiteralPath $quarantineDirectory -Recurse",
            source,
        )

    def test_python_older_than312_is_rejected(self) -> None:
        if sys.version_info[:2] == (3, 12):
            self.skipTest("Python 3.12 is covered by runtime creation tests")
        with tempfile.TemporaryDirectory() as directory:
            plugin_data = self.make_plugin_data(Path(directory))

            completed = self.run_setup(sys.executable, plugin_data=plugin_data)

            self.assertNotEqual(0, completed.returncode)
            self.assertIn("Python 3.12", completed.stderr)
            self.assertFalse((plugin_data / "runtime.json").exists())

    def test_rerun_reuses_the_published_runtime(self) -> None:
        self.require_empty_versions_root("idempotency test requires an empty runtime root")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_python = self.make_source_runtime(root)
            plugin_data = self.make_plugin_data(root)

            first = self.run_setup(source_python, plugin_data=plugin_data)
            self.assertEqual(0, first.returncode, first.stderr)
            first_manifest = self.read_manifest(plugin_data)
            interpreter = self.register_runtime_cleanup(first_manifest)
            configuration = interpreter.parents[1] / "pyvenv.cfg"
            original_mtime = configuration.stat().st_mtime_ns

            second = self.run_setup(source_python, plugin_data=plugin_data)

            self.assertEqual(0, second.returncode, second.stderr)
            second_manifest = self.read_manifest(plugin_data)
            self.assertEqual(first_manifest["interpreter"], second_manifest["interpreter"])
            self.assertEqual(original_mtime, configuration.stat().st_mtime_ns)

    def test_plugin_data_environment_is_used_when_explicit_path_is_absent(self) -> None:
        self.require_python312()
        self.require_empty_versions_root("environment test requires an empty runtime root")
        with tempfile.TemporaryDirectory() as directory:
            plugin_data = self.make_plugin_data(Path(directory))
            environment = os.environ.copy()
            environment["PLUGIN_DATA"] = str(plugin_data)

            completed = self.run_setup(sys.executable, environment=environment)

            self.assertEqual(0, completed.returncode, completed.stderr)
            self.register_runtime_cleanup(self.read_manifest(plugin_data))

    def test_explicit_plugin_data_overrides_poisoned_environment(self) -> None:
        self.require_python312()
        self.require_empty_versions_root("override test requires an empty runtime root")
        with tempfile.TemporaryDirectory() as directory:
            plugin_data = self.make_plugin_data(Path(directory))
            environment = os.environ.copy()
            environment["PLUGIN_DATA"] = "relative-poison"

            completed = self.run_setup(
                sys.executable,
                plugin_data=plugin_data,
                environment=environment,
            )

            self.assertEqual(0, completed.returncode, completed.stderr)
            self.register_runtime_cleanup(self.read_manifest(plugin_data))

    def test_powershell7_can_bootstrap_the_runtime(self) -> None:
        self.require_python312()
        powershell7 = shutil.which("pwsh.exe")
        if powershell7 is None:
            self.skipTest("PowerShell 7 is not installed")
        self.require_empty_versions_root("PowerShell 7 test requires an empty runtime root")
        with tempfile.TemporaryDirectory() as directory:
            plugin_data = self.make_plugin_data(Path(directory))

            completed = self.run_setup(
                sys.executable,
                plugin_data=plugin_data,
                shell=powershell7,
            )

            self.assertEqual(0, completed.returncode, completed.stderr)
            self.register_runtime_cleanup(self.read_manifest(plugin_data))

    def test_plugin_data_reparse_point_is_rejected_before_python_runs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            data_root = root / "codex-home" / "plugins" / "data"
            data_root.mkdir(parents=True)
            plugin_data = data_root / PLUGIN_NAME
            self.make_junction(plugin_data, target)

            completed = self.run_setup(self.powershell, plugin_data=plugin_data)

            self.assertNotEqual(0, completed.returncode)
            self.assertIn("reparse", completed.stderr.lower())
            self.assertFalse((target / "runtime.json").exists())

    def test_discovered_plugin_data_reparse_point_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            codex_home = root / "codex-home"
            data_root = codex_home / "plugins" / "data"
            data_root.mkdir(parents=True)
            plugin_data = data_root / f"{PLUGIN_NAME}-cachebuster123"
            self.make_junction(plugin_data, target)

            completed = self.run_setup(self.powershell, codex_home=codex_home)

            self.assertNotEqual(0, completed.returncode)
            self.assertIn("reparse", completed.stderr.lower())
            self.assertFalse((target / "runtime.json").exists())

    def test_plugin_data_reparse_swap_during_venv_creation_is_rejected(self) -> None:
        self.require_empty_versions_root("plugin-data race test requires an empty root")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_python = self.make_source_runtime(root)
            plugin_data = self.make_plugin_data(root)
            original_plugin_data = plugin_data.with_name(f"{PLUGIN_NAME}-original")
            target = root / "junction-target"
            target.mkdir()
            signal = root / "venv-started"
            release = root / "continue-venv"
            wrapper = root / "python-wrapper.cmd"
            wrapper.write_text(
                "\r\n".join(
                    (
                        "@echo off",
                        'if "%~4"=="venv" (',
                        f'  type nul > "{signal}"',
                        "  :wait_for_release",
                        f'  if not exist "{release}" (',
                        "    >nul 2>&1 ping -n 2 127.0.0.1",
                        "    goto wait_for_release",
                        "  )",
                        ")",
                        f'"{source_python}" %*',
                        "",
                    )
                ),
                encoding="utf-8",
            )
            command = [
                str(self.powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(SETUP_SCRIPT),
                "-PythonPath",
                str(wrapper),
                "-PluginDataPath",
                str(plugin_data),
            ]
            existing_versions = set(self.versions_root.iterdir())
            process = subprocess.Popen(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.addCleanup(self.stop_process, process)
            deadline = time.monotonic() + 15
            while not signal.exists() and process.poll() is None:
                if time.monotonic() >= deadline:
                    self.fail("setup did not reach venv creation")
                time.sleep(0.05)

            swap_succeeded = False
            try:
                try:
                    plugin_data.rename(original_plugin_data)
                    self.make_junction(plugin_data, target)
                    swap_succeeded = True
                except OSError:
                    self.assertTrue(plugin_data.is_dir())
                release.touch()
                _, stderr = process.communicate(timeout=60)
            finally:
                release.touch(exist_ok=True)
                if swap_succeeded and plugin_data.exists():
                    os.rmdir(plugin_data)
                if original_plugin_data.exists():
                    original_plugin_data.rename(plugin_data)
            for created in set(self.versions_root.iterdir()) - existing_versions:
                self.addCleanup(shutil.rmtree, created, True)

            if swap_succeeded:
                self.assertNotEqual(0, process.returncode, stderr)
                self.assertIn("reparse", stderr.lower())
            else:
                self.assertEqual(0, process.returncode, stderr)
                self.assertTrue((plugin_data / "runtime.json").is_file())
            self.assertFalse((target / "runtime.json").exists())

    def test_python_path_through_a_reparse_point_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plugin_data = self.make_plugin_data(root)
            source_link = root / "python-source"
            interpreter = Path(sys.executable)
            self.make_junction(source_link, interpreter.parent)

            completed = self.run_setup(
                source_link / interpreter.name,
                plugin_data=plugin_data,
            )

            self.assertNotEqual(0, completed.returncode)
            self.assertIn("reparse", completed.stderr.lower())
            self.assertFalse((plugin_data / "runtime.json").exists())

    def test_plugin_data_outside_fixed_parent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plugin_data = Path(directory) / PLUGIN_NAME
            plugin_data.mkdir()

            completed = self.run_setup(self.powershell, plugin_data=plugin_data)

            self.assertNotEqual(0, completed.returncode)
            self.assertIn("fixed plugins data directory", completed.stderr)
            self.assertFalse((plugin_data / "runtime.json").exists())

    def test_relative_plugin_data_environment_does_not_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plugin_data = self.make_plugin_data(root)
            environment = os.environ.copy()
            environment["PLUGIN_DATA"] = "relative-poison"

            completed = self.run_setup(
                self.powershell,
                codex_home=root / "codex-home",
                environment=environment,
            )

            self.assertNotEqual(0, completed.returncode)
            self.assertIn("absolute path", completed.stderr)
            self.assertFalse((plugin_data / "runtime.json").exists())

    def test_existing_runtime_manifest_reparse_point_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plugin_data = self.make_plugin_data(root)
            target = root / "manifest-target"
            target.mkdir()
            self.make_junction(plugin_data / "runtime.json", target)

            completed = self.run_setup(self.powershell, plugin_data=plugin_data)

            self.assertNotEqual(0, completed.returncode)
            self.assertIn("reparse", completed.stderr.lower())
            self.assertEqual([], list(target.iterdir()))

    def test_existing_runtime_version_reparse_point_is_rejected(self) -> None:
        self.require_empty_versions_root("runtime reparse test requires an empty root")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_python = self.make_source_runtime(root)
            plugin_data = self.make_plugin_data(root)
            first = self.run_setup(source_python, plugin_data=plugin_data)
            self.assertEqual(0, first.returncode, first.stderr)
            manifest = self.read_manifest(plugin_data)
            version_directory = Path(str(manifest["interpreter"])).parents[1]
            self.assertEqual(self.versions_root, version_directory.parent)
            shutil.rmtree(version_directory)
            self.make_junction(version_directory, source_python.parents[1])
            self.addCleanup(os.rmdir, version_directory)

            second = self.run_setup(source_python, plugin_data=plugin_data)

            self.assertNotEqual(0, second.returncode)
            self.assertIn("reparse", second.stderr.lower())

    def test_explicit_prune_keeps_current_and_newest_old_runtime(self) -> None:
        self.require_empty_versions_root("prune test requires an empty runtime root")
        old_directories: list[Path] = []
        for index in range(3):
            old_directory = self.versions_root / f"py312-test-old-{index}"
            (old_directory / "Scripts").mkdir(parents=True)
            (old_directory / "Scripts" / "python.exe").write_bytes(b"not active")
            os.utime(old_directory, (1_700_000_000 + index, 1_700_000_000 + index))
            old_directories.append(old_directory)
            self.addCleanup(shutil.rmtree, old_directory, True)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_python = self.make_source_runtime(root)
            plugin_data = self.make_plugin_data(root)

            completed = self.run_setup(
                source_python,
                plugin_data=plugin_data,
                extra=("-PruneOldRuntime", "-Keep", "2"),
            )

            self.assertEqual(0, completed.returncode, completed.stderr)
            current_directory = self.register_runtime_cleanup(self.read_manifest(plugin_data)).parents[1]
            remaining = {path.name for path in self.versions_root.iterdir()}
            self.assertEqual(
                {current_directory.name, old_directories[-1].name},
                remaining,
                completed.stderr,
            )

    def test_setup_does_not_prune_old_runtimes_by_default(self) -> None:
        self.require_empty_versions_root("default prune test requires an empty runtime root")
        old_directories = [
            self.versions_root / "py312-test-default-old-0",
            self.versions_root / "py312-test-default-old-1",
        ]
        for old_directory in old_directories:
            (old_directory / "Scripts").mkdir(parents=True)
            (old_directory / "Scripts" / "python.exe").write_bytes(b"not active")
            self.addCleanup(shutil.rmtree, old_directory, True)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_python = self.make_source_runtime(root)
            plugin_data = self.make_plugin_data(root)

            completed = self.run_setup(source_python, plugin_data=plugin_data)

            self.assertEqual(0, completed.returncode, completed.stderr)
            self.register_runtime_cleanup(self.read_manifest(plugin_data))
            for old_directory in old_directories:
                self.assertTrue(old_directory.is_dir())

    def test_explicit_prune_skips_an_active_old_runtime(self) -> None:
        self.require_python312()
        self.require_empty_versions_root("active prune test requires an empty runtime root")
        old_directory = self.versions_root / "py312-test-active"
        subprocess.run(
            [sys.executable, "-m", "venv", str(old_directory)],
            text=True,
            capture_output=True,
            check=True,
        )
        self.addCleanup(shutil.rmtree, old_directory, True)
        inactive_directory = self.versions_root / "py312-test-newer-inactive"
        (inactive_directory / "Scripts").mkdir(parents=True)
        (inactive_directory / "Scripts" / "python.exe").write_bytes(b"not active")
        self.addCleanup(shutil.rmtree, inactive_directory, True)
        os.utime(old_directory, (1_700_000_000, 1_700_000_000))
        os.utime(inactive_directory, (1_700_000_100, 1_700_000_100))

        active_process = subprocess.Popen(
            [
                old_directory / "Scripts" / "python.exe",
                "-I",
                "-S",
                "-c",
                "import time; time.sleep(60)",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(self.stop_process, active_process)
        time.sleep(0.25)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_python = self.make_source_runtime(root)
            plugin_data = self.make_plugin_data(root)

            completed = self.run_setup(
                source_python,
                plugin_data=plugin_data,
                extra=("-PruneOldRuntime", "-Keep", "2"),
            )

            self.assertEqual(0, completed.returncode, completed.stderr)
            self.register_runtime_cleanup(self.read_manifest(plugin_data))
            self.assertTrue(old_directory.is_dir())
            self.assertIn("active old runtime", completed.stderr)

    def test_explicit_prune_skips_runtime_when_python_process_is_uninspectable(self) -> None:
        self.require_empty_versions_root("uninspectable prune test requires an empty root")
        old_directories = []
        for index in range(2):
            old_directory = self.versions_root / f"py312-test-uninspectable-{index}"
            (old_directory / "Scripts").mkdir(parents=True)
            (old_directory / "Scripts" / "python.exe").write_bytes(b"not active")
            os.utime(old_directory, (1_700_001_000 + index, 1_700_001_000 + index))
            old_directories.append(old_directory)
            self.addCleanup(shutil.rmtree, old_directory, True)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_python = self.make_source_runtime(root)
            plugin_data = self.make_plugin_data(root)
            environment = os.environ.copy()
            environment.update(
                {
                    "TEST_SETUP_SCRIPT": str(SETUP_SCRIPT),
                    "TEST_PYTHON_PATH": str(source_python),
                    "TEST_PLUGIN_DATA": str(plugin_data),
                }
            )
            command = [
                str(self.powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                (
                    "function Get-CimInstance { "
                    "[pscustomobject]@{ Name = 'python.exe'; ExecutablePath = $null } "
                    "}; & $env:TEST_SETUP_SCRIPT -PythonPath $env:TEST_PYTHON_PATH "
                    "-PluginDataPath $env:TEST_PLUGIN_DATA -PruneOldRuntime -Keep 2"
                ),
            ]

            completed = subprocess.run(
                command,
                text=True,
                capture_output=True,
                check=False,
                env=environment,
            )

            self.assertEqual(0, completed.returncode, completed.stderr)
            self.register_runtime_cleanup(self.read_manifest(plugin_data))
            self.assertTrue(old_directories[0].is_dir())
            self.assertIn("active-process inspection failed", completed.stderr)

    def test_explicit_prune_preserves_a_runtime_with_a_locked_file(self) -> None:
        self.require_empty_versions_root("locked prune test requires an empty root")
        old_directories: list[Path] = []
        for index in range(2):
            old_directory = self.versions_root / f"py312-test-locked-{index}"
            (old_directory / "Scripts").mkdir(parents=True)
            (old_directory / "Scripts" / "python.exe").write_bytes(b"not active")
            os.utime(old_directory, (1_700_003_000 + index, 1_700_003_000 + index))
            old_directories.append(old_directory)
            self.addCleanup(shutil.rmtree, old_directory, True)
        locked_file = old_directories[0] / "locked.dat"
        locked_file.write_bytes(b"keep intact")
        os.utime(old_directories[0], (1_700_003_000, 1_700_003_000))
        original_files = {
            path.relative_to(old_directories[0]) for path in old_directories[0].rglob("*") if path.is_file()
        }

        create_file = ctypes.windll.kernel32.CreateFileW
        create_file.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        create_file.restype = wintypes.HANDLE
        handle = create_file(str(locked_file), 0x80000000, 0, None, 3, 0x80, None)
        self.assertNotEqual(wintypes.HANDLE(-1).value, handle)
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source_python = self.make_source_runtime(root)
                plugin_data = self.make_plugin_data(root)
                completed = self.run_setup(
                    source_python,
                    plugin_data=plugin_data,
                    extra=("-PruneOldRuntime", "-Keep", "2"),
                )
                self.assertEqual(0, completed.returncode, completed.stderr)
                self.register_runtime_cleanup(self.read_manifest(plugin_data))
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)

        preserved_files = {
            path.relative_to(old_directories[0]) for path in old_directories[0].rglob("*") if path.is_file()
        }
        self.assertEqual(original_files, preserved_files, completed.stderr)
        self.assertIn("could not be pruned", completed.stderr)

    def test_explicit_prune_deletes_a_child_junction_without_following_it(self) -> None:
        self.require_empty_versions_root("junction prune test requires an empty root")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "external-target"
            target.mkdir()
            sentinel = target / "sentinel.txt"
            sentinel.write_text("keep", encoding="utf-8")
            old_directories: list[Path] = []
            for index in range(2):
                old_directory = self.versions_root / f"py312-test-junction-{index}"
                (old_directory / "Scripts").mkdir(parents=True)
                (old_directory / "Scripts" / "python.exe").write_bytes(b"not active")
                old_directories.append(old_directory)
                self.addCleanup(shutil.rmtree, old_directory, True)
            self.make_junction(old_directories[0] / "external-link", target)
            os.utime(old_directories[0], (1_700_004_000, 1_700_004_000))
            os.utime(old_directories[1], (1_700_004_100, 1_700_004_100))
            source_python = self.make_source_runtime(root)
            plugin_data = self.make_plugin_data(root)

            completed = self.run_setup(
                source_python,
                plugin_data=plugin_data,
                extra=("-PruneOldRuntime", "-Keep", "2"),
            )

            self.assertEqual(0, completed.returncode, completed.stderr)
            self.register_runtime_cleanup(self.read_manifest(plugin_data))
            self.assertFalse(old_directories[0].exists(), completed.stderr)
            self.assertEqual("keep", sentinel.read_text(encoding="utf-8"))

    def test_prune_preserves_active_runtime_when_cim_misses_the_process(self) -> None:
        self.require_python312()
        self.require_empty_versions_root("prune gate test requires an empty runtime root")
        old_directory = self.versions_root / "py312-test-cim-false-negative"
        subprocess.run(
            [sys.executable, "-m", "venv", str(old_directory)],
            text=True,
            capture_output=True,
            check=True,
        )
        self.addCleanup(shutil.rmtree, old_directory, True)
        inactive_directory = self.versions_root / "py312-test-newer-for-gate"
        (inactive_directory / "Scripts").mkdir(parents=True)
        (inactive_directory / "Scripts" / "python.exe").write_bytes(b"not active")
        self.addCleanup(shutil.rmtree, inactive_directory, True)
        os.utime(old_directory, (1_700_002_000, 1_700_002_000))
        os.utime(inactive_directory, (1_700_002_100, 1_700_002_100))
        original_files = {path.relative_to(old_directory) for path in old_directory.rglob("*") if path.is_file()}
        old_python = old_directory / "Scripts" / "python.exe"
        active_process = subprocess.Popen(
            [old_python, "-I", "-S", "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(self.stop_process, active_process)
        time.sleep(0.25)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_python = self.make_source_runtime(root)
            plugin_data = self.make_plugin_data(root)
            environment = os.environ.copy()
            environment.update(
                {
                    "TEST_SETUP_SCRIPT": str(SETUP_SCRIPT),
                    "TEST_PYTHON_PATH": str(source_python),
                    "TEST_PLUGIN_DATA": str(plugin_data),
                }
            )
            command = [
                str(self.powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                (
                    "function Get-CimInstance { @() }; "
                    "& $env:TEST_SETUP_SCRIPT -PythonPath $env:TEST_PYTHON_PATH "
                    "-PluginDataPath $env:TEST_PLUGIN_DATA -PruneOldRuntime -Keep 2"
                ),
            ]

            completed = subprocess.run(
                command,
                text=True,
                capture_output=True,
                check=False,
                env=environment,
            )

            self.assertEqual(0, completed.returncode, completed.stderr)
            self.register_runtime_cleanup(self.read_manifest(plugin_data))
            remaining_files = {path.relative_to(old_directory) for path in old_directory.rglob("*") if path.is_file()}
            self.assertEqual(original_files, remaining_files)
            self.stop_process(active_process)
            smoke = subprocess.run(
                [old_python, "-I", "-S", "-c", "import sys"],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, smoke.returncode, completed.stderr + smoke.stderr)
            self.assertIn("active old runtime", completed.stderr)

    def test_prune_rejects_keep_below_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plugin_data = self.make_plugin_data(Path(directory))

            completed = self.run_setup(
                self.powershell,
                plugin_data=plugin_data,
                extra=("-PruneOldRuntime", "-Keep", "1"),
            )

            self.assertNotEqual(0, completed.returncode)
            self.assertIn("2", completed.stderr)
            self.assertFalse((plugin_data / "runtime.json").exists())


if __name__ == "__main__":
    unittest.main()
