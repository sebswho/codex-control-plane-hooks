from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "codex-control-plane-hooks" / "scripts"


class PolicyStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data_dir = Path(self.temp.name) / "plugin-data"
        self.data_dir.mkdir()
        environment = os.environ.copy()
        environment.pop("CONTROL_PLANE_POLICY", None)
        environment["PLUGIN_DATA"] = str(self.data_dir)
        self.environment = mock.patch.dict(
            os.environ,
            environment,
            clear=True,
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        sys.path.insert(0, str(SCRIPTS))
        self.addCleanup(sys.path.remove, str(SCRIPTS))

    def load_module(self):
        sys.modules.pop("control_plane.policy", None)
        return importlib.import_module("control_plane.policy")

    def test_policy_loads_a_validated_immutable_view(self) -> None:
        (self.data_dir / "policy.json").write_text(
            json.dumps(
                {
                    "sensitive_markers": ["  marker  ", "", 3],
                    "sensitive_terms": ["term"],
                    "durable_destination_markers": ["durable"],
                    "enable_natural_language_approvals": True,
                    "enable_sensitive_disclosure_approvals": "true",
                    "enable_scoped_git_transactions": True,
                    "enable_constrained_github_clone": False,
                }
            ),
            encoding="utf-8",
        )

        view = self.load_module().load_policy()

        self.assertEqual(("marker",), view.markers)
        self.assertEqual(("term",), view.terms)
        self.assertEqual(("durable",), view.durable_markers)
        self.assertTrue(view.enable_natural_language_approvals)
        self.assertFalse(view.enable_sensitive_disclosure_approvals)
        self.assertTrue(view.enable_scoped_git_transactions)
        self.assertFalse(view.enable_constrained_github_clone)
        with self.assertRaises(FrozenInstanceError):
            view.markers = ()
        with self.assertRaises(AttributeError):
            view.markers.append("changed")

    def test_default_and_explicit_missing_policy_remain_distinct(self) -> None:
        policy = self.load_module()

        self.assertEqual(policy.PolicyView(), policy.load_policy())
        missing = self.data_dir / "missing-policy.json"
        with mock.patch.dict(
            os.environ,
            {"CONTROL_PLANE_POLICY": str(missing)},
            clear=False,
        ):
            expected = (
                "Windows policy must use PLUGIN_DATA/policy.json"
                if os.name == "nt"
                else "configured policy file is unavailable"
            )
            with self.assertRaisesRegex(
                RuntimeError, expected
            ):
                policy.load_policy()


if __name__ == "__main__":
    unittest.main()
