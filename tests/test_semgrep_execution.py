"""Fixed Semgrep configuration/target selection boundary; live checks are a separate acceptance command."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aegis_audit_contract import canonical
from aegis_semgrep_sandbox import PROFILE, _targets, launch, validate_rules
from aegis_sandbox import SandboxFailure
from aegis_supervisor import ExecutionDenied


class SemgrepPolicyTests(unittest.TestCase):
    def setUp(self):
        self.config={"rules":[{"id":"fixture","languages":["javascript","typescript"],
            "pattern":"eval($VALUE)","message":"Synthetic boundary only","severity":"WARNING"}]}

    def test_only_canonical_simple_patterns_and_exact_selected_rules(self):
        validate_rules(canonical(self.config),["fixture"])
        for change in (lambda c:c.update(include="/host/private"),
                       lambda c:c["rules"][0].update(validators=[{"http":{"url":"https://example.invalid"}}]),
                       lambda c:c["rules"][0].update(**{"pattern-where-python":"__import__('os').system('id')"}),
                       lambda c:c["rules"][0].update(languages=["python"]),
                       lambda c:c["rules"][0].update(languages=[{}]),
                       lambda c:c["rules"][0].update(severity=[]),
                       lambda c:c["rules"][0].update(pattern="x"*2049)):
            doc=copy.deepcopy(self.config);change(doc)
            with self.assertRaises(ExecutionDenied):validate_rules(canonical(doc),["fixture"])
        with self.assertRaises(ExecutionDenied):validate_rules(canonical(self.config)+b"\n",["fixture"])
        with self.assertRaises(ExecutionDenied):validate_rules(canonical(self.config),["different"])

    def test_launch_has_no_target_command_or_network_escape(self):
        with self.assertRaises(SandboxFailure):launch(PROFILE,3,4,5,Path("/private/jail"),20,broker_fd=8)
        with self.assertRaises(SandboxFailure):launch(PROFILE,3,4,5,Path("/private/jail"),20,source_kind="history")
        with self.assertRaises(SandboxFailure):launch("shell",3,4,5,Path("/private/jail"),20)

    def test_target_manifest_is_exact_and_rejects_links_and_unsupported_suffixes(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/"file.tsx").write_text("export const a = <p>safe</p>;")
            self.assertEqual(_targets(root),["Targets",[["CodeTarget",{"path":"file.tsx","analyzer":"typescript","products":["sast"]}]]])
            (root/"outside.js").symlink_to(root/"file.tsx")
            with self.assertRaises(SandboxFailure):_targets(root)
            (root/"outside.js").unlink();(root/"secret.env").write_text("not selected for SAST")
            with self.assertRaises(SandboxFailure):_targets(root)

    def test_target_size_and_count_are_bounded(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/"big.js").write_bytes(b" "*1048577)
            with self.assertRaises(SandboxFailure):_targets(root)
            (root/"big.js").unlink()
            for n in range(129):(root/(str(n)+".js")).write_bytes(b"x")
            with self.assertRaises(SandboxFailure):_targets(root)

    def test_unreadable_inventory_is_not_silently_partial(self):
        def inaccessible(root, *, followlinks, onerror):
            onerror(PermissionError("synthetic inaccessible directory"))
            return []
        with patch("aegis_semgrep_sandbox.os.walk", side_effect=inaccessible):
            with self.assertRaisesRegex(SandboxFailure, "could not be read"):
                _targets(Path("/private/source"))
