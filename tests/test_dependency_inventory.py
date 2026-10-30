"""Synthetic manifest corpus; fixtures are read as data, never restored or built."""
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import aegis_dependency_worker as worker
from aegis_intelligence import canonical, correlate, IntelligenceDenied, validate_snapshot


class DependencyInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def put(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(json.dumps(value).encode() if isinstance(value, dict) else value.encode())
        return path

    def read(self):
        return worker._inventory(str(self.root))

    def corpus(self):
        corpus = json.loads((Path(__file__).parent / "fixtures" / "dependency-corpus.json").read_text())
        for name, value in corpus.items():
            self.put(name, value)
        return self.read()

    def snapshot(self):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        pairs = [("PyPI", "requests", "2.31.0"), ("npm", "lodash", "4.17.20"),
                 ("NuGet", "Newtonsoft.Json", "13.0.1"), ("Maven", "org.example:unsafe-fixture", "1.0.0"),
                 ("Go", "example.org/unsafe", "v1.0.0")]
        return validate_snapshot({"format":"AEGIS-OSV-v1", "source":"OSV", "source_url":"https://api.osv.dev",
            "retrieved_at_utc":now, "records":[{"id":f"GHSA-FIXTURE-{index:04d}", "affected":[
                {"package":{"ecosystem":ec,"name":name},"versions":[version]}]} for index,(ec,name,version) in enumerate(pairs)]})

    def test_monorepo_corpus_provenance_conflicts_and_safe_controls(self):
        result = self.corpus()
        self.assertEqual({p["ecosystem"] for p in result["packages"]}, {"PyPI","npm","NuGet","Maven","Go"})
        self.assertEqual(result["summary"]["duplicate_coordinates"], 1)
        self.assertEqual(result["summary"]["packages_with_conflicting_versions"], 1)
        self.assertEqual(result, self.read())
        self.assertEqual(result["coverage"]["status"], "partial")
        for entry in result["packages"] + result["unresolved"]:
            self.assertEqual(entry["manifest_sha256"], hashlib.sha256((self.root / entry["source"]).read_bytes()).hexdigest())
            self.assertIn(entry["evidence_kind"], ("declared", "locked"))
        leads = correlate(result, self.snapshot())["leads"]
        self.assertEqual(len(leads), 6)  # Both NuGet framework origins survive.
        self.assertEqual(sum(p["ecosystem"] == "NuGet" for p in leads), 2)
        self.assertNotIn("safe-control", json.dumps(leads))
        self.assertNotIn("example.org/safe", json.dumps(leads))
        self.assertNotIn("SECRET_PASSWORD", json.dumps(result))
        self.assertNotIn("not-installed", json.dumps(result))
        self.assertTrue(all("manifest_sha256" in lead and "origin" in lead for lead in leads))

    def test_missing_and_unsupported_manifests_are_gaps(self):
        result = self.read()
        self.assertEqual(result["coverage"]["gaps"][0]["reason"], "no_supported_manifests")
        self.put("go.sum", "example.org/missing v1.0.0 h1:irrelevant")
        self.put("project.csproj", "<Project/>")
        result = self.read()
        self.assertFalse(result["packages"])
        self.assertIn("checksum_not_installed_inventory", {g["reason"] for g in result["coverage"]["gaps"]})

    def test_markers_ranges_local_links_and_go_replacements_unresolved(self):
        result = self.corpus()
        reasons = {p["reason"] for p in result["unresolved"]}
        self.assertTrue({"marker_requires_resolution", "local_or_external_dependency",
                         "replacement_or_exclusion_requires_resolution", "property_range_or_managed_version"} <= reasons)
        self.assertFalse(any(p["name"] in ("example.org/local", "example.org/excluded") for p in result["packages"]))

    def test_malformed_duplicate_keys_and_xml_entities_do_not_admit_partial_data(self):
        for filename, value in [("package-lock.json", '{"lockfileVersion":2,"lockfileVersion":3,"packages":{}}'),
                                ("packages.lock.json", '{"version":2,"dependencies":{}}'),
                                ("pom.xml", '<!DOCTYPE project [<!ENTITY secret SYSTEM "file:///etc/passwd">]><project>&secret;</project>'),
                                ("go.mod", "require (\nexample.org/unsafe v1.0.0\n")]:
            with self.subTest(filename=filename):
                self.put(filename, value)
        result = self.read()
        self.assertFalse(result["packages"])
        self.assertTrue(all(m["status"] == "malformed_or_unsupported" for m in result["manifests"]))

    def test_symlink_hardlink_and_special_manifests_fail_closed(self):
        outside = self.root / "outside.txt"
        outside.write_text("private==1.0.0")
        path = self.root / "requirements.txt"
        path.symlink_to(outside)
        with self.assertRaises(ValueError):
            self.read()
        path.unlink()
        os.link(outside, path)
        with self.assertRaises(ValueError):
            self.read()
        path.unlink()
        os.mkfifo(path)
        with self.assertRaises(ValueError):
            self.read()

    def test_outside_directory_link_and_include_never_read(self):
        with tempfile.TemporaryDirectory() as outside:
            (Path(outside) / "requirements.txt").write_text("outside-secret==1.0.0")
            (self.root / "linked-app").symlink_to(outside, target_is_directory=True)
            self.put("requirements.txt", "-r ../outside/requirements.txt\n")
            result = self.read()
        self.assertFalse(result["packages"])
        self.assertNotIn("outside-secret", json.dumps(result))
        with self.assertRaises(ValueError):
            worker.inventory(str(self.root))

    def test_coordinate_file_depth_and_entry_caps_are_explicit(self):
        self.put("requirements.txt", "a==1\nb==2\nc==3\n")
        with mock.patch.object(worker, "MAX_COORDS", 2):
            result = self.read()
        self.assertEqual(len(result["packages"]), 2)
        self.assertIn("coordinates", result["coverage"]["limits_hit"])
        self.put("app/requirements.txt", "d==4")
        with mock.patch.object(worker, "MAX_MANIFESTS", 1):
            self.assertIn("manifests", self.read()["coverage"]["limits_hit"])
        with mock.patch.object(worker, "MAX_DEPTH", 0):
            self.assertIn("depth", self.read()["coverage"]["limits_hit"])
        with mock.patch.object(worker, "MAX_ENTRIES", 1):
            self.assertIn("entries", self.read()["coverage"]["limits_hit"])

    def test_byte_and_evidence_caps_are_explicit(self):
        self.put("requirements.txt", "a==1\n" * 200)
        with mock.patch.object(worker, "MAX_REQUIREMENTS", 20):
            result = self.read()
        self.assertFalse(result["packages"])
        self.assertIn("bytes", result["coverage"]["limits_hit"])
        result = self.read()
        self.assertLessEqual(len(worker._encoded(result)), 32768)
        self.assertIn("evidence_bytes", result["coverage"]["limits_hit"])
        self.assertTrue(result["coverage"]["remaining_entries_unknown"])

    def test_changed_file_rejected_and_budget_charged(self):
        self.put("requirements.txt", "a==1\n")
        with mock.patch.object(worker, "read_regular", side_effect=ValueError("changed")):
            result = self.read()
        self.assertEqual(result["coverage"]["bytes_charged"], 5)
        self.assertFalse(result["packages"])
        self.assertIn("manifest_unreadable_or_changed", {g["reason"] for g in result["coverage"]["gaps"]})

    def test_canonical_coordinates_and_provenance_tampering(self):
        self.assertEqual(canonical("NuGet", "Newtonsoft.Json"), "newtonsoft.json")
        self.assertEqual(canonical("Maven", "org.Example:Artifact"), "org.Example:Artifact")
        self.assertIsNone(canonical("Go", "example.org/../outside"))
        inventory = self.corpus()
        inventory["packages"][0]["manifest_sha256"] = "0" * 64
        with self.assertRaises(IntelligenceDenied):
            correlate(inventory, self.snapshot())
        inventory = self.corpus()
        inventory["manifests"][0]["bytes"] += 1
        with self.assertRaises(IntelligenceDenied):
            correlate(inventory, self.snapshot())


if __name__ == "__main__":
    unittest.main()
