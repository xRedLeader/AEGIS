"""Measured behavior of the fixed regex detector, including its known mistakes."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aegis_worker import ENGINE, MAX_CANDIDATES, MAX_FILE_BYTES, MAX_OUTPUT, RULES, review

CORPUS = Path(__file__).parent / "fixtures" / "detector-corpus.json"


class DetectorCoverageTests(unittest.TestCase):
    def test_synthetic_corpus_has_measured_denominators_and_known_errors(self):
        corpus = json.loads(CORPUS.read_text())
        self.assertEqual(corpus["engine_version"], ENGINE["version"])
        counts = {}
        rule_categories = {}
        observed_extensions = set()
        for case in corpus["cases"]:
            with self.subTest(case=case["id"]), tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / case["filename"]).write_bytes(case["source"].encode())
                result = review(tmp, 100, 4 * 1024 * 1024)
                actual = [candidate["id"] for candidate in result["candidates"]]
                self.assertEqual(actual, case["expected_rules"])
                self.assertEqual(result["coverage"]["assessment_status"], case["expected_assessment"])
                category = counts.setdefault(case["category"], {"fixtures": 0, "with_leads": 0, "without_leads": 0})
                category["fixtures"] += 1
                category["with_leads" if actual else "without_leads"] += 1
                for rid in case["expected_rules"]:
                    rule_categories.setdefault(rid, set()).add(case["category"])
                if actual:
                    observed_extensions.add(Path(case["filename"]).suffix)
                self.assertTrue(all(c["status"] == "unverified_static_lead" and "severity" not in c
                                    for c in result["candidates"]))
        self.assertEqual({name: value["fixtures"] for name, value in counts.items()},
                         {"vulnerable": 9, "safe_control": 9, "known_false_positive": 6,
                          "known_false_negative": 6, "unsupported": 6})
        self.assertEqual(set(rule_categories), {rule[0] for rule in RULES})
        self.assertEqual(observed_extensions, {".py", ".js", ".jsx", ".ts", ".tsx"})
        self.assertTrue(all({"vulnerable", "known_false_positive"} <= values for values in rule_categories.values()))
        print("DETECTOR CORPUS OBSERVATIONS:", json.dumps(counts, sort_keys=True))

    def test_supported_and_unsupported_files_are_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.PY").write_text("value = 1\n")
            (root / "app.cs").write_text("// eval(untrusted)\n")
            result = review(tmp, 20, 1024)
            coverage = result["coverage"]
            self.assertEqual(coverage["counts"]["assessed"], 1)
            self.assertEqual(coverage["counts"]["unsupported"], 1)
            self.assertEqual(coverage["assessment_status"], "incomplete")
            unsupported = next(item for item in coverage["files"] if item["status"] == "unsupported")
            self.assertEqual(unsupported["rule_ids"], [])
            self.assertNotIn("content_sha256", unsupported)
            assessed = next(item for item in coverage["files"] if item["status"] == "assessed")
            self.assertEqual(set(assessed["rule_ids"]), {rid for rid, _, _, applies in RULES if applies == ".py"})

    def test_source_and_ruleset_identity_are_deterministic_and_content_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "app.py"
            target.write_bytes(b"value = 1\n")
            first = review(tmp, 20, 1024)
            again = review(tmp, 20, 1024)
            self.assertEqual(first, again)
            self.assertEqual(first["coverage"]["files"][0]["content_sha256"], hashlib.sha256(target.read_bytes()).hexdigest())
            self.assertEqual(first["coverage"]["files"][0]["hash_scope"], "full_file")
            target.write_bytes(b"value = 2\n")
            changed = review(tmp, 20, 1024)
            self.assertNotEqual(first["coverage"]["source_identity"]["sha256"], changed["coverage"]["source_identity"]["sha256"])
            self.assertFalse(changed["coverage"]["source_identity"]["complete_repository"])
            self.assertEqual(first["coverage"]["engine"], changed["coverage"]["engine"])

    def test_partial_prefix_is_not_presented_as_full_file_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = b"#" + b"x" * MAX_FILE_BYTES + b"\neval(untrusted)\n"
            (Path(tmp) / "large.py").write_bytes(source)
            result = review(tmp, 20, 4 * 1024 * 1024)
            coverage = result["coverage"]
            self.assertEqual(result["candidates"], [])
            self.assertEqual(coverage["assessment_status"], "incomplete")
            self.assertIn("per_file_bytes", coverage["limits_hit"])
            self.assertEqual(coverage["files"][0]["hash_scope"], "prefix")
            self.assertEqual(coverage["files"][0]["content_sha256"], hashlib.sha256(source[:MAX_FILE_BYTES]).hexdigest())
            self.assertTrue(result["summary"]["truncated"])

    def test_file_and_byte_limits_leave_explicit_unassessed_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("a.py", "b.py"):
                (Path(tmp) / name).write_text("eval(untrusted)\n")
            limited = review(tmp, 1, 1024)["coverage"]
            self.assertIn("files", limited["limits_hit"])
            self.assertTrue(limited["remaining_entries_unknown"])
            self.assertEqual(limited["unrecorded_entries"], 1)
            short = review(tmp, 20, 4)
            self.assertIn("bytes", short["coverage"]["limits_hit"])
            self.assertEqual(short["summary"]["bytes_read"], 4)
            self.assertEqual(short["coverage"]["assessment_status"], "incomplete")

    def test_multiple_rules_on_one_line_never_overflow_candidate_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "app.py").write_text("eval(untrusted); pickle.loads(untrusted)\n" * 100)
            result = review(tmp, 20, 65536)
            self.assertEqual(len(result["candidates"]), MAX_CANDIDATES)
            self.assertIn("candidates", result["coverage"]["limits_hit"])
            self.assertEqual(result["coverage"]["files"][0]["status"], "partial")

    def test_evidence_limit_is_reported_without_oversized_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            for number in range(150):
                (Path(tmp) / ("unsupported_" + str(number).zfill(3) + ".java")).write_text("class Example {}\n")
            result = review(tmp, 1000, 4 * 1024 * 1024)
            self.assertLessEqual(len(json.dumps(result, separators=(",", ":")).encode()), MAX_OUTPUT)
            self.assertIn("evidence_bytes", result["coverage"]["limits_hit"])
            self.assertEqual(result["coverage"]["assessment_status"], "incomplete")
            self.assertGreater(result["coverage"]["unrecorded_entries"], 0)

    def test_excluded_links_directories_and_special_files_are_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            target = Path(tmp) / "outside.py"
            target.write_text("eval(untrusted)\n")
            (root / "link.py").symlink_to(target)
            os.link(target, root / "hard.py")
            os.mkfifo(root / "pipe.py")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "hidden.js").write_text("eval(untrusted)\n")
            result = review(str(root), 20, 1024)
            self.assertEqual(result["candidates"], [])
            self.assertEqual(result["summary"]["bytes_read"], 0)
            self.assertEqual(result["coverage"]["counts"]["excluded"], 4)
            self.assertEqual(result["coverage"]["assessment_status"], "incomplete")

    def test_unreadable_file_is_not_counted_as_assessed(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "blocked.py").write_text("eval(untrusted)\n")
            original = os.open
            def denied(path, flags, *args, **kwargs):
                if path == "blocked.py":
                    raise PermissionError("fixture denial")
                return original(path, flags, *args, **kwargs)
            with patch("aegis_worker.os.open", side_effect=denied):
                result = review(tmp, 20, 1024)
            self.assertEqual(result["coverage"]["counts"]["unreadable"], 1)
            self.assertEqual(result["coverage"]["counts"]["assessed"], 0)
            self.assertEqual(result["coverage"]["assessment_status"], "incomplete")

    def test_changed_file_is_rejected_and_read_bytes_still_charged(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "changing.py"
            before = b"eval(untrusted)\n"
            target.write_bytes(before)
            original = os.read
            def changed(fd, count):
                data = original(fd, count)
                target.write_bytes(b"short\n")
                return data
            with patch("aegis_worker.os.read", side_effect=changed):
                result = review(tmp, 20, 1024)
            self.assertEqual(result["candidates"], [])
            self.assertEqual(result["summary"]["bytes_read"], len(before))
            self.assertEqual(result["coverage"]["files"][0]["reason"], "unreadable_or_unstable_source")

    def test_encoding_failure_and_cut_multibyte_prefix_remain_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "app.py"
            target.write_bytes(b"\xff")
            invalid = review(tmp, 20, 1024)
            self.assertEqual(invalid["coverage"]["files"][0]["reason"], "invalid_utf8")
            target.write_bytes("€".encode())
            cut = review(tmp, 20, 1)
            self.assertEqual(cut["coverage"]["files"][0]["reason"], "source_byte_limit")
            self.assertEqual(cut["coverage"]["files"][0]["status"], "partial")

    def test_nonrepresentable_paths_and_invalid_limits_fail_honestly(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "space name.py").write_text("eval(untrusted)\n")
            result = review(tmp, 20, 1024)
            self.assertEqual(result["candidates"], [])
            self.assertEqual(result["coverage"]["files"][0]["reason"], "path_not_representable_in_canonical_report")
            for files, size in ((True, 100), (0, 100), (10, False), (10, 0)):
                with self.assertRaises(ValueError): review(tmp, files, size)
