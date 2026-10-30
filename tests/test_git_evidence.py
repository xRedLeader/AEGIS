"""Adversarial Git object storage and bounded subprocess evidence regressions."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import zlib

from aegis_git_evidence import _bounded_command, read_commit
from aegis_supervisor import ExecutionDenied


class GitEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="aegis-git-evidence-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git("init", "-q")
        (self.root/"nested").mkdir()
        (self.root/"one.txt").write_bytes(b"first\n")
        (self.root/"nested"/"two.txt").write_bytes(b"second\n")
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "Synthetic fixture")
        self.revision = self.git("rev-parse", "HEAD").decode().strip()

    def git(self, *args, data=None):
        env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
        return subprocess.run(["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-C", str(self.root), *args],
                              input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=True).stdout

    def object(self, kind, body):
        return self.git("hash-object", "--literally", "-t", kind, "-w", "--stdin", data=body).decode().strip()

    def overwrite(self, kind, oid, body):
        destination = self.root/".git"/"objects"/oid[:2]/oid[2:]
        destination.chmod(0o600)
        destination.write_bytes(zlib.compress(kind.encode()+b" "+str(len(body)).encode()+b"\0"+body))
        # Git does not itself rehash a loose object when reading it.
        self.assertEqual(self.git("cat-file", kind, oid), body)

    def commit_for_tree(self, tree):
        return self.object("commit", ("tree "+tree+"\nauthor Fixture <fixture@example.invalid> 1700000000 +0000\n"
                           "committer Fixture <fixture@example.invalid> 1700000000 +0000\n\nSynthetic fixture\n").encode())

    def test_exact_nested_and_selected_source_without_checkout(self):
        self.assertEqual(read_commit(self.root, self.revision), {"nested/two.txt": b"second\n", "one.txt": b"first\n"})
        (self.root/"one.txt").write_text("changed working tree")
        self.assertEqual(read_commit(self.root, self.revision, ["one.txt"]), {"one.txt": b"first\n"})
        self.git("gc", "--prune=now")
        self.assertEqual(read_commit(self.root, self.revision, ["nested/two.txt"]), {"nested/two.txt": b"second\n"})

    def test_corrupt_loose_commit_identity_is_rejected(self):
        body = self.git("cat-file", "commit", self.revision).replace(b"Synthetic", b"Corrupted")
        self.overwrite("commit", self.revision, body)
        with self.assertRaisesRegex(ExecutionDenied, "object hash"):
            read_commit(self.root, self.revision)

    def test_corrupt_root_and_nested_tree_identity_is_rejected(self):
        for target in ("HEAD^{tree}", "HEAD:nested"):
            with self.subTest(target=target):
                oid = self.git("rev-parse", target).decode().strip()
                original = self.git("cat-file", "tree", oid)
                body = original.replace(b"100644", b"100755", 1)
                self.overwrite("tree", oid, body)
                with self.assertRaisesRegex(ExecutionDenied, "object hash"):
                    read_commit(self.root, self.revision, ["nested/two.txt"])
                self.overwrite("tree", oid, original)

    def test_corrupt_blob_identity_is_rejected_even_when_length_matches(self):
        oid = self.git("rev-parse", "HEAD:one.txt").decode().strip()
        self.overwrite("blob", oid, b"false\n")
        with self.assertRaisesRegex(ExecutionDenied, "object hash"):
            read_commit(self.root, self.revision, ["one.txt"])

    def test_only_selected_tree_branches_are_read(self):
        oid = self.git("rev-parse", "HEAD:nested").decode().strip()
        self.overwrite("tree", oid, self.git("cat-file", "tree", oid).replace(b"100644", b"100755"))
        self.assertEqual(read_commit(self.root, self.revision, ["one.txt"]), {"one.txt": b"first\n"})

    def test_file_total_and_inventory_bounds(self):
        for kwargs in ({"maximum_file": 5}, {"maximum_total": 12}, {"paths": ["missing.txt"]},
                       {"paths": ["nested"]}, {"paths": ["one.txt", "one.txt"]}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ExecutionDenied):
                read_commit(self.root, self.revision, **kwargs)
        blob = self.git("rev-parse", "HEAD:one.txt").decode().strip()
        tree = self.object("tree", b"".join(b"100644 "+str(i).encode()+b"\0"+bytes.fromhex(blob) for i in range(513)))
        with self.assertRaisesRegex(ExecutionDenied, "inventory exceeds"):
            read_commit(self.root, self.commit_for_tree(tree))

    def test_metadata_and_depth_bounds(self):
        blob = self.git("rev-parse", "HEAD:one.txt").decode().strip()
        tree = self.object("tree", b"100644 leaf\0"+bytes.fromhex(blob))
        for _ in range(64):
            tree = self.object("tree", b"40000 d\0"+bytes.fromhex(tree))
        with self.assertRaisesRegex(ExecutionDenied, "traversal exceeds"):
            read_commit(self.root, self.commit_for_tree(tree))
        tree = self.object("tree", b"100644 x\0"+bytes.fromhex(blob))
        commit = self.git("cat-file", "commit", self.commit_for_tree(tree))+b"x"*65536
        with self.assertRaisesRegex(ExecutionDenied, "output exceeds"):
            read_commit(self.root, self.object("commit", commit))

    def test_promisor_configuration_is_rejected_without_fetching(self):
        self.git("config", "remote.origin.promisor", "true")
        self.git("config", "remote.origin.url", "https://example.invalid/do-not-contact")
        with self.assertRaises(ExecutionDenied):
            read_commit(self.root, self.revision)

    def test_unselected_hooks_filters_and_replacements_do_not_run(self):
        marker = self.root/"MUST_NOT_EXIST"
        hook = self.root/".git"/"hooks"/"post-checkout"
        hook.write_text("#!/bin/sh\ntouch '"+str(marker)+"'\n")
        hook.chmod(0o700)
        self.git("config", "filter.hostile.smudge", "touch '"+str(marker)+"'")
        (self.root/".gitattributes").write_text("*.txt filter=hostile\n")
        self.git("replace", self.revision, self.commit_for_tree(self.object("tree", b"")))
        self.assertEqual(read_commit(self.root, self.revision, ["one.txt"]), {"one.txt": b"first\n"})
        self.assertFalse(marker.exists())


class BoundedGitCommandTests(unittest.TestCase):
    def command(self, script, *, maximum=1024, data=None, seconds=2, guard=lambda: None):
        return _bounded_command([sys.executable, "-I", "-S", "-c", script], {"PATH": "/usr/bin:/bin"},
                                maximum=maximum, deadline=time.monotonic()+seconds, guard=guard, data=data)

    def test_flood_is_stopped_before_output_accumulates(self):
        with self.assertRaisesRegex(ExecutionDenied, "output exceeds"):
            self.command("import os\nwhile True: os.write(1, b'x'*65536)")

    def test_input_and_output_are_drained_concurrently(self):
        data = b"x"*262144
        output = self.command("import os,sys\nos.write(1,b'y'*262144)\nprint(len(sys.stdin.buffer.read()))",
                              maximum=len(data)+32, data=data)
        self.assertEqual(output, b"y"*262144+b"262144\n")

    def test_deadline_and_guard_interrupt_silent_child(self):
        with self.assertRaisesRegex(ExecutionDenied, "timed out"):
            self.command("import time; time.sleep(30)", seconds=0.1)
        calls = 0
        def stop():
            nonlocal calls
            calls += 1
            if calls > 4:
                raise ExecutionDenied("revoked")
        with self.assertRaisesRegex(ExecutionDenied, "revoked"):
            self.command("import time; time.sleep(30)", guard=stop)


if __name__ == "__main__":
    unittest.main()
