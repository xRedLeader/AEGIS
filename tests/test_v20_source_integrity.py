"""Reproducible tracked-file SHA-256 manifest and path-integrity checks."""
import hashlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from aegis_source_integrity import SourceIntegrityError, verify


class TrackedSourceTests(unittest.TestCase):
    def test_exact_manifest_and_tampering_fail_closed(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            (root/'tests').mkdir()
            p = root/'tests'/'one.py'
            p.write_bytes(b'print(1)\n')
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
            (root/'SHA256SUMS.txt').write_text(digest+'  tests/one.py\n',encoding='ascii')
            tracked = {'tests/one.py','SHA256SUMS.txt'}
            self.assertEqual(verify(root,tracked)['verified_files'],1)
            p.write_bytes(b'print(2)\n')
            with self.assertRaises(SourceIntegrityError):verify(root,tracked)
            p.write_bytes(b'print(1)\n')
            with self.assertRaises(SourceIntegrityError):verify(root,tracked|{'unexpected.py'})
            (root/'SHA256SUMS.txt').write_text(digest+'  tests/../tests/one.py\n',encoding='ascii')
            with self.assertRaises(SourceIntegrityError):verify(root,tracked)

    def test_symlink_and_duplicate_paths_are_denied(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            origin = root/'original.py'
            origin.write_bytes(b'x')
            (root/'link.py').symlink_to(origin)
            digest=hashlib.sha256(b'x').hexdigest()
            manifest=root/'SHA256SUMS.txt'
            manifest.write_text(digest+'  link.py\n')
            with self.assertRaises(SourceIntegrityError):verify(root,{'link.py','SHA256SUMS.txt'})
            manifest.write_text(digest+'  original.py\n'+digest+'  original.py\n')
            with self.assertRaises(SourceIntegrityError):verify(root,{'original.py','SHA256SUMS.txt'})

if __name__ == '__main__':unittest.main()
