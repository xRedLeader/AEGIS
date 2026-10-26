"""Independent signed audit-anchor tests including full hash-chain forgery."""
from __future__ import annotations

import hashlib
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from aegis_audit import AuditError, create_checkpoint, read_ledger, verify_checkpoint
from aegis_supervisor import ExecutionDenied


class AuditAnchorTests(unittest.TestCase):
    def setUp(self):
        from test_runtime import AegisRuntimeTests
        self.fixture = AegisRuntimeTests('test_real_readonly_review_and_canonical_artifact')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fx = self.fixture.fx
        self.state = self.fixture.state
        self.fixture.supervisor().scan(self.fx.repo, 5)
        self.private = self.fx.p / 'audit-private.pem'
        self.public = self.fx.p / 'audit-public.pem'
        self.checkpoint = self.fx.p / 'external-checkpoints' / 'first.anchor.json'
        self.checkpoint.parent.mkdir(mode=0o700)
        key = Ed25519PrivateKey.generate()
        self.private.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        self.public.write_bytes(key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        self.private.chmod(0o600)

    def anchor(self):
        return create_checkpoint(self.state, self.private, self.checkpoint)

    def test_signed_checkpoint_matches_verified_ledger(self):
        made = self.anchor()
        result = verify_checkpoint(self.state, self.checkpoint, self.public)
        self.assertEqual(result['status'], 'AUDIT_ANCHOR_VERIFIED')
        self.assertEqual(result['unanchored_events'], 0)
        self.assertGreaterEqual(result['anchored_sequence'], 2)
        self.assertEqual(made['head_sha256'], result['current_head_sha256'])

    def test_legitimate_appended_events_do_not_invalidate_earlier_checkpoint(self):
        self.anchor()
        self.fixture.supervisor().scan(self.fx.repo, 5)
        v = verify_checkpoint(self.state, self.checkpoint, self.public)
        self.assertEqual(v['unanchored_events'], 2)

    def test_fully_rewritten_hash_chain_is_detected_by_signed_anchor(self):
        self.anchor()
        with closing(sqlite3.connect(self.state / 'ledger.sqlite3')) as con, con:
            items = con.execute('SELECT seq,event FROM audit ORDER BY seq').fetchall()
            old = '0' * 64
            for seq, event in items:
                altered = json.loads(event)
                altered['fake_rewritten_event'] = seq
                forged_event = json.dumps(altered, sort_keys=True, separators=(',', ':'))
                forged_digest = hashlib.sha256((old+'\n'+forged_event).encode()).hexdigest()
                con.execute('UPDATE audit SET event=?,previous_hash=?,digest=? WHERE seq=?',
                            (forged_event, old, forged_digest, seq))
                old = forged_digest
            con.commit()
        # The LOCAL chain is self-consistent, demonstrating the exact weakness
        # in a self-hashed SQLite ledger. The off-box signed prefix detects it.
        self.assertTrue(self.fixture.supervisor().verify_audit_chain())
        with self.assertRaisesRegex(AuditError, 'diverges'):
            verify_checkpoint(self.state, self.checkpoint, self.public)

    def test_truncated_history_denied(self):
        self.anchor()
        with closing(sqlite3.connect(self.state / 'ledger.sqlite3')) as con, con:
            con.execute('DELETE FROM audit WHERE seq >= 2')
        with self.assertRaisesRegex(AuditError, 'truncated'):
            verify_checkpoint(self.state, self.checkpoint, self.public)

    def test_altered_checkpoint_signature_denied(self):
        self.anchor()
        tampered = json.loads(self.checkpoint.read_text())
        tampered['payload']['head_sha256'] = '1' * 64
        self.checkpoint.write_text(json.dumps(tampered))
        with self.assertRaisesRegex(AuditError, 'signature invalid'):
            verify_checkpoint(self.state, self.checkpoint, self.public)

    def test_wrong_public_key_denied(self):
        self.anchor()
        another = Ed25519PrivateKey.generate().public_key()
        wrong_pub = self.fx.p / 'wrong-public.pem'
        wrong_pub.write_bytes(another.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        with self.assertRaisesRegex(AuditError, 'signature invalid'):
            verify_checkpoint(self.state, self.checkpoint, wrong_pub)

    def test_missing_or_empty_ledger_cannot_be_anchored(self):
        empty = self.fx.p / 'empty-state'
        empty.mkdir(mode=0o700)
        with self.assertRaisesRegex(AuditError, 'missing'):
            create_checkpoint(empty, self.private, self.fx.p / 'unused.json')

    def test_checkpoint_cannot_be_written_in_runtime_state(self):
        with self.assertRaisesRegex(AuditError, 'outside protected runtime state'):
            create_checkpoint(self.state, self.private, self.state / 'anchor.json')

    def test_existing_checkpoint_cannot_be_overwritten(self):
        self.anchor()
        with self.assertRaises(FileExistsError):
            self.anchor()

    def test_gap_detected_and_new_action_denied(self):
        with closing(sqlite3.connect(self.state / 'ledger.sqlite3')) as con, con:
            con.execute('DELETE FROM audit WHERE seq=1')
        self.assertFalse(self.fixture.supervisor().verify_audit_chain())
        with self.assertRaisesRegex(ExecutionDenied, 'audit integrity'):
            self.fixture.supervisor().scan(self.fx.repo, 5)

    def test_ledger_id_cannot_change_after_anchor(self):
        self.anchor()
        with closing(sqlite3.connect(self.state / 'ledger.sqlite3')) as con, con:
            con.execute("UPDATE ledger_meta SET value='a5cc7f5a-f797-40c8-ae28-cbaaa17423f2' WHERE name='ledger_id'")
        with self.assertRaisesRegex(AuditError, 'different ledger identity'):
            verify_checkpoint(self.state, self.checkpoint, self.public)

    def test_create_does_not_modify_audit_ledger(self):
        before = read_ledger(self.state)
        self.anchor()
        after = read_ledger(self.state)
        self.assertEqual(before, after)


if __name__ == '__main__':
    unittest.main()
