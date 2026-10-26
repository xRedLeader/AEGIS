#!/usr/bin/env python3
"""AEGIS 1.3.1 operator-side, externally anchored audit checkpoints.

An audit checkpoint is signed by a SEPARATE operator Ed25519 private key. Store
it outside the supervisor state/host, and pin the independent public key. This
module cannot protect a signing key or destination on a compromised host.

The supervisor's hash chain alone is not tamper-evident against an attacker who
can rewrite the whole SQLite database; an independently retained signed anchor
allows detecting rewriting or removal of the anchored prefix.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

AUDIT_CONTEXT = b'AEGIS-audit-checkpoint-v1\x00'
GENESIS = '0' * 64
HEX_64 = re.compile(r'^[0-9a-f]{64}$')
MAX_CHECKPOINT_BYTES = 4096


class AuditError(ValueError):
    pass


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')


def verify_rows(rows) -> tuple[int, str, dict[int, str]]:
    """Verify strict sequence continuity and the full hash chain."""
    previous = GENESIS
    by_sequence = {0: GENESIS}
    expected_seq = 1
    for seq, event, declared_prev, digest in rows:
        if type(seq) is not int or seq != expected_seq:
            raise AuditError('audit sequence contains gaps, duplicates or reordering')
        if not isinstance(event, str) or not isinstance(declared_prev, str) or not isinstance(digest, str):
            raise AuditError('audit has invalid column types')
        if declared_prev != previous or not HEX_64.fullmatch(digest):
            raise AuditError('audit hash chain disconnected or malformed')
        recomputed = hashlib.sha256((previous + '\n' + event).encode()).hexdigest()
        if digest != recomputed:
            raise AuditError('audit event digest mismatch')
        by_sequence[seq] = digest
        previous = digest
        expected_seq += 1
    return expected_seq - 1, previous, by_sequence


def read_ledger(state_root: Path) -> tuple[str, int, str, dict[int, str]]:
    """Read a trusted snapshot; requires the ledger created by v1.3.1 supervisor."""
    path = Path(state_root) / 'ledger.sqlite3'
    if not path.is_file() or path.is_symlink():
        raise AuditError('audit ledger missing or symlinked')
    try:
        # Immutable snapshots can be passed to this command on an offline
        # auditor; for live databases use SQLite read-only locking semantics.
        from urllib.parse import quote
        uri = 'file:' + quote(str(path.resolve()), safe='/') + '?mode=ro'
        with closing(sqlite3.connect(uri, uri=True, timeout=5)) as con:
            con.execute('BEGIN')
            ident_rows = con.execute("SELECT value FROM ledger_meta WHERE name='ledger_id'").fetchall()
            rows = con.execute('SELECT seq,event,previous_hash,digest FROM audit ORDER BY seq').fetchall()
            con.commit()
    except sqlite3.Error as exc:
        raise AuditError(f'cannot read protected audit ledger: {exc}') from exc
    if len(ident_rows) != 1 or not isinstance(ident_rows[0][0], str):
        raise AuditError('ledger identity missing')
    ledger_id = ident_rows[0][0]
    try:
        if str(uuid.UUID(ledger_id)) != ledger_id:
            raise ValueError('noncanonical UUID')
    except ValueError as exc:
        raise AuditError('ledger identity invalid') from exc
    count, head, by_sequence = verify_rows(rows)
    return ledger_id, count, head, by_sequence


def _validate_payload(payload: object) -> dict:
    if not isinstance(payload, dict) or set(payload) != {
        'format', 'ledger_id', 'sequence', 'head_sha256', 'created_utc'
    }:
        raise AuditError('checkpoint payload has missing or extra fields')
    if payload['format'] != 'AEGIS-audit-checkpoint-v1':
        raise AuditError('unsupported checkpoint format')
    if type(payload['sequence']) is not int or payload['sequence'] < 1:
        raise AuditError('checkpoint must cover at least one event')
    if not isinstance(payload['ledger_id'], str):
        raise AuditError('checkpoint ledger ID invalid')
    try:
        if str(uuid.UUID(payload['ledger_id'])) != payload['ledger_id']:
            raise ValueError('noncanonical UUID')
    except ValueError as exc:
        raise AuditError('checkpoint ledger ID malformed') from exc
    if not isinstance(payload['head_sha256'], str) or not HEX_64.fullmatch(payload['head_sha256']):
        raise AuditError('checkpoint digest invalid')
    if not isinstance(payload['created_utc'], str):
        raise AuditError('checkpoint timestamp invalid')
    try:
        datetime.strptime(payload['created_utc'], '%Y-%m-%dT%H:%M:%SZ')
    except ValueError as exc:
        raise AuditError('checkpoint must contain canonical UTC timestamp') from exc
    return payload


def create_checkpoint(state_root: Path, key_path: Path, output: Path) -> dict:
    """Operator action; never make this command available to the AI worker."""
    state_root = Path(state_root).resolve(strict=True)
    output = Path(output).absolute()
    if output == state_root or state_root in output.parents:
        raise AuditError('checkpoint must be outside protected runtime state')
    if not output.parent.is_dir() or output.is_symlink():
        raise AuditError('checkpoint output parent missing or output is symlinked')
    key = load_pem_private_key(Path(key_path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise AuditError('audit signing key must be Ed25519')
    ledger_id, seq, digest, _ = read_ledger(state_root)
    if seq < 1:
        raise AuditError('cannot anchor an empty audit')
    payload = _validate_payload({
        'format': 'AEGIS-audit-checkpoint-v1', 'ledger_id': ledger_id,
        'sequence': seq, 'head_sha256': digest,
        'created_utc': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    })
    signature = key.sign(AUDIT_CONTEXT + _canonical(payload))
    bundle = {'payload': payload, 'signature_hex': signature.hex()}
    blob = _canonical(bundle) + b'\n'
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        try:
            os.unlink(output)
        except OSError:
            pass
        raise
    return {'status': 'SIGNED_CHECKPOINT_CREATED', **payload, 'checkpoint': str(output)}


def verify_checkpoint(state_root: Path, checkpoint: Path, public_key: Path) -> dict:
    """Detect rewriting or truncation of an externally anchored audit prefix."""
    file_size = Path(checkpoint).stat().st_size
    if file_size > MAX_CHECKPOINT_BYTES:
        raise AuditError('checkpoint exceeds maximum size')
    raw = Path(checkpoint).read_bytes()
    if len(raw) > MAX_CHECKPOINT_BYTES:
        raise AuditError('checkpoint exceeds maximum size')
    try:
        bundle = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AuditError('checkpoint is not valid JSON') from exc
    if not isinstance(bundle, dict) or set(bundle) != {'payload', 'signature_hex'}:
        raise AuditError('checkpoint record malformed')
    payload = _validate_payload(bundle['payload'])
    signature_hex = bundle['signature_hex']
    if not isinstance(signature_hex, str) or len(signature_hex) != 128:
        raise AuditError('checkpoint signature malformed')
    try:
        signature = bytes.fromhex(signature_hex)
        key = load_pem_public_key(Path(public_key).read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise AuditError('audit verification key must be Ed25519')
        key.verify(signature, AUDIT_CONTEXT + _canonical(payload))
    except (InvalidSignature, ValueError) as exc:
        raise AuditError('checkpoint signature invalid') from exc
    ledger_id, seq, digest, by_sequence = read_ledger(state_root)
    if payload['ledger_id'] != ledger_id:
        raise AuditError('checkpoint bound to a different ledger identity')
    if seq < payload['sequence']:
        raise AuditError('audit ledger truncated below signed checkpoint')
    if by_sequence[payload['sequence']] != payload['head_sha256']:
        raise AuditError('audit history diverges from independently signed checkpoint')
    return {
        'status': 'AUDIT_ANCHOR_VERIFIED', 'ledger_id': ledger_id,
        'anchored_sequence': payload['sequence'], 'current_sequence': seq,
        'current_head_sha256': digest,
        'unanchored_events': seq - payload['sequence'],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description='AEGIS independent audit checkpoint utility; operator-only')
    sub = ap.add_subparsers(dest='command', required=True)
    p = sub.add_parser('create', help='Sign current verified head using offline operator key')
    p.add_argument('--state-root', required=True, type=Path)
    p.add_argument('--private-key', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p = sub.add_parser('verify', help='Check an independently retained signed checkpoint')
    p.add_argument('--state-root', required=True, type=Path)
    p.add_argument('--checkpoint', required=True, type=Path)
    p.add_argument('--public-key', required=True, type=Path)
    args = ap.parse_args(argv)
    try:
        if args.command == 'create':
            result = create_checkpoint(args.state_root, args.private_key, args.output)
        else:
            result = verify_checkpoint(args.state_root, args.checkpoint, args.public_key)
        print(json.dumps(result, indent=2))
        return 0
    except (AuditError, OSError, ValueError, TypeError, sqlite3.Error) as exc:
        print('DENIED: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
