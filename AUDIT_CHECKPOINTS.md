# Independently verifiable audit checkpoints (v1.3.1)

**Purpose:** The supervisor's SQLite hash chain can detect individual row changes but cannot detect a wholesale rewrite when all hashes are recomputed. An operator-held Ed25519 signature over an earlier head gives a separate reference for detecting tampering of the signed history.

## Trusted operator workflow

1. Generate a **separate audit key pair** using `python aegis_admin.py keygen --private /secure/operator/audit-private.pem --public /secure/operator/audit-public.pem` on an operator-controlled system. Do not reuse the scope-signing key. Never give the signing private key to AEGIS, its scanner, the target repository, or an AI orchestrator.
2. Obtain a consistent copy of the protected SQLite ledger or run this command in a tightly controlled operator maintenance session with access to the protected state. `aegis_audit.py create` validates the full chain before signing, then writes a new checkpoint file **outside** the runtime state. For a remote signing host, transfer an authenticated ledger snapshot and run the same command there. The operator must establish snapshot provenance; this package does not provide transport or remote attestation.
3. Immediately copy the checkpoint to an operator-controlled **independent host or immutable store**. Pin the audit verification public key independently, and restrict checkpoint deletion/rewriting. Keep historical checkpoints.
4. Verify with the independently pinned key after every assessment and on a regular external schedule. Investigate missing, stale, or mismatched checkpoints. Signing frequency and acceptable detection delay are operational policies; this package does not schedule them.

Example commands on a trusted operator host using protected or securely replicated state:

```bash
python aegis_audit.py create \
  --state-root /var/lib/aegis/protected-state \
  --private-key /secure/operator/audit-private.pem \
  --output /secure/operator/checkpoints/engagement-2026-10-26.anchor.json

python aegis_audit.py verify \
  --state-root /var/lib/aegis/protected-state \
  --checkpoint /secure/operator/checkpoints/engagement-2026-10-26.anchor.json \
  --public-key /secure/operator/audit-public.pem
```

The verification result includes `anchored_sequence` and `unanchored_events`. A passing result **does not** establish authenticity of the entire unanchored suffix or protect against an attacker who compromises the signing key and checkpoint store. The independent store/public-key provisioning must be enforced outside AEGIS. The signing command should never be callable by an AI assessment worker.

Do not treat `python aegis_supervisor.py ... audit` as independent anchoring: that command only checks the self-consistency of the local hash chain.
