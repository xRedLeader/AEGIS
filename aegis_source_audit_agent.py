"""Sign a bounded source-research reply; model input never includes signing keys."""
import argparse
import base64
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from aegis_agent_client import _private_file
from aegis_audit_contract import canonical, decode, digest, require, read_relative
from aegis_audit_coordinator import SIGNING_CONTEXT
from aegis_supervisor import ExecutionDenied, open_directory_nofollow


def sign_reply(assignment, result, key):
    unsigned = {k: v for k, v in assignment.items() if k != "assignment_id"}
    require(assignment["assignment_id"] == digest(unsigned), "assignment integrity mismatch")
    require(isinstance(key, Ed25519PrivateKey), "research signer must be Ed25519")
    require(isinstance(result, dict) and len(canonical(result)) <= 16384, "unbounded research reply")
    record = {"assignment_id": assignment["assignment_id"], "agent_id": assignment["agent_id"], "result": result}
    return {**record, "signature": base64.b64encode(key.sign(SIGNING_CONTEXT + canonical(record))).decode("ascii")}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assignment", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        require(args.assignment.is_absolute(), "assignment path must be absolute")
        with open_directory_nofollow(args.assignment.parent) as parent:
            assignment = decode(read_relative(parent, args.assignment.name, 131072), 131072)
        result = decode(sys.stdin.buffer.read(16385), 16384)
        key = load_pem_private_key(_private_file(args.key), password=None)
        print(canonical(sign_reply(assignment, result, key)).decode("ascii"))
        return 0
    except (ExecutionDenied, ValueError, OSError, TypeError, KeyError) as exc:
        print("DENIED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
