#!/usr/bin/env python3
"""Check AEGIS versioned canonical findings JSON against its matching schema.

Schema validation establishes structure, not evidence authenticity, signer
identity, production impact or ownership of the enclosing package.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
from jsonschema import Draft202012Validator


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("findings", type=Path)
    args = parser.parse_args()
    try:
        if args.findings.stat().st_size > 65536:
            raise ValueError("report exceeds 64 KiB")
        report = json.loads(args.findings.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            raise ValueError("report must be a JSON object")
        version = report.get("schema_version")
        if type(version) is not int or version not in (1, 2):
            raise ValueError("unsupported canonical schema version")
        filename = "findings.schema.json" if version == 1 else "findings-v2.schema.json"
        schema = json.loads((Path(__file__).resolve().parent / filename).read_text(encoding="utf-8"))
        problems = list(Draft202012Validator(schema).iter_errors(report))
        if problems:
            for error in problems[:10]:
                print(f"INVALID {'.'.join(map(str, error.path))}: {error.message}", file=sys.stderr)
            return 2
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        print(f"INVALID: {type(exc).__name__}", file=sys.stderr)
        return 2
    print(f"VALID v{version} findings: {len(report['findings'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
