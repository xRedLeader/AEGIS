#!/usr/bin/env python3
"""Check canonical findings.json against the shipped schema; exit nonzero if invalid."""

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
        report = json.loads(args.findings.read_text(encoding="utf-8"))
        schema = json.loads((Path(__file__).resolve().parent / "findings.schema.json").read_text(encoding="utf-8"))
        problems = list(Draft202012Validator(schema).iter_errors(report))
        if problems:
            for error in problems[:10]:
                print(f"INVALID {'.'.join(map(str, error.path))}: {error.message}", file=sys.stderr)
            return 2
    except (OSError, ValueError) as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 2
    print(f"VALID findings: {len(report['findings'])}; observed controls: {len(report['control_observations'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
