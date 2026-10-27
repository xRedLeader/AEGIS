"""Fixed, bounded synthetic local contracts shared by trusted parent and jailed tester.

No dynamic imports, target-controlled schemas, file access, networking, or execution.
These contracts establish *local invariant mismatches*, not deployed exploitation.
"""
from __future__ import annotations

import hashlib
import json
import random

CONTRACTS = frozenset({"strict_tenant_owner_v1", "json_resource_access_v1",
                       "versioned_cas_v1"})


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      allow_nan=False, separators=(",", ":"))


def case_digest(fixtures):
    return hashlib.sha256(canonical(fixtures).encode("ascii")).hexdigest()


def _json_cases(seed: int, count: int):
    # All values are synthetic. Unexpected fields, types, and encodings are
    # deliberate checks of an operator-declared exact-object contract.
    fixtures = [
        {"actor": "tenant-a", "owner": "tenant-a", "operation": "read"},
        {"actor": "tenant-a", "owner": "tenant-b", "operation": "read"},
        {"actor": "TENANT-A", "owner": "tenant-a", "operation": "read"},
        {"actor": "", "owner": "", "operation": "read"},
        {"actor": None, "owner": None, "operation": "read"},
        {"actor": 0, "owner": "0", "operation": "read"},
        {"actor": True, "owner": 1, "operation": "read"},
        {"actor": "a/b", "owner": "a//b", "operation": "read"},
        {"actor": "tenant-a", "owner": "tenant-a", "operation": "write"},
        {"actor": "tenant-a", "owner": "tenant-a", "operation": "Read"},
        {"actor": "tenant-a", "owner": "tenant-a", "operation": "read", "admin": True},
        {"actor": "tenant-a", "owner": "tenant-a"},
        {"actor": ["tenant-a"], "owner": "tenant-a", "operation": "read"},
        {"actor": {"id": "tenant-a"}, "owner": "tenant-a", "operation": "read"},
        {"actor": "../../a", "owner": "a", "operation": "read"},
        {"actor": "a\u0000x", "owner": "a", "operation": "read"},
        {"actor": "a\u00e9", "owner": "ae", "operation": "read"},
        {"actor": "tenant-a ", "owner": "tenant-a", "operation": "read"},
    ]
    rng = random.Random(seed ^ 0xAE6150)
    alphabet = "abcxyz0123456789-_/"
    while len(fixtures) < count:
        actor = "synthetic-" + "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 18)))
        owner = actor if rng.randrange(4) == 0 else (actor.upper() if rng.randrange(3) == 0 else
            "synthetic-" + "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 18))))
        fixtures.append({"actor": actor, "owner": owner,
                         "operation": "read" if rng.randrange(6) != 0 else "write"})
    return fixtures[:count]


def _cas_cases(seed: int, count: int):
    # Sequential interleavings model stale reads and retries, not genuine
    # simultaneous OS scheduling. Each step is one synthetic caller action.
    fixtures = [
        {"initial": {"version": 0, "value": 0}, "steps": [{"version": 0, "delta": 1}, {"version": 0, "delta": 1}]},
        {"initial": {"version": 1, "value": 0}, "steps": [{"version": 1, "delta": 1}, {"version": 2, "delta": 1}]},
        {"initial": {"version": 1, "value": 0}, "steps": [{"version": 0, "delta": 1}, {"version": 1, "delta": 1}]},
        {"initial": {"version": 5, "value": 2}, "steps": [{"version": 5, "delta": 1}, {"version": 5, "delta": 1}, {"version": 6, "delta": 1}]},
        {"initial": {"version": 1, "value": 0}, "steps": [{"version": True, "delta": 1}]},
        {"initial": {"version": 1, "value": 0}, "steps": [{"version": "1", "delta": 1}]},
        {"initial": {"version": 1, "value": 0}, "steps": [{"version": 1, "delta": 0}]},
        {"initial": {"version": 1, "value": 0}, "steps": [{"version": 1, "delta": -1}]},
        {"initial": {"version": 1, "value": 0}, "steps": [{"version": 1, "delta": 2}]},
        {"initial": {"version": 1, "value": 0}, "steps": [{"version": 1, "delta": True}]},
        {"initial": {"version": 10, "value": 0}, "steps": [{"version": 10, "delta": 1}, {"version": 10, "delta": 1}]},
        {"initial": {"version": 2, "value": 3}, "steps": [{"version": None, "delta": 1}]},
        {"initial": {"version": 2, "value": 3}, "steps": [{"version": 2, "delta": None}]},
        {"initial": {"version": 2, "value": 3}, "steps": [{"version": 2, "delta": 1}, {"version": 3, "delta": 1}, {"version": 2, "delta": 1}]},
        {"initial": {"version": 0, "value": 0}, "steps": [{"version": 0, "delta": 1}, {"version": 0, "delta": 1}, {"version": 1, "delta": 1}]},
        {"initial": {"version": 8, "value": 7}, "steps": [{"version": 9, "delta": 1}, {"version": 8, "delta": 1}]},
    ]
    rng = random.Random(seed ^ 0xCA5107)
    while len(fixtures) < count:
        version = rng.randrange(0, 20)
        steps = [{"version": version, "delta": 1},
                 {"version": version if rng.randrange(2) else version + 1, "delta": 1}]
        if rng.randrange(3) == 0:
            steps.append({"version": version + 1, "delta": 1})
        if rng.randrange(2) == 0:
            steps.reverse()
        fixtures.append({"initial": {"version": version, "value": rng.randrange(0, 20)},
                         "steps": steps})
    return fixtures[:count]


def fixtures(contract: str, seed: int, count: int):
    if contract == "json_resource_access_v1":
        return _json_cases(seed, count)
    if contract == "versioned_cas_v1":
        return _cas_cases(seed, count)
    raise ValueError("unrecognized local contract")


def oracle(contract: str, fixture):
    if contract == "json_resource_access_v1":
        return (type(fixture) is dict and set(fixture) == {"actor", "owner", "operation"}
                and fixture["operation"] == "read" and
                type(fixture["actor"]) is str and bool(fixture["actor"]) and
                type(fixture["owner"]) is str and fixture["actor"] == fixture["owner"])
    if contract == "versioned_cas_v1":
        state = dict(fixture["initial"])
        decisions = []
        for step in fixture["steps"]:
            permitted = (type(step["version"]) is int and step["version"] == state["version"]
                         and type(step["delta"]) is int and step["delta"] == 1)
            decisions.append(permitted)
            if permitted:
                state["version"] += 1
                state["value"] += 1
        return {"decisions": decisions, "state": state}
    raise ValueError("unrecognized local contract")


def safe_observation(contract: str, value):
    """Validate only small, synthetic types. Never serialize target exceptions."""
    if contract == "json_resource_access_v1":
        return type(value) is bool
    if contract == "versioned_cas_v1":
        return (type(value) is dict and set(value) == {"decisions", "state"} and
                type(value["decisions"]) is list and 1 <= len(value["decisions"]) <= 3 and
                all(type(d) is bool for d in value["decisions"]) and
                type(value["state"]) is dict and set(value["state"]) == {"version", "value"} and
                all(type(v) is int and 0 <= v <= 100000
                    for v in value["state"].values()))
    return False
