#!/usr/bin/env python3
"""Fixed offline dependency inventory worker; operates ONLY inside AEGIS's source jail.

No target code, install scripts, package managers, network, shell, or external tools
are executed. Only two root manifests are read through no-follow file descriptors.
Only bounded package coordinates are returned; no raw manifest lines/URLs/secrets.
"""
from __future__ import annotations
import json
import os
import re
import stat
import sys

O_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
O_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
MAX_REQUIREMENTS = 512 * 1024
MAX_LOCKFILE = 4 * 1024 * 1024
MAX_COORDS = 150
PIP_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
PIP_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.!+_-]{0,79}\Z")
NPM_NAME = re.compile(r"(?:@[a-z0-9_.-]{1,80}/)?[a-z0-9_.-]{1,100}\Z")
NPM_VERSION = re.compile(r"[0-9][0-9A-Za-z.!+_-]{0,79}\Z")


def read_regular(dirfd: int, filename: str, maximum: int) -> bytes | None:
    try:
        fd = os.open(filename, O_FILE, dir_fd=dirfd)
    except FileNotFoundError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > maximum or st.st_size < 0:
            raise ValueError("invalid dependency manifest type or size")
        data = os.read(fd, maximum + 1)
        if len(data) > maximum:
            raise ValueError("dependency manifest exceeds bounded parser limit")
        return data
    finally:
        os.close(fd)


def inventory(repo: str = "/repo") -> dict:
    if repo != "/repo":
        raise ValueError("worker may only inspect its read-only /repo mount")
    dirfd = os.open(repo, O_DIR)
    packages = []
    skipped = 0
    present = []
    truncated = False
    try:
        raw = read_regular(dirfd, "requirements.txt", MAX_REQUIREMENTS)
        if raw is not None:
            present.append("requirements.txt")
            for line in raw.decode("utf-8", errors="replace").splitlines():
                # Markers, URL requirements, options and ranges are unresolved,
                # never misrepresented as an installed exact version.
                entry = line.split("#", 1)[0].strip()
                if not entry or entry.startswith("#"):
                    continue
                if entry.count("==") != 1:
                    skipped += 1
                    continue
                name, version = (piece.strip() for piece in entry.split("=="))
                if not PIP_NAME.fullmatch(name) or not PIP_VERSION.fullmatch(version):
                    skipped += 1
                    continue
                if len(packages) >= MAX_COORDS:
                    truncated = True
                    break
                packages.append({"ecosystem": "PyPI", "name": re.sub(r"[-_.]+", "-", name).lower(),
                                 "version": version, "source": "requirements.txt", "classification": "declared_pin_not_verified_installed"})
        raw = read_regular(dirfd, "package-lock.json", MAX_LOCKFILE)
        if raw is not None:
            present.append("package-lock.json")
            try:
                obj = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid numeric constant")))
            except (ValueError, UnicodeDecodeError):
                raise ValueError("malformed package-lock.json") from None
            if not isinstance(obj, dict) or obj.get("lockfileVersion") not in (2, 3) or not isinstance(obj.get("packages"), dict):
                raise ValueError("unsupported lockfile; requires npm lockfileVersion 2 or 3")
            for location, record in sorted(obj["packages"].items()):
                if not isinstance(location, str) or not isinstance(record, dict) or not location:
                    skipped += 1
                    continue
                if not location.startswith("node_modules/") and "/node_modules/" not in location:
                    skipped += 1
                    continue
                name = location.rsplit("node_modules/", 1)[-1]
                version = record.get("version")
                if record.get("link") or not NPM_NAME.fullmatch(name) or not isinstance(version, str) or not NPM_VERSION.fullmatch(version):
                    skipped += 1
                    continue
                if len(packages) >= MAX_COORDS:
                    truncated = True
                    break
                packages.append({"ecosystem": "npm", "name": name, "version": version,
                                 "source": "package-lock.json", "classification": "lockfile_entry_not_verified_installed"})
        return {"status": "OFFLINE_DEPENDENCY_INVENTORY_NOT_VULNERABILITY_VERIFICATION",
                "packages": packages, "summary": {"manifest_files": present, "packages_recorded": len(packages),
                "entries_unresolved": skipped, "truncated": truncated},
                "limitations": ["Pinned/lockfile dependency declarations are not proof of installation or reachability.",
                                "Ranges, URL dependencies, lockfile links and unsupported manifests are not assessed."]}
    finally:
        os.close(dirfd)


def main():
    try:
        sys.stdout.write(json.dumps(inventory(), separators=(",", ":")))
        return 0
    except (OSError, ValueError) as exc:
        sys.stderr.write("INVENTORY_DENIED: " + type(exc).__name__ + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
