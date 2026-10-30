#!/usr/bin/env python3
"""Bounded offline manifest inventory in the authorized read-only /repo.

No project code, package manager, build, includes or downloads are executed.
Coordinates retain their manifest digest and declared/locked evidence kind.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import stat
import sys
import xml.etree.ElementTree as ET

O_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
O_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
MAX_REQUIREMENTS = 512 * 1024
MAX_LOCKFILE = 4 * 1024 * 1024
MAX_BYTES = 4 * 1024 * 1024
MAX_COORDS = 150
MAX_ENTRIES = 1000
MAX_MANIFESTS = 64
MAX_DEPTH = 8
MAX_OUTPUT = 32768
PIP_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
PIP_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.!+_-]{0,79}\Z")
NPM_NAME = re.compile(r"(?:@[a-z0-9_.-]{1,80}/)?[a-z0-9_.-]{1,100}\Z")
NPM_VERSION = re.compile(r"[0-9][0-9A-Za-z.!+_-]{0,79}\Z")
MAVEN_NAME = re.compile(r"[A-Za-z0-9_.-]{1,80}:[A-Za-z0-9_.-]{1,80}\Z")
GO_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._!~+-]*(?:/[A-Za-z0-9._!~+-]+)+\Z")
GO_VERSION = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.+-]+)?\Z")
PATH = re.compile(r"[A-Za-z0-9_.@-]+(?:/[A-Za-z0-9_.@-]+)*\Z")
SUPPORTED = {"requirements.txt", "package-lock.json", "packages.lock.json", "pom.xml", "go.mod"}
UNSUPPORTED = {"package.json", "yarn.lock", "pnpm-lock.yaml", "pyproject.toml", "Pipfile",
               "Pipfile.lock", "poetry.lock", "uv.lock", "setup.py", "setup.cfg", "go.sum",
               "go.work", "build.gradle", "build.gradle.kts", "gradle.lockfile", "packages.config",
               "project.assets.json", "Directory.Packages.props", "Cargo.lock", "Gemfile.lock"}
SKIP_DIRS = {".git", ".hg", "node_modules", "vendor", ".venv", "venv", "__pycache__", "bin", "obj"}


def canonical_package(ecosystem, name):
    """Validate coordinates without interpreting them as paths or URLs."""
    if not isinstance(name, str):
        return None
    if ecosystem in ("PyPI", "NuGet") and PIP_NAME.fullmatch(name):
        return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "PyPI" else name.lower()
    if ecosystem == "npm" and NPM_NAME.fullmatch(name):
        return name
    if ecosystem == "Maven" and MAVEN_NAME.fullmatch(name):
        return name
    if ecosystem == "Go" and len(name) <= 180 and GO_NAME.fullmatch(name) and all(p not in (".", "..") for p in name.split("/")):
        return name
    return None


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _identity(st):
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink


def read_regular(dirfd: int, filename: str, maximum: int) -> bytes | None:
    try:
        fd = os.open(filename, O_FILE, dir_fd=dirfd)
    except FileNotFoundError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or not 0 <= st.st_size <= maximum:
            raise ValueError("invalid dependency manifest type or size")
        chunks, size = [], 0
        while size <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if (size != st.st_size or size > maximum or _identity(st) != _identity(os.fstat(fd)) or
                _identity(st) != _identity(os.stat(filename, dir_fd=dirfd, follow_symlinks=False))):
            raise ValueError("dependency manifest changed during read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _json(raw):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("duplicate manifest key")
            obj[key] = value
        return obj
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


class _Limit(Exception):
    pass


class _Inventory:
    def __init__(self):
        self.data = {"status": "OFFLINE_DEPENDENCY_INVENTORY_NOT_VULNERABILITY_VERIFICATION",
                     "schema_version": 2, "packages": [], "unresolved": [], "manifests": [],
                     "summary": {"manifest_files": [], "packages_recorded": 0, "entries_unresolved": 0,
                                 "truncated": False},
                     "coverage": {"status": "partial", "gaps": [], "limits_hit": [],
                                  "limits": {"depth": MAX_DEPTH, "entries": MAX_ENTRIES, "manifests": MAX_MANIFESTS,
                                             "bytes": MAX_BYTES, "coordinates": MAX_COORDS, "evidence_bytes": MAX_OUTPUT},
                                  "entries_seen": 0, "bytes_charged": 0, "remaining_entries_unknown": False},
                     "limitations": ["Declarations and lockfiles do not prove installation, reachability or an exploitable vulnerability.",
                                     "No package restoration, builds, includes, property resolution or network access occurs.",
                                     "Digests bind read manifests, not a complete repository or atomic source revision."]}
        self.source = ""
        self.digest = ""

    def limit(self, reason):
        cov = self.data["coverage"]
        if reason not in cov["limits_hit"]:
            cov["limits_hit"].append(reason)
        cov["remaining_entries_unknown"] = True
        self.data["summary"]["truncated"] = True

    def append(self, field, value):
        self.data[field].append(value)
        if len(_encoded(self.data)) > MAX_OUTPUT - 1536:
            self.data[field].pop()
            self.limit("evidence_bytes")
            raise _Limit()

    def gap(self, path, reason):
        value = {"path": path[:180], "path_sha256": hashlib.sha256(os.fsencode(path)).hexdigest(), "reason": reason}
        self.data["coverage"]["gaps"].append(value)
        if len(_encoded(self.data)) > MAX_OUTPUT - 1536:
            self.data["coverage"]["gaps"].pop()
            self.limit("evidence_bytes")
            raise _Limit()

    def add(self, ecosystem, name, version, kind, origin, *, reason="", constraint=""):
        if len(self.data["packages"]) + len(self.data["unresolved"]) >= MAX_COORDS:
            self.limit("coordinates")
            raise _Limit()
        normalized = canonical_package(ecosystem, name)
        entry = {"ecosystem": ecosystem, "name": normalized, "source": self.source,
                 "manifest_sha256": self.digest, "evidence_kind": kind, "origin": origin}
        if not reason and normalized and isinstance(version, str) and PIP_VERSION.fullmatch(version):
            entry.update(version=version, classification=("lockfile_entry_not_verified_installed" if kind == "locked" else "declared_pin_not_verified_installed"))
            self.append("packages", entry)
        else:
            # Raw URLs, source expressions, markers and scripts cannot enter evidence.
            entry.update(reason=reason or "invalid_coordinate", constraint=(constraint if isinstance(constraint, str) and
                         len(constraint) <= 100 and re.fullmatch(r"[A-Za-z0-9_. *!=<>~^,|()\[\]+-]*", constraint) else "redacted_or_unsupported"))
            self.append("unresolved", entry)


def _requirements(raw, out):
    for lineno, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]{0,127})\s*==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]{0,79})", entry)
        name = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", entry)
        reason = "" if match else ("marker_requires_resolution" if ";" in entry else "constraint_include_or_external_dependency")
        out.add("PyPI", match[1] if match else (name[0] if name else None), match[2] if match else None,
                "declared", f"line:{lineno}", reason=reason, constraint=entry[len(name[0]):].strip() if name else "")


def _npm(raw, out):
    obj = _json(raw)
    if not isinstance(obj, dict) or type(obj.get("lockfileVersion")) is not int or obj["lockfileVersion"] not in (2, 3) or not isinstance(obj.get("packages"), dict):
        raise ValueError("unsupported npm lockfile")
    for index, (location, record) in enumerate(sorted(obj["packages"].items())):
        location_valid = (bool(PATH.fullmatch(location)) and all(p not in (".", "..") for p in location.split("/")) and
                          (location.startswith("node_modules/") or "/node_modules/" in location))
        name = location.rsplit("node_modules/", 1)[-1] if location_valid else None
        version = record.get("version") if isinstance(record, dict) else None
        reason = ""
        if not isinstance(record, dict) or not name:
            reason = "project_or_workspace_entry"
        elif record.get("link") or (isinstance(record.get("resolved"), str) and not record["resolved"].startswith("https://registry.npmjs.org/")):
            reason = "local_or_external_dependency"
        elif not isinstance(version, str) or not NPM_VERSION.fullmatch(version):
            reason = "unresolved_version"
        out.add("npm", name, version, "locked", f"package:{index}", reason=reason, constraint=version or "")


def _nuget(raw, out):
    obj = _json(raw)
    if not isinstance(obj, dict) or type(obj.get("version")) is not int or obj["version"] != 1 or not isinstance(obj.get("dependencies"), dict):
        raise ValueError("unsupported NuGet lockfile")
    for framework_index, (framework, dependencies) in enumerate(sorted(obj["dependencies"].items())):
        if not isinstance(dependencies, dict):
            raise ValueError("invalid framework dependencies")
        for index, (name, entry) in enumerate(sorted(dependencies.items())):
            if not isinstance(entry, dict):
                raise ValueError("invalid NuGet entry")
            version = entry.get("resolved")
            reason = "" if entry.get("type") in ("Direct", "Transitive") and isinstance(version, str) and NPM_VERSION.fullmatch(version) else "project_or_unresolved_dependency"
            out.add("NuGet", name, version, "locked", f"framework:{framework_index}/package:{index}",
                    reason=reason, constraint=entry.get("requested", ""))


def _maven(raw, out):
    decoded = raw.decode("utf-8")
    if "\x00" in decoded or re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", decoded, re.I):
        raise ValueError("XML declarations unsupported")
    root = ET.fromstring(decoded)
    namespace = "{http://maven.apache.org/POM/4.0.0}" if root.tag.startswith("{") else ""
    if root.tag != namespace + "project":
        raise ValueError("invalid Maven project")
    def text(parent, tag):
        node = parent.find(namespace + tag)
        return (node.text or "").strip() if node is not None else ""
    for container_index, container in enumerate(root.findall(namespace + "dependencies")):
        for index, dep in enumerate(container.findall(namespace + "dependency")):
            name = text(dep, "groupId") + ":" + text(dep, "artifactId")
            version = text(dep, "version")
            resolved = bool(PIP_VERSION.fullmatch(version)) and version.upper() not in ("LATEST", "RELEASE")
            out.add("Maven", name, version, "declared", f"dependencies:{container_index}/entry:{index}",
                    reason="" if resolved else "property_range_or_managed_version", constraint=version)
    out.gap(out.source, "maven_effective_model_and_transitive_graph_unresolved")


def _go(raw, out):
    requirements, replaced, excluded = [], set(), set()
    block = None
    for lineno, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        line = line.split("//", 1)[0].strip()
        if not line:
            continue
        if line == ")":
            block = None
            continue
        pieces = line.split()
        directive, values = (block, pieces) if block else (pieces[0], pieces[1:])
        if values == ["("]:
            block = directive
            continue
        if directive == "require":
            requirements.append((lineno, values))
        elif directive == "replace":
            if values:
                replaced.add(values[0])
            out.gap(out.source, "go_replace_requires_resolution")
        elif directive == "exclude":
            if len(values) == 2:
                excluded.add(tuple(values))
            else:
                out.gap(out.source, "unsupported_go_exclude")
        elif directive not in ("module", "go", "toolchain", "retract"):
            out.gap(out.source, "unsupported_go_directive")
    if block:
        raise ValueError("unterminated Go directive")
    for lineno, values in requirements:
        name, version = (values + [None, None])[:2]
        reason = ""
        if len(values) != 2 or not isinstance(version, str) or not GO_VERSION.fullmatch(version):
            reason = "unsupported_go_requirement"
        elif name in replaced or (name, version) in excluded:
            reason = "replacement_or_exclusion_requires_resolution"
        out.add("Go", name, version, "declared", f"line:{lineno}", reason=reason, constraint=version or "")
    out.gap(out.source, "go_selected_build_graph_unresolved")


PARSERS = {"requirements.txt": _requirements, "package-lock.json": _npm, "packages.lock.json": _nuget,
           "pom.xml": _maven, "go.mod": _go}


def _inventory(root):
    out = _Inventory()
    data, cov = out.data, out.data["coverage"]

    def walk(fd, relative="", depth=0):
        names = []
        with os.scandir(fd) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) + cov["entries_seen"] > MAX_ENTRIES:
                    out.limit("entries")
                    raise _Limit()
        cov["entries_seen"] += len(names)
        for name in sorted(names):
            path = relative + name
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if len(path) > 180 or not PATH.fullmatch(path) or any(p in (".", "..") for p in path.split("/")):
                out.gap(path, "unsupported_path")
                continue
            if stat.S_ISDIR(st.st_mode):
                if name in SKIP_DIRS:
                    out.gap(path, "excluded_directory")
                elif depth >= MAX_DEPTH:
                    out.limit("depth")
                    out.gap(path, "directory_depth_limit")
                else:
                    child = os.open(name, O_DIR, dir_fd=fd)
                    try:
                        yield from walk(child, path + "/", depth + 1)
                    finally:
                        os.close(child)
            else:
                yield fd, name, path, st

    rootfd = os.open(root, O_DIR)
    try:
        for fd, name, path, st in walk(rootfd):
            if name not in SUPPORTED:
                if name in UNSUPPORTED or name.endswith((".csproj", ".fsproj", ".vbproj")):
                    out.gap(path, "checksum_not_installed_inventory" if name == "go.sum" else "unsupported_manifest")
                elif not stat.S_ISREG(st.st_mode):
                    out.gap(path, "excluded_link_or_special_file")
                continue
            if len(data["manifests"]) >= MAX_MANIFESTS:
                out.limit("manifests")
                raise _Limit()
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise ValueError("linked or special dependency manifest")
            maximum = MAX_LOCKFILE if name.endswith(".json") else MAX_REQUIREMENTS
            if st.st_size > maximum or cov["bytes_charged"] + st.st_size > MAX_BYTES:
                out.limit("bytes")
                out.gap(path, "manifest_byte_limit")
                continue
            # Charge before reading, including rejected/racing files, so retries cannot evade the byte cap.
            maximum = min(maximum, MAX_BYTES - cov["bytes_charged"])
            cov["bytes_charged"] += st.st_size
            try:
                raw = read_regular(fd, name, min(maximum, st.st_size))
                if raw is None:
                    out.gap(path, "manifest_disappeared")
                    continue
                out.source, out.digest = path, hashlib.sha256(raw).hexdigest()
                record = {"path": path, "sha256": out.digest, "bytes": len(raw), "format": name, "status": "parsed"}
                out.append("manifests", record)
                data["summary"]["manifest_files"].append(path)
                before_packages, before_unresolved = len(data["packages"]), len(data["unresolved"])
                try:
                    PARSERS[name](raw, out)
                except (ValueError, UnicodeError, ET.ParseError, RecursionError):
                    del data["packages"][before_packages:]
                    del data["unresolved"][before_unresolved:]
                    record["status"] = "malformed_or_unsupported"
                    out.gap(path, "malformed_or_unsupported_manifest")
            except (OSError, ValueError):
                out.gap(path, "manifest_unreadable_or_changed")
    except _Limit:
        pass
    finally:
        os.close(rootfd)
    if not data["manifests"] and not cov["limits_hit"]:
        try:
            out.gap(".", "no_supported_manifests")
        except _Limit:
            pass
    coordinates = [(p["ecosystem"], p["name"], p["version"]) for p in data["packages"]]
    data["summary"].update(packages_recorded=len(data["packages"]), entries_unresolved=len(data["unresolved"]),
                           duplicate_coordinates=len(coordinates) - len(set(coordinates)))
    versions = {}
    for ecosystem, name, version in coordinates:
        versions.setdefault((ecosystem, name), set()).add(version)
    data["summary"]["packages_with_conflicting_versions"] = sum(len(v) > 1 for v in versions.values())
    cov["status"] = "partial" if cov["gaps"] or cov["limits_hit"] or data["unresolved"] else "declared_or_locked_coordinates_only"
    data["manifest_set_sha256"] = hashlib.sha256(_encoded(data["manifests"])).hexdigest()
    if len(_encoded(data)) > MAX_OUTPUT:
        raise ValueError("inventory evidence exceeds output limit")
    return data


def inventory(repo: str = "/repo") -> dict:
    if repo != "/repo":
        raise ValueError("worker may only inspect its read-only /repo mount")
    return _inventory(repo)


def main():
    try:
        sys.stdout.write(_encoded(inventory()).decode("ascii"))
        return 0
    except (OSError, ValueError) as exc:
        sys.stderr.write("INVENTORY_DENIED: " + type(exc).__name__ + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
