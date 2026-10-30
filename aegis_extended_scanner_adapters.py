"""Pure Trivy/Grype and ZAP/Nuclei report parsers. No scanner execution or I/O."""
import base64
import binascii
from datetime import datetime, timedelta, timezone
import hashlib
import re
from urllib.parse import unquote, urlsplit

from aegis_audit_contract import require
from aegis_scanner_contract import identifier, observation, sha256, VERSION

PACKAGE_RELEASES = {("trivy", "0.58.2", "trivy-json-v2"), ("trivy", "0.76.1", "trivy-json-v2"), ("grype", "0.85.0", "grype-json-v0.85")}
STAGING_RELEASES = {("nuclei", "3.3.8", "nuclei-json-export-v3.3.8"),
                    ("zap", "reports-0.35.0", "traditional-json")}
TRIVY_TYPES = {"npm": "npm", "node-pkg": "npm", "pip": "PyPI", "python-pkg": "PyPI",
               "nuget": "NuGet", "dotnet-core": "NuGet", "jar": "Maven", "pom": "Maven",
               "gomod": "Go", "gobinary": "Go"}
GRYPE_TYPES = {"npm": "npm", "python": "PyPI", "dotnet": "NuGet", "java-archive": "Maven", "go-module": "Go"}


def _stamp(value):
    """UTC nanoseconds without Python-version-dependent ISO parsing or rounding."""
    require(isinstance(value, str) and len(value) <= 64, "missing scanner timestamp")
    match = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})", value, re.ASCII)
    require(match is not None, "invalid scanner RFC3339 timestamp")
    try:
        zone = match[8]
        offset = timedelta(0)
        if zone != "Z":
            hours, minutes = int(zone[1:3]), int(zone[4:6])
            require(hours <= 23 and minutes <= 59, "invalid scanner timezone offset")
            offset = timedelta(hours=hours, minutes=minutes) * (-1 if zone[0] == "-" else 1)
        result = datetime(*(int(match[i]) for i in range(1, 7)), tzinfo=timezone(offset))
        elapsed = result.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    except (ValueError, OverflowError):
        require(False, "invalid scanner timestamp")
    return (elapsed.days * 86400 + elapsed.seconds) * 1_000_000_000 + int((match[7] or "0").ljust(9, "0"))


def _whole_second(value):
    # Package admission's observed_at is explicitly a whole UTC second. Staging
    # interval and database comparisons always retain the full event precision.
    return _stamp(value) // 1_000_000_000 * 1_000_000_000


def _release(policy, supported):
    detector = policy["detector"]
    require((detector["name"], detector["version"], detector["report_schema"]) in supported,
            "unsupported scanner release/schema")
    return detector["name"]


def _dict(value):
    require(isinstance(value, dict), "invalid scanner object")
    return value


def _list(value):
    require(isinstance(value, list) and len(value) <= 2000, "invalid scanner list")
    return value


def _result(records, unresolved, limitations):
    return {"observations": records, "coverage": {"assessed_records": len(records),
            "unresolved_records": unresolved, "limitations": limitations}}


def _sbom_coordinates(artifact):
    """Require typed package identities; equal names across ecosystems are unrelated."""
    artifact = _dict(artifact)
    if artifact.get("bomFormat") == "CycloneDX" and artifact.get("specVersion") in ("1.5", "1.6"):
        packages = _list(artifact.get("components", []))
        refs = [_dict(p).get("purl") for p in packages]
    else:
        require(artifact.get("spdxVersion") == "SPDX-2.3", "unsupported SBOM schema")
        packages = _list(artifact.get("packages", []))
        refs = [ref.get("referenceLocator") for p in packages for ref in _list(_dict(p).get("externalRefs", []))
                if isinstance(ref, dict) and ref.get("referenceType") == "purl"]
    coordinates = set()
    ecosystems = {"pypi":"PyPI", "npm":"npm", "nuget":"NuGet", "maven":"Maven", "golang":"Go",
                  "apk":"os", "deb":"os", "rpm":"os"}
    for value in refs:
        if not isinstance(value, str) or len(value) > 1024:
            continue
        match = re.fullmatch(r"pkg:([a-z0-9]+)/([^?#]+)(?:\?[^#]*)?(?:#.*)?", value)
        if not match or match[1] not in ecosystems or "@" not in match[2]:
            continue
        package, version = (unquote(v) for v in match[2].rsplit("@", 1))
        ecosystem = ecosystems[match[1]]
        if ecosystem == "Maven":
            package = package.replace("/", ":")
        elif ecosystem == "os":
            package = package.rsplit("/", 1)[-1]
        if ecosystem in ("PyPI", "NuGet"):
            package = re.sub(r"[-_.]+", "-", package).lower() if ecosystem == "PyPI" else package.lower()
        coordinates.add((ecosystem, package, version))
    return coordinates


def parse_package_report(doc, policy, context):
    name = _release(policy, PACKAGE_RELEASES)
    doc = _dict(doc)
    selected = context["input_identity"]
    kind = selected["kind"]
    require(kind in ("source", "sbom", "image"), "package report requires source, SBOM or image identity")
    require(policy["database"] is not None, "vulnerability database identity and age are required")
    sha256(policy["database"]["sha256"])
    limitations = ["Vendor matches are unverified leads; package presence does not prove reachable or deployed impact.",
                   "Database/configuration identity and omitted producer metadata are independently operator attested."]
    records, unresolved = [], 0
    inventory = _sbom_coordinates(context["artifact"]) if kind == "sbom" else None
    if kind == "sbom":
        limitations.append("SBOM inventory belongs to its separately admitted generator; the vulnerability matcher does not establish authorship or image contents.")
    elif kind == "source":
        limitations.append("Source declarations do not establish installed inventory.")
    else:
        limitations.append("Image identity is bound to the selected immutable " + selected["image_digest_kind"] + " digest.")

    def add(rule, package, version, ecosystem):
        nonlocal unresolved
        identifier(rule)
        identifier(package)
        if ecosystem is None:
            unresolved += 1
            return
        if not isinstance(version, str) or not VERSION.fullmatch(version):
            unresolved += 1
            return
        if inventory is not None:
            category = "os" if ecosystem.startswith("os/") else ecosystem
            normalized = (re.sub(r"[-_.]+", "-", package).lower() if category == "PyPI" else package.lower() if category == "NuGet" else package)
            require((category, normalized, version) in inventory, "typed scanner package is absent from the selected SBOM")
        records.append(observation("package", rule, package=package, version=version, ecosystem=ecosystem))

    if name == "trivy":
        require(type(doc.get("SchemaVersion")) is int and doc["SchemaVersion"] == 2, "unsupported Trivy schema")
        artifact_type = doc.get("ArtifactType")
        require(artifact_type in ({"container_image"} if kind == "image" else {"cyclonedx", "spdx"} if kind == "sbom" else {"filesystem", "repository"}),
                "Trivy artifact class differs from approved input")
        metadata = _dict(doc.get("Metadata", {}))
        if kind == "image":
            if selected["image_digest_kind"] == "config":
                require(metadata.get("ImageID") == selected["image_digest"], "Trivy image config digest differs")
            else:
                digests = _list(metadata.get("RepoDigests", []))
                require(any(isinstance(d, str) and d.endswith("@" + selected["image_digest"]) for d in digests),
                        "Trivy report lacks the approved immutable image manifest")
        if doc.get("CreatedAt"):
            require(_whole_second(doc["CreatedAt"]) == _stamp(policy["observed_at_utc"]),
                    "Trivy observed time differs from admission")
        else:
            limitations.append("Trivy report omits observed time; the approved scan time is externally attested.")
        limitations.append("Trivy JSON does not embed the scanner build or vulnerability database checksum.")
        for result in _list(doc.get("Results", [])):
            result = _dict(result)
            if kind == "source":
                require(result.get("Target") in context["source"], "Trivy result escaped selected source files")
            class_ = result.get("Class")
            type_ = result.get("Type")
            require(isinstance(type_, str) and isinstance(class_, str), "invalid Trivy package class")
            ecosystem = "os/" + identifier(type_) if class_ == "os-pkgs" else TRIVY_TYPES.get(type_) if class_ == "lang-pkgs" else None
            for entry in _list(result.get("Vulnerabilities", [])):
                entry = _dict(entry)
                add(entry.get("VulnerabilityID"), entry.get("PkgName"), entry.get("InstalledVersion"), ecosystem)
            unresolved += sum(len(_list(result[field])) for field in ("Misconfigurations", "Secrets", "Licenses") if field in result)
    else:
        descriptor = _dict(doc.get("descriptor"))
        require(descriptor.get("name") == "grype", "Grype producer is absent")
        require(descriptor.get("version") in ("0.85.0", "[not provided]"), "Grype producer version differs")
        if descriptor.get("version") == "[not provided]":
            limitations.append("Grype exporter omits build identity; the protected producer attestation supplies the pinned release.")
        if descriptor.get("timestamp"):
            require(_whole_second(descriptor["timestamp"]) == _stamp(policy["observed_at_utc"]),
                    "Grype observed time differs from admission")
        database = descriptor.get("db")
        if database:
            database = _dict(database)
            checksum = database.get("checksum")
            if isinstance(checksum, str):
                require(checksum.removeprefix("sha256:") == policy["database"]["sha256"], "Grype database checksum differs")
            if database.get("built"):
                require(_stamp(database["built"]) == _stamp(policy["database"]["built_at_utc"]), "Grype database age differs")
        source = _dict(doc.get("source"))
        if kind == "image":
            target = _dict(source.get("target"))
            field = "manifestDigest" if selected["image_digest_kind"] == "manifest" else "imageID"
            require(source.get("type") == "image" and target.get(field) == selected["image_digest"], "Grype image identity differs")
        elif kind == "source":
            require(source.get("type") == "directory" and source.get("target") == policy["input"]["repository"],
                    "Grype source root differs")
        else:
            require(source.get("type") in ("file", "image", "directory"), "Grype SBOM source identity is absent")
        for match in _list(doc.get("matches")):
            match = _dict(match)
            artifact = _dict(match.get("artifact"))
            vulnerability = _dict(match.get("vulnerability"))
            type_ = artifact.get("type")
            require(isinstance(type_, str), "invalid Grype package class")
            ecosystem = "os/" + type_ if type_ in ("apk", "deb", "rpm") else GRYPE_TYPES.get(type_)
            if kind == "source":
                locations = _list(artifact.get("locations", []))
                require(bool(locations), "Grype source coordinate has no file origin")
                root = policy["input"]["repository"].rstrip("/") + "/"
                require(all(isinstance(p, dict) and isinstance(p.get("path"), str) and
                            (p["path"][len(root):] if p["path"].startswith(root) else p["path"]) in context["source"] for p in locations),
                        "Grype coordinate escaped selected source files")
            add(vulnerability.get("id"), artifact.get("name"), artifact.get("version"), ecosystem)
        unresolved += len(_list(doc.get("ignoredMatches", [])))
    return _result(records, unresolved, limitations)


def _location(value, context, *, enforce_route=True):
    require(isinstance(value, str) and 1 <= len(value) <= 4096 and not any(ord(c) < 32 for c in value), "invalid scanner URL")
    try:
        parts = urlsplit(value)
        require(parts.scheme in ("http", "https") and parts.hostname and not parts.username and not parts.password,
                "scanner URL credentials or scheme are inadmissible")
        host = parts.hostname.lower()
        host = "[" + host + "]" if ":" in host else host
        port = parts.port
        origin = parts.scheme + "://" + host + (":" + str(port) if port and port != (443 if parts.scheme == "https" else 80) else "")
    except ValueError:
        require(False, "invalid scanner URL authority")
    route = parts.path or "/"
    require(origin == context["origin"], "scanner origin escaped admitted staging scope")
    require(not any(c in route for c in ("%", "\\")) and "//" not in route and
            not any(p in (".", "..") for p in route.split("/")), "ambiguous scanner route")
    require(not enforce_route or route in context["routes"], "scanner route escaped admitted staging scope")
    return origin, route


def parse_staging_report(doc, policy, context):
    name = _release(policy, STAGING_RELEASES)
    selected = context["input_identity"]
    require(selected["kind"] == "staging" and selected["origin"] == context["origin"], "staging identity is absent")
    sha256(selected["deployment_sha256"])
    start, finish = _stamp(selected["scan_started_at_utc"]), _stamp(selected["scan_finished_at_utc"])
    require(start <= finish == _stamp(policy["observed_at_utc"]), "staging scan interval differs")
    records, unresolved = [], 0
    limitations = ["Import only: no spider, scanner, template, browser, callback or target request is executed.",
                  "Scanner observations are unverified leads; independently signed staging proof remains required.",
                  "Only selected rule IDs, origin and query-free routes survive; raw requests, responses, cookies and credentials are discarded."]
    if name == "nuclei":
        for entry in _list(doc):
            entry = _dict(entry)
            require(entry.get("type") == "http" and entry.get("matcher-status") is True, "unsupported Nuclei result kind/status")
            require(start <= _stamp(entry.get("timestamp")) <= finish, "Nuclei event is outside admitted scan time")
            origin, route = _location(entry.get("matched-at"), context)
            if "url" in entry:
                _location(entry["url"], context, enforce_route=False)
            identifier(entry.get("template-id"))
            if "template-encoded" in entry:
                try:
                    require(isinstance(entry["template-encoded"], str), "invalid Nuclei embedded template")
                    template = base64.b64decode(entry["template-encoded"], validate=True)
                except (ValueError, binascii.Error):
                    require(False, "invalid Nuclei embedded template")
                require(hashlib.sha256(template).hexdigest() == policy["configuration"]["sha256"],
                        "Nuclei embedded template differs from selected configuration")
            records.append(observation("staging", entry["template-id"], origin=origin, route=route))
        limitations.append("Nuclei engine identity is independently attested; when present, the embedded template must match the selected single-template configuration hash.")
    else:
        doc = _dict(doc)
        require(doc.get("@programName") == "ZAP" and isinstance(doc.get("@version"), str), "invalid ZAP exporter")
        # This pin selects the report add-on/template, not an invented ZAP core build.
        limitations.append("The selected ZAP reports add-on is 0.35.0; core build and timezone-free report time require separate producer attestation.")
        if "created" in doc:
            require(start <= _stamp(doc["created"]) <= finish, "ZAP report is outside admitted scan time")
        for site in _list(doc.get("site")):
            site = _dict(site)
            _location(site.get("@name"), context, enforce_route=False)
            target = urlsplit(context["origin"])
            require(site.get("@host") == target.hostname and site.get("@port") == str(target.port or (443 if target.scheme == "https" else 80)) and
                    site.get("@ssl") == ("true" if target.scheme == "https" else "false"), "ZAP site authority disagrees with admitted origin")
            for alert in _list(site.get("alerts")):
                alert = _dict(alert)
                rule = alert.get("pluginid")
                require(isinstance(rule, str) and re.fullmatch(r"[0-9]{1,10}", rule), "invalid ZAP rule")
                instances = _list(alert.get("instances"))
                if not instances:
                    unresolved += 1
                for instance in instances:
                    origin, route = _location(_dict(instance).get("uri"), context)
                    records.append(observation("staging", rule, origin=origin, route=route))
    return _result(records, unresolved, limitations)
