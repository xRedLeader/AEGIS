"""HTTP scope enforcement primitives: exact signed origin plus pinned address.

All destination IPs must appear in BOTH the signed manifest network list and
independently trusted network list (verified at preflight). Public DNS alone is
never authorization to send traffic. No path-driven host changes or redirects.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from aegis_preflight import normal_origin


class HttpPolicyDenied(ValueError):
    pass


def deny(message: str):
    raise HttpPolicyDenied(message)


def inspect_url(url: str, signed_origins: list[str], excluded_origins: list[str]) -> dict:
    if (not isinstance(url, str) or not url.isascii() or len(url) > 4096 or not url or
        any(ord(c) <= 32 or ord(c) >= 127 for c in url) or any(c in url for c in "\\#@")):
        deny("URL must be an ASCII absolute HTTP(S) URL without userinfo, fragment or controls")
    try:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc or parts.hostname is None:
            deny("only absolute HTTP/HTTPS URLs are supported")
        if parts.username is not None or parts.password is not None:
            deny("userinfo is forbidden")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        host = parts.hostname
        origin = normal_origin(f"{parts.scheme}://{parts.netloc}")
    except (ValueError, TypeError) as exc:
        raise HttpPolicyDenied("malformed URL or authority") from exc
    # Bind *exactly* to the signed serialized origin, including port spelling.
    if origin not in signed_origins or origin in excluded_origins:
        deny("URL origin not present in active authorized scope")
    if not host.isascii() or host != host.lower() or "%" in host or host.endswith("."):
        deny("non-canonical hostname")
    try:
        literal = ipaddress.ip_address(host)
        if str(literal) != host:
            deny("IP literal must be canonical")
    except ValueError:
        if ":" in host or len(host) > 253 or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*", host):
            deny("hostname is not a canonical ASCII DNS name")
        # Avoid alternate numeric representations such as 0177.0.0.1.
        if re.fullmatch(r"[0-9.]+", host):
            deny("ambiguous numeric hostname")
    target = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
    if len(target) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in target):
        deny("invalid request target")
    return {"origin": origin, "hostname": host, "scheme": parts.scheme,
            "port": port, "target": target}


def pinned_address(addresses: list[str], signed_cidrs: list[str], excluded_cidrs: list[str],
                   literal_hostname: str | None = None) -> str:
    if not addresses or len(addresses) > 16 or not signed_cidrs:
        deny("no DNS answers or no independently authorized destination CIDRs")
    networks = [ipaddress.ip_network(n, strict=True) for n in signed_cidrs]
    excludes = [ipaddress.ip_network(n, strict=True) for n in excluded_cidrs]
    valid = []
    for raw in addresses:
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise HttpPolicyDenied("invalid resolved address") from exc
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if ip.is_unspecified or ip.is_multicast or ip.is_link_local or (
                ip.version == 4 and int(ip) == 0xFFFFFFFF):
            deny("unsafe destination address category")
        if not any(ip in net for net in networks):
            deny("DNS answer outside signed and trusted destination networks")
        if any(ip in net for net in excludes):
            deny("DNS answer matches excluded network")
        if literal_hostname is not None:
            try:
                literal = ipaddress.ip_address(literal_hostname)
            except ValueError:
                literal = None
            if literal is not None and ip != literal:
                deny("numeric host was unexpectedly resolved to another address")
        valid.append(ip)
    if len(set(valid)) != len(valid):
        # Duplicates are expected in DNS and are safe; deterministic selection.
        pass
    return str(sorted(set(valid), key=lambda x: (x.version, int(x)))[0])
