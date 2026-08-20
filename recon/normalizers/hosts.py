"""
Hostname / domain normalization and deduplication.
"""
from __future__ import annotations

import re
from typing import Iterable, List, Set

_TRAILING_DOT = re.compile(r"\.+$")
_INVALID = re.compile(r"[^a-z0-9.\-_]")


def normalize_hostname(value: str) -> str | None:
    if not value or not isinstance(value, str):
        return None
    h = value.strip().lower()
    h = _TRAILING_DOT.sub("", h)
    # strip scheme if present
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/")[0].split("?")[0].split("#")[0]
    # strip port
    if ":" in h and not h.count(":") > 1:  # not IPv6
        host, _, port = h.rpartition(":")
        if port.isdigit():
            h = host
    h = h.strip(".")
    if not h or len(h) > 253:
        return None
    if _INVALID.search(h):
        return None
    if ".." in h:
        return None
    return h


def dedupe_hostnames(values: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for v in values:
        n = normalize_hostname(v)
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return sorted(out)


def is_subdomain_of(hostname: str, root: str) -> bool:
    h = normalize_hostname(hostname)
    r = normalize_hostname(root)
    if not h or not r:
        return False
    return h == r or h.endswith("." + r)


INTERESTING_PREFIXES = (
    "admin", "api", "dev", "staging", "stage", "test", "internal",
    "portal", "dashboard", "login", "vpn", "git", "gitlab", "jenkins",
    "ci", "cdn", "mail", "smtp", "ftp", "sso", "auth", "beta", "uat",
)


def is_interesting_hostname(hostname: str) -> bool:
    h = normalize_hostname(hostname) or ""
    labels = h.split(".")
    if not labels:
        return False
    first = labels[0]
    return any(first == p or first.startswith(p + "-") or first.endswith("-" + p) for p in INTERESTING_PREFIXES)
