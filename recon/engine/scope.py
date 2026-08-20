"""
Scope enforcement — backend must validate every target.
"""
from __future__ import annotations

import fnmatch
from typing import Iterable, List, Literal, Tuple

from recon.normalizers.hosts import normalize_hostname

ScopeStatus = Literal["IN_SCOPE", "OUT_OF_SCOPE", "UNKNOWN"]


def match_pattern(hostname: str, pattern: str) -> bool:
    h = normalize_hostname(hostname)
    p = pattern.strip().lower()
    if not h or not p:
        return False
    # support *.example.com and example.com
    if p.startswith("*."):
        root = p[2:]
        return h == root or h.endswith("." + root) or fnmatch.fnmatch(h, p)
    return h == normalize_hostname(p) or fnmatch.fnmatch(h, p)


def check_scope(
    hostname: str,
    include_patterns: Iterable[str],
    exclude_patterns: Iterable[str],
) -> ScopeStatus:
    h = normalize_hostname(hostname)
    if not h:
        return "UNKNOWN"

    for excl in exclude_patterns:
        if match_pattern(h, excl):
            return "OUT_OF_SCOPE"

    includes = list(include_patterns)
    if not includes:
        return "UNKNOWN"

    for inc in includes:
        if match_pattern(h, inc):
            return "IN_SCOPE"

    return "OUT_OF_SCOPE"


def filter_in_scope(
    hostnames: Iterable[str],
    include_patterns: Iterable[str],
    exclude_patterns: Iterable[str],
) -> Tuple[List[str], List[str], List[str]]:
    """Returns (in_scope, out_of_scope, unknown)."""
    inn, out, unk = [], [], []
    for host in hostnames:
        st = check_scope(host, include_patterns, exclude_patterns)
        if st == "IN_SCOPE":
            inn.append(host)
        elif st == "OUT_OF_SCOPE":
            out.append(host)
        else:
            unk.append(host)
    return inn, out, unk
