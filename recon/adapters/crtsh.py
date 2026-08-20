"""
crt.sh certificate transparency adapter — pure HTTP, no binary required.
"""
from __future__ import annotations

import json
import logging
from typing import Any, List

import requests

from recon.adapters.base import ToolAdapter, ToolResult
from recon.normalizers.hosts import normalize_hostname, dedupe_hostnames

logger = logging.getLogger(__name__)


class CrtShAdapter(ToolAdapter):
    name = "crtsh"
    binary_names: List[str] = []  # network-only

    def is_available(self) -> bool:
        return True

    def build_command(self, target: str, **kwargs) -> List[str]:
        # Not used — HTTP API
        return []

    def execute(self, target: str, timeout: int = 60, **kwargs) -> ToolResult:
        domain = normalize_hostname(target)
        if not domain:
            return ToolResult(tool=self.name, success=False, error="invalid domain")

        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Secure-Recon/4.0"})
            if resp.status_code != 200:
                return ToolResult(
                    tool=self.name,
                    success=False,
                    error=f"crt.sh HTTP {resp.status_code}",
                    raw=resp.text[:2000],
                )
            # crt.sh sometimes returns empty or HTML on overload
            text = resp.text.strip()
            if not text or text.startswith("<"):
                return ToolResult(tool=self.name, success=True, items=[], raw=text[:500])

            data = resp.json()
            hosts = self.parse_json(data)
            hosts = [h for h in hosts if h.endswith(domain) or h == domain]
            hosts = dedupe_hostnames(hosts)
            return ToolResult(
                tool=self.name,
                success=True,
                items=hosts,
                raw=json.dumps(data)[:200_000] if isinstance(data, list) else text[:50_000],
                meta={"count": len(hosts)},
            )
        except requests.Timeout:
            return ToolResult(tool=self.name, success=False, error="timeout")
        except Exception as e:
            logger.exception("crt.sh failed")
            return ToolResult(tool=self.name, success=False, error=str(e)[:300])

    def parse(self, stdout: str) -> List[Any]:
        try:
            data = json.loads(stdout)
            return self.parse_json(data)
        except Exception:
            return []

    def parse_json(self, data: Any) -> List[str]:
        hosts: List[str] = []
        if not isinstance(data, list):
            return hosts
        for entry in data:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name_value") or entry.get("common_name") or ""
            for part in str(name).split("\n"):
                part = part.strip()
                if part.startswith("*."):
                    part = part[2:]
                n = normalize_hostname(part)
                if n:
                    hosts.append(n)
        return hosts

    def installation_hint(self) -> str:
        return "crt.sh uses public HTTP API — no local install required."
