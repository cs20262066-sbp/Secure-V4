"""
Lightweight live-host probe using requests (fallback when httpx binary absent).
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from recon.adapters.base import ToolAdapter, ToolResult
from recon.normalizers.hosts import normalize_hostname

logger = logging.getLogger(__name__)

# Simple tech fingerprints from headers / body snippets
TECH_HINTS = [
    ("cloudflare", lambda h, b: "cf-ray" in h or "cloudflare" in h.get("server", "").lower()),
    ("nginx", lambda h, b: "nginx" in h.get("server", "").lower()),
    ("apache", lambda h, b: "apache" in h.get("server", "").lower()),
    ("iis", lambda h, b: "microsoft-iis" in h.get("server", "").lower()),
    ("react", lambda h, b: "react" in b.lower() or "__NEXT_DATA__" in b),
    ("next.js", lambda h, b: "__NEXT_DATA__" in b or "x-nextjs" in str(h).lower()),
    ("wordpress", lambda h, b: "wp-content" in b.lower() or "wordpress" in b.lower()),
    ("django", lambda h, b: "csrftoken" in str(h).lower() or "django" in b.lower()),
    ("flask", lambda h, b: "werkzeug" in h.get("server", "").lower()),
    ("express", lambda h, b: "express" in h.get("x-powered-by", "").lower()),
]


class HttpProbeAdapter(ToolAdapter):
    name = "http_probe"
    binary_names: List[str] = []

    def is_available(self) -> bool:
        return True

    def build_command(self, target: str, **kwargs) -> List[str]:
        return []

    def execute(
        self,
        target: str,
        timeout: int = 8,
        hosts: Optional[List[str]] = None,
        max_workers: int = 20,
        **kwargs,
    ) -> ToolResult:
        host_list = hosts or [target]
        results: List[Dict[str, Any]] = []

        def probe(host: str) -> Optional[Dict[str, Any]]:
            host = normalize_hostname(host)
            if not host:
                return None
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}"
                try:
                    r = requests.get(
                        url,
                        timeout=timeout,
                        allow_redirects=True,
                        headers={"User-Agent": "Secure-Recon/4.0"},
                        verify=True,
                    )
                    headers = {k.lower(): v for k, v in r.headers.items()}
                    body = r.text[:8000] if r.text else ""
                    title = ""
                    if "<title" in body.lower():
                        try:
                            start = body.lower().index("<title")
                            start = body.index(">", start) + 1
                            end = body.lower().index("</title>", start)
                            title = body[start:end].strip()[:200]
                        except Exception:
                            pass
                    techs = []
                    for name, fn in TECH_HINTS:
                        try:
                            if fn(headers, body):
                                techs.append(name)
                        except Exception:
                            pass
                    status_class = "live"
                    if r.status_code in (301, 302, 303, 307, 308):
                        status_class = "redirect"
                    elif r.status_code == 403:
                        status_class = "forbidden"
                    elif r.status_code >= 500:
                        status_code = "error"
                        status_class = "error"
                    return {
                        "hostname": host,
                        "url": r.url,
                        "scheme": scheme,
                        "status_code": r.status_code,
                        "status": status_class,
                        "title": title,
                        "server": headers.get("server", ""),
                        "content_type": headers.get("content-type", ""),
                        "technologies": techs,
                        "final_url": r.url,
                    }
                except requests.exceptions.SSLError:
                    continue
                except requests.exceptions.RequestException:
                    continue
            return {
                "hostname": host,
                "url": f"https://{host}",
                "status_code": None,
                "status": "dead",
                "title": "",
                "technologies": [],
            }

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futs = {pool.submit(probe, h): h for h in host_list}
            for fut in as_completed(futs):
                try:
                    item = fut.result()
                    if item:
                        results.append(item)
                except Exception as e:
                    logger.debug("probe error: %s", e)

        return ToolResult(
            tool=self.name,
            success=True,
            items=results,
            meta={"probed": len(host_list), "live": sum(1 for r in results if r.get("status") == "live")},
        )

    def parse(self, stdout: str) -> List[Any]:
        return []
