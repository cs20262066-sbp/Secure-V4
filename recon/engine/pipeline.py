"""
Recon pipeline orchestration — passive-first, concurrent collectors.
"""
from __future__ import annotations

import datetime
import logging
from pathlib import Path
from typing import Callable, Dict, List, Optional

from models.database import db
from models.recon import (
    Asset,
    Certificate,
    Observation,
    Project,
    ReconScan,
    Scope,
    TimelineEvent,
    ToolRun,
)
from recon.adapters.crtsh import CrtShAdapter
from recon.adapters.http_probe import HttpProbeAdapter
from recon.engine.scope import check_scope, filter_in_scope
from recon.normalizers.hosts import (
    dedupe_hostnames,
    is_interesting_hostname,
    normalize_hostname,
)

logger = logging.getLogger(__name__)

ProgressCallback = Optional[Callable[[str, int, str], None]]


def _timeline(project_id: str, scan_id: str, message: str, level: str = "info", event_type: str = "recon"):
    db.session.add(
        TimelineEvent(
            project_id=project_id,
            scan_id=scan_id,
            event_type=event_type,
            message=message,
            level=level,
        )
    )


def _upsert_asset(project_id: str, asset_type: str, value: str, **fields) -> Asset:
    value = normalize_hostname(value) if asset_type in ("domain", "subdomain") else value
    if not value:
        raise ValueError("empty asset value")
    asset = Asset.query.filter_by(project_id=project_id, asset_type=asset_type, value=value).first()
    now = datetime.datetime.utcnow()
    if asset:
        asset.last_seen = now
        for k, v in fields.items():
            if v is not None:
                setattr(asset, k, v)
        # merge sources
        if "sources" in fields and fields["sources"]:
            existing = set(asset.sources or [])
            existing.update(fields["sources"])
            asset.sources = sorted(existing)
    else:
        asset = Asset(
            project_id=project_id,
            asset_type=asset_type,
            value=value,
            first_seen=now,
            last_seen=now,
            **{k: v for k, v in fields.items() if v is not None},
        )
        db.session.add(asset)
    return asset


def _priority(hostname: str, status: str, title: str, techs: List[str]) -> tuple:
    score = 0
    reasons = []
    if status == "live":
        score += 20
        reasons.append("Live HTTPS/HTTP service")
    if is_interesting_hostname(hostname):
        score += 30
        reasons.append("Interesting hostname pattern")
    title_l = (title or "").lower()
    for kw in ("login", "admin", "dashboard", "api", "portal"):
        if kw in title_l or kw in hostname.lower():
            score += 15
            reasons.append(f"Keyword: {kw}")
            break
    if techs:
        score += min(10, len(techs) * 3)
        reasons.append(f"Technologies: {', '.join(techs[:4])}")
    level = "HIGH" if score >= 45 else "MEDIUM" if score >= 25 else "LOW"
    return score, reasons, level


class ReconPipeline:
    """Runs a recon profile for a project."""

    def __init__(self, project: Project, scan: ReconScan, raw_dir: Optional[Path] = None):
        self.project = project
        self.scan = scan
        self.raw_dir = raw_dir or Path("data/raw") / project.id / scan.id
        self.raw_dir.mkdir(parents=True, exist_ok=True)

    def _scopes(self):
        scopes = Scope.query.filter_by(project_id=self.project.id).all()
        includes = [s.pattern for s in scopes if s.scope_type == "include"]
        excludes = [s.pattern for s in scopes if s.scope_type == "exclude"]
        if not includes:
            includes = [f"*.{self.project.root_domain}", self.project.root_domain]
        return includes, excludes

    def _set_progress(self, step: str, progress: int):
        self.scan.current_step = step
        self.scan.progress = progress
        db.session.commit()

    def run(self) -> Dict:
        self.scan.status = "running"
        self.scan.started_at = datetime.datetime.utcnow()
        self.scan.progress = 0
        db.session.commit()

        includes, excludes = self._scopes()
        root = normalize_hostname(self.project.root_domain)
        stats = {
            "subdomains": 0,
            "live_hosts": 0,
            "certificates": 0,
            "technologies": 0,
        }

        try:
            # --- Root asset ---
            _upsert_asset(
                self.project.id,
                "domain",
                root,
                status="unknown",
                sources=["seed"],
            )
            db.session.commit()

            # --- Passive: crt.sh ---
            self._set_progress("Certificate / subdomain discovery (crt.sh)", 10)
            _timeline(self.project.id, self.scan.id, "Starting crt.sh certificate enumeration")

            crt = CrtShAdapter()
            tool_run = ToolRun(
                project_id=self.project.id,
                scan_id=self.scan.id,
                tool_name="crtsh",
                status="running",
                command_summary=f"crt.sh query %.{root}",
                started_at=datetime.datetime.utcnow(),
            )
            db.session.add(tool_run)
            db.session.commit()

            result = crt.execute(root, timeout=90)
            tool_run.finished_at = datetime.datetime.utcnow()
            tool_run.status = "completed" if result.success else "failed"
            tool_run.exit_code = 0 if result.success else 1
            tool_run.error_message = result.error
            tool_run.result_count = len(result.items)
            if result.raw:
                raw_path = self.raw_dir / "crtsh.json"
                raw_path.write_text(result.raw[:500_000], encoding="utf-8", errors="replace")
                tool_run.raw_path = str(raw_path)

            hosts = dedupe_hostnames([root] + list(result.items))
            in_scope, out_scope, _ = filter_in_scope(hosts, includes, excludes)

            for h in in_scope:
                atype = "domain" if h == root else "subdomain"
                _upsert_asset(self.project.id, atype, h, sources=["crtsh"])
                db.session.add(
                    Observation(
                        project_id=self.project.id,
                        scan_id=self.scan.id,
                        source="crtsh",
                        observation_type="subdomain",
                        raw_data={"hostname": h},
                        confidence=0.9,
                    )
                )

            # Certificate SANs → Certificate model
            if result.items:
                cert = Certificate(
                    project_id=self.project.id,
                    common_name=root,
                    sans=list(result.items)[:500],
                    source="crtsh",
                    scan_id=self.scan.id,
                )
                db.session.add(cert)
                stats["certificates"] = 1

            stats["subdomains"] = len(in_scope)
            _timeline(
                self.project.id,
                self.scan.id,
                f"crt.sh: {len(result.items)} names → {len(in_scope)} in-scope unique hosts",
                level="success",
            )
            db.session.commit()

            # --- Live host probe ---
            if self.scan.profile in ("passive", "enumeration", "web", "full") or True:
                self._set_progress("Live host validation", 50)
                _timeline(self.project.id, self.scan.id, f"Probing {len(in_scope)} hosts")

                probe = HttpProbeAdapter()
                # Cap concurrent probe set for safety / resources
                probe_list = in_scope[:200]
                probe_result = probe.execute(root, hosts=probe_list, timeout=6, max_workers=15)

                live_count = 0
                for item in probe_result.items:
                    host = item.get("hostname")
                    if not host:
                        continue
                    if check_scope(host, includes, excludes) != "IN_SCOPE":
                        continue
                    status = item.get("status") or "unknown"
                    techs = item.get("technologies") or []
                    score, reasons, _level = _priority(host, status, item.get("title") or "", techs)
                    atype = "domain" if host == root else "subdomain"
                    _upsert_asset(
                        self.project.id,
                        atype,
                        host,
                        status=status,
                        title=item.get("title"),
                        http_status=item.get("status_code"),
                        technologies=techs,
                        priority_score=score,
                        priority_reasons=reasons,
                        sources=["http_probe"],
                        meta={
                            "url": item.get("url"),
                            "server": item.get("server"),
                            "content_type": item.get("content_type"),
                        },
                    )
                    if status == "live":
                        live_count += 1
                    if techs:
                        stats["technologies"] += len(techs)

                stats["live_hosts"] = live_count
                _timeline(
                    self.project.id,
                    self.scan.id,
                    f"Live hosts: {live_count}/{len(probe_list)}",
                    level="success",
                )
                db.session.commit()

            self._set_progress("Correlation complete", 100)
            self.scan.status = "completed"
            self.scan.finished_at = datetime.datetime.utcnow()
            self.scan.stats = stats
            self.project.status = "complete"
            self.project.updated_at = datetime.datetime.utcnow()
            _timeline(self.project.id, self.scan.id, f"Recon complete: {stats}", level="success")
            db.session.commit()
            return {"ok": True, "stats": stats}

        except Exception as e:
            logger.exception("Recon pipeline failed")
            self.scan.status = "failed"
            self.scan.error_message = str(e)[:500]
            self.scan.finished_at = datetime.datetime.utcnow()
            self.project.status = "error"
            _timeline(self.project.id, self.scan.id, f"Recon failed: {e}", level="error")
            db.session.commit()
            return {"ok": False, "error": str(e)}
