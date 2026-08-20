"""
Recon API routes — projects, scans, assets, tools health.
"""
from __future__ import annotations

import datetime
import logging
import threading
from functools import wraps

from flask import Blueprint, jsonify, request, session

from models.database import db
from models.recon import (
    Asset,
    Certificate,
    Project,
    ReconScan,
    Scope,
    TimelineEvent,
    ToolRun,
)
from recon.adapters.crtsh import CrtShAdapter
from recon.adapters.http_probe import HttpProbeAdapter
from recon.engine.pipeline import ReconPipeline
from recon.normalizers.hosts import normalize_hostname

logger = logging.getLogger(__name__)

recon_bp = Blueprint("recon", __name__, url_prefix="/api/recon")


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)

    return wrapper


@recon_bp.route("/projects", methods=["GET"])
@login_required
def list_projects():
    q = Project.query
    uid = session.get("user_id")
    if not session.get("is_admin"):
        q = q.filter_by(owner_user_id=uid)
    projects = q.order_by(Project.updated_at.desc()).limit(100).all()
    return jsonify({"projects": [p.to_dict() for p in projects]})


@recon_bp.route("/projects", methods=["POST"])
@login_required
def create_project():
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    root = normalize_hostname(data.get("root_domain") or data.get("domain") or "")
    if not root:
        return jsonify({"error": "root_domain is required"}), 400
    if not name:
        name = root

    project = Project(
        name=name,
        root_domain=root,
        status="ready",
        owner_user_id=session.get("user_id"),
        notes=(data.get("notes") or "")[:2000] or None,
    )
    db.session.add(project)
    db.session.flush()

    # Default scope
    includes = data.get("include") or [f"*.{root}", root]
    excludes = data.get("exclude") or []
    for pat in includes:
        db.session.add(Scope(project_id=project.id, pattern=pat, scope_type="include"))
    for pat in excludes:
        db.session.add(Scope(project_id=project.id, pattern=pat, scope_type="exclude"))

    db.session.commit()
    return jsonify(project.to_dict()), 201


@recon_bp.route("/projects/<project_id>", methods=["GET"])
@login_required
def get_project(project_id):
    project = Project.query.get(project_id)
    if not project:
        return jsonify({"error": "Project not found"}), 404
    scopes = Scope.query.filter_by(project_id=project_id).all()
    assets_count = Asset.query.filter_by(project_id=project_id).count()
    live = Asset.query.filter_by(project_id=project_id, status="live").count()
    last_scan = (
        ReconScan.query.filter_by(project_id=project_id)
        .order_by(ReconScan.started_at.desc())
        .first()
    )
    return jsonify(
        {
            **project.to_dict(),
            "scopes": [s.to_dict() for s in scopes],
            "assets_count": assets_count,
            "live_hosts": live,
            "last_scan": last_scan.to_dict() if last_scan else None,
        }
    )


@recon_bp.route("/projects/<project_id>/scans", methods=["POST"])
@login_required
def start_scan(project_id):
    project = Project.query.get(project_id)
    if not project:
        return jsonify({"error": "Project not found"}), 404

    data = request.get_json(force=True) or {}
    profile = (data.get("profile") or "passive").strip().lower()
    if profile not in ("passive", "enumeration", "web", "full"):
        profile = "passive"

    # Active-ish profiles require explicit authorization
    authorized = bool(data.get("authorized"))
    if profile in ("web", "full") and not authorized:
        return jsonify(
            {
                "error": "Active web probing requires authorized=true and written permission for the target scope"
            }
        ), 403

    # Passive always allowed
    if profile == "passive":
        authorized = True

    scan = ReconScan(
        project_id=project.id,
        profile=profile,
        status="queued",
        authorized=authorized,
        created_by=session.get("user_id"),
        progress=0,
        current_step="queued",
    )
    db.session.add(scan)
    project.status = "running"
    db.session.commit()

    from flask import current_app
    flask_app = current_app._get_current_object()

    def _run(app=flask_app, pid=project_id, sid=scan.id):
        with app.app_context():
            try:
                p = Project.query.get(pid)
                s = ReconScan.query.get(sid)
                if not p or not s:
                    return
                pipeline = ReconPipeline(p, s)
                pipeline.run()
            except Exception:
                logger.exception("Background recon failed")

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    return jsonify(scan.to_dict()), 202


@recon_bp.route("/projects/<project_id>/scans", methods=["GET"])
@login_required
def list_scans(project_id):
    scans = (
        ReconScan.query.filter_by(project_id=project_id)
        .order_by(ReconScan.started_at.desc())
        .limit(50)
        .all()
    )
    return jsonify({"scans": [s.to_dict() for s in scans]})


@recon_bp.route("/scans/<scan_id>", methods=["GET"])
@login_required
def get_scan(scan_id):
    scan = ReconScan.query.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan.to_dict())


@recon_bp.route("/projects/<project_id>/assets", methods=["GET"])
@login_required
def list_assets(project_id):
    q = Asset.query.filter_by(project_id=project_id)
    status = request.args.get("status")
    if status:
        q = q.filter_by(status=status)
    asset_type = request.args.get("type")
    if asset_type:
        q = q.filter_by(asset_type=asset_type)
    search = (request.args.get("q") or "").strip().lower()
    if search:
        q = q.filter(Asset.value.contains(search))
    live_only = request.args.get("live") == "1"
    if live_only:
        q = q.filter_by(status="live")
    interesting = request.args.get("interesting") == "1"
    if interesting:
        q = q.filter(Asset.priority_score >= 25)

    page = max(1, int(request.args.get("page", 1)))
    per_page = min(200, max(10, int(request.args.get("per_page", 50))))
    total = q.count()
    items = (
        q.order_by(Asset.priority_score.desc(), Asset.value.asc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return jsonify(
        {
            "assets": [a.to_dict() for a in items],
            "total": total,
            "page": page,
            "per_page": per_page,
        }
    )


@recon_bp.route("/projects/<project_id>/timeline", methods=["GET"])
@login_required
def timeline(project_id):
    events = (
        TimelineEvent.query.filter_by(project_id=project_id)
        .order_by(TimelineEvent.created_at.desc())
        .limit(200)
        .all()
    )
    return jsonify({"events": [e.to_dict() for e in events]})


@recon_bp.route("/projects/<project_id>/certificates", methods=["GET"])
@login_required
def certificates(project_id):
    certs = Certificate.query.filter_by(project_id=project_id).order_by(Certificate.created_at.desc()).all()
    return jsonify({"certificates": [c.to_dict() for c in certs]})


@recon_bp.route("/projects/<project_id>/summary", methods=["GET"])
@login_required
def summary(project_id):
    project = Project.query.get(project_id)
    if not project:
        return jsonify({"error": "Project not found"}), 404
    total = Asset.query.filter_by(project_id=project_id).count()
    live = Asset.query.filter_by(project_id=project_id, status="live").count()
    subs = Asset.query.filter_by(project_id=project_id, asset_type="subdomain").count()
    interesting = Asset.query.filter(
        Asset.project_id == project_id, Asset.priority_score >= 25
    ).count()
    last_scan = (
        ReconScan.query.filter_by(project_id=project_id)
        .order_by(ReconScan.started_at.desc())
        .first()
    )
    return jsonify(
        {
            "project": project.to_dict(),
            "subdomains": subs,
            "assets": total,
            "live_hosts": live,
            "interesting": interesting,
            "last_scan": last_scan.to_dict() if last_scan else None,
        }
    )


@recon_bp.route("/tools", methods=["GET"])
@login_required
def tools_health():
    adapters = [
        CrtShAdapter(),
        HttpProbeAdapter(),
    ]
    # Optional binaries
    optional = [
        ("subfinder", ["subfinder"]),
        ("assetfinder", ["assetfinder"]),
        ("findomain", ["findomain"]),
        ("amass", ["amass"]),
        ("httpx", ["httpx"]),
        ("dnsx", ["dnsx"]),
        ("katana", ["katana"]),
        ("nmap", ["nmap"]),
    ]
    import shutil

    tools = []
    for a in adapters:
        tools.append(
            {
                "name": a.name,
                "installed": a.is_available(),
                "hint": a.installation_hint(),
            }
        )
    for name, bins in optional:
        path = None
        for b in bins:
            path = shutil.which(b)
            if path:
                break
        tools.append(
            {
                "name": name,
                "installed": bool(path),
                "path": path,
                "hint": f"Install {name} (e.g. go install or apt) — optional for enhanced recon",
            }
        )
    return jsonify({"tools": tools})


@recon_bp.route("/export/<project_id>/subdomains.txt", methods=["GET"])
@login_required
def export_subdomains(project_id):
    assets = (
        Asset.query.filter(
            Asset.project_id == project_id,
            Asset.asset_type.in_(["domain", "subdomain"]),
        )
        .order_by(Asset.value)
        .all()
    )
    body = "\n".join(a.value for a in assets) + ("\n" if assets else "")
    from flask import Response

    return Response(body, mimetype="text/plain", headers={
        "Content-Disposition": f"attachment; filename={project_id}-subdomains.txt"
    })
