"""
Recon / attack-surface models for Secure v4.
"""
from __future__ import annotations

import datetime
import uuid

from models.database import db


def _uid() -> str:
    return str(uuid.uuid4())


class Project(db.Model):
    __tablename__ = "projects"

    id = db.Column(db.String(36), primary_key=True, default=_uid)
    name = db.Column(db.String(255), nullable=False)
    root_domain = db.Column(db.String(255), nullable=False, index=True)
    status = db.Column(db.String(32), default="ready")  # ready, running, complete, error
    owner_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    notes = db.Column(db.Text)

    scopes = db.relationship("Scope", backref="project", lazy="dynamic", cascade="all, delete-orphan")
    scans = db.relationship("ReconScan", backref="project", lazy="dynamic", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "root_domain": self.root_domain,
            "status": self.status,
            "owner_user_id": self.owner_user_id,
            "created_at": self.created_at.isoformat() + "Z" if self.created_at else None,
            "updated_at": self.updated_at.isoformat() + "Z" if self.updated_at else None,
            "notes": self.notes,
        }


class Scope(db.Model):
    __tablename__ = "scopes"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(36), db.ForeignKey("projects.id"), nullable=False, index=True)
    pattern = db.Column(db.String(512), nullable=False)  # e.g. *.example.com
    scope_type = db.Column(db.String(16), default="include")  # include | exclude
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "pattern": self.pattern,
            "scope_type": self.scope_type,
        }


class ReconScan(db.Model):
    __tablename__ = "recon_scans"

    id = db.Column(db.String(36), primary_key=True, default=_uid)
    project_id = db.Column(db.String(36), db.ForeignKey("projects.id"), nullable=False, index=True)
    profile = db.Column(db.String(64), default="passive")  # passive, enumeration, web, full
    status = db.Column(db.String(32), default="queued")  # queued, running, completed, failed, cancelled
    authorized = db.Column(db.Boolean, default=False)
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
    progress = db.Column(db.Integer, default=0)
    current_step = db.Column(db.String(128))
    error_message = db.Column(db.Text)
    stats = db.Column(db.JSON)  # counts snapshot
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "profile": self.profile,
            "status": self.status,
            "authorized": self.authorized,
            "started_at": self.started_at.isoformat() + "Z" if self.started_at else None,
            "finished_at": self.finished_at.isoformat() + "Z" if self.finished_at else None,
            "progress": self.progress,
            "current_step": self.current_step,
            "error_message": self.error_message,
            "stats": self.stats or {},
        }


class Asset(db.Model):
    """Unified asset node (domain, subdomain, IP, URL, etc.)."""
    __tablename__ = "assets"

    id = db.Column(db.String(36), primary_key=True, default=_uid)
    project_id = db.Column(db.String(36), db.ForeignKey("projects.id"), nullable=False, index=True)
    asset_type = db.Column(db.String(32), nullable=False, index=True)  # domain, subdomain, ip, url, endpoint
    value = db.Column(db.String(2048), nullable=False, index=True)
    status = db.Column(db.String(32), default="unknown")  # live, dead, redirect, forbidden, error, unknown
    title = db.Column(db.String(512))
    ip_address = db.Column(db.String(45), index=True)
    cname = db.Column(db.String(512))
    http_status = db.Column(db.Integer)
    technologies = db.Column(db.JSON)  # list of tech names
    priority_score = db.Column(db.Integer, default=0)
    priority_reasons = db.Column(db.JSON)
    first_seen = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    sources = db.Column(db.JSON)  # list of tool names
    meta = db.Column(db.JSON)

    __table_args__ = (
        db.UniqueConstraint("project_id", "asset_type", "value", name="uq_asset_project_type_value"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "asset_type": self.asset_type,
            "value": self.value,
            "status": self.status,
            "title": self.title,
            "ip_address": self.ip_address,
            "cname": self.cname,
            "http_status": self.http_status,
            "technologies": self.technologies or [],
            "priority_score": self.priority_score,
            "priority_reasons": self.priority_reasons or [],
            "first_seen": self.first_seen.isoformat() + "Z" if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() + "Z" if self.last_seen else None,
            "sources": self.sources or [],
            "meta": self.meta or {},
        }


class DNSRecord(db.Model):
    __tablename__ = "dns_records"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(36), db.ForeignKey("projects.id"), nullable=False, index=True)
    hostname = db.Column(db.String(512), nullable=False, index=True)
    record_type = db.Column(db.String(16), nullable=False)  # A, AAAA, CNAME, MX, NS, TXT, SOA
    value = db.Column(db.Text, nullable=False)
    ttl = db.Column(db.Integer)
    scan_id = db.Column(db.String(36), db.ForeignKey("recon_scans.id"), nullable=True)
    source = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "hostname": self.hostname,
            "record_type": self.record_type,
            "value": self.value,
            "ttl": self.ttl,
            "source": self.source,
            "created_at": self.created_at.isoformat() + "Z" if self.created_at else None,
        }


class Certificate(db.Model):
    __tablename__ = "certificates"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(36), db.ForeignKey("projects.id"), nullable=False, index=True)
    common_name = db.Column(db.String(512))
    subject = db.Column(db.Text)
    issuer = db.Column(db.Text)
    sans = db.Column(db.JSON)  # list of SAN domains
    not_before = db.Column(db.DateTime)
    not_after = db.Column(db.DateTime)
    fingerprint = db.Column(db.String(128), index=True)
    source = db.Column(db.String(64))
    scan_id = db.Column(db.String(36), db.ForeignKey("recon_scans.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "common_name": self.common_name,
            "subject": self.subject,
            "issuer": self.issuer,
            "sans": self.sans or [],
            "not_before": self.not_before.isoformat() + "Z" if self.not_before else None,
            "not_after": self.not_after.isoformat() + "Z" if self.not_after else None,
            "fingerprint": self.fingerprint,
            "source": self.source,
        }


class Technology(db.Model):
    __tablename__ = "technologies"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(36), db.ForeignKey("projects.id"), nullable=False, index=True)
    asset_id = db.Column(db.String(36), db.ForeignKey("assets.id"), nullable=True, index=True)
    name = db.Column(db.String(128), nullable=False, index=True)
    version = db.Column(db.String(64))
    confidence = db.Column(db.Float, default=0.5)
    source = db.Column(db.String(64))
    detected_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "asset_id": self.asset_id,
            "name": self.name,
            "version": self.version,
            "confidence": self.confidence,
            "source": self.source,
            "detected_at": self.detected_at.isoformat() + "Z" if self.detected_at else None,
        }


class Endpoint(db.Model):
    __tablename__ = "endpoints"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(36), db.ForeignKey("projects.id"), nullable=False, index=True)
    asset_id = db.Column(db.String(36), db.ForeignKey("assets.id"), nullable=True, index=True)
    url = db.Column(db.String(4096), nullable=False)
    method = db.Column(db.String(16), default="GET")
    status_code = db.Column(db.Integer)
    content_type = db.Column(db.String(128))
    source_page = db.Column(db.String(4096))
    source = db.Column(db.String(64))
    is_api = db.Column(db.Boolean, default=False)
    potential_secret = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "asset_id": self.asset_id,
            "url": self.url,
            "method": self.method,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "source_page": self.source_page,
            "source": self.source,
            "is_api": self.is_api,
            "potential_secret": self.potential_secret,
        }


class Relationship(db.Model):
    __tablename__ = "relationships"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(36), db.ForeignKey("projects.id"), nullable=False, index=True)
    source_asset_id = db.Column(db.String(36), db.ForeignKey("assets.id"), nullable=False, index=True)
    target_asset_id = db.Column(db.String(36), db.ForeignKey("assets.id"), nullable=False, index=True)
    relation_type = db.Column(db.String(64), nullable=False)  # resolves_to, cname, hosts, uses, ...
    meta = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "source_asset_id": self.source_asset_id,
            "target_asset_id": self.target_asset_id,
            "relation_type": self.relation_type,
            "meta": self.meta or {},
        }


class Observation(db.Model):
    __tablename__ = "observations"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(36), db.ForeignKey("projects.id"), nullable=False, index=True)
    scan_id = db.Column(db.String(36), db.ForeignKey("recon_scans.id"), nullable=True, index=True)
    asset_id = db.Column(db.String(36), db.ForeignKey("assets.id"), nullable=True, index=True)
    source = db.Column(db.String(64), nullable=False)
    observation_type = db.Column(db.String(64))
    raw_data = db.Column(db.JSON)
    confidence = db.Column(db.Float, default=1.0)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "scan_id": self.scan_id,
            "asset_id": self.asset_id,
            "source": self.source,
            "observation_type": self.observation_type,
            "raw_data": self.raw_data,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat() + "Z" if self.created_at else None,
        }


class ToolRun(db.Model):
    __tablename__ = "tool_runs"

    id = db.Column(db.String(36), primary_key=True, default=_uid)
    project_id = db.Column(db.String(36), db.ForeignKey("projects.id"), nullable=False, index=True)
    scan_id = db.Column(db.String(36), db.ForeignKey("recon_scans.id"), nullable=True, index=True)
    tool_name = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(32), default="queued")  # queued, running, completed, failed, skipped
    command_summary = db.Column(db.String(512))  # sanitized, no secrets
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
    exit_code = db.Column(db.Integer)
    error_message = db.Column(db.Text)
    result_count = db.Column(db.Integer, default=0)
    raw_path = db.Column(db.String(1024))

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "scan_id": self.scan_id,
            "tool_name": self.tool_name,
            "status": self.status,
            "command_summary": self.command_summary,
            "started_at": self.started_at.isoformat() + "Z" if self.started_at else None,
            "finished_at": self.finished_at.isoformat() + "Z" if self.finished_at else None,
            "exit_code": self.exit_code,
            "error_message": self.error_message,
            "result_count": self.result_count,
        }


class TimelineEvent(db.Model):
    __tablename__ = "timeline_events"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(36), db.ForeignKey("projects.id"), nullable=False, index=True)
    scan_id = db.Column(db.String(36), db.ForeignKey("recon_scans.id"), nullable=True)
    event_type = db.Column(db.String(64))
    message = db.Column(db.Text)
    level = db.Column(db.String(16), default="info")  # info, success, warn, error
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "scan_id": self.scan_id,
            "event_type": self.event_type,
            "message": self.message,
            "level": self.level,
            "created_at": self.created_at.isoformat() + "Z" if self.created_at else None,
        }
