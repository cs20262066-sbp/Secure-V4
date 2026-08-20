"""
Existing authentication / admin models — preserved for migration compatibility.
"""
from __future__ import annotations

import datetime
import uuid

from models.database import db


class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    company_name = db.Column(db.String(255))
    plan = db.Column(db.String(20), default="free")
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_login_at = db.Column(db.DateTime)
    failed_login_count = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "company_name": self.company_name,
            "plan": self.plan,
            "is_admin": self.is_admin,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() + "Z" if self.created_at else None,
            "last_login_at": (self.last_login_at.isoformat() + "Z") if self.last_login_at else None,
            "failed_login_count": self.failed_login_count,
        }


class LoginEvent(db.Model):
    __tablename__ = "login_event"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    email = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    success = db.Column(db.Boolean, default=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    reason = db.Column(db.String(120))
    threat_level = db.Column(db.String(20), default="low")

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() + "Z" if self.timestamp else None,
            "email": self.email,
            "success": self.success,
            "ip_address": self.ip_address,
            "reason": self.reason,
            "threat_level": self.threat_level,
        }


class ActiveSession(db.Model):
    __tablename__ = "active_session"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    session_token = db.Column(db.String(64), unique=True)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "ip_address": self.ip_address,
            "created_at": self.created_at.isoformat() + "Z" if self.created_at else None,
            "last_activity": self.last_activity.isoformat() + "Z" if self.last_activity else None,
            "is_active": self.is_active,
        }


class ThreatAlert(db.Model):
    __tablename__ = "threat_alert"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    threat_type = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    description = db.Column(db.Text)
    affected_resource = db.Column(db.String(500))
    ip_address = db.Column(db.String(45))
    details = db.Column(db.JSON)
    resolved = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() + "Z" if self.timestamp else None,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "description": self.description,
            "affected_resource": self.affected_resource,
            "ip_address": self.ip_address,
            "details": self.details,
            "resolved": self.resolved,
        }


class ScanResult(db.Model):
    __tablename__ = "scan_result"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    scan_type = db.Column(db.String(20))
    input_data = db.Column(db.Text)
    score = db.Column(db.Integer)
    risk_level = db.Column(db.String(20))
    findings = db.Column(db.JSON)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    cvss_score = db.Column(db.Float)
    vulnerabilities = db.Column(db.JSON)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() + "Z" if self.timestamp else None,
            "scan_type": self.scan_type,
            "input_data": self.input_data,
            "score": self.score,
            "risk_level": self.risk_level,
            "findings": self.findings,
            "cvss_score": self.cvss_score,
            "vulnerabilities": self.vulnerabilities,
        }


class MaliciousIP(db.Model):
    __tablename__ = "malicious_ip"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True)
    threat_level = db.Column(db.String(20))
    first_detected = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    reason = db.Column(db.Text)
    blocked = db.Column(db.Boolean, default=False)
    details = db.Column(db.JSON)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "threat_level": self.threat_level,
            "first_detected": self.first_detected.isoformat() + "Z" if self.first_detected else None,
            "last_seen": self.last_seen.isoformat() + "Z" if self.last_seen else None,
            "reason": self.reason,
            "blocked": self.blocked,
        }


class MonitoredTarget(db.Model):
    __tablename__ = "monitored_target"

    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    url = db.Column(db.String(2048), nullable=False)
    name = db.Column(db.String(255))
    interval_seconds = db.Column(db.Integer, default=60)
    enabled = db.Column(db.Boolean, default=True)
    last_scan_at = db.Column(db.DateTime)
    last_score = db.Column(db.Integer)
    last_risk = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.uid,
            "url": self.url,
            "name": self.name or self.url,
            "interval_seconds": self.interval_seconds,
            "enabled": self.enabled,
            "last_scan_at": (self.last_scan_at.isoformat() + "Z") if self.last_scan_at else None,
            "last_score": self.last_score,
            "last_risk": self.last_risk,
        }
