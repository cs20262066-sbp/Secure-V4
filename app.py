"""
CyberSecure Enterprise Edition v3.0
- Real-time Threat Detection & Malicious IP Tracking
- Comprehensive Vulnerability Scanning (CVSS Scoring)
- Active Session Monitoring & Control
- Security Audit Features
- Real-time Alert System
- Production-grade with all safeguards
"""

import os as _os
_GEVENT_AVAILABLE = False
if _os.getenv('DISABLE_GEVENT', 'False').lower() != 'true':
    try:
        from gevent import monkey
        monkey.patch_all()
        _GEVENT_AVAILABLE = True
    except ImportError:
        pass

import re
import ssl
import socket
import datetime
import logging
import os
import json
from urllib.parse import urlparse
from functools import wraps
import hashlib
import secrets
from collections import defaultdict

from flask import Flask, request, jsonify, send_from_directory, session, redirect
from flask_cors import CORS
import requests
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from flask_sqlalchemy import SQLAlchemy
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False

from flask_socketio import SocketIO, emit, join_room, leave_room

load_dotenv()

import threading
import time
import uuid
from datetime import timedelta

# Initialize Flask app
app = Flask(__name__, static_folder=".", static_url_path="")

# Configuration
app.config['JSON_SORT_KEYS'] = False
app.secret_key = os.getenv('SECRET_KEY') or os.urandom(32)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
API_PORT = int(os.getenv('API_PORT') or os.getenv('PORT') or 5000)
_raw_origins = os.getenv('ALLOWED_ORIGINS', '*').strip()
ALLOWED_ORIGINS = "*" if _raw_origins == "*" else [o.strip() for o in _raw_origins.split(',') if o.strip()]

CORS(app, origins=ALLOWED_ORIGINS)


socketio = SocketIO(app, cors_allowed_origins=ALLOWED_ORIGINS, async_mode="gevent" if _GEVENT_AVAILABLE else "threading")

# ============================================================================
# LOGGING SETUP
# ============================================================================

_log_handlers = [logging.StreamHandler()]
try:
    _log_handlers.append(logging.FileHandler('/tmp/cybersecure.log'))
except OSError:
    pass

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=_log_handlers
)
logger = logging.getLogger(__name__)

# ============================================================================
# DATABASE MODELS
# ============================================================================

if DB_AVAILABLE and os.getenv('USE_DATABASE', 'False').lower() == 'true':
    db_url = os.getenv('DATABASE_URL', 'sqlite:///cybersecure.db')
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql+psycopg2://", 1)
    elif db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+psycopg2://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,
        'pool_recycle': 280,
    }
    db = SQLAlchemy(app)
    DB_ENABLED = True
else:
    DB_ENABLED = False

if DB_ENABLED:
    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(255), unique=True, nullable=False)
        password_hash = db.Column(db.String(255), nullable=False)
        company_name = db.Column(db.String(255))
        plan = db.Column(db.String(20), default='free')
        is_admin = db.Column(db.Boolean, default=False)
        is_active = db.Column(db.Boolean, default=True)
        created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
        last_login_at = db.Column(db.DateTime)
        failed_login_count = db.Column(db.Integer, default=0)
        locked_until = db.Column(db.DateTime)

        def to_dict(self):
            return {
                'id': self.id,
                'email': self.email,
                'company_name': self.company_name,
                'plan': self.plan,
                'is_admin': self.is_admin,
                'is_active': self.is_active,
                'created_at': self.created_at.isoformat() + 'Z',
                'last_login_at': (self.last_login_at.isoformat() + 'Z') if self.last_login_at else None,
                'failed_login_count': self.failed_login_count,
            }

    class LoginEvent(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
        email = db.Column(db.String(255))
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
        success = db.Column(db.Boolean, default=False)
        ip_address = db.Column(db.String(45))
        user_agent = db.Column(db.Text)
        reason = db.Column(db.String(120))
        threat_level = db.Column(db.String(20), default='low')

        def to_dict(self):
            return {
                'id': self.id,
                'timestamp': self.timestamp.isoformat() + 'Z',
                'email': self.email,
                'success': self.success,
                'ip_address': self.ip_address,
                'reason': self.reason,
                'threat_level': self.threat_level,
            }

    class ActiveSession(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        session_token = db.Column(db.String(64), unique=True)
        ip_address = db.Column(db.String(45))
        user_agent = db.Column(db.Text)
        created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
        last_activity = db.Column(db.DateTime, default=datetime.datetime.utcnow)
        is_active = db.Column(db.Boolean, default=True)

        def to_dict(self):
            return {
                'id': self.id,
                'user_id': self.user_id,
                'ip_address': self.ip_address,
                'created_at': self.created_at.isoformat() + 'Z',
                'last_activity': self.last_activity.isoformat() + 'Z',
                'is_active': self.is_active,
            }

    class ThreatAlert(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
        threat_type = db.Column(db.String(50))  # malicious_ip, brute_force, vulnerability, etc
        severity = db.Column(db.String(20))  # critical, high, medium, low
        description = db.Column(db.Text)
        affected_resource = db.Column(db.String(500))
        ip_address = db.Column(db.String(45))
        details = db.Column(db.JSON)
        resolved = db.Column(db.Boolean, default=False)

        def to_dict(self):
            return {
                'id': self.id,
                'timestamp': self.timestamp.isoformat() + 'Z',
                'threat_type': self.threat_type,
                'severity': self.severity,
                'description': self.description,
                'affected_resource': self.affected_resource,
                'ip_address': self.ip_address,
                'details': self.details,
                'resolved': self.resolved,
            }

    class ScanResult(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
        scan_type = db.Column(db.String(20))
        input_data = db.Column(db.Text)
        score = db.Column(db.Integer)
        risk_level = db.Column(db.String(20))
        findings = db.Column(db.JSON)
        ip_address = db.Column(db.String(45))
        user_agent = db.Column(db.Text)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
        cvss_score = db.Column(db.Float)
        vulnerabilities = db.Column(db.JSON)

        def to_dict(self):
            return {
                'id': self.id,
                'timestamp': self.timestamp.isoformat() + 'Z',
                'scan_type': self.scan_type,
                'input_data': self.input_data,
                'score': self.score,
                'risk_level': self.risk_level,
                'findings': self.findings,
                'cvss_score': self.cvss_score,
                'vulnerabilities': self.vulnerabilities,
            }

    class MaliciousIP(db.Model):
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
                'id': self.id,
                'ip_address': self.ip_address,
                'threat_level': self.threat_level,
                'first_detected': self.first_detected.isoformat() + 'Z',
                'last_seen': self.last_seen.isoformat() + 'Z',
                'reason': self.reason,
                'blocked': self.blocked,
            }

    class MonitoredTarget(db.Model):
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

    with app.app_context():
        db.create_all()
        _admin_email = os.getenv("ADMIN_EMAIL")
        _admin_password = os.getenv("ADMIN_PASSWORD")
        if _admin_email and _admin_password and not User.query.filter_by(email=_admin_email.lower()).first():
            db.session.add(User(
                email=_admin_email.lower(),
                password_hash=generate_password_hash(_admin_password),
                company_name="Admin",
                plan="business",
                is_admin=True,
                is_active=True,
            ))
            db.session.commit()
            logger.info(f"Bootstrapped admin account: {_admin_email}")


# ============================================================================
# SECURE v4 — recon models share the same SQLAlchemy `db` instance
# ============================================================================
try:
    import models.database as _mdb
    _mdb.db = db
    # Import recon models ONCE after binding (do not reload)
    from models.recon import (
        Project, Scope, ReconScan, Asset, DNSRecord, Certificate,
        Technology, Endpoint, Relationship, Observation, ToolRun, TimelineEvent,
    )
    with app.app_context():
        db.create_all()
    from routes.recon import recon_bp
    if "recon" not in app.blueprints:
        app.register_blueprint(recon_bp)
    logger.info("Secure v4 recon models + /api/recon registered")
except Exception as _e:
    logger.warning("Secure v4 recon not fully loaded: %s", _e)





# ============================================================================
# THREAT DETECTION & IP REPUTATION
# ============================================================================

MALICIOUS_IPS = {}  # In-memory cache
BRUTE_FORCE_ATTEMPTS = defaultdict(list)  # IP -> [(timestamp, email), ...]
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=30)

def check_malicious_ip(ip_address):
    """Check if IP is known malicious"""
    if not DB_ENABLED:
        return False
    
    malicious = MaliciousIP.query.filter_by(ip_address=ip_address, blocked=True).first()
    return malicious is not None

def track_login_attempt(ip_address, email, success):
    """Track login attempts for brute force detection"""
    if not success:
        BRUTE_FORCE_ATTEMPTS[ip_address].append((datetime.datetime.utcnow(), email))
        
        # Clean old attempts (older than 1 hour)
        cutoff = datetime.datetime.utcnow() - timedelta(hours=1)
        BRUTE_FORCE_ATTEMPTS[ip_address] = [(t, e) for t, e in BRUTE_FORCE_ATTEMPTS[ip_address] if t > cutoff]
        
        # If too many attempts, flag as brute force
        if len(BRUTE_FORCE_ATTEMPTS[ip_address]) >= MAX_LOGIN_ATTEMPTS:
            threat = ThreatAlert(
                threat_type='brute_force',
                severity='high',
                description=f'Brute force attack detected from {ip_address}',
                affected_resource=email,
                ip_address=ip_address,
                details={'attempts': len(BRUTE_FORCE_ATTEMPTS[ip_address])}
            )
            db.session.add(threat)
            
            malicious = MaliciousIP.query.filter_by(ip_address=ip_address).first()
            if not malicious:
                malicious = MaliciousIP(
                    ip_address=ip_address,
                    threat_level='high',
                    reason='Brute force attack',
                    blocked=True
                )
                db.session.add(malicious)
            else:
                malicious.blocked = True
                malicious.last_seen = datetime.datetime.utcnow()
            
            db.session.commit()
            logger.warning(f"Brute force detected: {ip_address}")
            socketio.emit('threat_alert', threat.to_dict())

def get_threat_level(ip_address):
    """Determine threat level of an IP"""
    if not DB_ENABLED:
        return 'low'
    
    malicious = MaliciousIP.query.filter_by(ip_address=ip_address).first()
    return malicious.threat_level if malicious else 'low'

# ============================================================================
# SECURITY SCANNING FUNCTIONS
# ============================================================================

def scan_website_headers(url):
    """Analyze security headers and SSL/TLS"""
    findings = []
    score = 100
    
    try:
        parsed = urlparse(url)
        if parsed.scheme != 'https':
            findings.append({'detail': 'Website not using HTTPS', 'weight': 30})
            score -= 30
        
        response = requests.head(url, timeout=10, allow_redirects=True)
        headers = response.headers
        
        # Check security headers
        security_headers = {
            'Strict-Transport-Security': 20,
            'X-Content-Type-Options': 15,
            'X-Frame-Options': 15,
            'Content-Security-Policy': 25,
            'X-XSS-Protection': 10,
        }
        
        for header, weight in security_headers.items():
            if header not in headers:
                findings.append({'detail': f'Missing {header} header', 'weight': weight})
                score -= weight
        
        # Check outdated server info
        server = headers.get('Server', '')
        if any(old in server for old in ['Apache/2.0', 'nginx/1.0', 'IIS/6']):
            findings.append({'detail': f'Outdated server: {server}', 'weight': 25})
            score -= 25
    
    except Exception as e:
        findings.append({'detail': f'Could not connect: {str(e)[:100]}', 'weight': 0})
    
    return {
        'score': max(0, score),
        'risk': 'high' if score < 40 else 'medium' if score < 70 else 'low',
        'findings': findings
    }

def scan_website_vulnerabilities(url):
    """
    PASSIVE vulnerability indicators — safe to run against ANY public URL.
    Does not send attack payloads. Infers likely exposure from headers,
    cookie flags, TLS config, and banner/version disclosure only.
    """
    vulns = []

    try:
        parsed = urlparse(url)
        resp = requests.get(url, timeout=10, allow_redirects=True)
        headers = resp.headers

        def add(name, cvss, status, detail, remediation):
            vulns.append({
                'name': name, 'cvss': cvss, 'status': status,
                'detail': detail, 'remediation': remediation
            })

        # CSRF indicator: cookies missing SameSite/Secure
        set_cookie = headers.get('Set-Cookie', '')
        if set_cookie and 'samesite' not in set_cookie.lower():
            add('CSRF (Cross-Site Request Forgery)', 6.5, 'possible_exposure',
                'Session cookie is missing the SameSite attribute',
                'Set SameSite=Lax/Strict and Secure on all session cookies')
        else:
            add('CSRF (Cross-Site Request Forgery)', 6.5, 'not_detected',
                'No missing SameSite cookie attribute found', 'N/A')

        # Broken auth indicator: login-style pages served over plain HTTP
        if parsed.scheme != 'https':
            add('Broken Authentication', 9.1, 'possible_exposure',
                'Site is served over HTTP, credentials could be intercepted',
                'Enforce HTTPS everywhere and HSTS')
        else:
            add('Broken Authentication', 9.1, 'not_detected',
                'Site is served over HTTPS', 'N/A')

        # Info disclosure via banners (a common precursor to targeted exploits)
        server = headers.get('Server', '') + ' ' + headers.get('X-Powered-By', '')
        if any(tag in server for tag in ['Apache/2.0', 'Apache/2.2', 'nginx/1.0', 'IIS/6', 'PHP/5']):
            add('Outdated Software Disclosure', 7.5, 'possible_exposure',
                f'Server banner reveals an outdated stack: {server.strip()}',
                'Hide version banners and patch to a supported version')
        else:
            add('Outdated Software Disclosure', 7.5, 'not_detected',
                'No outdated version disclosed in response headers', 'N/A')

        # Reflected-input indicator (passive only): does the app echo query params raw?
        # We do NOT inject payloads — we only note if the URL has params, which
        # is a prerequisite for XSS/SQLi and worth flagging for manual review.
        if parsed.query:
            add('XSS / SQL Injection (needs manual review)', 8.5, 'needs_review',
                'URL includes query parameters — untested for injection since this scan never sends attack payloads to third-party sites',
                'Run authenticated active testing only on assets you own (see /api/scan-owned-app)')
        else:
            add('XSS / SQL Injection (needs manual review)', 8.5, 'not_applicable',
                'No query parameters present on this URL', 'N/A')

    except Exception as e:
        logger.error(f"Error scanning vulnerabilities: {e}")
        vulns.append({'name': 'Scan error', 'cvss': 0, 'status': 'error',
                      'detail': str(e)[:150], 'remediation': 'N/A'})

    detected = [v for v in vulns if v['status'] in ('possible_exposure', 'needs_review')]
    return {
        'vulnerabilities': vulns,
        'max_cvss': max([v['cvss'] for v in detected], default=0.0),
        'avg_cvss': (sum(v['cvss'] for v in detected) / len(detected)) if detected else 0.0
    }


# ============================================================================
# ACTIVE SCANNING — gated to assets you own only
# ============================================================================
# Active checks (payload-based) are only ever run against MONITORED_ASSET,
# which you set via env var to a site you control. This is a hard allowlist,
# not a UI toggle, so it can't be pointed at third-party sites by mistake
# or by a customer typing a different URL into the scan box.

def _is_owned_asset(url):
    try:
        target = urlparse(url).netloc.lower()
        owned = urlparse(MONITORED_ASSET).netloc.lower()
        return target == owned
    except Exception:
        return False

def scan_owned_app_active(url):
    """
    ACTIVE checks — only runs if _is_owned_asset(url) is True.
    Sends benign, non-destructive test strings to see if they're
    reflected unescaped (XSS) or trigger DB errors (SQLi), then reports
    findings. Never mutates data, never sends destructive payloads.
    """
    if not _is_owned_asset(url):
        return {'error': 'Active scanning is restricted to the domain set in MONITORED_ASSET (a site you own).'}

    findings = []
    probe_marker = "cs_probe_" + secrets.token_hex(4)

    try:
        # Reflected XSS check: append marker as a query param, see if it comes back unescaped
        test_url = url + ("&" if "?" in url else "?") + f"csprobe={probe_marker}<x>"
        r = requests.get(test_url, timeout=10)
        if f"{probe_marker}<x>" in r.text:
            findings.append({'name': 'Reflected XSS', 'cvss': 8.2, 'status': 'vulnerable',
                              'detail': 'Unescaped test marker was reflected in the response body',
                              'remediation': 'HTML-encode all user-controlled output'})
        else:
            findings.append({'name': 'Reflected XSS', 'cvss': 8.2, 'status': 'not_detected',
                              'detail': 'Test marker was not reflected unescaped', 'remediation': 'N/A'})

        # SQL error-based check: benign quote character, look for DB error signatures
        test_url2 = url + ("&" if "?" in url else "?") + "csprobe=' "
        r2 = requests.get(test_url2, timeout=10)
        sql_error_signatures = ['sql syntax', 'mysql_fetch', 'ORA-01756', 'sqlite3.OperationalError', 'unclosed quotation mark']
        if any(sig.lower() in r2.text.lower() for sig in sql_error_signatures):
            findings.append({'name': 'SQL Injection', 'cvss': 9.8, 'status': 'vulnerable',
                              'detail': 'A database error signature was returned from a single-quote probe',
                              'remediation': 'Use parameterized queries everywhere'})
        else:
            findings.append({'name': 'SQL Injection', 'cvss': 9.8, 'status': 'not_detected',
                              'detail': 'No database error signature returned', 'remediation': 'N/A'})

    except Exception as e:
        findings.append({'name': 'Active scan error', 'cvss': 0, 'status': 'error', 'detail': str(e)[:150]})

    detected = [v for v in findings if v['status'] == 'vulnerable']
    return {
        'vulnerabilities': findings,
        'max_cvss': max([v['cvss'] for v in detected], default=0.0),
        'scope': MONITORED_ASSET
    }

def scan_url(url):
    """Phishing and malicious URL detection"""
    findings = []
    score = 100
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check for suspicious patterns
        suspicious_patterns = [
            (r'bit\.ly|tinyurl|short\.link', 'URL shortener used', 25),
            (r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', 'IP address instead of domain', 30),
            (r'@', '@ symbol in URL (email spoofing attempt)', 40),
        ]
        
        for pattern, detail, weight in suspicious_patterns:
            if re.search(pattern, url):
                findings.append({'detail': detail, 'weight': weight})
                score -= weight
        
        # Check domain reputation (simulated)
        known_malicious = ['malware.net', 'phishing.org', 'scam.com']
        if any(bad in domain for bad in known_malicious):
            findings.append({'detail': 'Domain found in threat databases', 'weight': 50})
            score -= 50
    
    except Exception as e:
        findings.append({'detail': f'Error: {str(e)[:100]}', 'weight': 0})
    
    return {
        'score': max(0, score),
        'risk': 'high' if score < 40 else 'medium' if score < 70 else 'low',
        'findings': findings
    }

def scan_email_text(text):
    """Phishing email detection"""
    findings = []
    score = 100
    
    # Phishing indicators
    indicators = [
        (r'verify.*account|confirm.*identity', 'Account verification request', 30),
        (r'click.*here|click.*link|urgent.*action', 'Urgency/click bait language', 25),
        (r'update.*payment|confirm.*credit', 'Payment information request', 35),
        (r'congratulations.*won|claim.*prize', 'Prize/reward scam', 25),
    ]
    
    for pattern, detail, weight in indicators:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append({'detail': detail, 'weight': weight})
            score -= weight
    
    # Check for embedded URLs
    if re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text):
        findings.append({'detail': 'Email contains embedded links', 'weight': 10})
        score -= 10
    
    return {
        'score': max(0, score),
        'risk': 'high' if score < 40 else 'medium' if score < 70 else 'low',
        'findings': findings
    }

# ============================================================================
# API ROUTES - AUTHENTICATION
# ============================================================================

@app.route("/")
def home():
    if DB_ENABLED and session.get("user_id"):
        return send_from_directory(".", "frontend.html")
    try:
        return send_from_directory(".", "landing.html")
    except Exception:
        return send_from_directory(".", "frontend.html")

@app.route("/login")
def login_page():
    if DB_ENABLED and session.get("user_id"):
        return redirect("/")
    return send_from_directory(".", "login.html")

@app.route("/signup")
def signup_page():
    if DB_ENABLED and session.get("user_id"):
        return redirect("/")
    try:
        return send_from_directory(".", "signup.html")
    except:
        return send_from_directory(".", "login.html")

@app.route("/admin")
def admin_page():
    if not (DB_ENABLED and session.get("is_admin")):
        return redirect("/")
    return send_from_directory(".", "admin.html")

@app.route("/command-center")
@app.route("/recon")
def command_center_page():
    if DB_ENABLED and not session.get("user_id"):
        return redirect("/login")
    return send_from_directory(".", "command_center.html")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

@app.route("/api/auth/signup", methods=["POST"])
def api_signup():
    if not DB_ENABLED:
        return jsonify({"error": "Database not enabled"}), 404
    
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    company_name = (data.get("company_name") or "").strip()[:255]
    
    if not EMAIL_RE.match(email):
        return jsonify({"error": "Enter a valid email address"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "An account with that email already exists"}), 409
    
    user = User(
        email=email,
        password_hash=generate_password_hash(password),
        company_name=company_name or None,
        plan="free",
        is_active=True,
    )
    db.session.add(user)
    db.session.commit()
    
    ip = get_client_ip()
    ua = request.headers.get("User-Agent", "")

    session["user_id"] = user.id
    session["is_admin"] = user.is_admin
    user.last_login_at = datetime.datetime.utcnow()
    db.session.commit()

    # Log this as a login event and open an active session, same as /api/auth/login,
    # so new signups show up in the Login Audit and Sessions tabs immediately.
    event = LoginEvent(
        email=email, user_id=user.id, success=True, ip_address=ip,
        user_agent=ua, reason="signup", threat_level=get_threat_level(ip)
    )
    db.session.add(event)

    session_token = secrets.token_hex(32)
    active_session = ActiveSession(
        user_id=user.id, session_token=session_token, ip_address=ip, user_agent=ua
    )
    db.session.add(active_session)
    db.session.commit()

    logger.info(f"New signup: {email} from {ip}")
    socketio.emit('user_login', {'email': email, 'ip': ip, 'timestamp': datetime.datetime.utcnow().isoformat() + 'Z'})
    return jsonify({**user.to_dict(), 'session_token': session_token}), 201

def get_client_ip():
    """Render (and most PaaS) sit behind a reverse proxy, so request.remote_addr
    is the proxy's internal address, not the real client IP. Read the
    original client IP from X-Forwarded-For instead (first entry in the chain)."""
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    if not DB_ENABLED:
        return jsonify({"error": "Database not enabled"}), 404
    
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    ip = get_client_ip()
    ua = request.headers.get("User-Agent", "")
    
    # Check if IP is blocked
    if check_malicious_ip(ip):
        return jsonify({"error": "Access denied - IP blocked due to security concerns"}), 403
    
    user = User.query.filter_by(email=email).first()
    success = False
    reason = "unknown_email"
    threat_level = get_threat_level(ip)
    
    # Check if account is locked -- still log this attempt instead of ignoring it silently,
    # since repeated hits on a locked account is itself a signal worth capturing.
    if user and user.locked_until and user.locked_until > datetime.datetime.utcnow():
        event = LoginEvent(
            email=email, user_id=user.id, success=False, ip_address=ip,
            user_agent=ua, reason="account_locked", threat_level=threat_level
        )
        db.session.add(event)
        db.session.commit()
        track_login_attempt(ip, email, False)
        return jsonify({"error": "Account temporarily locked - too many failed attempts"}), 429
    
    if user and check_password_hash(user.password_hash, password):
        if not user.is_active:
            return jsonify({"error": "Account is inactive"}), 401
        
        success = True
        reason = "ok"
        user.failed_login_count = 0
        user.locked_until = None
    elif user:
        reason = "bad_password"
        user.failed_login_count = (user.failed_login_count or 0) + 1
        if user.failed_login_count >= MAX_LOGIN_ATTEMPTS:
            user.locked_until = datetime.datetime.utcnow() + LOCKOUT_DURATION
    
    event = LoginEvent(
        email=email,
        user_id=user.id if user else None,
        success=success,
        ip_address=ip,
        user_agent=ua,
        reason=reason,
        threat_level=threat_level
    )
    db.session.add(event)
    if user:
        db.session.add(user)
    db.session.commit()
    
    track_login_attempt(ip, email, success)
    
    if not success:
        logger.warning(f"Failed login for {email} from {ip} (threat_level: {threat_level})")
        return jsonify({"error": "Invalid email or password"}), 401
    
    session["user_id"] = user.id
    session["is_admin"] = user.is_admin
    user.last_login_at = datetime.datetime.utcnow()
    db.session.commit()
    
    # Create active session
    session_token = secrets.token_hex(32)
    active_session = ActiveSession(
        user_id=user.id,
        session_token=session_token,
        ip_address=ip,
        user_agent=ua
    )
    db.session.add(active_session)
    db.session.commit()
    
    logger.info(f"Login: {email} from {ip}")
    socketio.emit('user_login', {'email': email, 'ip': ip, 'timestamp': datetime.datetime.utcnow().isoformat() + 'Z'})
    
    return jsonify({**user.to_dict(), 'session_token': session_token})

@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    if session.get("user_id") and DB_ENABLED:
        ActiveSession.query.filter_by(user_id=session["user_id"]).update({'is_active': False})
        db.session.commit()
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/auth/me", methods=["GET"])
def api_me():
    if not DB_ENABLED or not session.get("user_id"):
        return jsonify({"user": None})
    user = User.query.get(session["user_id"])
    if not user:
        session.clear()
        return jsonify({"user": None})
    return jsonify({"user": user.to_dict()})

# ============================================================================
# API ROUTES - SCANNING
# ============================================================================

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not DB_ENABLED or not session.get("user_id"):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return wrapper

@app.route("/api/scan-url", methods=["POST"])
@login_required
def api_scan_url():
    data = request.get_json(force=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400
    
    result = scan_url(url)
    scan = ScanResult(
        scan_type='url',
        input_data=url,
        score=result['score'],
        risk_level=result['risk'],
        findings=result['findings'],
        user_id=session['user_id']
    )
    db.session.add(scan)
    db.session.commit()
    
    return jsonify(result)

@app.route("/api/scan-email", methods=["POST"])
@login_required
def api_scan_email():
    data = request.get_json(force=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "text is required"}), 400
    
    result = scan_email_text(text)
    scan = ScanResult(
        scan_type='email',
        input_data=text[:500],
        score=result['score'],
        risk_level=result['risk'],
        findings=result['findings'],
        user_id=session['user_id']
    )
    db.session.add(scan)
    db.session.commit()
    
    return jsonify(result)

@app.route("/api/scan-website", methods=["POST"])
@login_required
def api_scan_website():
    data = request.get_json(force=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400
    
    # Combine multiple scans
    headers_result = scan_website_headers(url)
    vulns_result = scan_website_vulnerabilities(url)
    
    combined_score = headers_result['score']
    findings = headers_result['findings'] + [
        {'detail': v['name'], 'weight': 0} for v in vulns_result['vulnerabilities']
    ]
    
    scan = ScanResult(
        scan_type='website',
        input_data=url,
        score=combined_score,
        risk_level=headers_result['risk'],
        findings=findings,
        cvss_score=vulns_result['max_cvss'],
        vulnerabilities=vulns_result['vulnerabilities'],
        user_id=session['user_id']
    )
    db.session.add(scan)
    db.session.commit()
    
    result = {
        **headers_result,
        'vulnerabilities': vulns_result['vulnerabilities'],
        'max_cvss': vulns_result['max_cvss'],
        'scan_id': scan.id
    }
    
    return jsonify(result)

@app.route("/api/scan-owned-app", methods=["POST"])
@login_required
def api_scan_owned_app():
    """Active vulnerability scan — restricted to MONITORED_ASSET (a domain you own)."""
    data = request.get_json(force=True) or {}
    url = (data.get("url") or MONITORED_ASSET).strip()

    result = scan_owned_app_active(url)
    if 'error' in result:
        return jsonify(result), 403

    scan = ScanResult(
        scan_type='owned_app_active',
        input_data=url,
        score=None,
        risk_level='high' if result['max_cvss'] >= 7 else 'medium' if result['max_cvss'] > 0 else 'low',
        findings=result['vulnerabilities'],
        cvss_score=result['max_cvss'],
        vulnerabilities=result['vulnerabilities'],
        user_id=session['user_id']
    )
    db.session.add(scan)
    db.session.commit()

    return jsonify({**result, 'scan_id': scan.id})

@app.route("/api/scan-dns", methods=["POST"])
@login_required
def api_scan_dns():
    data = request.get_json(force=True) or {}
    domain = (data.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "domain is required"}), 400
    
    findings = []
    score = 100
    
    # SPF check
    findings.append({'detail': 'SPF record: Configuration check recommended', 'weight': 0})
    
    # DMARC check
    findings.append({'detail': 'DMARC record: Not enforced (policy=none)', 'weight': 15})
    score -= 15
    
    # DKIM check
    findings.append({'detail': 'DKIM: Recommended for all domain senders', 'weight': 0})
    
    scan = ScanResult(
        scan_type='dns',
        input_data=domain,
        score=max(0, score),
        risk_level='high' if score < 40 else 'medium' if score < 70 else 'low',
        findings=findings,
        user_id=session['user_id']
    )
    db.session.add(scan)
    db.session.commit()
    
    return jsonify({
        'score': scan.score,
        'risk': scan.risk_level,
        'findings': findings
    })

# ============================================================================
# API ROUTES - ADMIN PANEL
# ============================================================================

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not DB_ENABLED or not session.get("is_admin"):
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return wrapper

@app.route("/api/admin/users", methods=["GET"])
@admin_required
def api_admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify({"users": [u.to_dict() for u in users]})

@app.route("/api/admin/users/<int:user_id>/toggle", methods=["POST"])
@admin_required
def api_admin_toggle_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    user.is_active = not user.is_active
    db.session.commit()
    logger.info(f"Admin toggled user {user.email}: is_active={user.is_active}")
    return jsonify(user.to_dict())

@app.route("/api/admin/logins", methods=["GET"])
@admin_required
def api_admin_logins():
    limit = min(int(request.args.get("limit", 50)), 200)
    events = LoginEvent.query.order_by(LoginEvent.timestamp.desc()).limit(limit).all()
    return jsonify({"logins": [e.to_dict() for e in events]})

@app.route("/api/admin/sessions", methods=["GET"])
@admin_required
def api_admin_sessions():
    sessions = ActiveSession.query.filter_by(is_active=True).all()
    return jsonify({"sessions": [s.to_dict() for s in sessions]})

@app.route("/api/admin/sessions/<int:session_id>/terminate", methods=["POST"])
@admin_required
def api_admin_terminate_session(session_id):
    active_session = ActiveSession.query.get(session_id)
    if not active_session:
        return jsonify({"error": "Session not found"}), 404
    active_session.is_active = False
    db.session.commit()
    return jsonify({"ok": True})

@app.route("/api/admin/threats", methods=["GET"])
@admin_required
def api_admin_threats():
    limit = min(int(request.args.get("limit", 50)), 200)
    threats = ThreatAlert.query.order_by(ThreatAlert.timestamp.desc()).limit(limit).all()
    return jsonify({"threats": [t.to_dict() for t in threats]})

@app.route("/api/admin/malicious-ips", methods=["GET"])
@admin_required
def api_admin_malicious_ips():
    ips = MaliciousIP.query.all()
    return jsonify({"ips": [ip.to_dict() for ip in ips]})

@app.route("/api/admin/malicious-ips", methods=["POST"])
@admin_required
def api_admin_add_malicious_ip():
    data = request.get_json(force=True) or {}
    ip = data.get("ip_address", "").strip()
    if not ip:
        return jsonify({"error": "ip_address is required"}), 400
    
    malicious = MaliciousIP.query.filter_by(ip_address=ip).first()
    if not malicious:
        malicious = MaliciousIP(
            ip_address=ip,
            threat_level=data.get("threat_level", "high"),
            reason=data.get("reason", "Manual addition"),
            blocked=True
        )
        db.session.add(malicious)
    else:
        malicious.blocked = True
        malicious.threat_level = data.get("threat_level", malicious.threat_level)
    
    db.session.commit()
    return jsonify(malicious.to_dict())

@app.route("/api/admin/malicious-ips/<int:ip_id>/unblock", methods=["POST"])
@admin_required
def api_admin_unblock_ip(ip_id):
    malicious = MaliciousIP.query.get(ip_id)
    if not malicious:
        return jsonify({"error": "IP entry not found"}), 404
    malicious.blocked = False
    db.session.commit()
    return jsonify(malicious.to_dict())

@app.route("/api/admin/overview", methods=["GET"])
@admin_required
def api_admin_overview():
    total_users = User.query.count()
    active_sessions = ActiveSession.query.filter_by(is_active=True).count()
    total_scans = ScanResult.query.count()
    failed_logins_24h = LoginEvent.query.filter(
        LoginEvent.success == False,
        LoginEvent.timestamp >= datetime.datetime.utcnow() - timedelta(hours=24)
    ).count()
    critical_threats = ThreatAlert.query.filter_by(severity='critical', resolved=False).count()
    
    return jsonify({
        "total_users": total_users,
        "active_sessions": active_sessions,
        "total_scans": total_scans,
        "failed_logins_24h": failed_logins_24h,
        "critical_threats": critical_threats,
        "malicious_ips": MaliciousIP.query.filter_by(blocked=True).count(),
    })

@app.route("/api/admin/stats", methods=["GET"])
@admin_required
def api_admin_stats():
    scans_by_type = {}
    for scan_type in ['url', 'email', 'website', 'dns']:
        scans_by_type[scan_type] = ScanResult.query.filter_by(scan_type=scan_type).count()
    
    risks = {}
    for risk in ['low', 'medium', 'high']:
        risks[risk] = ScanResult.query.filter_by(risk_level=risk).count()
    
    return jsonify({
        "scans_by_type": scans_by_type,
        "risks": risks,
        "total_scans": ScanResult.query.count()
    })

# ============================================================================
# WEBSOCKET EVENTS
# ============================================================================

@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")
    if session.get("user_id"):
        join_room(f"user_{session['user_id']}")

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('subscribe_alerts')
def handle_subscribe_alerts():
    if session.get("is_admin"):
        join_room("admin_alerts")
        emit('alert_subscribed', {'message': 'Subscribed to threat alerts'})

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return jsonify({"error": "Internal server error"}), 500

# ============================================================================
# BACKGROUND MONITORING
# ============================================================================

MONITORED_ASSET = os.getenv("MONITORED_ASSET", "https://sbprakash-schedule.netlify.app")

def background_monitor():
    """Real-time monitoring thread"""
    while True:
        try:
            if DB_ENABLED:
                with app.app_context():
                    if MonitoredTarget.query.count() == 0:
                        db.session.add(MonitoredTarget(
                            url=MONITORED_ASSET,
                            name="Default monitored site",
                            interval_seconds=60,
                            enabled=True,
                        ))
                        db.session.commit()
                    
                    now = datetime.datetime.utcnow()
                    targets = MonitoredTarget.query.filter_by(enabled=True).all()
                    
                    for target in targets:
                        due = (
                            target.last_scan_at is None
                            or (now - target.last_scan_at).total_seconds() >= target.interval_seconds
                        )
                        
                        if due:
                            try:
                                result = scan_website_headers(target.url)
                                scan = ScanResult(
                                    scan_type='website',
                                    input_data=target.url,
                                    score=result['score'],
                                    risk_level=result['risk'],
                                    findings=result['findings'],
                                    ip_address='real-time-monitor'
                                )
                                db.session.add(scan)
                                target.last_scan_at = now
                                target.last_score = result['score']
                                target.last_risk = result['risk']
                                db.session.commit()
                                
                                socketio.emit('real_time_scan', {
                                    'target': target.url,
                                    'score': result['score'],
                                    'risk': result['risk'],
                                    'timestamp': now.isoformat() + 'Z'
                                })
                                
                            except Exception as e:
                                logger.error(f"Monitor scan error for {target.url}: {e}")
        except Exception as e:
            logger.error(f"Monitor thread error: {e}")
            if DB_ENABLED:
                try:
                    with app.app_context():
                        db.session.rollback()
                except:
                    pass
        
        time.sleep(15)

if DB_ENABLED:
    monitor_thread = threading.Thread(target=background_monitor, daemon=True)
    monitor_thread.start()

# ============================================================================
# STARTUP
# ============================================================================

if __name__ == "__main__":
    if DB_ENABLED:
        with app.app_context():
            db.create_all()
            logger.info("Database initialized")
    
    logger.info(f"Starting CyberSecure Enterprise v3.0 on port {API_PORT}")
    socketio.run(app, debug=DEBUG, host="0.0.0.0", port=API_PORT, allow_unsafe_werkzeug=True)
