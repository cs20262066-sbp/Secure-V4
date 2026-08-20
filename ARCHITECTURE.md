# SECURE v4 — Architecture Analysis & Migration Plan

## STEP 1: Repository Architecture Analysis (Existing)

### Project Layout (Current)
```
Secure/
├── app.py              # Monolithic Flask app (~1216 lines)
├── admin.html          # Admin dashboard (threats, users, sessions, IPs)
├── frontend.html       # Authenticated scanner dashboard
├── landing.html        # Public marketing page
├── login.html
├── signup.html
├── requirements.txt
├── Procfile            # gunicorn + eventlet
├── runtime.txt         # python-3.12.7
├── env.example
└── .gitignore
```

### Runtime Stack
- **Backend:** Flask 3.0.3 + Flask-SocketIO (eventlet or threading)
- **DB:** SQLAlchemy; SQLite default, PostgreSQL via DATABASE_URL
- **Auth:** Session cookies, werkzeug password hashing, login lockout
- **Realtime:** Socket.IO (threat_alert, user_login, real_time_scan)
- **Deploy:** Render-oriented (Procfile, PORT env)

### Existing Routes
| Path | Methods | Auth | Purpose |
|------|---------|------|---------|
| `/` | GET | optional | Landing or frontend |
| `/login`, `/signup`, `/admin` | GET | page | HTML pages |
| `/api/auth/signup` | POST | public | Create user |
| `/api/auth/login` | POST | public | Login + session |
| `/api/auth/logout` | POST | session | Logout |
| `/api/auth/me` | GET | session | Current user |
| `/api/scan-url` | POST | login | Phishing URL |
| `/api/scan-email` | POST | login | Phishing email |
| `/api/scan-website` | POST | login | Headers + passive vulns |
| `/api/scan-owned-app` | POST | login | Active XSS/SQLi (owned only) |
| `/api/scan-dns` | POST | login | SPF/DMARC hygiene |
| `/api/admin/*` | various | admin | Users, sessions, threats, IPs, stats |

### Existing Models
- **User** — email, password_hash, plan, is_admin, is_active, lockout fields
- **LoginEvent** — audit trail with threat_level
- **ActiveSession** — session_token, IP, last_activity
- **ThreatAlert** — brute_force, severity, details JSON
- **ScanResult** — scan_type, score, findings, CVSS
- **MaliciousIP** — blocklist
- **MonitoredTarget** — background monitor targets

### Existing Scanner Functions
- `scan_website_headers` — HTTPS + security headers
- `scan_website_vulnerabilities` — passive indicators only
- `scan_owned_app_active` — gated by MONITORED_ASSET
- `scan_url` — phishing patterns
- `scan_email_text` — phishing language
- DNS hygiene (placeholder-style findings)

### Socket.IO Events
- `connect` / `disconnect`
- `subscribe_alerts` (admin room)
- Emits: `threat_alert`, `user_login`, `real_time_scan`

### Environment Variables
SECRET_KEY, ADMIN_EMAIL, ADMIN_PASSWORD, DEBUG, API_PORT/PORT,
ALLOWED_ORIGINS, MONITORED_ASSET, USE_DATABASE, DATABASE_URL,
DEFAULT_SCAN_INTERVAL_SECONDS, DISABLE_EVENTLET

### PostgreSQL Assumptions
- DATABASE_URL conversion `postgres://` → `postgresql+psycopg2://`
- pool_pre_ping / pool_recycle for managed Postgres
- SQLite works when USE_DATABASE=True and DATABASE_URL=sqlite:///...

### Strengths to Preserve
- Working auth + admin panel
- Passive-first scanning with hard allowlist for active tests
- Brute-force detection + IP blocklist
- Real-time threat alerts
- Background monitor thread

### Gaps for v4 Recon Platform
- No Project / Scope model
- No subdomain / DNS / cert / endpoint / asset correlation
- No tool adapters (subfinder, httpx, etc.)
- Monolithic app.py
- No attack-surface graph
- UI is functional but not Kali/SOC recon workstation density

---

## STEP 2: Feature Inventory (Preserve)

1. Authentication (signup, login, logout, me)
2. Session management + admin terminate
3. Password hashing + account lockout
4. Website security scan (passive)
5. URL phishing detection
6. Email phishing detection
7. DNS/email hygiene scan
8. Active scan gated to owned asset
9. Threat alerts + malicious IP blocklist
10. Admin overview / users / sessions / logins / stats
11. Socket.IO real-time
12. Background monitoring of MONITORED_ASSET
13. PostgreSQL + SQLite dual support

---

## STEP 3: Database Migration Plan

### Keep existing tables (no data loss)
users, login_event, active_session, threat_alert, scan_result,
malicious_ip, monitored_target

### Add recon tables (new)
- projects
- scopes
- recon_scans
- assets
- domains / subdomains
- ips / ports / services
- dns_records
- certificates
- technologies
- urls / endpoints
- screenshots
- relationships
- observations
- tool_runs
- timeline_events
- findings (recon)

All new tables keyed by project_id where applicable.
Observations retain: source, timestamp, scan_id, raw_data, confidence.

Default local: `DATABASE_URL=sqlite:///secure.db`
Production: existing PostgreSQL URL still works.

---

## STEP 4+: Implementation Order

1. Modular package layout (config, models, routes, services, recon/)
2. Project + Scope system
3. Tool adapter base + health checks
4. Subdomain engine (crt.sh first — no binary deps)
5. Live-host validation (httpx if present, else requests)
6. DNS + certificate intelligence
7. Technology fingerprinting
8. Endpoint discovery (Katana if present)
9. Correlation engine + graph data API
10. Kali-inspired UI (Command Center)
11. Migrate existing security pages into new nav
12. Tests, exports, resume, caching

**Rule:** Every phase must leave existing auth/scans/admin working.
