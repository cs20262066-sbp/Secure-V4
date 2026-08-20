# SECURE v4 — Local Security Intelligence + Bug Bounty Recon

Drop-in upgrade of **CyberSecure Enterprise** for Render (or local).

Previous live URL pattern: `https://secure-lvws.onrender.com`

---

## Deploy on Render (replace existing app)

### 1. Push this folder as the Git repo root

All files in this directory are the application root (same layout as the previous Secure app).

```bash
# From this Secure/ directory (or copy its contents into your existing repo root)
git init   # if new
git add .
git commit -m "Secure v4 — recon platform upgrade"
git remote add origin <YOUR_GITHUB_REPO_URL>
git push -u origin main
```

If you already have the old Secure repo on Render:

1. Replace the repo contents with these files (overwrite `app.py`, HTML, add `models/`, `recon/`, `routes/`, `command_center.html`, etc.).
2. `git push` to the branch Render deploys.

### 2. Render service settings

| Setting | Value |
|---------|--------|
| Runtime | Python |
| Build command | `pip install -r requirements.txt` |
| Start command | *(use Procfile)* `gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:$PORT app:app` |
| `runtime.txt` | `python-3.12.7` |

### 3. Environment variables (Render Dashboard → Environment)

| Key | Required | Notes |
|-----|----------|--------|
| `SECRET_KEY` | **Yes** | Long random string |
| `USE_DATABASE` | **Yes** | `True` |
| `DATABASE_URL` | **Yes** | From Render PostgreSQL (Internal URL). Auto-fixed if `postgres://` |
| `ADMIN_EMAIL` | Recommended | Bootstrap admin once |
| `ADMIN_PASSWORD` | Recommended | Bootstrap admin once |
| `ALLOWED_ORIGINS` | Optional | `*` is fine for single-service deploy |
| `MONITORED_ASSET` | Optional | Only domain allowed for *active* owned-app scan |
| `DEBUG` | Optional | `False` in production |

Attach a **PostgreSQL** database on Render and copy its Internal Database URL into `DATABASE_URL`.

### 4. After deploy

1. Open `https://<your-service>.onrender.com/`
2. Sign up or log in with `ADMIN_EMAIL`
3. **Command Center (recon):** `/command-center`
4. Legacy scanners: `/` (logged in)
5. Admin: `/admin`

---

## Local run

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp env.example .env
# edit SECRET_KEY, ADMIN_*, USE_DATABASE=True, DATABASE_URL=sqlite:///secure.db
python app.py
```

---

## What is included

### Preserved (v3)

- Auth (signup / login / sessions / lockout)
- Website, URL, email, DNS scans
- Owned-app active scan (gated)
- Admin panel, threat alerts, malicious IPs
- Socket.IO real-time
- Background monitor

### New (v4 recon)

- Projects + scope
- crt.sh subdomain discovery
- Live-host probing + light tech fingerprint
- Asset priority / interesting hosts
- Timeline + exports
- `/api/recon/*` API
- Command Center UI (`/command-center`)

---

## Recon API (authenticated session)

- `POST /api/recon/projects` — `{ "root_domain": "example.com" }`
- `POST /api/recon/projects/:id/scans` — `{ "profile": "passive", "authorized": true }`
- `GET /api/recon/projects/:id/assets`
- `GET /api/recon/projects/:id/summary`
- `GET /api/recon/tools`

Profiles: `passive` | `enumeration` | `web` | `full`  
`web` / `full` require `"authorized": true`.

---

## Project layout

```
app.py                 # Flask + Socket.IO + legacy routes + recon registration
command_center.html    # Recon UI
frontend.html          # Legacy scanners
admin.html / login.html / signup.html / landing.html
models/                # recon + shared database hook
routes/recon.py
recon/                 # adapters, pipeline, normalizers
config/
Procfile
requirements.txt
runtime.txt
env.example
```

See `ARCHITECTURE.md` for the full migration plan and remaining phases (graph, more tool adapters, etc.).
