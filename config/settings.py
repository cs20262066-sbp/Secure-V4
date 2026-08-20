"""
Central configuration for Secure v4.
Local-first: SQLite by default. PostgreSQL remains supported.
"""
from __future__ import annotations

import os
from pathlib import Path
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
PROJECTS_DIR = BASE_DIR / "projects"
LOGS_DIR = BASE_DIR / "logs"
RAW_DIR = DATA_DIR / "raw"

for d in (DATA_DIR, PROJECTS_DIR, LOGS_DIR, RAW_DIR):
    d.mkdir(parents=True, exist_ok=True)


def _normalize_db_url(url: str) -> str:
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg2://", 1)
    if url.startswith("postgresql://") and "+psycopg2" not in url:
        return url.replace("postgresql://", "postgresql+psycopg2://", 1)
    return url


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY") or os.urandom(32).hex()
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    API_PORT = int(os.getenv("API_PORT") or os.getenv("PORT") or 5000)

    _raw_origins = os.getenv("ALLOWED_ORIGINS", "*").strip()
    ALLOWED_ORIGINS = (
        "*" if _raw_origins == "*" else [o.strip() for o in _raw_origins.split(",") if o.strip()]
    )

    USE_DATABASE = os.getenv("USE_DATABASE", "True").lower() == "true"
    # Local-first default
    DATABASE_URL = _normalize_db_url(
        os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'secure.db'}")
    )

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)

    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
    MONITORED_ASSET = os.getenv("MONITORED_ASSET", "https://sbprakash-schedule.netlify.app")
    DEFAULT_SCAN_INTERVAL_SECONDS = int(os.getenv("DEFAULT_SCAN_INTERVAL_SECONDS", "60"))
    DISABLE_EVENTLET = os.getenv("DISABLE_EVENTLET", "False").lower() == "true"

    # Optional external APIs (never required)
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
    CENSYS_API_ID = os.getenv("CENSYS_API_ID", "")
    CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET", "")
    HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", "")

    # Recon
    MAX_CONCURRENT_TOOLS = int(os.getenv("MAX_CONCURRENT_TOOLS", "4"))
    TOOL_TIMEOUT_SECONDS = int(os.getenv("TOOL_TIMEOUT_SECONDS", "300"))
    CACHE_TTL_HOURS = int(os.getenv("CACHE_TTL_HOURS", "24"))

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 280,
    }
