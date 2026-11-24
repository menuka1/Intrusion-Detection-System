"""Application configuration. All secrets come from environment variables / .env."""
import os
import secrets
import logging
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

log = logging.getLogger(__name__)


def _bool(name, default=False):
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _int(name, default):
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


class Config:
    ENV = os.getenv("APP_ENV", "development")
    DEBUG = False  # never enable the Werkzeug debugger through config

    # ---- secrets -------------------------------------------------------
    SECRET_KEY = os.getenv("SECRET_KEY", "")

    # ---- database ------------------------------------------------------
    # "mysql" is the supported production backend. "sqlite" exists only so the
    # automated tests / offline demos can run on machines without MySQL.
    DB_BACKEND = os.getenv("DB_BACKEND", "mysql").lower()
    MYSQL_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
    MYSQL_PORT = _int("MYSQL_PORT", 3306)
    MYSQL_USER = os.getenv("MYSQL_USER", "mlids")
    MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
    MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "ml_ids")
    MYSQL_POOL_SIZE = _int("MYSQL_POOL_SIZE", 8)
    SQLITE_PATH = os.getenv("SQLITE_PATH", str(BASE_DIR / "ml_ids_dev.sqlite3"))

    # ---- storage -------------------------------------------------------
    UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", BASE_DIR / "datasets" / "uploaded"))
    PROCESSED_DIR = Path(os.getenv("PROCESSED_DIR", BASE_DIR / "datasets" / "processed"))
    SAMPLE_DIR = BASE_DIR / "datasets" / "sample"
    MODEL_DIR = Path(os.getenv("MODEL_DIR", BASE_DIR / "models" / "saved_models"))
    REPORT_DIR = Path(os.getenv("REPORT_DIR", BASE_DIR / "reports"))
    MAX_UPLOAD_MB = _int("MAX_UPLOAD_MB", 200)
    MAX_CONTENT_LENGTH = MAX_UPLOAD_MB * 1024 * 1024
    ALLOWED_EXTENSIONS = {".csv", ".txt"}

    # ---- sessions / security ------------------------------------------
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", False)  # True behind HTTPS
    SESSION_HOURS = _int("SESSION_HOURS", 8)
    LOGIN_MAX_FAILURES = _int("LOGIN_MAX_FAILURES", 5)
    LOGIN_LOCK_SECONDS = _int("LOGIN_LOCK_SECONDS", 300)
    MIN_PASSWORD_LENGTH = 10

    # ---- jobs ----------------------------------------------------------
    JOBS_SYNC = False  # tests run background jobs inline
    TESTING = False


def load_config(overrides=None):
    """Return a configuration dict (Flask-style) with overrides applied."""
    cfg = {k: getattr(Config, k) for k in dir(Config) if k.isupper()}
    if overrides:
        cfg.update(overrides)
    if not cfg.get("SECRET_KEY"):
        if cfg.get("ENV") == "production":
            raise RuntimeError("SECRET_KEY must be set in the environment for production use.")
        # Development convenience: ephemeral key (sessions reset on restart).
        cfg["SECRET_KEY"] = secrets.token_hex(32)
        log.warning("SECRET_KEY not set; using an ephemeral development key.")
    for key in ("UPLOAD_DIR", "PROCESSED_DIR", "MODEL_DIR", "REPORT_DIR"):
        cfg[key] = Path(cfg[key])
        cfg[key].mkdir(parents=True, exist_ok=True)
    cfg["MAX_CONTENT_LENGTH"] = int(cfg["MAX_UPLOAD_MB"]) * 1024 * 1024
    return cfg
