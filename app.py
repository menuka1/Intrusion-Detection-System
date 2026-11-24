"""ML-IDS application entry point.

Usage:
    python app.py init-db        create the MySQL database + tables
    python app.py init-admin     create the first administrator (prompts / env vars)
    python app.py create-user    create another user
    python app.py run            start the web application (default)
"""
import argparse
import getpass
import logging
import os
import sys
from datetime import timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from config import BASE_DIR, load_config
from dashboard.alert_routes import alert_bp
from dashboard.auth import auth_bp, create_user
from dashboard.dataset_routes import dataset_bp
from dashboard.model_routes import model_bp
from dashboard.report_routes import report_bp
from dashboard.routes import main_bp
from dashboard.traffic_routes import traffic_bp
from dashboard.utils import check_csrf, csrf_token, fail
from database.db_connection import DatabaseError, init_db
from database.repositories import Jobs, Users
from detection.engine import DetectionEngine
from detection.traffic_replay import ReplayManager
from models.trainer import JobRunner

log = logging.getLogger("mlids")

CSP = ("default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")


def configure_logging(app):
    if app.config.get("TESTING"):
        return
    logdir = Path(BASE_DIR) / "logs"
    logdir.mkdir(exist_ok=True)
    handler = RotatingFileHandler(logdir / "mlids.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    if not any(isinstance(h, RotatingFileHandler) for h in root.handlers):
        root.addHandler(handler)
    if not root.handlers or len(root.handlers) == 1:
        root.addHandler(logging.StreamHandler())


def create_app(overrides=None):
    cfg = load_config(overrides)
    app = Flask(__name__)
    app.config.update(cfg)
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=int(cfg["SESSION_HOURS"]))
    configure_logging(app)

    db = init_db(cfg)
    try:
        if cfg["DB_BACKEND"] == "sqlite" or os.getenv("AUTO_INIT_DB", "true").lower() == "true":
            db.init_schema()
        Jobs.fail_interrupted()
    except DatabaseError as exc:
        log.error("Database not ready at startup: %s", exc)
    except Exception as exc:  # noqa: BLE001
        log.error("Database initialisation problem: %s", exc)

    engine = DetectionEngine(cfg["MODEL_DIR"])
    app.extensions["engine"] = engine
    app.extensions["replay"] = ReplayManager(engine)
    app.extensions["train_runner"] = JobRunner(workers=1, sync=cfg["JOBS_SYNC"])
    app.extensions["light_runner"] = JobRunner(workers=2, sync=cfg["JOBS_SYNC"])

    for bp in (auth_bp, main_bp, dataset_bp, model_bp, traffic_bp, alert_bp, report_bp):
        app.register_blueprint(bp)

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def _csrf():
        return check_csrf()

    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("Content-Security-Policy", CSP)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        if request.path.startswith("/api/") or request.path in ("/login",):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def _error(status, message):
        if request.path.startswith("/api/"):
            return fail(message, status)
        return render_template("error.html", status=status, message=message, nav="", page_title="Error", user=None,
                               csrf=""), status

    @app.errorhandler(404)
    def _404(_):
        return _error(404, "The requested resource was not found.")

    @app.errorhandler(403)
    def _403(_):
        return _error(403, "You do not have access to this resource.")

    @app.errorhandler(405)
    def _405(_):
        return _error(405, "Method not allowed.")

    @app.errorhandler(413)
    def _413(_):
        return _error(413, f"The upload exceeds the {cfg['MAX_UPLOAD_MB']} MB limit.")

    @app.errorhandler(DatabaseError)
    def _db(exc):
        log.error("Database error: %s", exc)
        return _error(503, "The database is unavailable. Check the MySQL connection settings.")

    @app.errorhandler(Exception)
    def _500(exc):
        from werkzeug.exceptions import HTTPException
        if isinstance(exc, HTTPException):
            return _error(exc.code or 500, exc.description)
        log.exception("Unhandled error")
        return _error(500, "An unexpected error occurred.")

    return app


# ----------------------------------------------------------------------- CLI
def _cli_init_db(app):
    from database.db_connection import get_db
    created = get_db().init_schema(create_database=True)
    print("Database schema created." if created else "Database schema already exists.")


def _prompt(label, env, secret=False):
    val = os.getenv(env, "").strip()
    if val:
        return val
    return getpass.getpass(label + ": ") if secret else input(label + ": ").strip()


def _cli_init_admin(app, role="admin"):
    if role == "admin" and Users.count() > 0 and not os.getenv("ALLOW_EXTRA_ADMIN"):
        print("Users already exist. Use `create-user --role admin` to add another administrator.")
        return 1
    username = _prompt("Username", "ADMIN_USERNAME")
    email = _prompt("Email", "ADMIN_EMAIL")
    password = _prompt("Password (min 10 chars, letters + digits)", "ADMIN_PASSWORD", secret=True)
    try:
        create_user(username, email, password, role)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1
    print(f"{role.capitalize()} '{username}' created.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="ML-IDS")
    parser.add_argument("command", nargs="?", default="run", choices=["run", "init-db", "init-admin", "create-user"])
    parser.add_argument("--role", default="analyst", choices=["admin", "analyst"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args(argv)
    app = create_app()
    if args.command == "init-db":
        _cli_init_db(app)
    elif args.command == "init-admin":
        return _cli_init_admin(app, "admin")
    elif args.command == "create-user":
        return _cli_init_admin(app, args.role) if args.role != "admin" else _cli_init_admin_force(app)
    else:
        print(f"ML-IDS running at http://{args.host}:{args.port}  (Ctrl+C to stop)")
        app.run(host=args.host, port=args.port, debug=False, threaded=True, use_reloader=False)
    return 0


def _cli_init_admin_force(app):
    os.environ["ALLOW_EXTRA_ADMIN"] = "1"
    return _cli_init_admin(app, "admin")


if __name__ == "__main__":
    sys.exit(main())
