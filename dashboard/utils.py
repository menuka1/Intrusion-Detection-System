"""Shared web helpers: JSON responses, auth decorators, CSRF, validation."""
import functools
import hmac
import re
import secrets
from datetime import datetime

from flask import abort, current_app, g, jsonify, redirect, request, session, url_for

from database.repositories import Users

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def ok(data=None, status=200, **extra):
    body = {"ok": True, "data": data}
    body.update(extra)
    return jsonify(body), status


def fail(message, status=400, **extra):
    body = {"ok": False, "error": message}
    body.update(extra)
    return jsonify(body), status


# ------------------------------------------------------------------ CSRF
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf():
    if request.method not in UNSAFE_METHODS:
        return None
    sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    expected = session.get("csrf", "")
    if not expected or not hmac.compare_digest(str(sent), str(expected)):
        return fail("Missing or invalid CSRF token. Reload the page and try again.", 403)
    return None


# ------------------------------------------------------------------ auth
def current_user():
    if "user" in g.__dict__:
        return g.user
    uid = session.get("user_id")
    g.user = Users.get(uid) if uid else None
    if uid and g.user is None:
        session.clear()
    return g.user


def _deny(status, message):
    if request.path.startswith("/api/"):
        return fail(message, status)
    if status == 401:
        return redirect(url_for("auth.login_page", next=request.path))
    abort(status)


def login_required(fn):
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        if current_user() is None:
            return _deny(401, "Authentication required.")
        return fn(*a, **kw)
    return wrapper


def role_required(*roles):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            user = current_user()
            if user is None:
                return _deny(401, "Authentication required.")
            if user["role"] not in roles:
                return _deny(403, "You do not have permission to perform this action.")
            return fn(*a, **kw)
        return wrapper
    return deco


admin_required = role_required("admin")


# ------------------------------------------------------------------ validation
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")


def validate_password(pw, min_len=10):
    if not isinstance(pw, str) or len(pw) < min_len:
        return f"Password must be at least {min_len} characters."
    if not (re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw)):
        return "Password must contain letters and digits."
    return None


def json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def parse_date(value):
    """Accept YYYY-MM-DD; return the string or None."""
    if not value:
        return None
    try:
        datetime.strptime(value, "%Y-%m-%d")
        return value
    except ValueError:
        return None


def safe_int(value, default=None, lo=None, hi=None):
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    if lo is not None and v < lo:
        return default
    if hi is not None and v > hi:
        return default
    return v


def traffic_filters(args):
    return {"q": (args.get("q") or "").strip()[:100], "ip": (args.get("ip") or "").strip()[:45],
            "protocol": (args.get("protocol") or "").strip()[:20],
            "result": args.get("result") or "", "date_from": parse_date(args.get("date_from")),
            "date_to": parse_date(args.get("date_to")), "model": (args.get("model") or "").strip()[:50]}
