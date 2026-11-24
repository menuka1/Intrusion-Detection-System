"""Authentication: login, logout, session, change password, admin bootstrap."""
import logging
import secrets
import time

from flask import Blueprint, current_app, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from dashboard.utils import (EMAIL_RE, USERNAME_RE, csrf_token, current_user, fail, json_body, login_required, ok,
                             validate_password)
from database.repositories import Users

log = logging.getLogger(__name__)
auth_bp = Blueprint("auth", __name__)

_DUMMY_HASH = generate_password_hash(secrets.token_hex(8))


def _failures():
    """Per-application failure counters: (login, ip) -> (count, locked_until)."""
    return current_app.extensions.setdefault("login_failures", {})


def _key(login):
    return (login.lower(), request.remote_addr or "")


def _locked(login):
    count, until = _failures().get(_key(login), (0, 0))
    return until > time.time()


def _record_failure(login):
    cfg = current_app.config
    count, _ = _failures().get(_key(login), (0, 0))
    count += 1
    until = time.time() + cfg["LOGIN_LOCK_SECONDS"] if count >= cfg["LOGIN_MAX_FAILURES"] else 0
    _failures()[_key(login)] = (0 if until else count, until)


def public_user(u):
    return {"user_id": u["user_id"], "username": u["username"], "email": u["email"], "role": u["role"],
            "created_at": u["created_at"], "last_login_at": u.get("last_login_at")}


def create_user(username, email, password, role="analyst"):
    """Validate and create a user with a hashed password. Returns user_id."""
    if not USERNAME_RE.match(username or ""):
        raise ValueError("Username must be 3-64 characters (letters, digits, . _ -).")
    if not EMAIL_RE.match(email or ""):
        raise ValueError("A valid email address is required.")
    problem = validate_password(password)
    if problem:
        raise ValueError(problem)
    if role not in ("admin", "analyst"):
        raise ValueError("Role must be admin or analyst.")
    if Users.find_by_login(username) or Users.find_by_login(email):
        raise ValueError("A user with that username or email already exists.")
    return Users.create(username, email.lower(), generate_password_hash(password), role)


@auth_bp.get("/login")
def login_page():
    if current_user():
        return redirect(url_for("main.index"))
    return render_template("login.html", csrf=csrf_token(), no_users=Users.count() == 0)


@auth_bp.post("/api/auth/login")
def api_login():
    body = json_body()
    login = str(body.get("login", "")).strip()
    password = str(body.get("password", ""))
    if not login or not password:
        return fail("Username/email and password are required.", 400)
    if _locked(login):
        return fail("Too many failed attempts. Try again later.", 429)
    user = Users.find_by_login(login)
    valid = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)
    if not (user and valid):
        _record_failure(login)
        log.warning("Failed login attempt for '%s'", login[:40])
        return fail("Invalid username/email or password.", 401)
    _failures().pop(_key(login), None)
    session.clear()  # prevents session fixation
    session.permanent = True
    session["user_id"] = user["user_id"]
    csrf_token()
    Users.touch_login(user["user_id"])
    return ok({"user": public_user(user), "csrf_token": session["csrf"]})


@auth_bp.post("/api/auth/logout")
def api_logout():
    session.clear()
    return ok({"message": "Logged out."})


@auth_bp.get("/api/auth/me")
@login_required
def api_me():
    return ok({"user": public_user(current_user()), "csrf_token": csrf_token()})


@auth_bp.post("/api/auth/change-password")
@login_required
def api_change_password():
    body = json_body()
    user = current_user()
    if not check_password_hash(user["password_hash"], str(body.get("current_password", ""))):
        return fail("Current password is incorrect.", 400)
    new = str(body.get("new_password", ""))
    problem = validate_password(new, current_app.config["MIN_PASSWORD_LENGTH"])
    if problem:
        return fail(problem, 422)
    if new == body.get("current_password"):
        return fail("The new password must differ from the current one.", 422)
    Users.update_password(user["user_id"], generate_password_hash(new))
    return ok({"message": "Password updated."})
