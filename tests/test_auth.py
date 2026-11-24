"""Authentication, sessions, CSRF, role-based access."""
from werkzeug.security import check_password_hash

from database.repositories import Users
from tests.conftest import ADMIN, ANALYST, Api


def test_valid_login_sets_session_and_me_works(app):
    api = Api(app, ADMIN)
    me = api.get("/api/auth/me").get_json()["data"]["user"]
    assert me["username"] == ADMIN[0] and me["role"] == "admin"
    assert "password_hash" not in me


def test_login_by_email_works(app):
    r = Api(app).post("/api/auth/login", {"login": ADMIN[1], "password": ADMIN[2]})
    assert r.status_code == 200


def test_invalid_login_rejected_with_generic_message(app):
    api = Api(app)
    bad_pw = api.post("/api/auth/login", {"login": ADMIN[0], "password": "wrong-password"})
    bad_user = api.post("/api/auth/login", {"login": "nobody", "password": "whatever12345"})
    assert bad_pw.status_code == bad_user.status_code == 401
    assert bad_pw.get_json()["error"] == bad_user.get_json()["error"]  # no user enumeration


def test_missing_fields_rejected(app):
    assert Api(app).post("/api/auth/login", {"login": "", "password": ""}).status_code == 400


def test_passwords_are_hashed_not_plain(app):
    user = Users.find_by_login(ADMIN[0])
    assert user["password_hash"] != ADMIN[2]
    assert check_password_hash(user["password_hash"], ADMIN[2])


def test_protected_api_requires_login(anon):
    for url in ("/api/dashboard/statistics", "/api/datasets", "/api/models", "/api/alerts", "/api/traffic", "/api/settings"):
        r = anon.get(url)
        assert r.status_code == 401, url
        assert r.get_json()["ok"] is False


def test_protected_pages_redirect_to_login(anon):
    for url in ("/", "/datasets", "/alerts", "/settings"):
        r = anon.get(url)
        assert r.status_code == 302 and "/login" in r.headers["Location"], url


def test_login_page_is_public_and_renders(anon):
    r = anon.get("/login")
    assert r.status_code == 200 and b"Sign in" in r.data


def test_csrf_required_for_state_changing_requests(app):
    api = Api(app, ADMIN)
    r = api.client.post("/api/auth/logout")  # no token header
    assert r.status_code == 403
    r = api.client.post("/api/auth/logout", headers={"X-CSRF-Token": "forged"})
    assert r.status_code == 403
    assert api.post("/api/auth/logout").status_code == 200


def test_logout_ends_session(app):
    api = Api(app, ADMIN)
    assert api.post("/api/auth/logout").status_code == 200
    assert api.get("/api/auth/me").status_code == 401


def test_analyst_cannot_use_admin_endpoints(analyst):
    assert analyst.post("/api/datasets/load-sample", {"type": "nsl-kdd"}).status_code == 403
    assert analyst.post("/api/models/train", {"algorithm": "ann", "dataset_id": 1}).status_code == 403
    assert analyst.post("/api/traffic/replay/start", {"dataset_id": 1}).status_code == 403
    assert analyst.put("/api/settings", {"replay_speed": 3}).status_code == 403
    assert analyst.delete("/api/datasets/1").status_code == 403


def test_change_password_flow(app):
    api = Api(app, ANALYST)
    assert api.post("/api/auth/change-password", {"current_password": "bad", "new_password": "NewPassw0rd123"}).status_code == 400
    assert api.post("/api/auth/change-password", {"current_password": ANALYST[2], "new_password": "short1"}).status_code == 422
    assert api.post("/api/auth/change-password", {"current_password": ANALYST[2], "new_password": "onlyletterslong"}).status_code == 422
    assert api.post("/api/auth/change-password", {"current_password": ANALYST[2], "new_password": "NewPassw0rd123"}).status_code == 200
    api.post("/api/auth/logout")
    assert Api(app).post("/api/auth/login", {"login": ANALYST[0], "password": ANALYST[2]}).status_code == 401
    assert Api(app).post("/api/auth/login", {"login": ANALYST[0], "password": "NewPassw0rd123"}).status_code == 200


def test_lockout_after_repeated_failures(app):
    api = Api(app)
    for _ in range(app.config["LOGIN_MAX_FAILURES"]):
        assert api.post("/api/auth/login", {"login": ADMIN[0], "password": "nope-nope-1"}).status_code == 401
    assert api.post("/api/auth/login", {"login": ADMIN[0], "password": ADMIN[2]}).status_code == 429


def test_security_headers_present(anon):
    r = anon.get("/login")
    assert "Content-Security-Policy" in r.headers and r.headers["X-Frame-Options"] == "DENY"


def test_create_user_validation(app):
    from dashboard.auth import create_user
    import pytest
    with pytest.raises(ValueError):
        create_user("x", "bad-email", "Password12345")
    with pytest.raises(ValueError):
        create_user("validname", "a@b.test", "short")
    with pytest.raises(ValueError):
        create_user(ADMIN[0], "other@b.test", "Password12345")  # duplicate username
