"""Shared fixtures. Tests run against the SQLite fallback backend (no MySQL server needed) and the
bundled SYNTHETIC sample datasets; real MySQL / benchmark data are documented separately in the README."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import create_app  # noqa: E402
from dashboard.auth import create_user  # noqa: E402
from database.db_connection import get_db, use_db  # noqa: E402

ADMIN = ("admin_test", "admin@example.test", "TestPassw0rd!x")
ANALYST = ("analyst_test", "analyst@example.test", "AnalystPassw0rd1")


def make_app(tmp_path):
    for sub in ("up", "proc", "models", "rep"):
        (tmp_path / sub).mkdir(exist_ok=True)
    app = create_app({
        "TESTING": True, "SECRET_KEY": "test-secret-key", "DB_BACKEND": "sqlite",
        "SQLITE_PATH": str(tmp_path / "test.sqlite3"), "UPLOAD_DIR": tmp_path / "up",
        "PROCESSED_DIR": tmp_path / "proc", "MODEL_DIR": tmp_path / "models", "REPORT_DIR": tmp_path / "rep",
        "JOBS_SYNC": True, "MAX_UPLOAD_MB": 5})
    return app


class Api:
    """Thin client wrapper that sends the CSRF header and parses the JSON envelope."""

    def __init__(self, app, creds=None):
        self.client = app.test_client()
        self.token = "test-csrf-token"
        with self.client.session_transaction() as s:
            s["csrf"] = self.token
        if creds:
            r = self.post("/api/auth/login", {"login": creds[0], "password": creds[2]})
            assert r.status_code == 200, r.get_json()
            self.token = r.get_json()["data"]["csrf_token"]  # session is renewed on login

    def _h(self):
        return {"X-CSRF-Token": self.token}

    def get(self, url, **kw):
        return self.client.get(url, **kw)

    def post(self, url, json=None, **kw):
        return self.client.post(url, json=json, headers=self._h(), **kw)

    def patch(self, url, json=None):
        return self.client.patch(url, json=json, headers=self._h())

    def put(self, url, json=None):
        return self.client.put(url, json=json, headers=self._h())

    def delete(self, url):
        return self.client.delete(url, headers=self._h())


@pytest.fixture()
def app(tmp_path):
    app = make_app(tmp_path)
    create_user(*ADMIN, role="admin")
    create_user(*ANALYST, role="analyst")
    return app


@pytest.fixture()
def admin(app):
    return Api(app, ADMIN)


@pytest.fixture()
def analyst(app):
    return Api(app, ANALYST)


@pytest.fixture()
def anon(app):
    return Api(app)


@pytest.fixture(scope="session")
def world(tmp_path_factory):
    """A fully prepared system: NSL-KDD sample ingested + preprocessed, three models trained, RF active."""
    tmp = tmp_path_factory.mktemp("world")
    app = make_app(tmp)
    create_user(*ADMIN, role="admin")
    create_user(*ANALYST, role="analyst")
    admin = Api(app, ADMIN)
    r = admin.post("/api/datasets/load-sample", {"type": "nsl-kdd"})
    assert r.status_code == 201, r.get_json()
    ds_id = r.get_json()["data"]["dataset_id"]
    r = admin.post(f"/api/datasets/{ds_id}/preprocess", {"scaling": "standard", "feature_selection": "f_classif",
                                                          "k_features": 30})
    assert r.status_code == 202, r.get_json()
    models = {}
    for algo, params in (("decision_tree", {"max_depth": 12}), ("random_forest", {"n_estimators": 20}),
                         ("ann", {"hidden_layers": "32,16", "epochs": 4})):
        r = admin.post("/api/models/train", {"dataset_id": ds_id, "algorithm": algo, "params": params})
        assert r.status_code == 202, r.get_json()
        job = r.get_json()["data"]
        job = admin.get(f"/api/models/jobs/{job['job_id']}").get_json()["data"]
        assert job["job_status"] == "Completed", job
        models[algo] = job["model_id"]
    r = admin.post(f"/api/models/{models['random_forest']}/activate")
    assert r.status_code == 200, r.get_json()
    return {"app": app, "db": get_db(), "dataset_id": ds_id, "models": models, "tmp": tmp}


@pytest.fixture()
def wadmin(world):
    use_db(world["db"])  # other tests create their own app/database; point back at the shared one
    return Api(world["app"], ADMIN)


@pytest.fixture()
def wanalyst(world):
    use_db(world["db"])
    return Api(world["app"], ANALYST)
