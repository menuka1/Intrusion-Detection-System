"""API integration: dashboard, traffic, reports, settings, pages and the full acceptance workflow."""
import csv
import io

import pytest

from tests.test_detection import sample_records


def test_dashboard_statistics_are_real_database_values(world, wadmin):
    recs, _ = sample_records(30, seed=44)
    out = wadmin.post("/api/detection/predict", {"records": recs}).get_json()["data"]
    s = wadmin.get("/api/dashboard/statistics").get_json()["data"]
    assert s["total"] == s["normal"] + s["malicious"] >= 30
    assert s["active_alerts"] >= 1
    mal = sum(o["prediction"] == "Malicious" for o in out)
    s2 = wadmin.post("/api/detection/predict", {"records": recs}).get_json()["data"] and wadmin.get("/api/dashboard/statistics").get_json()["data"]
    assert s2["total"] == s["total"] + 30 and s2["malicious"] == s["malicious"] + mal
    assert s["selected_model"]["algorithm"] == "random_forest" and 0.8 < s["selected_model"]["accuracy"] <= 1
    assert s["system"]["database"]["ok"] and s["system"]["ml_engine"]["state"] == "ready"
    assert s["system"]["health"] == "healthy"


def test_dashboard_summaries(world, wadmin):
    t = wadmin.get("/api/dashboard/traffic-summary").get_json()["data"]
    assert t["timeline"] and t["protocols"] and t["recent"] and sum(b["normal"] + b["malicious"] for b in t["timeline"]) > 0
    a = wadmin.get("/api/dashboard/alert-summary").get_json()["data"]
    assert sum(a["by_level"].values()) == sum(a["by_status"].values()) > 0 and a["recent"]
    m = wadmin.get("/api/models/metrics").get_json()["data"]
    assert {x["algorithm"] for x in m} == {"decision_tree", "random_forest", "ann"}


def test_dashboard_empty_state_for_fresh_install(admin):
    s = admin.get("/api/dashboard/statistics").get_json()["data"]
    assert (s["total"], s["normal"], s["malicious"], s["active_alerts"]) == (0, 0, 0, 0)
    assert s["selected_model"] is None and s["system"]["ml_engine"]["state"] == "no_model"
    assert admin.get("/api/dashboard/traffic-summary").get_json()["data"]["recent"] == []


def test_traffic_filters_pagination_sorting(world, wadmin):
    base = wadmin.get("/api/traffic?per_page=10&page=2").get_json()["data"]
    assert base["page"] == 2 and len(base["items"]) == 10 and base["total"] > 20
    mal = wadmin.get("/api/traffic?result=Malicious&per_page=50").get_json()["data"]
    assert mal["items"] and all(r["prediction_result"] == "Malicious" for r in mal["items"])
    proto = mal["items"][0]["protocol"]
    pr = wadmin.get(f"/api/traffic?protocol={proto.lower()}&per_page=50").get_json()["data"]
    assert pr["items"] and all(r["protocol"] == proto for r in pr["items"])
    ip = mal["items"][0]["source_ip"]
    assert all(ip in (r["source_ip"], r["destination_ip"]) for r in wadmin.get(f"/api/traffic?ip={ip}").get_json()["data"]["items"])
    asc = [r["packet_size"] for r in wadmin.get("/api/traffic?sort=packet_size&order=asc&per_page=50").get_json()["data"]["items"]]
    assert asc == sorted(asc)
    assert wadmin.get("/api/traffic?date_from=2999-01-01").get_json()["data"]["total"] == 0
    assert wadmin.get("/api/traffic?per_page=abc&page=-3").status_code == 200
    assert wadmin.get("/api/traffic/99999999").status_code == 404


@pytest.mark.parametrize("rtype", ["traffic", "intrusion", "threat_summary", "ml_performance", "dataset_analysis", "alert_history"])
def test_every_report_type_generates_from_real_data(world, wadmin, rtype):
    r = wadmin.get(f"/api/reports/summary?type={rtype}")
    assert r.status_code == 200, r.get_json()
    rep = r.get_json()["data"]
    assert rep["title"] and rep["kpis"] and rep["tables"] is not None and rep["generated_at"]
    if rtype == "ml_performance":
        assert len(rep["tables"][0]["rows"]) >= 3
    if rtype == "traffic":
        kp = {k["label"]: k["value"] for k in rep["kpis"]}
        stats = wadmin.get("/api/dashboard/statistics").get_json()["data"]
        assert kp["Total records"] == stats["total"]


def test_report_filters_and_csv_export(world, wadmin):
    empty = wadmin.get("/api/reports/summary?type=traffic&date_from=2999-01-01").get_json()["data"]
    assert empty["kpis"][0]["value"] == 0
    r = wadmin.get("/api/reports/export?type=ml_performance")
    assert r.status_code == 200 and r.mimetype == "text/csv" and "attachment" in r.headers["Content-Disposition"]
    rows = list(csv.reader(io.StringIO(r.get_data(as_text=True))))
    assert rows[0] == ["Machine Learning Performance Report"]
    assert any(row and row[0] == "Random Forest" for row in rows)
    assert wadmin.get("/api/reports/summary?type=nope").status_code == 400
    assert wadmin.get("/api/reports/export?type=nope").status_code == 400


def test_settings_read_update_and_validation(world, wadmin):
    s = wadmin.get("/api/settings").get_json()["data"]
    assert "replay_speed" in s["settings"] and "secret" not in str(s).lower() and s["active_model"]["algorithm"] == "random_forest"
    assert wadmin.put("/api/settings", {"replay_speed": 9, "dashboard_refresh_seconds": 7}).status_code == 200
    assert wadmin.get("/api/settings").get_json()["data"]["settings"]["replay_speed"] == "9"
    assert wadmin.put("/api/settings", {"replay_speed": 100000}).status_code == 422
    assert wadmin.put("/api/settings", {"alert_min_confidence": 7}).status_code == 422
    assert wadmin.put("/api/settings", {"nonsense": 1}).status_code == 422
    assert wadmin.put("/api/settings", {"default_dataset_id": 424242}).status_code == 422
    assert wadmin.put("/api/settings", {"default_dataset_id": world["dataset_id"]}).status_code == 200


def test_error_responses_are_json_for_api_and_html_for_pages(wadmin, anon):
    r = wadmin.get("/api/does-not-exist")
    assert r.status_code == 404 and r.get_json()["ok"] is False
    assert wadmin.get("/does-not-exist").status_code == 404
    assert wadmin.get("/datasets/99999").status_code == 404
    assert wadmin.client.get("/api/alerts/1", method="DELETE").status_code in (404, 405)
    assert anon.get("/healthz").get_json()["data"]["status"] == "up"


@pytest.mark.parametrize("path", ["/", "/traffic", "/datasets", "/preprocessing", "/training", "/comparison", "/alerts",
                                  "/reports", "/settings", "/profile"])
def test_all_pages_render_for_logged_in_user(world, wadmin, path):
    r = wadmin.get(path)
    assert r.status_code == 200 and b"ML-IDS" in r.data and b"csrf-token" in r.data


def test_dataset_detail_page_renders(world, wadmin):
    assert wadmin.get(f"/datasets/{world['dataset_id']}").status_code == 200


def test_full_acceptance_workflow_end_to_end(app):
    """Login -> upload -> preprocess -> train 3 models -> compare -> activate -> detect -> alerts -> report -> logout."""
    from tests.conftest import ADMIN, Api
    api = Api(app, ADMIN)
    d = api.post("/api/datasets/load-sample", {"type": "unsw-nb15"}).get_json()["data"]
    assert d["processing_status"] == "Uploaded"
    assert api.post(f"/api/datasets/{d['dataset_id']}/preprocess", {"feature_selection": "mutual_info", "k_features": 25}).status_code == 202
    ds = api.get(f"/api/datasets/{d['dataset_id']}").get_json()["data"]
    assert ds["processing_status"] == "Preprocessed" and ds["preprocess_summary"]["after"]["selected_features"] == 25
    for algo, params in (("decision_tree", {}), ("random_forest", {"n_estimators": 15}), ("ann", {"epochs": 3})):
        job = api.post("/api/models/train", {"dataset_id": d["dataset_id"], "algorithm": algo, "params": params}).get_json()["data"]
        assert api.get(f"/api/models/jobs/{job['job_id']}").get_json()["data"]["job_status"] == "Completed"
    cmp_ = api.get(f"/api/models/comparison?dataset_id={d['dataset_id']}").get_json()["data"]
    assert len(cmp_["models"]) == 3
    best = cmp_["best_model_id"]
    assert api.post(f"/api/models/{best}/activate").status_code == 200
    r = api.post("/api/traffic/replay/start", {"dataset_id": d["dataset_id"], "speed": 200, "max_records": 200})
    assert r.status_code == 202
    import time
    for _ in range(100):
        s = api.get("/api/traffic/replay/status").get_json()["data"]
        if not s["running"]:
            break
        time.sleep(0.2)
    assert s["processed"] == 200
    stats = api.get("/api/dashboard/statistics").get_json()["data"]
    assert stats["total"] == 200 and stats["malicious"] == s["malicious"] and stats["active_alerts"] == s["alerts"]
    assert api.get("/api/alerts").get_json()["data"]["total"] == s["alerts"]
    rep = api.get("/api/reports/summary?type=intrusion").get_json()["data"]
    assert rep["kpis"][1]["value"] == s["malicious"]
    assert api.post("/api/auth/logout").status_code == 200
    assert api.get("/api/dashboard/statistics").status_code == 401
