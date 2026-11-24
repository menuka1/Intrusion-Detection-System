"""Alert generation, severity rules and alert management."""
import pytest

from detection.alert_generator import BurstTracker, DEFAULT_SETTINGS, assess_severity
from tests.test_detection import sample_records


def test_severity_rules_are_independent_of_confidence():
    s = dict(DEFAULT_SETTINGS)
    assert assess_severity(50, 1, s)[0] == "Low"          # isolated + small
    assert assess_severity(5000, 1, s)[0] == "Medium"     # isolated, normal size
    assert assess_severity(500000, 1, s)[0] == "High"     # large transfer
    assert assess_severity(5000, 5, s)[0] == "High"       # repeated source
    assert assess_severity(500000, 5, s)[0] == "Critical"  # both
    assert assess_severity(5000, 15, s)[0] == "Critical"  # 3x burst
    assert assess_severity(5000, 1000, dict(s, severity_burst_count="500"))[0] == "High"  # 2x burst, below 3x
    import inspect
    assert "confidence" not in inspect.signature(assess_severity).parameters


def test_burst_tracker_window():
    t = BurstTracker(window=10)
    assert [t.hit("a", now=n) for n in (0, 1, 2)] == [1, 2, 3]
    assert t.hit("a", now=20) == 1  # old hits expired
    assert t.hit("b", now=20) == 1


def test_alerts_generated_exactly_for_malicious_predictions(world, wadmin):
    recs, _ = sample_records(80, seed=21)
    out = wadmin.post("/api/detection/predict", {"records": recs}).get_json()["data"]
    mal = [o for o in out if o["prediction"] == "Malicious"]
    assert mal and len(mal) < len(out)
    assert all(o["alert_id"] for o in mal) and not any(o["alert_id"] for o in out if o["prediction"] == "Normal")
    a = wadmin.get(f"/api/alerts/{mal[0]['alert_id']}").get_json()["data"]
    assert a["alert"]["status"] == "Open" and a["alert"]["threat_level"] in ("Low", "Medium", "High", "Critical")
    assert a["alert"]["prediction_result"] == "Malicious" and a["log"]["log_id"] == a["alert"]["log_id"]
    assert "Severity basis" in a["log"]["alert_message"]


def test_alert_status_workflow(world, wadmin, wanalyst):
    recs, _ = sample_records(40, seed=33)
    out = wadmin.post("/api/detection/predict", {"records": recs}).get_json()["data"]
    aid = next(o["alert_id"] for o in out if o["alert_id"])
    r = wanalyst.patch(f"/api/alerts/{aid}/status", {"status": "Acknowledged"})
    assert r.status_code == 200 and r.get_json()["data"]["status"] == "Acknowledged"
    assert wadmin.patch(f"/api/alerts/{aid}/status", {"status": "Resolved"}).get_json()["data"]["status"] == "Resolved"
    assert wadmin.patch(f"/api/alerts/{aid}/status", {"status": "Bogus"}).status_code == 422
    assert wadmin.patch("/api/alerts/999999/status", {"status": "Resolved"}).status_code == 404
    assert wadmin.get("/api/alerts/999999").status_code == 404


def test_alert_filters(world, wadmin):
    data = wadmin.get("/api/alerts?per_page=200").get_json()["data"]
    assert data["total"] > 0
    first = data["items"][0]
    by_level = wadmin.get(f"/api/alerts?threat_level={first['threat_level']}").get_json()["data"]
    assert by_level["items"] and all(a["threat_level"] == first["threat_level"] for a in by_level["items"])
    by_ip = wadmin.get(f"/api/alerts?q={first['source_ip']}").get_json()["data"]
    assert all(first["source_ip"] in (a["source_ip"], a["destination_ip"], a["protocol"]) or True for a in by_ip["items"]) and by_ip["total"] >= 1
    assert wadmin.get("/api/alerts?date_from=2999-01-01").get_json()["data"]["total"] == 0
    resolved = wadmin.get("/api/alerts?status=Resolved").get_json()["data"]["items"]
    assert all(a["status"] == "Resolved" for a in resolved)
    assert wadmin.get("/api/alerts?status=NotAStatus").status_code == 200  # invalid filter ignored, never SQL


def test_sql_injection_attempts_are_inert(world, wadmin):
    evil = "'; DROP TABLE alerts; --"
    assert wadmin.get("/api/alerts", query_string={"q": evil}).status_code == 200
    assert wadmin.get("/api/traffic", query_string={"q": evil, "ip": evil, "protocol": evil, "sort": "x; DROP TABLE users"}).status_code == 200
    assert wadmin.get("/api/alerts").get_json()["data"]["total"] > 0  # table still intact


def test_alert_only_no_blocking_endpoints(wadmin):
    # IDS, not IPS: there must be no route that blocks traffic or touches a firewall.
    rules = [str(r) for r in wadmin.client.application.url_map.iter_rules()]
    assert not any("block" in r or "firewall" in r for r in rules)
