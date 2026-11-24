"""Detection engine: real predictions, stored results, replay."""
import time
from pathlib import Path

import numpy as np
import pytest

from database.repositories import Models
from models.model_registry import load_artifacts
from preprocessing.dataset_loader import binarize_labels, df_to_clean_json_records, read_dataset

SAMPLE = Path(__file__).resolve().parents[1] / "datasets" / "sample"


def sample_records(n=60, seed=1):
    df = read_dataset(SAMPLE / "nslkdd_synthetic_sample.csv", "nsl-kdd").sample(n, random_state=seed)
    y = binarize_labels(df["label"]).astype(int).to_numpy()
    return df_to_clean_json_records(df.drop(columns=["label"])), y


def test_predict_response_shape_and_real_confidence(world, wadmin):
    recs, y = sample_records(40)
    r = wadmin.post("/api/detection/predict", {"records": recs})
    assert r.status_code == 200, r.get_json()
    out = r.get_json()["data"]
    assert len(out) == 40
    for item in out:
        assert item["prediction"] in ("Normal", "Malicious")
        assert 0.5 <= item["confidence"] <= 1.0
        assert item["model"] == "Random Forest"
        assert item["status"] == ("Threat Detected" if item["prediction"] == "Malicious" else "Normal")
        assert item["alert_generated"] == (item["prediction"] == "Malicious")
    assert len({round(i["malicious_probability"], 4) for i in out}) > 3  # not a constant / hard-coded score
    acc = np.mean([(o["prediction"] == "Malicious") == bool(t) for o, t in zip(out, y)])
    assert acc > 0.9


def test_engine_matches_direct_model_computation(world, wadmin):
    recs, _ = sample_records(10, seed=5)
    out = wadmin.post("/api/detection/predict", {"records": recs}).get_json()["data"]
    import pandas as pd
    row = Models.active()
    pipeline, model = load_artifacts(row, world["app"].config["MODEL_DIR"])
    expected = model.predict_proba(pipeline.transform(pd.DataFrame(recs)))
    assert np.allclose([o["malicious_probability"] for o in out], expected, atol=1e-5)


def test_single_record_form(world, wadmin):
    recs, _ = sample_records(1)
    r = wadmin.post("/api/detection/predict", {"record": recs[0]})
    assert r.status_code == 200 and isinstance(r.get_json()["data"], dict)


def test_predict_input_validation(world, wadmin):
    recs, _ = sample_records(1)
    assert wadmin.post("/api/detection/predict", {}).status_code == 400
    assert wadmin.post("/api/detection/predict", {"records": []}).status_code == 400
    assert wadmin.post("/api/detection/predict", {"records": ["x"]}).status_code == 400
    partial = {k: v for k, v in recs[0].items() if k != "src_bytes"}
    r = wadmin.post("/api/detection/predict", {"record": partial})
    assert r.status_code == 422 and "src_bytes" in r.get_json()["error"]
    bad = dict(recs[0], src_bytes="not-a-number")
    assert wadmin.post("/api/detection/predict", {"record": bad}).status_code == 422
    assert wadmin.post("/api/detection/predict", {"records": [recs[0]] * 501}).status_code == 413


def test_predict_without_active_model_gives_clear_error(admin):
    recs, _ = sample_records(1)
    r = admin.post("/api/detection/predict", {"record": recs[0]})
    assert r.status_code == 409 and "No active detection model" in r.get_json()["error"]


def test_results_are_persisted_and_label_never_stored_as_feature(world, wadmin):
    recs, _ = sample_records(5, seed=9)
    ids = [o["log_id"] for o in wadmin.post("/api/detection/predict", {"records": recs}).get_json()["data"]]
    detail = wadmin.get(f"/api/traffic/{ids[0]}").get_json()["data"]
    assert detail["model_name"] == "Random Forest" and detail["raw_data"]["features"]
    assert "label" not in detail["raw_data"]["features"]
    hist = wadmin.get("/api/detection/history?per_page=100").get_json()["data"]
    assert set(ids) <= {r["log_id"] for r in hist["items"]}


def test_analyst_can_run_predictions(world, wanalyst):
    recs, _ = sample_records(1)
    assert wanalyst.post("/api/detection/predict", {"record": recs[0]}).status_code == 200


def test_switching_active_model_changes_reported_model(world, wadmin):
    recs, _ = sample_records(3)
    wadmin.post(f"/api/models/{world['models']['decision_tree']}/activate")
    assert wadmin.post("/api/detection/predict", {"records": recs}).get_json()["data"][0]["model"] == "Decision Tree"
    wadmin.post(f"/api/models/{world['models']['ann']}/activate")
    out = wadmin.post("/api/detection/predict", {"records": recs}).get_json()["data"]
    assert out[0]["model"] == "Artificial Neural Network" and 0.5 <= out[0]["confidence"] <= 1
    wadmin.post(f"/api/models/{world['models']['random_forest']}/activate")


def _wait_replay(api, timeout=60):
    t0 = time.time()
    while time.time() - t0 < timeout:
        s = api.get("/api/traffic/replay/status").get_json()["data"]
        if not s["running"]:
            return s
        time.sleep(0.3)
    raise AssertionError("replay did not finish")


def test_replay_runs_through_real_engine_and_stores_records(world, wadmin):
    before = wadmin.get("/api/traffic?per_page=1").get_json()["data"]["total"]
    r = wadmin.post("/api/traffic/replay/start", {"dataset_id": world["dataset_id"], "speed": 100, "max_records": 150})
    assert r.status_code == 202, r.get_json()
    assert r.get_json()["data"]["simulated"] is True
    s = _wait_replay(wadmin)
    assert s["state"] == "completed" and s["processed"] == 150
    assert s["normal"] + s["malicious"] == 150
    assert s["ground_truth_accuracy"] > 0.85  # label used only for evaluation
    after = wadmin.get("/api/traffic?per_page=200").get_json()["data"]
    assert after["total"] == before + 150
    rec = wadmin.get(f"/api/traffic/{after['items'][0]['log_id']}").get_json()["data"]
    assert rec["source"] == "replay" and rec["raw_data"]["meta"]["simulated_endpoints"] is True
    assert "label" not in rec["raw_data"]["features"]


def test_replay_can_be_stopped(world, wadmin):
    assert wadmin.post("/api/traffic/replay/start", {"dataset_id": world["dataset_id"], "speed": 2}).status_code == 202
    assert wadmin.post("/api/traffic/replay/start", {"dataset_id": world["dataset_id"], "speed": 2}).status_code == 422  # already running
    time.sleep(1.2)
    s = wadmin.post("/api/traffic/replay/stop").get_json()["data"]
    assert s["state"] == "stopped" and not s["running"]


def test_replay_rejects_incompatible_dataset_and_bad_speed(world, wadmin):
    u = wadmin.post("/api/datasets/load-sample", {"type": "unsw-nb15"}).get_json()["data"]
    r = wadmin.post("/api/traffic/replay/start", {"dataset_id": u["dataset_id"], "speed": 5})
    assert r.status_code == 422 and "different feature structure" in r.get_json()["error"]
    assert wadmin.post("/api/traffic/replay/start", {"dataset_id": 999}).status_code == 404


def test_replay_requires_active_model(admin):
    d = admin.post("/api/datasets/load-sample", {"type": "nsl-kdd"}).get_json()["data"]
    r = admin.post("/api/traffic/replay/start", {"dataset_id": d["dataset_id"], "speed": 5})
    assert r.status_code == 409
