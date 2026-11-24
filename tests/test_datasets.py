"""Dataset upload, validation, preview and deletion."""
import io
from pathlib import Path

import pandas as pd

SAMPLE = Path(__file__).resolve().parents[1] / "datasets" / "sample"


def _upload(api, name, data, dtype="auto", filename=None, **form):
    payload = {"file": (io.BytesIO(data if isinstance(data, bytes) else data.encode()), filename or name),
               "dataset_type": dtype, **form}
    return api.client.post("/api/datasets/upload", data=payload, content_type="multipart/form-data",
                           headers=api._h())


def test_upload_nsl_kdd_headerless_official_format(admin):
    data = (SAMPLE / "nslkdd_synthetic_sample.csv").read_bytes()
    r = _upload(admin, "KDDTrain+.txt", data, "auto")
    assert r.status_code == 201, r.get_json()
    d = r.get_json()["data"]
    assert d["dataset_type"] == "nsl-kdd" and d["label_column"] == "label"
    assert d["row_count"] > 5000 and d["column_count"] == 43
    assert d["class_counts"]["normal"] > 0 and d["class_counts"]["malicious"] > 0
    detail = admin.get(f"/api/datasets/{d['dataset_id']}?preview=5").get_json()["data"]
    assert len(detail["preview"]) == 5 and "protocol_type" in detail["preview"][0]
    assert detail["metadata"]["duplicate_rows"] >= 1


def test_upload_unsw_nb15(admin):
    r = _upload(admin, "UNSW_NB15_training-set.csv", (SAMPLE / "unsw_nb15_synthetic_sample.csv").read_bytes(), "auto")
    assert r.status_code == 201, r.get_json()
    d = r.get_json()["data"]
    assert d["dataset_type"] == "unsw-nb15" and d["label_column"] == "label"


def test_custom_csv_with_detected_label(admin):
    df = pd.DataFrame({"a": range(60), "b": [i % 7 for i in range(60)], "proto": ["tcp", "udp"] * 30,
                       "class": ["BENIGN", "DDoS"] * 30})
    r = _upload(admin, "mydata.csv", df.to_csv(index=False), "custom")
    assert r.status_code == 201, r.get_json()
    assert r.get_json()["data"]["label_column"] == "class"
    assert r.get_json()["data"]["class_counts"] == {"normal": 30, "malicious": 30, "missing_label": 0}


def test_custom_csv_without_label_is_accepted_but_flagged(admin):
    df = pd.DataFrame({"x": range(40), "y": range(40, 80), "z": range(80, 120)})
    r = _upload(admin, "nolabel.csv", df.to_csv(index=False), "custom")
    assert r.status_code == 201
    assert r.get_json()["data"]["label_column"] is None


def test_wrong_structure_for_declared_type_rejected(admin):
    df = pd.DataFrame({"x": range(40), "y": range(40), "label": [0, 1] * 20})
    r = _upload(admin, "fake.csv", df.to_csv(index=False), "nsl-kdd")
    assert r.status_code == 422 and "missing columns" in r.get_json()["error"]


def test_invalid_uploads_rejected(admin):
    assert _upload(admin, "x.exe", b"MZ\x90\x00", "custom").status_code == 415
    assert _upload(admin, "x.csv", b"", "custom").status_code == 422
    assert _upload(admin, "bin.csv", b"\x00\x01\x02binary" * 50, "custom").status_code == 422
    assert _upload(admin, "tiny.csv", "a,b,c\n1,2,3\n", "custom").status_code == 422
    assert _upload(admin, "one.csv", "a\n1\n2\n3\n", "custom").status_code == 422
    assert _upload(admin, "ok.csv", "a,b,c\n" + "1,2,3\n" * 30, "bogus-type").status_code == 400
    r = admin.client.post("/api/datasets/upload", data={}, content_type="multipart/form-data", headers=admin._h())
    assert r.status_code == 400


def test_unknown_label_column_rejected(admin):
    df = pd.DataFrame({"a": range(40), "b": range(40), "c": range(40)})
    r = _upload(admin, "d.csv", df.to_csv(index=False), "custom", label_column="does_not_exist")
    assert r.status_code == 422


def test_upload_size_limit_enforced(admin):
    big = b"a,b,c\n" + b"1,2,3\n" * (2 * 1024 * 1024)  # ~12 MB > 5 MB test limit
    assert _upload(admin, "big.csv", big, "custom").status_code == 413


def test_path_traversal_filename_is_neutralised(admin, app):
    df = pd.DataFrame({"a": range(40), "b": range(40), "label": [0, 1] * 20})
    r = _upload(admin, "x", df.to_csv(index=False), "custom", filename="../../evil.csv")
    assert r.status_code == 201
    stored = Path(admin.get("/api/datasets").get_json()["data"][0]["original_filename"])
    assert ".." not in str(stored) and "/" not in str(stored)
    for f in Path(app.config["UPLOAD_DIR"]).iterdir():
        assert f.parent == Path(app.config["UPLOAD_DIR"])


def test_delete_dataset_removes_row_and_file(admin):
    d = admin.post("/api/datasets/load-sample", {"type": "unsw-nb15"}).get_json()["data"]
    row = admin.get(f"/api/datasets/{d['dataset_id']}").get_json()["data"]
    assert admin.delete(f"/api/datasets/{d['dataset_id']}").status_code == 200
    assert admin.get(f"/api/datasets/{d['dataset_id']}").status_code == 404
    assert admin.delete("/api/datasets/9999").status_code == 404


def test_analyst_can_read_but_not_upload(analyst, admin):
    admin.post("/api/datasets/load-sample", {"type": "nsl-kdd"})
    assert analyst.get("/api/datasets").status_code == 200
    assert len(analyst.get("/api/datasets").get_json()["data"]) == 1
    assert _upload(analyst, "a.csv", "a,b,c\n" + "1,2,3\n" * 30, "custom").status_code == 403
