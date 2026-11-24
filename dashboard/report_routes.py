"""Reporting: every report is computed from database rows and stored evaluation results."""
import csv
import io
from datetime import datetime, timezone

from flask import Blueprint, Response, request

from dashboard.utils import fail, login_required, ok, parse_date, safe_int
from database.db_connection import get_db
from database.repositories import Alerts, Datasets, Models, Stats, Traffic, day_end, day_start
from models.model_registry import ALGORITHMS

report_bp = Blueprint("reports_api", __name__, url_prefix="/api/reports")

REPORT_TYPES = {
    "traffic": "Network Traffic Report",
    "intrusion": "Intrusion Detection Report",
    "threat_summary": "Threat Summary Report",
    "ml_performance": "Machine Learning Performance Report",
    "dataset_analysis": "Dataset Analysis Report",
    "alert_history": "Historical Alert Report",
}


def _pct(n, d):
    return round(100.0 * n / d, 2) if d else 0.0


def _range_sql(col, f, where, params):
    if f.get("date_from"):
        where.append(f"{col} >= %s")
        params.append(day_start(f["date_from"]))
    if f.get("date_to"):
        where.append(f"{col} <= %s")
        params.append(day_end(f["date_to"]))


def _kpi(label, value, tone=None):
    return {"label": label, "value": value, "tone": tone}


def _table(title, columns, rows):
    return {"title": title, "columns": columns, "rows": [list(r) for r in rows]}


def _chart(title, kind, labels, series):
    return {"title": title, "type": kind, "labels": labels, "series": series}


def _model_filter_sql(f, where, params):
    if f.get("model"):
        where.append("p.model_name=%s")
        params.append(f["model"])


# ------------------------------------------------------------------ builders
def traffic_report(f):
    where, params = [], []
    _range_sql("l.timestamp", f, where, params)
    _model_filter_sql(f, where, params)
    if f.get("dataset_id"):
        where.append("l.dataset_id=%s")
        params.append(f["dataset_id"])
    w = (" WHERE " + " AND ".join(where)) if where else ""
    db = get_db()
    tot = db.query_one(
        "SELECT COUNT(*) AS n, COALESCE(SUM(CASE WHEN p.prediction_result='Malicious' THEN 1 ELSE 0 END),0) AS m "
        f"FROM network_logs l JOIN predictions p ON p.log_id=l.log_id{w}", params)
    n, m = int(tot["n"]), int(tot["m"])
    protos = db.query_all(
        "SELECT COALESCE(l.protocol,'UNKNOWN') AS protocol, COUNT(*) AS total, "
        "SUM(CASE WHEN p.prediction_result='Malicious' THEN 1 ELSE 0 END) AS malicious, "
        f"AVG(l.packet_size) AS avg_size FROM network_logs l JOIN predictions p ON p.log_id=l.log_id{w} "
        "GROUP BY l.protocol ORDER BY total DESC", params)
    recent = db.query_all(
        "SELECT l.timestamp, l.source_ip, l.destination_ip, l.protocol, l.packet_size, p.prediction_result, "
        f"p.confidence_score, p.model_name FROM network_logs l JOIN predictions p ON p.log_id=l.log_id{w} "
        "ORDER BY l.log_id DESC LIMIT 200", params)
    tl = Stats.timeline(bucket_seconds=3600, date_from=f.get("date_from"), date_to=f.get("date_to")) \
        if (f.get("date_from") or f.get("date_to")) else Stats.timeline(minutes=24 * 60, bucket_seconds=3600)
    return {
        "kpis": [_kpi("Total records", n), _kpi("Normal traffic", n - m, "ok"), _kpi("Malicious traffic", m, "danger" if m else None),
                 _kpi("Malicious share", f"{_pct(m, n)}%")],
        "charts": [_chart("Traffic over time (hourly)", "line", [t["t"][5:16].replace("T", " ") for t in tl],
                          [{"name": "Normal", "data": [t["normal"] for t in tl]},
                           {"name": "Malicious", "data": [t["malicious"] for t in tl]}]),
                   _chart("Protocol distribution", "bar", [r["protocol"] for r in protos],
                          [{"name": "Normal", "data": [int(r["total"]) - int(r["malicious"]) for r in protos]},
                           {"name": "Malicious", "data": [int(r["malicious"]) for r in protos]}])],
        "tables": [_table("Protocol statistics", ["Protocol", "Records", "Malicious", "Malicious %", "Avg packet size"],
                          [[r["protocol"], int(r["total"]), int(r["malicious"]), _pct(int(r["malicious"]), int(r["total"])),
                            round(float(r["avg_size"] or 0), 1)] for r in protos]),
                   _table("Latest 200 analysed records", ["Timestamp", "Source IP", "Destination IP", "Protocol", "Packet size",
                                                          "Prediction", "Confidence", "Model"],
                          [[str(r["timestamp"]), r["source_ip"], r["destination_ip"], r["protocol"], r["packet_size"],
                            r["prediction_result"], round(r["confidence_score"], 4), r["model_name"]] for r in recent])],
    }


def intrusion_report(f):
    where, params = [], []
    _range_sql("a.created_at", f, where, params)
    _model_filter_sql(f, where, params)
    w = (" WHERE " + " AND ".join(where)) if where else ""
    db = get_db()
    by_model = db.query_all(
        "SELECT p.model_name, COUNT(*) AS alerts, AVG(p.confidence_score) AS avg_conf FROM alerts a "
        f"JOIN predictions p ON p.prediction_id=a.prediction_id{w} GROUP BY p.model_name", params)
    where2, p2 = [], []
    _range_sql("p.created_at", f, where2, p2)
    _model_filter_sql(f, where2, p2)
    w2 = (" WHERE " + " AND ".join(where2)) if where2 else ""
    det = db.query_one(
        "SELECT COUNT(*) AS n, COALESCE(SUM(CASE WHEN p.prediction_result='Malicious' THEN 1 ELSE 0 END),0) AS m "
        f"FROM predictions p{w2}", p2)
    n, m = int(det["n"]), int(det["m"])
    levels = db.query_all(f"SELECT a.threat_level, COUNT(*) AS n FROM alerts a JOIN predictions p ON p.prediction_id=a.prediction_id{w} GROUP BY a.threat_level", params)
    alerts_total = sum(int(r["alerts"]) for r in by_model)
    return {
        "kpis": [_kpi("Records analysed", n), _kpi("Intrusions detected", m, "danger" if m else None),
                 _kpi("Detection rate", f"{_pct(m, n)}%"), _kpi("Alerts raised", alerts_total)],
        "charts": [_chart("Alerts by threat level", "doughnut", [r["threat_level"] for r in levels],
                          [{"name": "Alerts", "data": [int(r["n"]) for r in levels]}])],
        "tables": [_table("Detections by model", ["Model", "Alerts", "Average confidence"],
                          [[r["model_name"], int(r["alerts"]), round(float(r["avg_conf"] or 0), 4)] for r in by_model])],
    }


def threat_summary_report(f):
    where, params = [], []
    _range_sql("a.created_at", f, where, params)
    w = (" WHERE " + " AND ".join(where)) if where else ""
    db = get_db()
    br = Stats.alert_breakdown(f.get("date_from"), f.get("date_to"))
    top_src = db.query_all(
        "SELECT l.source_ip, COUNT(*) AS n, MAX(a.created_at) AS last_seen FROM alerts a "
        "JOIN predictions p ON p.prediction_id=a.prediction_id JOIN network_logs l ON l.log_id=p.log_id"
        f"{w} GROUP BY l.source_ip ORDER BY n DESC LIMIT 10", params)
    top_proto = db.query_all(
        "SELECT l.protocol, COUNT(*) AS n FROM alerts a JOIN predictions p ON p.prediction_id=a.prediction_id "
        f"JOIN network_logs l ON l.log_id=p.log_id{w} GROUP BY l.protocol ORDER BY n DESC LIMIT 10", params)
    total = sum(br["by_level"].values())
    order = ["Critical", "High", "Medium", "Low"]
    return {
        "kpis": [_kpi("Total alerts", total), _kpi("Critical", br["by_level"].get("Critical", 0), "danger"),
                 _kpi("High", br["by_level"].get("High", 0), "warn"), _kpi("Open", br["by_status"].get("Open", 0), "danger")],
        "charts": [_chart("Threat level distribution", "doughnut", [l for l in order if l in br["by_level"]],
                          [{"name": "Alerts", "data": [br["by_level"][l] for l in order if l in br["by_level"]]}]),
                   _chart("Alert status", "doughnut", list(br["by_status"]), [{"name": "Alerts", "data": list(br["by_status"].values())}])],
        "tables": [_table("Top alerting source addresses", ["Source IP", "Alerts", "Last seen"],
                          [[r["source_ip"], int(r["n"]), str(r["last_seen"])] for r in top_src]),
                   _table("Alerts by protocol", ["Protocol", "Alerts"], [[r["protocol"], int(r["n"])] for r in top_proto]),
                   _table("Severity rules", ["Rule"], [
                       ["Base level MEDIUM for every malicious detection"],
                       ["LOW if isolated and packet size < severity_small_size"],
                       ["+1 level for large transfers (>= severity_size_threshold)"],
                       ["+1 level for repeated detections from one source in 60 s (+2 at 3x the burst count)"],
                       ["Severity is independent of model confidence"]])],
    }


def ml_performance_report(f):
    models = Models.list(f.get("dataset_id"), f.get("algorithm"))
    labels = [f"{ALGORITHMS[m['algorithm']].display_name} v{m['version']} ({m['dataset_name']})" for m in models]
    rows = [[ALGORITHMS[m["algorithm"]].display_name, m["dataset_name"], f"v{m['version']}", round(m["accuracy"], 4),
             round(m["precision_score"], 4), round(m["recall_score"], 4), round(m["f1_score"], 4), round(m["fpr"], 4),
             round(m["fnr"], 4), round(m["training_seconds"], 2), round(m["prediction_seconds"], 4),
             "Yes" if m["is_active"] else ""] for m in models]
    cms = [[labels[i], str(m["metrics"]["confusion_matrix"][0][0]), str(m["metrics"]["confusion_matrix"][0][1]),
            str(m["metrics"]["confusion_matrix"][1][0]), str(m["metrics"]["confusion_matrix"][1][1])]
           for i, m in enumerate(models)]
    return {
        "kpis": [_kpi("Trained models", len(models)), _kpi("Active model", next((l for l, m in zip(labels, models) if m["is_active"]), "None"))],
        "charts": [_chart("Test-set metrics (malicious class)", "bar", labels, [
            {"name": "Accuracy", "data": [round(m["accuracy"], 4) for m in models]},
            {"name": "Precision", "data": [round(m["precision_score"], 4) for m in models]},
            {"name": "Recall", "data": [round(m["recall_score"], 4) for m in models]},
            {"name": "F1", "data": [round(m["f1_score"], 4) for m in models]}])],
        "tables": [_table("Model evaluation (held-out test split)", [
            "Algorithm", "Dataset", "Version", "Accuracy", "Precision", "Recall", "F1", "FPR", "FNR", "Train s", "Predict s", "Active"], rows),
            _table("Confusion matrices", ["Model", "TN", "FP", "FN", "TP"], cms)],
    }


def dataset_analysis_report(f):
    ds_list = Datasets.list()
    if f.get("dataset_id"):
        ds_list = [d for d in ds_list if d["dataset_id"] == f["dataset_id"]]
    rows, tables = [], []
    for d in ds_list:
        full = Datasets.get(d["dataset_id"])
        meta = full["metadata"] or {}
        cc = meta.get("class_counts") or {}
        rows.append([d["dataset_name"], d["dataset_type"], d["row_count"], d["column_count"], d["label_column"] or "-",
                     cc.get("normal", "-"), cc.get("malicious", "-"), (meta.get("missing") or {}).get("total", 0),
                     meta.get("duplicate_rows", 0), d["processing_status"]])
        if f.get("dataset_id"):
            tables.append(_table("Columns", ["Column", "Kind", "Missing", "Unique values"],
                                 [[c["name"], c["kind"], c["missing"], c["unique"]] for c in meta.get("columns", [])]))
    return {
        "kpis": [_kpi("Datasets", len(rows)), _kpi("Total records", sum(int(r[2]) for r in rows))],
        "charts": [_chart("Class balance", "bar", [r[0] for r in rows if r[5] != "-"],
                          [{"name": "Normal", "data": [r[5] for r in rows if r[5] != "-"]},
                           {"name": "Malicious", "data": [r[6] for r in rows if r[5] != "-"]}])],
        "tables": [_table("Dataset overview", ["Dataset", "Type", "Rows", "Columns", "Label", "Normal", "Malicious",
                                               "Missing values", "Duplicate rows", "Status"], rows)] + tables,
    }


def alert_history_report(f):
    filt = {"date_from": f.get("date_from"), "date_to": f.get("date_to"), "model": f.get("model"), "status": f.get("status")}
    data = Alerts.list({k: v for k, v in filt.items() if v}, 1, 200)
    br = Stats.alert_breakdown(f.get("date_from"), f.get("date_to"))
    return {
        "kpis": [_kpi("Alerts in range", data["total"]), _kpi("Open", br["by_status"].get("Open", 0), "danger"),
                 _kpi("Acknowledged", br["by_status"].get("Acknowledged", 0), "warn"),
                 _kpi("Resolved", br["by_status"].get("Resolved", 0), "ok")],
        "charts": [_chart("Alerts by status", "doughnut", list(br["by_status"]), [{"name": "Alerts", "data": list(br["by_status"].values())}])],
        "tables": [_table("Alerts (latest 200)", ["ID", "Created", "Source IP", "Destination IP", "Protocol", "Model", "Confidence",
                                                  "Level", "Status"],
                          [[a["alert_id"], a["created_at"], a["source_ip"], a["destination_ip"], a["protocol"], a["model_name"],
                            round(a["confidence_score"], 4), a["threat_level"], a["status"]] for a in data["items"]])],
    }


BUILDERS = {"traffic": traffic_report, "intrusion": intrusion_report, "threat_summary": threat_summary_report,
            "ml_performance": ml_performance_report, "dataset_analysis": dataset_analysis_report,
            "alert_history": alert_history_report}


def _filters():
    a = request.args
    algo = a.get("algorithm")
    return {"date_from": parse_date(a.get("date_from")), "date_to": parse_date(a.get("date_to")),
            "dataset_id": safe_int(a.get("dataset_id")), "model": (a.get("model") or "").strip()[:50] or None,
            "algorithm": algo if algo in ALGORITHMS else None,
            "status": a.get("status") if a.get("status") in ("Open", "Acknowledged", "Resolved") else None}


def build_report(rtype, f):
    rep = BUILDERS[rtype](f)
    rep.update({"type": rtype, "title": REPORT_TYPES[rtype], "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
                "filters": {k: v for k, v in f.items() if v}})
    return rep


@report_bp.get("/summary")
@login_required
def summary():
    rtype = request.args.get("type", "traffic")
    if rtype not in BUILDERS:
        return fail(f"Unknown report type. Use one of {list(BUILDERS)}.", 400)
    return ok(build_report(rtype, _filters()))


@report_bp.get("/types")
@login_required
def types():
    return ok([{"type": k, "title": v} for k, v in REPORT_TYPES.items()])


def _safe_cell(v):
    """Neutralise spreadsheet formula injection in exported CSV cells."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") and not s.replace(".", "", 1).lstrip("-").isdigit() else s


@report_bp.get("/export")
@login_required
def export():
    rtype = request.args.get("type", "traffic")
    if rtype not in BUILDERS:
        return fail("Unknown report type.", 400)
    rep = build_report(rtype, _filters())
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([rep["title"]])
    w.writerow(["Generated (UTC)", rep["generated_at"]])
    for k, v in rep["filters"].items():
        w.writerow([f"Filter: {k}", v])
    w.writerow([])
    for k in rep["kpis"]:
        w.writerow([_safe_cell(k["label"]), _safe_cell(k["value"])])
    for t in rep["tables"]:
        w.writerow([])
        w.writerow([t["title"]])
        w.writerow(t["columns"])
        for r in t["rows"]:
            w.writerow([_safe_cell(c) for c in r])
    name = f"mlids_{rtype}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={name}"})
