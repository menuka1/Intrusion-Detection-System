"""Page routes, dashboard statistics, system status and application settings."""
from flask import Blueprint, abort, current_app, render_template

from dashboard.utils import admin_required, csrf_token, current_user, fail, json_body, login_required, ok, safe_int
from database.db_connection import get_db
from database.repositories import Alerts, Datasets, Jobs, Models, Settings, Stats, Traffic
from detection.alert_generator import DEFAULT_SETTINGS

main_bp = Blueprint("main", __name__)

PAGES = {
    "index": ("dashboard.html", "dashboard", "Dashboard"),
    "traffic": ("traffic.html", "traffic", "Traffic Monitoring"),
    "datasets": ("datasets.html", "datasets", "Datasets"),
    "preprocessing": ("preprocessing.html", "preprocessing", "Preprocessing"),
    "training": ("model_training.html", "training", "Model Training"),
    "comparison": ("model_comparison.html", "comparison", "Model Comparison"),
    "alerts": ("alerts.html", "alerts", "Intrusion Alerts"),
    "reports": ("reports.html", "reports", "Reports"),
    "settings": ("settings.html", "settings", "Settings"),
    "profile": ("profile.html", "profile", "Profile"),
}


def _page(name, **ctx):
    tpl, nav, title = PAGES[name]
    return render_template(tpl, nav=nav, page_title=title, user=current_user(), csrf=csrf_token(), **ctx)


@main_bp.get("/")
@login_required
def index():
    return _page("index")


@main_bp.get("/traffic")
@login_required
def traffic():
    return _page("traffic")


@main_bp.get("/datasets")
@login_required
def datasets():
    return _page("datasets")


@main_bp.get("/datasets/<int:dataset_id>")
@login_required
def dataset_details(dataset_id):
    if not Datasets.get(dataset_id):
        abort(404)
    tpl, nav, _ = "dataset_details.html", "datasets", ""
    return render_template(tpl, nav=nav, page_title="Dataset Details", user=current_user(), csrf=csrf_token(),
                           dataset_id=dataset_id)


@main_bp.get("/preprocessing")
@login_required
def preprocessing():
    return _page("preprocessing")


@main_bp.get("/training")
@login_required
def training():
    return _page("training")


@main_bp.get("/comparison")
@login_required
def comparison():
    return _page("comparison")


@main_bp.get("/alerts")
@login_required
def alerts():
    return _page("alerts")


@main_bp.get("/reports")
@login_required
def reports():
    return _page("reports")


@main_bp.get("/settings")
@login_required
def settings():
    return _page("settings")


@main_bp.get("/profile")
@login_required
def profile():
    return _page("profile")


@main_bp.get("/healthz")
def healthz():
    """Unauthenticated liveness probe; exposes nothing beyond up/down."""
    return ok({"status": "up", "database": get_db().ping()})


# ------------------------------------------------------------------ system status
def system_status():
    db_ok = get_db().ping()
    engine = current_app.extensions["engine"].status() if db_ok else {"state": "unknown", "label": "Database unavailable"}
    replay = current_app.extensions["replay"].status()
    active = Models.active() if db_ok else None
    pre = Datasets.count_processing() if db_ok else 0
    jobs = Jobs.running_count() if db_ok else 0
    healthy = db_ok and engine["state"] != "error"
    return {
        "database": {"ok": db_ok, "backend": current_app.config["DB_BACKEND"],
                     "label": "Connected" if db_ok else "Disconnected"},
        "ml_engine": engine,
        "selected_model": ({"model_id": active["model_id"], "algorithm": active["algorithm"], "version": active["version"],
                            "dataset_name": active["dataset_name"]} if active else None),
        "dataset_processing": {"preprocessing": pre, "training_jobs_active": jobs,
                               "label": "Busy" if (pre or jobs) else "Idle"},
        "replay": {"state": replay["state"], "running": replay["running"], "processed": replay["processed"]},
        "health": "healthy" if healthy else "degraded",
    }


@main_bp.get("/api/system/status")
@login_required
def api_system_status():
    return ok(system_status())


@main_bp.get("/api/dashboard/statistics")
@login_required
def dashboard_statistics():
    totals = Stats.totals()
    active = Models.active()
    sel = None
    if active:
        sel = {"model_id": active["model_id"], "algorithm": active["algorithm"], "version": active["version"],
               "accuracy": active["accuracy"], "f1_score": active["f1_score"], "dataset_name": active["dataset_name"]}
    return ok({**totals, "selected_model": sel, "system": system_status()})


@main_bp.get("/api/dashboard/traffic-summary")
@login_required
def dashboard_traffic_summary():
    from flask import request
    minutes = safe_int(request.args.get("minutes"), 30, 5, 1440)
    bucket = 60 if minutes <= 120 else 600
    return ok({
        "timeline": Stats.timeline(minutes=minutes, bucket_seconds=bucket), "bucket_seconds": bucket,
        "protocols": [{"protocol": r["protocol"], "total": int(r["total"]), "malicious": int(r["malicious"] or 0)}
                      for r in Stats.protocol_distribution()],
        "recent": Traffic.recent(15), "totals": Stats.totals()})


@main_bp.get("/api/dashboard/alert-summary")
@login_required
def dashboard_alert_summary():
    return ok({**Stats.alert_breakdown(), "recent": Alerts.recent(8)})


# ------------------------------------------------------------------ settings
def _validate_setting(key, raw):
    raw = "" if raw is None else str(raw).strip()
    if key == "default_dataset_id":
        if raw == "":
            return ""
        did = safe_int(raw)
        if not did or not Datasets.get(did):
            raise ValueError("default_dataset_id must reference an existing dataset.")
        return str(did)
    ranges = {"replay_speed": (1, 200, int), "dashboard_refresh_seconds": (2, 120, int),
              "severity_burst_count": (1, 1000, int), "severity_size_threshold": (0, 10**12, int),
              "severity_small_size": (0, 10**12, int), "alert_min_confidence": (0.0, 1.0, float)}
    lo, hi, typ = ranges[key]
    try:
        val = typ(raw)
    except ValueError as exc:
        raise ValueError(f"{key} must be a number.") from exc
    if not lo <= val <= hi:
        raise ValueError(f"{key} must be between {lo} and {hi}.")
    return str(val)


@main_bp.get("/api/settings")
@login_required
def get_settings():
    cfg = current_app.config
    active = Models.active()
    return ok({
        "settings": {**DEFAULT_SETTINGS, **Settings.all()},
        "active_model": ({"model_id": active["model_id"], "algorithm": active["algorithm"], "version": active["version"],
                          "dataset_name": active["dataset_name"]} if active else None),
        "system": system_status(),
        "application": {"environment": cfg["ENV"], "database_backend": cfg["DB_BACKEND"],
                        "max_upload_mb": cfg["MAX_UPLOAD_MB"], "session_hours": cfg["SESSION_HOURS"],
                        "allowed_extensions": sorted(cfg["ALLOWED_EXTENSIONS"])},
    })


@main_bp.put("/api/settings")
@admin_required
def put_settings():
    body = json_body()
    clean = {}
    for key, raw in body.items():
        if key not in DEFAULT_SETTINGS:
            return fail(f"Unknown setting '{key}'.", 422)
        try:
            clean[key] = _validate_setting(key, raw)
        except ValueError as exc:
            return fail(str(exc), 422)
    for k, v in clean.items():
        Settings.set(k, v)
    current_app.extensions["engine"].refresh_settings()
    return ok({**DEFAULT_SETTINGS, **Settings.all()})
