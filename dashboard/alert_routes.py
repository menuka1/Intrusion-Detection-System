"""Intrusion alert management API. Alerts are informational: nothing here blocks traffic."""
from flask import Blueprint, request

from dashboard.utils import current_user, fail, json_body, login_required, ok, parse_date, safe_int
from database.repositories import Alerts, Stats, Traffic

alert_bp = Blueprint("alerts_api", __name__, url_prefix="/api/alerts")
STATUSES = ("Open", "Acknowledged", "Resolved")
LEVELS = ("Low", "Medium", "High", "Critical")


@alert_bp.get("")
@login_required
def list_alerts():
    a = request.args
    f = {"q": (a.get("q") or "").strip()[:100],
         "threat_level": a.get("threat_level") if a.get("threat_level") in LEVELS else None,
         "status": a.get("status") if a.get("status") in STATUSES else None,
         "date_from": parse_date(a.get("date_from")), "date_to": parse_date(a.get("date_to")),
         "model": (a.get("model") or "").strip()[:50]}
    data = Alerts.list(f, safe_int(a.get("page"), 1, 1), safe_int(a.get("per_page"), 25, 1, 200))
    data["summary"] = Stats.alert_breakdown()
    return ok(data)


@alert_bp.get("/<int:alert_id>")
@login_required
def get_alert(alert_id):
    alert = Alerts.get(alert_id)
    if not alert:
        return fail("Alert not found.", 404)
    log = Traffic.detail(alert["log_id"])
    return ok({"alert": alert, "log": log, "related": Alerts.related(alert["source_ip"], alert["log_id"])})


@alert_bp.patch("/<int:alert_id>/status")
@login_required
def set_status(alert_id):
    status = json_body().get("status")
    if status not in STATUSES:
        return fail(f"Status must be one of {list(STATUSES)}.", 422)
    if not Alerts.get(alert_id):
        return fail("Alert not found.", 404)
    Alerts.set_status(alert_id, status, current_user()["user_id"])
    return ok(Alerts.get(alert_id))
