"""Traffic monitoring, detection and replay API."""
import logging

from flask import Blueprint, current_app, request

from dashboard.utils import (admin_required, current_user, fail, json_body, login_required, ok, safe_int,
                             traffic_filters)
from database.repositories import Datasets, Traffic
from detection.engine import EngineError
from detection.traffic_replay import MAX_SPEED
from preprocessing.dataset_loader import DatasetError

log = logging.getLogger(__name__)
traffic_bp = Blueprint("traffic_api", __name__, url_prefix="/api")

MAX_PREDICT_RECORDS = 500


def _list_args():
    a = request.args
    return traffic_filters(a), safe_int(a.get("page"), 1, 1), safe_int(a.get("per_page"), 25, 1, 200), \
        a.get("sort", "log_id"), a.get("order", "desc")


@traffic_bp.get("/traffic")
@login_required
def list_traffic():
    f, page, per, sort, order = _list_args()
    return ok(Traffic.list(f, page, per, sort, order))


@traffic_bp.get("/traffic/protocols")
@login_required
def protocols():
    return ok(Traffic.protocols())


@traffic_bp.get("/traffic/<int:log_id>")
@login_required
def traffic_detail(log_id):
    row = Traffic.detail(log_id)
    return ok(row) if row else fail("Traffic record not found.", 404)


@traffic_bp.get("/detection/history")
@login_required
def detection_history():
    f, page, per, sort, order = _list_args()
    return ok(Traffic.list(f, page, per, sort, order))


@traffic_bp.post("/detection/predict")
@login_required
def predict():
    """Classify one record (``record``) or a batch (``records``) of prepared feature rows."""
    body = json_body()
    records = body.get("records")
    if records is None and isinstance(body.get("record"), dict):
        records = [body["record"]]
    if not isinstance(records, list) or not records or not all(isinstance(r, dict) for r in records):
        return fail("Provide 'record' (object) or 'records' (non-empty list of objects).", 400)
    if len(records) > MAX_PREDICT_RECORDS:
        return fail(f"At most {MAX_PREDICT_RECORDS} records per request.", 413)
    try:
        results = current_app.extensions["engine"].classify(records, user_id=current_user()["user_id"], source="api")
    except DatasetError as exc:
        return fail(str(exc), 422)
    except EngineError as exc:
        return fail(str(exc), 409)
    return ok(results[0] if "record" in body and "records" not in body else results)


# ------------------------------------------------------------------ replay (simulation)
@traffic_bp.get("/traffic/replay/status")
@login_required
def replay_status():
    return ok(current_app.extensions["replay"].status())


@traffic_bp.post("/traffic/replay/start")
@admin_required
def replay_start():
    body = json_body()
    ds = Datasets.get(safe_int(body.get("dataset_id"), 0) or 0)
    if not ds:
        return fail("Select an existing dataset to replay.", 404)
    speed = safe_int(body.get("speed"), 5, 1, MAX_SPEED)
    max_records = safe_int(body.get("max_records"), None, 1, 10_000_000)
    try:
        status = current_app.extensions["replay"].start(ds, speed, current_user()["user_id"], max_records)
    except EngineError as exc:
        return fail(str(exc), 409)
    except DatasetError as exc:
        return fail(str(exc), 422)
    return ok(status, 202)


@traffic_bp.post("/traffic/replay/stop")
@admin_required
def replay_stop():
    return ok(current_app.extensions["replay"].stop())
