"""Model training, registry, comparison and activation API."""
import logging

from flask import Blueprint, current_app, request

from dashboard.utils import admin_required, current_user, fail, json_body, login_required, ok, safe_int
from database.repositories import Datasets, Jobs, Models
from models.base import ParamError
from models.model_registry import (ALGORITHMS, METRIC_COLUMNS, algorithm_catalog, best_model, get_algorithm)
from models.trainer import run_training
from preprocessing.dataset_loader import DatasetError
from preprocessing.pipeline import PreprocessConfig

log = logging.getLogger(__name__)
model_bp = Blueprint("models_api", __name__, url_prefix="/api/models")


def _model_public(m, full=False):
    out = {k: m[k] for k in ("model_id", "algorithm", "dataset_id", "dataset_name", "version", "accuracy",
                             "precision_score", "recall_score", "f1_score", "fpr", "fnr", "training_seconds",
                             "prediction_seconds", "threshold", "is_active", "created_at")}
    out["display_name"] = ALGORITHMS[m["algorithm"]].display_name
    mt = m.get("metrics") or {}
    out["confusion_matrix"] = mt.get("confusion_matrix")
    out["roc_auc"] = mt.get("roc_auc")
    out["macro"] = mt.get("macro")
    out["n_test"] = mt.get("n_samples")
    if full:
        out["metrics"] = mt
        out["feature_schema"] = {k: v for k, v in (m.get("feature_schema") or {}).items() if k != "categories"}
        out["training_config"] = m.get("training_config")
    return out


@model_bp.get("/algorithms")
@login_required
def algorithms():
    """Algorithm catalog + latest model / job per algorithm for the training page cards."""
    cat = algorithm_catalog()
    models = Models.list()
    jobs = Jobs.list(60)
    for a in cat:
        mine = [m for m in models if m["algorithm"] == a["algorithm"]]
        a["latest_model"] = _model_public(mine[0]) if mine else None
        job = next((j for j in jobs if j["algorithm"] == a["algorithm"]), None)
        a["latest_job"] = {k: job[k] for k in ("job_id", "job_status", "progress", "progress_message", "error_message",
                                              "dataset_name")} if job else None
        a["model_count"] = len(mine)
    return ok(cat)


@model_bp.post("/train")
@admin_required
def train():
    body = json_body()
    algorithm = body.get("algorithm")
    try:
        algo = get_algorithm(algorithm)
        params = algo.validate_params(body.get("params") or {})
    except (ValueError, ParamError) as exc:
        return fail(str(exc), 422)
    dataset_id = safe_int(body.get("dataset_id"))
    ds = Datasets.get(dataset_id) if dataset_id else None
    if not ds:
        return fail("Select an existing dataset.", 404 if dataset_id else 400)
    if ds["processing_status"] == "Preprocessing":
        return fail("The dataset is still being preprocessed.", 409)
    override = body.get("preprocess") or {}
    try:
        cfg = PreprocessConfig.from_dict({"label_column": ds["label_column"], **(ds.get("preprocess_config") or {}), **override})
        if not cfg.label_column:
            raise DatasetError("The dataset has no label column. Set it on the Preprocessing page first.")
    except DatasetError as exc:
        return fail(str(exc), 422)
    user = current_user()
    job_id = Jobs.create(dataset_id, algorithm, {"params": params, "preprocess": cfg.to_dict()}, user["user_id"])
    current_app.extensions["train_runner"].submit(
        run_training, job_id, dataset_id, algorithm, params, cfg.to_dict(), user["user_id"], current_app.config["MODEL_DIR"])
    return ok(Jobs.get(job_id), 202)


@model_bp.get("/jobs")
@login_required
def jobs():
    return ok(Jobs.list(safe_int(request.args.get("limit"), 30, 1, 100)))


@model_bp.get("/jobs/<int:job_id>")
@login_required
def job(job_id):
    j = Jobs.get(job_id)
    return ok(j) if j else fail("Job not found.", 404)


@model_bp.get("")
@login_required
def list_models():
    rows = Models.list(safe_int(request.args.get("dataset_id")), request.args.get("algorithm") or None)
    return ok([_model_public(m) for m in rows])


@model_bp.get("/metrics")
@login_required
def metrics():
    """Latest model per algorithm (for the dashboard performance chart)."""
    dataset_id = safe_int(request.args.get("dataset_id"))
    rows = Models.list(dataset_id)
    latest = {}
    for m in rows:  # rows are newest first
        latest.setdefault((m["algorithm"], m["dataset_id"]), m)
    return ok([_model_public(m) for m in latest.values()])


@model_bp.get("/comparison")
@login_required
def comparison():
    """Compare the newest model of each algorithm on one dataset."""
    metric = request.args.get("metric", "f1_score")
    if metric not in METRIC_COLUMNS:
        return fail("Unknown metric.", 400)
    all_models = Models.list()
    dataset_id = safe_int(request.args.get("dataset_id"))
    if not dataset_id and all_models:
        active = next((m for m in all_models if m["is_active"]), all_models[0])
        dataset_id = active["dataset_id"]
    mine = [m for m in all_models if m["dataset_id"] == dataset_id]
    latest = {}
    for m in mine:
        latest.setdefault(m["algorithm"], m)
    rows = list(latest.values())
    datasets = {}
    for m in all_models:
        if m["dataset_id"]:
            datasets[m["dataset_id"]] = m["dataset_name"]
    ds = Datasets.get(dataset_id) if dataset_id else None
    return ok({
        "dataset_id": dataset_id, "metric": metric, "best_model_id": best_model(rows, metric),
        "models": [_model_public(m, full=True) for m in rows],
        "versions": [_model_public(m) for m in mine],
        "datasets": [{"dataset_id": k, "dataset_name": v} for k, v in datasets.items()],
        "dataset": ({"dataset_id": ds["dataset_id"], "dataset_name": ds["dataset_name"], "dataset_type": ds["dataset_type"],
                     "row_count": ds["row_count"], "column_count": ds["column_count"]} if ds else None),
        "note": "Metrics are measured on the held-out test split; precision/recall/F1 are for the malicious class.",
    })


@model_bp.get("/<int:model_id>")
@login_required
def get_model(model_id):
    m = Models.get(model_id)
    return ok(_model_public(m, full=True)) if m else fail("Model not found.", 404)


@model_bp.post("/<int:model_id>/activate")
@admin_required
def activate(model_id):
    m = Models.get(model_id)
    if not m:
        return fail("Model not found.", 404)
    engine = current_app.extensions["engine"]
    try:  # make sure it really loads before it becomes the detection model
        engine.cache.invalidate()
        from models.model_registry import load_artifacts
        load_artifacts(m, current_app.config["MODEL_DIR"])
    except Exception as exc:  # noqa: BLE001
        return fail(f"This model cannot be activated: {exc}", 422)
    Models.activate(model_id)
    engine.cache.invalidate()
    return ok(_model_public(Models.get(model_id)))
