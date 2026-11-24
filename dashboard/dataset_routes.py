"""Dataset management API."""
import logging
import re
import uuid
from pathlib import Path

from flask import Blueprint, current_app, request
from werkzeug.utils import secure_filename

from dashboard.services import DATASET_TYPES, ingest_file, preprocess_dataset, remove_dataset_files
from dashboard.utils import admin_required, fail, json_body, login_required, ok, safe_int
from database.repositories import Datasets
from preprocessing.dataset_loader import DatasetError, df_to_clean_json_records, read_dataset
from preprocessing.pipeline import PreprocessConfig

log = logging.getLogger(__name__)
dataset_bp = Blueprint("datasets_api", __name__, url_prefix="/api/datasets")

SAMPLES = {
    "nsl-kdd": ("nslkdd_synthetic_sample.csv", "NSL-KDD structure sample (SYNTHETIC)"),
    "unsw-nb15": ("unsw_nb15_synthetic_sample.csv", "UNSW-NB15 structure sample (SYNTHETIC)"),
}


def _dataset_or_404(dataset_id):
    ds = Datasets.get(dataset_id)
    return ds


def _public(ds, detail=False):
    keep = ["dataset_id", "dataset_name", "original_filename", "dataset_type", "file_size", "row_count",
            "column_count", "label_column", "processing_status", "error_message", "created_at"]
    out = {k: ds.get(k) for k in keep}
    if "metadata" in ds:
        meta = ds["metadata"] or {}
        out["class_counts"] = meta.get("class_counts")
        out["missing_total"] = (meta.get("missing") or {}).get("total")
        out["duplicate_rows"] = meta.get("duplicate_rows")
    if detail:
        out["metadata"] = ds.get("metadata")
        out["preprocess_config"] = ds.get("preprocess_config")
        out["preprocess_summary"] = ds.get("preprocess_summary")
    return out


@dataset_bp.get("")
@login_required
def list_datasets():
    rows = Datasets.list()
    return ok([{**r} for r in rows])


@dataset_bp.post("/upload")
@admin_required
def upload():
    cfg = current_app.config
    f = request.files.get("file")
    if f is None or not f.filename:
        return fail("No file was uploaded.", 400)
    original = secure_filename(f.filename)
    ext = Path(original).suffix.lower()
    if not original or ext not in cfg["ALLOWED_EXTENSIONS"]:
        return fail("Unsupported file type. Upload a .csv or .txt file.", 415)
    dtype = (request.form.get("dataset_type") or "auto").lower()
    if dtype not in DATASET_TYPES:
        return fail("Unknown dataset type.", 400)
    name = re.sub(r"\s+", " ", (request.form.get("dataset_name") or Path(original).stem)).strip()[:150]
    if not name:
        return fail("Dataset name is required.", 400)
    label = (request.form.get("label_column") or "").strip() or None
    tmp = Path(cfg["UPLOAD_DIR"]) / f"tmp_{uuid.uuid4().hex}.upload"
    try:
        f.save(tmp)  # server-generated filename: the client name is never used as a path
        ds = ingest_file(tmp, original, name, dtype, label, _uid(), cfg["UPLOAD_DIR"])
    except DatasetError as exc:
        return fail(str(exc), 422)
    except Exception:  # noqa: BLE001
        log.exception("Dataset upload failed")
        return fail("The dataset could not be processed.", 500)
    finally:
        tmp.unlink(missing_ok=True)
    return ok(_public(ds, detail=True), 201)


@dataset_bp.post("/load-sample")
@admin_required
def load_sample():
    """Register one of the bundled SYNTHETIC structure samples (for demos and tests only)."""
    key = json_body().get("type")
    if key not in SAMPLES:
        return fail("type must be 'nsl-kdd' or 'unsw-nb15'.", 400)
    fname, title = SAMPLES[key]
    path = Path(current_app.config["SAMPLE_DIR"]) / fname
    if not path.exists():
        return fail("Sample file not found. Run: python scripts/generate_sample_data.py", 404)
    try:
        ds = ingest_file(path, fname, title, key, None, _uid(), current_app.config["UPLOAD_DIR"])
    except DatasetError as exc:
        return fail(str(exc), 422)
    return ok(_public(ds, detail=True), 201)


def _uid():
    from dashboard.utils import current_user
    u = current_user()
    return u["user_id"] if u else None


@dataset_bp.get("/<int:dataset_id>")
@login_required
def get_dataset(dataset_id):
    ds = _dataset_or_404(dataset_id)
    if not ds:
        return fail("Dataset not found.", 404)
    out = _public(ds, detail=True)
    n = safe_int(request.args.get("preview"), 0, 0, 100)
    if n:
        try:
            out["preview"] = df_to_clean_json_records(read_dataset(ds["file_path"], ds["dataset_type"], nrows=n))
        except (DatasetError, OSError) as exc:
            out["preview"] = []
            out["preview_error"] = str(exc)
    return ok(out)


@dataset_bp.delete("/<int:dataset_id>")
@admin_required
def delete_dataset(dataset_id):
    ds = _dataset_or_404(dataset_id)
    if not ds:
        return fail("Dataset not found.", 404)
    if ds["processing_status"] == "Preprocessing":
        return fail("The dataset is being processed; wait for it to finish.", 409)
    replay = current_app.extensions["replay"].status()
    if replay["running"] and replay["dataset_id"] == dataset_id:
        return fail("This dataset is currently being replayed. Stop the replay first.", 409)
    Datasets.delete(dataset_id)
    remove_dataset_files(ds, current_app.config["PROCESSED_DIR"])
    return ok({"deleted": dataset_id})


@dataset_bp.post("/<int:dataset_id>/preprocess")
@admin_required
def preprocess(dataset_id):
    ds = _dataset_or_404(dataset_id)
    if not ds:
        return fail("Dataset not found.", 404)
    if ds["processing_status"] == "Preprocessing":
        return fail("Preprocessing is already running for this dataset.", 409)
    body = json_body()
    columns = [c["name"] for c in (ds["metadata"] or {}).get("columns", [])]
    try:
        cfg = PreprocessConfig.from_dict({"label_column": ds["label_column"], **body})
        if not cfg.label_column:
            raise DatasetError("Select the label column.")
        if cfg.label_column not in columns:
            raise DatasetError(f"Label column '{cfg.label_column}' does not exist in this dataset.")
        bad = [c for c in cfg.exclude_columns if c not in columns]
        if bad:
            raise DatasetError("Unknown column(s) to exclude: " + ", ".join(bad[:5]))
        if cfg.test_dataset_id and not Datasets.get(cfg.test_dataset_id):
            raise DatasetError("The selected test dataset does not exist.")
    except DatasetError as exc:
        return fail(str(exc), 422)
    Datasets.update(dataset_id, processing_status="Preprocessing", error_message=None)
    current_app.extensions["light_runner"].submit(
        preprocess_dataset, dataset_id, cfg.to_dict(), current_app.config["PROCESSED_DIR"])
    return ok(_public(Datasets.get(dataset_id)), 202)
