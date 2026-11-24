"""Background training jobs: prepare data -> train -> evaluate -> persist -> register."""
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import joblib

from database.db_connection import utcnow
from database.repositories import Datasets, Jobs, Models
from models.base import evaluate, timed
from models.model_registry import get_algorithm, new_artifact_paths
from preprocessing.dataset_loader import DatasetError, get_profile, read_dataset, with_endpoint_columns
from preprocessing.pipeline import PreprocessConfig, prepare

log = logging.getLogger(__name__)


class JobRunner:
    """Runs jobs outside the HTTP request thread (inline when ``sync`` for tests)."""

    def __init__(self, workers=1, sync=False):
        self.sync = sync
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="mlids-job")
        self._futures = []
        self._lock = threading.Lock()

    def submit(self, fn, *args, **kwargs):
        if self.sync:
            fn(*args, **kwargs)
            return None
        fut = self._pool.submit(fn, *args, **kwargs)
        with self._lock:
            self._futures = [f for f in self._futures if not f.done()] + [fut]
        return fut

    def wait(self, timeout=None):
        for f in list(self._futures):
            f.result(timeout=timeout)


def load_prepared(dataset, cfg_dict, return_clean=False):
    """Read a dataset row's file and run the preprocessing pipeline for its type."""
    df = read_dataset(dataset["file_path"], dataset["dataset_type"])
    profile = with_endpoint_columns(get_profile(dataset["dataset_type"], list(df.columns)), df.columns)
    cfg = PreprocessConfig.from_dict({"label_column": dataset.get("label_column"), **(cfg_dict or {})})
    test_df = None
    if cfg.test_dataset_id:
        other = Datasets.get(cfg.test_dataset_id)
        if not other:
            raise DatasetError("The selected official test dataset does not exist.")
        test_df = read_dataset(other["file_path"], other["dataset_type"])
    return prepare(df, profile, cfg, test_df=test_df, return_clean=return_clean), cfg, profile


def run_training(job_id, dataset_id, algorithm, params, prep_override, user_id, model_dir):
    def progress(pct, msg):
        Jobs.update(job_id, progress=int(min(99, pct)), progress_message=str(msg)[:250])

    try:
        Jobs.update(job_id, job_status="Running", progress=2, progress_message="Loading dataset", started_at=utcnow())
        dataset = Datasets.get(dataset_id)
        if not dataset:
            raise DatasetError("Dataset no longer exists.")
        algo = get_algorithm(algorithm)
        params = algo.validate_params(params)

        progress(8, "Cleaning, splitting and fitting preprocessing on the training split")
        base_cfg = {**(dataset.get("preprocess_config") or {}), **(prep_override or {})}
        prepared, cfg, _ = load_prepared(dataset, base_cfg)

        model = algo(params)
        progress(30, f"Training {algo.display_name}")
        t0 = time.perf_counter()
        info = model.train(prepared.X_train, prepared.y_train, prepared.X_val, prepared.y_val, progress=progress)
        train_seconds = time.perf_counter() - t0

        progress(92, "Evaluating on the held-out test set")
        proba, pred_seconds = timed(model.predict_proba, prepared.X_test)
        metrics = evaluate(prepared.y_test, proba, 0.5)
        metrics["validation"] = evaluate(prepared.y_val, model.predict_proba(prepared.X_val), 0.5)
        metrics["prediction_ms_per_record"] = 1000.0 * pred_seconds / max(1, len(prepared.y_test))
        metrics["model_info"] = info
        metrics["splits"] = prepared.summary["splits"]
        metrics["split_mode"] = prepared.summary["split_mode"]
        if hasattr(model, "history") and model.history:
            metrics["history"] = {k: model.history[k] for k in ("loss", "val_loss") if k in model.history}

        progress(96, "Saving model and preprocessing pipeline")
        version = Models.next_version(algorithm, dataset_id)
        model_path, pipe_path = new_artifact_paths(model_dir, algorithm, dataset_id, version)
        model.save(model_path)
        joblib.dump(prepared.pipeline, pipe_path, compress=3)

        schema = {**prepared.pipeline.schema(), "label_column": cfg.label_column or dataset["label_column"],
                  "dataset_type": dataset["dataset_type"]}
        model_id = Models.create(
            algorithm=algorithm, dataset_id=dataset_id, dataset_name=dataset["dataset_name"], version=version,
            model_path=str(model_path), pipeline_path=str(pipe_path), feature_schema=schema,
            training_config={"params": params, "preprocess": cfg.to_dict(), "job_id": job_id},
            metrics=metrics, training_seconds=train_seconds, prediction_seconds=pred_seconds,
            threshold=0.5, created_by=user_id)
        Jobs.update(job_id, job_status="Completed", progress=100, progress_message="Completed",
                    model_id=model_id, completed_at=utcnow())
        log.info("Training job %s finished: model %s (%s v%s)", job_id, model_id, algorithm, version)
    except (DatasetError, ValueError) as exc:
        log.warning("Training job %s rejected: %s", job_id, exc)
        Jobs.update(job_id, job_status="Failed", error_message=str(exc)[:900], progress_message="Failed",
                    completed_at=utcnow())
    except Exception as exc:  # noqa: BLE001 - background job boundary
        log.exception("Training job %s failed", job_id)
        Jobs.update(job_id, job_status="Failed", error_message=f"Training failed: {type(exc).__name__}: {exc}"[:900],
                    progress_message="Failed", completed_at=utcnow())
