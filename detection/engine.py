"""Central intrusion detection engine.

validate -> preprocess (model's own pipeline) -> predict -> confidence ->
classify -> store log + prediction -> raise alert when malicious.
Nothing here is hard-coded: predictions come from the active trained model.
"""
import logging
import threading
import time

import numpy as np

from database.db_connection import get_db, utcnow
from database.repositories import Models, Settings, Traffic
from detection.alert_generator import BurstTracker, DEFAULT_SETTINGS, assess_severity, build_alert, setting_float
from detection.predictor import ModelCache, records_to_frame
from preprocessing.dataset_loader import DatasetError, extract_log_fields, get_profile, with_endpoint_columns

log = logging.getLogger(__name__)


class EngineError(RuntimeError):
    """The engine cannot classify (e.g. no active model)."""


def _py(v):
    if isinstance(v, (np.integer,)):
        return int(v)
    if isinstance(v, (np.floating, float)):
        return None if not np.isfinite(v) else float(v)
    if isinstance(v, np.bool_):
        return bool(v)
    return v


class DetectionEngine:
    def __init__(self, model_dir):
        self.cache = ModelCache(model_dir)
        self.burst = BurstTracker()
        self._settings_cache = (0.0, dict(DEFAULT_SETTINGS))
        self._lock = threading.Lock()
        self.last_error = None

    # ---- settings ------------------------------------------------------------
    def settings(self):
        ts, cached = self._settings_cache
        if time.monotonic() - ts > 3:
            merged = {**DEFAULT_SETTINGS, **Settings.all()}
            self._settings_cache = (time.monotonic(), merged)
            return merged
        return cached

    def refresh_settings(self):
        self._settings_cache = (0.0, self._settings_cache[1])

    # ---- model ---------------------------------------------------------------
    def active_model(self):
        row = Models.active()
        if row is None:
            raise EngineError("No active detection model. Train a model and activate it on the Model Comparison page.")
        try:
            return self.cache.get(row)
        except Exception as exc:  # noqa: BLE001
            self.last_error = str(exc)
            raise EngineError(f"The active model could not be loaded: {exc}") from exc

    def status(self):
        row = Models.active()
        if row is None:
            return {"state": "no_model", "label": "No active model", "model": None}
        try:
            self.cache.get(row)
            self.last_error = None
            return {"state": "ready", "label": "Ready", "model": row["algorithm"], "model_id": row["model_id"],
                    "version": row["version"]}
        except Exception as exc:  # noqa: BLE001
            self.last_error = str(exc)
            return {"state": "error", "label": "Model failed to load", "error": str(exc), "model": row["algorithm"]}

    # ---- classification ------------------------------------------------------------
    def classify(self, records, user_id=None, source="api", dataset_id=None, profile=None,
                 ground_truth=None, start_index=0):
        """Classify feature records and persist the results. Returns one result dict per record."""
        if not records:
            raise DatasetError("No records supplied.")
        loaded = self.active_model()
        df = records_to_frame(records)
        problems = loaded.validate(df)
        if problems:
            raise DatasetError(" ".join(problems))
        t0 = time.perf_counter()
        proba = loaded.malicious_probability(df)
        elapsed = time.perf_counter() - t0
        settings = self.settings()
        min_conf = setting_float(settings, "alert_min_confidence")
        if profile is None:
            schema = loaded.row["feature_schema"] or {}
            profile = get_profile(schema.get("dataset_type") or "custom", list(df.columns))
            profile = with_endpoint_columns(profile, df.columns)

        results = []
        now = utcnow()
        with get_db().transaction() as tx:
            for i, rec in enumerate(records):
                p = float(proba[i])
                malicious = p >= loaded.threshold
                confidence = p if malicious else 1.0 - p
                fields = extract_log_fields(rec, profile, start_index + i)
                raw = {c: _py(rec.get(c)) for c in loaded.feature_columns}
                meta = {"simulated_endpoints": fields["simulated_endpoints"], "source": source}
                if ground_truth is not None:
                    meta["ground_truth"] = "Malicious" if ground_truth[i] else "Normal"  # evaluation only
                log_rec = {"user_id": user_id, "timestamp": now, "source_ip": fields["source_ip"],
                       "destination_ip": fields["destination_ip"], "protocol": fields["protocol"],
                       "packet_size": fields["packet_size"], "raw_data": {"features": raw, "meta": meta},
                       "source": source, "dataset_id": dataset_id}
                alert, level = None, None
                if malicious and p >= min_conf:
                    with self._lock:
                        recent = self.burst.hit(fields["source_ip"])
                    level, reasons = assess_severity(fields["packet_size"], recent, settings)
                    alert = build_alert(fields, loaded.name, confidence, level, reasons)
                pred = {"model_id": loaded.model_id, "model_name": loaded.name, "model_version": loaded.version,
                        "prediction_result": "Malicious" if malicious else "Normal",
                        "confidence_score": confidence, "malicious_probability": p}
                log_id, pred_id, alert_id = Traffic.insert_detection(tx, log_rec, pred, alert)
                results.append({
                    "log_id": log_id, "prediction_id": pred_id, "alert_id": alert_id,
                    "prediction": pred["prediction_result"], "model": loaded.name, "model_version": loaded.version,
                    "confidence": round(confidence, 6), "malicious_probability": round(p, 6),
                    "status": "Threat Detected" if malicious else "Normal",
                    "alert_generated": alert_id is not None, "threat_level": level,
                    "source_ip": fields["source_ip"], "destination_ip": fields["destination_ip"],
                    "protocol": fields["protocol"], "packet_size": fields["packet_size"],
                    "simulated_endpoints": fields["simulated_endpoints"]})
        log.debug("classified %d records in %.3fs", len(records), elapsed)
        return results
