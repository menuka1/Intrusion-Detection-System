"""Dataset replay: a SIMULATION that feeds recorded dataset rows through the detection engine.

This is not live network capture. Dataset labels are kept out of the model input
(the label column is never part of the feature record); they are retained only
to report how often the model agreed with the ground truth.
"""
import logging
import threading
import time

import numpy as np

from database.repositories import Datasets
from preprocessing.dataset_loader import (DatasetError, binarize_labels, get_profile, read_dataset,
                                          with_endpoint_columns)

log = logging.getLogger(__name__)
MAX_SPEED = 200


class ReplayManager:
    def __init__(self, engine):
        self.engine = engine
        self._thread = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._status = self._blank()

    @staticmethod
    def _blank():
        return {"state": "idle", "dataset_id": None, "dataset_name": None, "speed": 0, "processed": 0, "total": 0,
                "normal": 0, "malicious": 0, "alerts": 0, "started_at": None, "error": None, "simulated": True,
                "agreement": {"tp": 0, "tn": 0, "fp": 0, "fn": 0}, "note":
                "Replay is a demonstration mode: recorded dataset rows, not live network capture."}

    def status(self):
        with self._lock:
            s = dict(self._status)
            s["agreement"] = dict(s["agreement"])
        a = s["agreement"]
        n = sum(a.values())
        s["ground_truth_accuracy"] = round((a["tp"] + a["tn"]) / n, 4) if n else None
        s["running"] = s["state"] in ("loading", "running")
        return s

    def is_running(self):
        return self.status()["running"]

    def _set(self, **kw):
        with self._lock:
            self._status.update(kw)

    def start(self, dataset, speed, user_id, max_records=None, seed=None):
        if self.is_running():
            raise DatasetError("A replay is already running. Stop it first.")
        speed = int(speed)
        if not 1 <= speed <= MAX_SPEED:
            raise DatasetError(f"Replay speed must be between 1 and {MAX_SPEED} records per second.")
        loaded = self.engine.active_model()  # raises EngineError if none
        head = read_dataset(dataset["file_path"], dataset["dataset_type"], nrows=5)
        missing = [c for c in loaded.feature_columns if c not in head.columns]
        if missing:
            raise DatasetError(
                "The active model was trained on a different feature structure; this dataset lacks: "
                + ", ".join(missing[:6]))
        self._stop.clear()
        self._status = self._blank()
        self._set(state="loading", dataset_id=dataset["dataset_id"], dataset_name=dataset["dataset_name"],
                  speed=speed, started_at=time.time())
        self._thread = threading.Thread(target=self._run, args=(dataset, speed, user_id, max_records, seed),
                                        daemon=True, name="mlids-replay")
        self._thread.start()
        return self.status()

    def stop(self):
        self._stop.set()
        t = self._thread
        if t and t.is_alive() and t is not threading.current_thread():
            t.join(timeout=5)
        if self._status["state"] in ("loading", "running"):
            self._set(state="stopped")
        return self.status()

    def _run(self, dataset, speed, user_id, max_records, seed):
        try:
            df = read_dataset(dataset["file_path"], dataset["dataset_type"])
            profile = with_endpoint_columns(get_profile(dataset["dataset_type"], list(df.columns)), df.columns)
            label = dataset.get("label_column") or profile.label_column
            truth = binarize_labels(df[label]).to_numpy() if label in df.columns else None
            order = np.random.default_rng(seed).permutation(len(df))
            if max_records:
                order = order[: int(max_records)]
            self._set(state="running", total=int(len(order)))
            feature_df = df.drop(columns=[c for c in [label] if c in df.columns])  # label never reaches the model
            pos = 0
            while pos < len(order) and not self._stop.is_set():
                tick = time.monotonic()
                idx = order[pos: pos + speed]
                records = feature_df.iloc[idx].astype(object).where(feature_df.iloc[idx].notna(), None).to_dict("records")
                gt = None if truth is None else truth[idx]
                results = self.engine.classify(
                    records, user_id=user_id, source="replay", dataset_id=dataset["dataset_id"], profile=profile,
                    ground_truth=None if gt is None else np.nan_to_num(gt, nan=0).astype(int), start_index=pos)
                with self._lock:
                    s = self._status
                    s["processed"] += len(results)
                    for j, r in enumerate(results):
                        mal = r["prediction"] == "Malicious"
                        s["malicious" if mal else "normal"] += 1
                        s["alerts"] += 1 if r["alert_generated"] else 0
                        if gt is not None and not np.isnan(gt[j]):
                            key = ("t" if (gt[j] == 1) == mal else "f") + ("p" if mal else "n")
                            s["agreement"][key] += 1
                pos += speed
                remaining = 1.0 - (time.monotonic() - tick)
                if remaining > 0:
                    self._stop.wait(remaining)
            if self._status["state"] in ("running", "loading"):
                self._set(state="stopped" if self._stop.is_set() else "completed")
        except Exception as exc:  # noqa: BLE001 - thread boundary
            log.exception("Replay failed")
            self._set(state="error", error=str(exc)[:300])
