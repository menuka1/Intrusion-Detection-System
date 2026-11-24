"""Loads the active model together with its matching preprocessing pipeline and predicts."""
import threading

import numpy as np
import pandas as pd

from models.model_registry import load_artifacts


class LoadedModel:
    def __init__(self, row, pipeline, model):
        self.row, self.pipeline, self.model = row, pipeline, model
        self.model_id = row["model_id"]
        self.name = {"decision_tree": "Decision Tree", "random_forest": "Random Forest",
                     "ann": "Artificial Neural Network"}.get(row["algorithm"], row["algorithm"])
        self.version = f"v{row['version']}"
        self.threshold = float(row.get("threshold") or 0.5)
        self.feature_columns = list(pipeline.feature_columns)

    def validate(self, df):
        return self.pipeline.validate_frame(df)

    def malicious_probability(self, df):
        """Probability of the malicious class for every row of ``df`` (raw feature columns)."""
        X = self.pipeline.transform(df)
        return np.asarray(self.model.predict_proba(X), dtype=float)


class ModelCache:
    """Keeps the loaded active model in memory; reloads when a different one is activated."""

    def __init__(self, model_dir):
        self.model_dir = model_dir
        self._lock = threading.Lock()
        self._loaded = None

    def get(self, row):
        with self._lock:
            if self._loaded is None or self._loaded.model_id != row["model_id"]:
                pipeline, model = load_artifacts(row, self.model_dir)
                self._loaded = LoadedModel(row, pipeline, model)
            return self._loaded

    def invalidate(self):
        with self._lock:
            self._loaded = None

    def loaded_id(self):
        return self._loaded.model_id if self._loaded else None


def records_to_frame(records):
    return pd.DataFrame.from_records(records)
