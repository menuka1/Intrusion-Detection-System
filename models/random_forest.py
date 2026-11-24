"""Random Forest classifier (scikit-learn)."""
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from models.base import as_choice, as_int


class RandomForestModel:
    algorithm = "random_forest"
    display_name = "Random Forest"
    description = ("An ensemble of decision trees trained on random subsets of records and "
                   "features; usually more robust and accurate than a single tree.")
    artifact_ext = ".joblib"

    @staticmethod
    def default_params():
        return {"n_estimators": 100, "max_depth": None, "min_samples_split": 2,
                "min_samples_leaf": 1, "max_features": "sqrt", "class_weight": None,
                "n_jobs": 2, "random_state": 42}

    @classmethod
    def validate_params(cls, params):
        p = params or {}
        return {
            "n_estimators": as_int(p, "n_estimators", 100, 5, 1000),
            "max_depth": as_int(p, "max_depth", None, 1, 200),
            "min_samples_split": as_int(p, "min_samples_split", 2, 2, 10000),
            "min_samples_leaf": as_int(p, "min_samples_leaf", 1, 1, 10000),
            "max_features": as_choice(p, "max_features", "sqrt", ["sqrt", "log2"]),
            "class_weight": as_choice(p, "class_weight", None, ["balanced", "balanced_subsample"]),
            "n_jobs": as_int(p, "n_jobs", 2, 1, 32),
            "random_state": as_int(p, "random_state", 42, 0, 2**31 - 1),
        }

    def __init__(self, params=None):
        self.params = self.validate_params(params)
        self.model = RandomForestClassifier(**{**self.params, "warm_start": True})

    def train(self, X_train, y_train, X_val=None, y_val=None, progress=None):
        """Grow the forest in chunks (warm start) so progress can be reported honestly."""
        total = self.params["n_estimators"]
        chunk = max(5, total // 10)
        built = 0
        while built < total:
            built = min(total, built + chunk)
            self.model.set_params(n_estimators=built)
            self.model.fit(X_train, y_train)
            if progress:
                progress(40 + int(50 * built / total), f"Trained {built}/{total} trees")
        return {"trees": int(built)}

    def predict_proba(self, X):
        proba = self.model.predict_proba(X)
        classes = list(self.model.classes_)
        return proba[:, classes.index(1)] if 1 in classes else np.zeros(len(X))

    def predict(self, X, threshold=0.5):
        return (self.predict_proba(X) >= threshold).astype(int)

    def save(self, path):
        joblib.dump({"algorithm": self.algorithm, "params": self.params, "model": self.model},
                    path, compress=3)

    @classmethod
    def load(cls, path):
        blob = joblib.load(path)
        obj = cls(blob["params"])
        obj.model = blob["model"]
        return obj
