"""Decision Tree classifier (scikit-learn)."""
import joblib
import numpy as np
from sklearn.tree import DecisionTreeClassifier

from models.base import as_choice, as_float, as_int


class DecisionTreeModel:
    algorithm = "decision_tree"
    display_name = "Decision Tree"
    description = ("A single tree of if/else rules learned from the traffic features. Fast, "
                   "interpretable and a good baseline.")
    artifact_ext = ".joblib"

    @staticmethod
    def default_params():
        return {"criterion": "gini", "max_depth": None, "min_samples_split": 2,
                "min_samples_leaf": 1, "class_weight": None, "random_state": 42}

    @classmethod
    def validate_params(cls, params):
        p = params or {}
        return {
            "criterion": as_choice(p, "criterion", "gini", ["gini", "entropy", "log_loss"]),
            "max_depth": as_int(p, "max_depth", None, 1, 200),
            "min_samples_split": as_int(p, "min_samples_split", 2, 2, 10000),
            "min_samples_leaf": as_int(p, "min_samples_leaf", 1, 1, 10000),
            "class_weight": as_choice(p, "class_weight", None, ["balanced"]),
            "random_state": as_int(p, "random_state", 42, 0, 2**31 - 1),
        }

    def __init__(self, params=None):
        self.params = self.validate_params(params)
        self.model = DecisionTreeClassifier(**self.params)

    def train(self, X_train, y_train, X_val=None, y_val=None, progress=None):
        if progress:
            progress(60, "Fitting decision tree")
        self.model.fit(X_train, y_train)
        return {"depth": int(self.model.get_depth()), "leaves": int(self.model.get_n_leaves())}

    def predict_proba(self, X):
        """Probability that each record is malicious."""
        proba = self.model.predict_proba(X)
        classes = list(self.model.classes_)
        return proba[:, classes.index(1)] if 1 in classes else np.zeros(len(X))

    def predict(self, X, threshold=0.5):
        return (self.predict_proba(X) >= threshold).astype(int)

    def save(self, path):
        joblib.dump({"algorithm": self.algorithm, "params": self.params, "model": self.model}, path)

    @classmethod
    def load(cls, path):
        blob = joblib.load(path)
        obj = cls(blob["params"])
        obj.model = blob["model"]
        return obj
