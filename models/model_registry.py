"""Algorithm lookup, artifact storage and loading for trained models.

Every trained model is stored as TWO files that are always used together:
the fitted preprocessing pipeline and the model itself. Artifacts are loaded
only from the controlled ``MODEL_DIR`` (joblib files are pickles, so paths read
from the database are confined to that directory).
"""
import uuid
from pathlib import Path

import joblib

from models.decision_tree import DecisionTreeModel
from models.neural_network import NeuralNetworkModel
from models.random_forest import RandomForestModel

ALGORITHMS = {m.algorithm: m for m in (DecisionTreeModel, RandomForestModel, NeuralNetworkModel)}

# metric key (UI/API) -> (registry column, higher_is_better)
METRIC_COLUMNS = {
    "f1_score": ("f1_score", True), "accuracy": ("accuracy", True), "precision": ("precision_score", True),
    "recall": ("recall_score", True), "fpr": ("fpr", False), "fnr": ("fnr", False),
}


class ModelLoadError(RuntimeError):
    pass


def get_algorithm(name):
    try:
        return ALGORITHMS[name]
    except KeyError as exc:
        raise ValueError(f"Unknown algorithm '{name}'. Choose one of {list(ALGORITHMS)}.") from exc


def algorithm_catalog():
    return [{"algorithm": a.algorithm, "display_name": a.display_name, "description": a.description,
             "defaults": a.default_params()} for a in ALGORITHMS.values()]


def new_artifact_paths(model_dir, algorithm, dataset_id, version):
    stem = f"{algorithm}_ds{dataset_id}_v{version}_{uuid.uuid4().hex[:8]}"
    ext = get_algorithm(algorithm).artifact_ext
    model_dir = Path(model_dir)
    return model_dir / f"{stem}{ext}", model_dir / f"{stem}_pipeline.joblib"


def safe_artifact_path(model_dir, path):
    base = Path(model_dir).resolve()
    p = Path(path).resolve()
    if base not in p.parents:
        raise ModelLoadError("Model artifact path is outside the controlled model directory.")
    if not p.exists():
        raise ModelLoadError("Model artifact file is missing on disk.")
    return p


def load_artifacts(row, model_dir):
    """Return (pipeline, model) for a registry row."""
    algo = get_algorithm(row["algorithm"])
    pipe_path = safe_artifact_path(model_dir, row["pipeline_path"])
    model_path = safe_artifact_path(model_dir, row["model_path"])
    try:
        pipeline = joblib.load(pipe_path)
        if algo.algorithm == "ann":
            model = algo.load(model_path, (row.get("training_config") or {}).get("params"))
        else:
            model = algo.load(model_path)
    except Exception as exc:  # noqa: BLE001
        raise ModelLoadError(f"Could not load model artifacts: {exc}") from exc
    return pipeline, model


def best_model(rows, metric="f1_score"):
    """Return the model_id with the best value of ``metric`` (None if no rows)."""
    col, higher = METRIC_COLUMNS.get(metric, METRIC_COLUMNS["f1_score"])
    rows = [r for r in rows if r.get(col) is not None]
    if not rows:
        return None
    return (max if higher else min)(rows, key=lambda r: r[col])["model_id"]
