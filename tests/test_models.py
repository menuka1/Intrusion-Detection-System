"""Model training, evaluation, registry and comparison (real training on the synthetic sample)."""
import numpy as np
import pytest

from models.base import ParamError, evaluate
from models.decision_tree import DecisionTreeModel
from models.model_registry import best_model
from models.neural_network import NeuralNetworkModel
from models.random_forest import RandomForestModel


def test_evaluate_known_confusion_matrix():
    y = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    proba = np.array([0.1, 0.2, 0.6, 0.3, 0.9, 0.8, 0.4, 0.7])  # one FP, one FN
    m = evaluate(y, proba)
    assert m["confusion_matrix"] == [[3, 1], [1, 3]]
    assert m["accuracy"] == pytest.approx(0.75)
    assert m["malicious"]["precision"] == pytest.approx(0.75)
    assert m["malicious"]["recall"] == pytest.approx(0.75)
    assert m["false_positive_rate"] == pytest.approx(0.25)
    assert m["false_negative_rate"] == pytest.approx(0.25)


def test_param_validation_rejects_bad_values():
    with pytest.raises(ParamError):
        RandomForestModel.validate_params({"n_estimators": 0})
    with pytest.raises(ParamError):
        DecisionTreeModel.validate_params({"criterion": "bogus"})
    with pytest.raises(ParamError):
        NeuralNetworkModel.validate_params({"hidden_layers": "abc"})


def test_decision_tree_and_forest_fit_predict_save_load(tmp_path):
    rng = np.random.default_rng(0)
    X = rng.normal(size=(300, 5))
    y = (X[:, 0] + X[:, 1] > 0).astype(int)
    for cls, params in ((DecisionTreeModel, {"max_depth": 6}), (RandomForestModel, {"n_estimators": 10})):
        m = cls(params)
        m.train(X, y)
        p = m.predict_proba(X)
        assert p.shape == (300,) and ((p >= 0) & (p <= 1)).all()
        assert (m.predict(X) == y).mean() > 0.9
        path = tmp_path / f"{cls.algorithm}.joblib"
        m.save(path)
        assert np.allclose(cls.load(path).predict_proba(X), p)


def test_registry_has_real_metrics_for_three_algorithms(world, wadmin):
    r = wadmin.get(f"/api/models/comparison?dataset_id={world['dataset_id']}")
    assert r.status_code == 200
    data = r.get_json()["data"]
    assert {m["algorithm"] for m in data["models"]} == {"decision_tree", "random_forest", "ann"}
    for m in data["models"]:
        cm = m["confusion_matrix"]
        assert sum(map(sum, cm)) == m["n_test"]  # confusion matrix covers the whole held-out test set
        assert 0.0 <= m["accuracy"] <= 1.0 and m["accuracy"] > 0.8
        assert m["training_seconds"] > 0
        assert m["metrics"]["split_mode"].startswith("stratified")
    assert data["best_model_id"] == best_model(data["models"], "f1_score")


def test_ann_training_has_history_and_probabilities(world, wadmin):
    mid = world["models"]["ann"]
    m = wadmin.get(f"/api/models/{mid}").get_json()["data"]
    assert "val_loss" in m["metrics"]["history"]
    assert m["training_config"]["params"]["hidden_layers"] == [32, 16]


def test_train_rejects_invalid_requests(world, wadmin, wanalyst):
    assert wadmin.post("/api/models/train", {"dataset_id": world["dataset_id"], "algorithm": "svm"}).status_code == 422
    assert wadmin.post("/api/models/train", {"dataset_id": 9999, "algorithm": "ann"}).status_code == 404
    bad = wadmin.post("/api/models/train", {"dataset_id": world["dataset_id"], "algorithm": "random_forest",
                                            "params": {"n_estimators": -4}})
    assert bad.status_code == 422
    assert wanalyst.post("/api/models/train", {"dataset_id": world["dataset_id"], "algorithm": "ann"}).status_code == 403


def test_versions_increment(world, wadmin):
    r = wadmin.post("/api/models/train", {"dataset_id": world["dataset_id"], "algorithm": "decision_tree",
                                          "params": {"max_depth": 5}})
    job = wadmin.get(f"/api/models/jobs/{r.get_json()['data']['job_id']}").get_json()["data"]
    assert job["job_status"] == "Completed"
    assert wadmin.get(f"/api/models/{job['model_id']}").get_json()["data"]["version"] == 2


def test_activate_switches_single_active_model(world, wadmin):
    ids = world["models"]
    assert wadmin.post(f"/api/models/{ids['decision_tree']}/activate").status_code == 200
    active = [m for m in wadmin.get("/api/models").get_json()["data"] if m["is_active"]]
    assert [m["model_id"] for m in active] == [ids["decision_tree"]]
    wadmin.post(f"/api/models/{ids['random_forest']}/activate")
    assert wadmin.post("/api/models/99999/activate").status_code == 404
