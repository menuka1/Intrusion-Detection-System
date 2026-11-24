"""Preprocessing logic: cleaning, encoding, leakage-free fitting, feature selection."""
import numpy as np
import pandas as pd
import pytest

from preprocessing.cleaning import clean_frame, coerce_frame, duplicate_count, infer_column_types, missing_summary
from preprocessing.dataset_loader import (DatasetError, PROFILES, binarize_labels, detect_dataset_type, extract_log_fields,
                                          get_profile, read_dataset, simulated_ip)
from preprocessing.feature_selection import FeatureSelector
from preprocessing.pipeline import PreprocessConfig, prepare

SAMPLE = "datasets/sample/"


def make_df(n=200, seed=0):
    rng = np.random.default_rng(seed)
    y = rng.integers(0, 2, n)
    return pd.DataFrame({"num1": rng.normal(y * 2, 1), "num2": rng.normal(0, 1, n), "proto": rng.choice(["tcp", "udp"], n),
                         "const": 1, "label": np.where(y == 1, "attack", "normal")})


def test_missing_and_duplicate_detection():
    df = pd.DataFrame({"a": [1, 1, None], "b": ["x", "x", None]})
    assert missing_summary(df)["total"] == 2
    assert duplicate_count(df) == 1


def test_binarize_labels_variants():
    s = pd.Series(["normal", "NORMAL", "BENIGN", "neptune", 0, 1, "0", np.nan])
    out = binarize_labels(s).tolist()
    assert out[:7] == [0, 0, 0, 1, 0, 1, 0] and np.isnan(out[7])


def test_infer_column_types_handles_numeric_strings():
    df = pd.DataFrame({"n": ["1", "2", "3.5"], "c": ["a", "b", "c"], "i": [1, 2, 3]})
    num, cat = infer_column_types(df)
    assert num == ["n", "i"] and cat == ["c"]


def test_clean_frame_drops_unlabelled_and_duplicates():
    df = pd.DataFrame({"a": [1, 1, 2, 3], "label": ["x", "x", "y", None]})
    y = binarize_labels(df["label"])
    out, yy, stats = clean_frame(df, "label", y, True)
    assert stats == {"rows_before": 4, "missing_label_removed": 1, "duplicates_removed": 1, "rows_after": 2}
    assert len(out) == len(yy) == 2


def test_prepare_splits_are_disjoint_stratified_and_reproducible():
    df = make_df(400)
    cfg = PreprocessConfig.from_dict({"label_column": "label", "scaling": "standard"})
    p1 = prepare(df, get_profile("custom", df.columns), cfg)
    p2 = prepare(df, get_profile("custom", df.columns), cfg)
    assert np.array_equal(p1.X_train, p2.X_train)
    total = len(p1.y_train) + len(p1.y_val) + len(p1.y_test)
    assert total == p1.summary["after"]["rows"]
    assert abs(len(p1.y_test) / total - 0.2) < 0.02
    ratio = lambda y: y.mean()  # noqa: E731
    assert abs(ratio(p1.y_train) - ratio(p1.y_test)) < 0.05
    assert "const" in p1.summary["constant_columns_removed"]


def test_scaler_fitted_on_training_data_only():
    df = make_df(500)
    cfg = PreprocessConfig.from_dict({"label_column": "label", "scaling": "standard"})
    p = prepare(df, get_profile("custom", df.columns), cfg)
    assert abs(p.X_train[:, 0].mean()) < 1e-5 and abs(p.X_train[:, 0].std() - 1) < 1e-3
    assert abs(p.X_test[:, 0].mean()) > 1e-4  # test split is NOT re-centred (no leakage)


def test_encoding_handles_unseen_category_and_missing_values():
    df = make_df(300)
    cfg = PreprocessConfig.from_dict({"label_column": "label"})
    p = prepare(df, get_profile("custom", df.columns), cfg)
    new = pd.DataFrame({"num1": [None, 1.0], "num2": [0.1, 0.2], "proto": ["icmp", None]})
    X = p.pipeline.transform(new)
    assert X.shape == (2, p.pipeline.n_features_out) and np.isfinite(X).all()


def test_feature_selection_keeps_k_best():
    df = make_df(400)
    cfg = PreprocessConfig.from_dict({"label_column": "label", "feature_selection": "f_classif", "k_features": 2})
    p = prepare(df, get_profile("custom", df.columns), cfg)
    assert p.pipeline.n_features_out == 2
    assert "num1" in p.pipeline.selector.selected_names  # the informative feature survives


def test_selector_rejects_unknown_method_and_config_validation():
    with pytest.raises(ValueError):
        FeatureSelector("bogus")
    with pytest.raises(DatasetError):
        PreprocessConfig.from_dict({"scaling": "weird"})
    with pytest.raises(DatasetError):
        PreprocessConfig.from_dict({"feature_selection": "f_classif"})  # k required
    with pytest.raises(DatasetError):
        PreprocessConfig.from_dict({"test_size": 0.9})


def test_single_class_dataset_rejected():
    df = make_df(100)
    df["label"] = "normal"
    with pytest.raises(DatasetError, match="at least 3 normal and 3 malicious"):
        prepare(df, get_profile("custom", df.columns), PreprocessConfig.from_dict({"label_column": "label"}))


def test_pipeline_rejects_missing_or_non_numeric_input():
    df = make_df(200)
    p = prepare(df, get_profile("custom", df.columns), PreprocessConfig.from_dict({"label_column": "label"}))
    with pytest.raises(DatasetError, match="Missing required"):
        p.pipeline.transform(pd.DataFrame({"num1": [1.0]}))
    with pytest.raises(DatasetError, match="must be numeric"):
        p.pipeline.transform(pd.DataFrame({"num1": ["abc"], "num2": [1.0], "proto": ["tcp"]}))


def test_official_test_file_is_used_when_given():
    train, test = make_df(300, 1), make_df(100, 2)
    cfg = PreprocessConfig.from_dict({"label_column": "label"})
    p = prepare(train, get_profile("custom", train.columns), cfg, test_df=test)
    assert p.summary["split_mode"] == "official train/test files"
    assert len(p.y_test) == len(test.drop_duplicates())


def test_nsl_kdd_profile_excludes_difficulty_and_unsw_excludes_leaky_columns():
    nsl = read_dataset(SAMPLE + "nslkdd_synthetic_sample.csv", "nsl-kdd")
    p = prepare(nsl, PROFILES["nsl-kdd"], PreprocessConfig.from_dict({"label_column": "label"}))
    assert "difficulty" not in p.pipeline.feature_columns and "label" not in p.pipeline.feature_columns
    unsw = read_dataset(SAMPLE + "unsw_nb15_synthetic_sample.csv", "unsw-nb15")
    p2 = prepare(unsw, PROFILES["unsw-nb15"], PreprocessConfig.from_dict({"label_column": "label"}))
    assert not {"id", "attack_cat", "label"} & set(p2.pipeline.feature_columns)  # attack_cat would leak the label
    assert set(p.pipeline.feature_columns) != set(p2.pipeline.feature_columns)  # distinct feature structures


def test_dataset_type_detection():
    assert detect_dataset_type(SAMPLE + "nslkdd_synthetic_sample.csv") == "nsl-kdd"
    assert detect_dataset_type(SAMPLE + "unsw_nb15_synthetic_sample.csv") == "unsw-nb15"


def test_log_field_extraction_and_simulated_endpoints():
    prof = PROFILES["nsl-kdd"]
    f = extract_log_fields({"protocol_type": "tcp", "src_bytes": 100, "dst_bytes": 50}, prof, 3)
    assert f["protocol"] == "TCP" and f["packet_size"] == 150 and f["simulated_endpoints"] is True
    assert simulated_ip(3, "src") == simulated_ip(3, "src")  # deterministic
    cust = get_profile("custom", ["srcip", "dstip", "proto", "bytes", "label"])
    g = extract_log_fields({"srcip": "1.2.3.4", "dstip": "5.6.7.8", "proto": "udp", "bytes": 9}, cust)
    assert (g["source_ip"], g["destination_ip"], g["simulated_endpoints"]) == ("1.2.3.4", "5.6.7.8", False)


def test_coerce_frame_normalises_types():
    df = pd.DataFrame({"n": ["1", "x", None], "c": [" TCP", "udp", None]})
    out = coerce_frame(df, ["n"], ["c"])
    assert out["n"].isna().tolist() == [False, True, True] and out["c"].tolist()[:2] == ["tcp", "udp"]
