"""End-to-end preprocessing: cleaning -> split -> (fit on train) encode/scale/select.

``FeaturePipeline`` is the object that is saved next to every trained model, so
the exact same transformations are applied at prediction time.
"""
from dataclasses import dataclass, field, asdict

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from preprocessing.cleaning import (clean_frame, coerce_frame, duplicate_count, infer_column_types,
                                     missing_summary)
from preprocessing.dataset_loader import DatasetError, binarize_labels
from preprocessing.encoding import SCALERS, build_column_transformer
from preprocessing.feature_selection import METHODS, FeatureSelector


@dataclass
class PreprocessConfig:
    label_column: str | None = None
    exclude_columns: list = field(default_factory=list)
    drop_duplicates: bool = True
    scaling: str = "standard"
    feature_selection: str = "none"
    k_features: int | None = None
    test_size: float = 0.2
    val_size: float = 0.1
    seed: int = 42
    test_dataset_id: int | None = None

    @classmethod
    def from_dict(cls, d):
        d = dict(d or {})
        cfg = cls()
        if d.get("label_column"):
            cfg.label_column = str(d["label_column"])
        cfg.exclude_columns = [str(c) for c in (d.get("exclude_columns") or [])]
        cfg.drop_duplicates = bool(d.get("drop_duplicates", True))
        cfg.scaling = str(d.get("scaling", "standard"))
        cfg.feature_selection = str(d.get("feature_selection", "none"))
        k = d.get("k_features")
        cfg.k_features = int(k) if k not in (None, "", 0) else None
        try:
            cfg.test_size = float(d.get("test_size", 0.2))
            cfg.val_size = float(d.get("val_size", 0.1))
            cfg.seed = int(d.get("seed", 42))
        except (TypeError, ValueError) as exc:
            raise DatasetError("Split sizes and seed must be numeric.") from exc
        tid = d.get("test_dataset_id")
        cfg.test_dataset_id = int(tid) if tid not in (None, "") else None
        cfg.validate()
        return cfg

    def validate(self):
        if self.scaling not in SCALERS:
            raise DatasetError(f"Scaling must be one of {list(SCALERS)}.")
        if self.feature_selection not in METHODS:
            raise DatasetError(f"Feature selection must be one of {list(METHODS)}.")
        if self.feature_selection != "none" and not self.k_features:
            raise DatasetError("Choose the number of features (k) when feature selection is enabled.")
        if self.k_features is not None and self.k_features < 1:
            raise DatasetError("k_features must be at least 1.")
        if not 0.05 <= self.test_size <= 0.5 or not 0.05 <= self.val_size <= 0.4:
            raise DatasetError("test_size must be 0.05-0.5 and val_size 0.05-0.4.")

    def to_dict(self):
        return asdict(self)


class FeaturePipeline:
    """Fitted preprocessing: type coercion, imputation, encoding, scaling, selection."""

    def __init__(self, feature_columns, numeric_columns, categorical_columns, cfg: PreprocessConfig):
        self.feature_columns = list(feature_columns)
        self.numeric_columns = list(numeric_columns)
        self.categorical_columns = list(categorical_columns)
        self.cfg = cfg
        self.transformer = None
        self.selector = None
        self.encoded_names = None
        self.categories = {}

    def fit(self, df, y):
        typed = coerce_frame(df, self.numeric_columns, self.categorical_columns)
        self.transformer = build_column_transformer(self.numeric_columns, self.categorical_columns, self.cfg.scaling)
        X = self.transformer.fit_transform(typed)
        self.encoded_names = list(self.transformer.get_feature_names_out())
        self.selector = FeatureSelector(self.cfg.feature_selection, self.cfg.k_features, self.cfg.seed)
        self.selector.fit(X, np.asarray(y), self.encoded_names)
        for col in self.categorical_columns:
            self.categories[col] = sorted(typed[col].dropna().unique().tolist())[:60]
        return self

    def validate_frame(self, df):
        """Return a list of human-readable problems with an incoming frame."""
        problems = []
        missing = [c for c in self.feature_columns if c not in df.columns]
        if missing:
            problems.append("Missing required feature(s): " + ", ".join(missing[:10]) + ("..." if len(missing) > 10 else ""))
            return problems
        for col in self.numeric_columns:
            raw = df[col]
            parsed = pd.to_numeric(raw, errors="coerce")
            bad = int((raw.notna() & parsed.isna()).sum())
            if bad:
                problems.append(f"Column '{col}' must be numeric ({bad} invalid value(s)).")
        return problems

    def transform(self, df):
        problems = self.validate_frame(df)
        if problems:
            raise DatasetError(" ".join(problems))
        typed = coerce_frame(df[self.feature_columns], self.numeric_columns, self.categorical_columns)
        X = self.transformer.transform(typed)
        return self.selector.transform(X).astype("float32")

    @property
    def n_features_out(self):
        return len(self.selector.keep_idx_)

    def schema(self):
        return {"feature_columns": self.feature_columns, "numeric_columns": self.numeric_columns,
                "categorical_columns": self.categorical_columns, "categories": self.categories,
                "encoded_feature_count": len(self.encoded_names), "selected_features": self.selector.selected_names,
                "n_features": self.n_features_out, "scaling": self.cfg.scaling,
                "feature_selection": self.cfg.feature_selection, "k_features": self.cfg.k_features}


@dataclass
class Prepared:
    pipeline: FeaturePipeline
    X_train: np.ndarray
    y_train: np.ndarray
    X_val: np.ndarray
    y_val: np.ndarray
    X_test: np.ndarray
    y_test: np.ndarray
    summary: dict
    clean_df: pd.DataFrame | None = None  # cleaned (deduplicated) frame incl. label, for replay


def _class_counts(y):
    y = np.asarray(y)
    return {"normal": int((y == 0).sum()), "malicious": int((y == 1).sum()), "total": int(len(y))}


def _check_classes(y, what):
    counts = _class_counts(y)
    if counts["normal"] < 3 or counts["malicious"] < 3:
        raise DatasetError(
            f"{what} must contain at least 3 normal and 3 malicious records "
            f"(found {counts['normal']} normal / {counts['malicious']} malicious).")


def prepare(df, profile, cfg: PreprocessConfig, test_df=None, return_clean=False):
    """Clean, split and fit the preprocessing pipeline on the training portion only."""
    label = cfg.label_column or profile.label_column
    if not label or label not in df.columns:
        raise DatasetError("Select a valid label column before preprocessing.")
    missing_before = missing_summary(df)
    dup_before = duplicate_count(df)
    raw_columns = int(df.shape[1])

    y_all = binarize_labels(df[label])
    df_c, y_c, clean_stats = clean_frame(df, label, y_all, cfg.drop_duplicates)
    _check_classes(y_c, "The cleaned dataset")

    excluded = set(profile.exclude_columns) | set(cfg.exclude_columns) | {label}
    candidate_cols = [c for c in df_c.columns if c not in excluded]
    if not candidate_cols:
        raise DatasetError("No feature columns remain after exclusions.")

    if test_df is not None:
        if label not in test_df.columns:
            raise DatasetError("The test dataset has no label column named '" + label + "'.")
        missing_cols = [c for c in candidate_cols if c not in test_df.columns]
        if missing_cols:
            raise DatasetError("The test dataset lacks feature columns: " + ", ".join(missing_cols[:6]))
        yt = binarize_labels(test_df[label])
        test_c, yt_c, test_stats = clean_frame(test_df, label, yt, cfg.drop_duplicates)
        _check_classes(yt_c, "The test dataset")
        tr_idx, va_idx = train_test_split(np.arange(len(df_c)), test_size=cfg.val_size,
                                          stratify=y_c, random_state=cfg.seed)
        te_df, y_te, split_mode = test_c, yt_c.to_numpy(), "official train/test files"
    else:
        idx = np.arange(len(df_c))
        trval_idx, te_idx = train_test_split(idx, test_size=cfg.test_size, stratify=y_c, random_state=cfg.seed)
        rel_val = cfg.val_size / (1 - cfg.test_size)
        tr_idx, va_idx = train_test_split(trval_idx, test_size=rel_val, stratify=y_c.iloc[trval_idx],
                                          random_state=cfg.seed)
        te_df, y_te, split_mode = df_c.iloc[te_idx], y_c.iloc[te_idx].to_numpy(), "stratified train/validation/test"
        test_stats = None

    train_df, val_df = df_c.iloc[tr_idx], df_c.iloc[va_idx]
    y_tr, y_va = y_c.iloc[tr_idx].to_numpy(), y_c.iloc[va_idx].to_numpy()
    _check_classes(y_tr, "The training split")

    # Column typing and constant-column removal use the TRAINING split only.
    numeric, categorical = infer_column_types(train_df[candidate_cols])
    constant = [c for c in numeric + categorical if train_df[c].nunique(dropna=True) <= 1]
    numeric = [c for c in numeric if c not in constant]
    categorical = [c for c in categorical if c not in constant]
    feature_cols = [c for c in candidate_cols if c not in constant]
    if not feature_cols:
        raise DatasetError("All remaining features are constant in the training data.")

    pipe = FeaturePipeline(feature_cols, numeric, categorical, cfg).fit(train_df[feature_cols], y_tr)
    X_tr = pipe.transform(train_df[feature_cols])
    X_va = pipe.transform(val_df[feature_cols])
    X_te = pipe.transform(te_df[feature_cols])

    summary = {
        "before": {"rows": clean_stats["rows_before"], "columns": raw_columns,
                   "missing_values": missing_before["total"], "duplicate_rows": dup_before},
        "cleaning": clean_stats,
        "after": {"rows": clean_stats["rows_after"], "feature_columns": len(feature_cols),
                  "numeric_columns": len(numeric), "categorical_columns": len(categorical),
                  "encoded_features": len(pipe.encoded_names), "selected_features": pipe.n_features_out},
        "excluded_columns": sorted(excluded - {label}), "constant_columns_removed": constant,
        "label_column": label, "scaling": cfg.scaling, "feature_selection": cfg.feature_selection,
        "k_features": cfg.k_features, "split_mode": split_mode, "seed": cfg.seed,
        "splits": {"train": _class_counts(y_tr), "validation": _class_counts(y_va), "test": _class_counts(y_te)},
        "selected_feature_names": pipe.selector.selected_names,
        "feature_ranking": pipe.selector.ranking(),
        "fit_on": "training split only (no test/validation leakage)",
    }
    return Prepared(pipe, X_tr, y_tr, X_va, y_va, X_te, np.asarray(y_te), summary,
                    df_c.assign(__label__=y_c) if return_clean else None)
