"""Shared helpers for the model implementations: parameter validation and evaluation."""
import time

import numpy as np
from sklearn.metrics import (accuracy_score, confusion_matrix, precision_recall_fscore_support,
                             roc_auc_score)


class ParamError(ValueError):
    """Invalid hyper-parameter supplied by the user."""


def as_int(params, name, default, lo, hi):
    v = params.get(name, default)
    if v in (None, "") and default is None:
        return None
    try:
        v = int(v)
    except (TypeError, ValueError) as exc:
        raise ParamError(f"'{name}' must be an integer.") from exc
    if not lo <= v <= hi:
        raise ParamError(f"'{name}' must be between {lo} and {hi}.")
    return v


def as_float(params, name, default, lo, hi):
    try:
        v = float(params.get(name, default))
    except (TypeError, ValueError) as exc:
        raise ParamError(f"'{name}' must be a number.") from exc
    if not lo <= v <= hi:
        raise ParamError(f"'{name}' must be between {lo} and {hi}.")
    return v


def as_choice(params, name, default, choices):
    v = params.get(name, default)
    if v in (None, "") and default is None:
        return None
    if v not in choices:
        raise ParamError(f"'{name}' must be one of {list(choices)}.")
    return v


def evaluate(y_true, proba, threshold=0.5):
    """Binary evaluation with 'malicious' (1) as the positive class.

    Returns overall accuracy, malicious-class precision/recall/F1 (the headline
    numbers), normal-class and macro averages, FPR, FNR, confusion matrix and ROC-AUC.
    """
    y_true = np.asarray(y_true).astype(int)
    proba = np.asarray(proba).ravel()
    pred = (proba >= threshold).astype(int)
    cm = confusion_matrix(y_true, pred, labels=[0, 1])
    tn, fp, fn, tp = (int(v) for v in cm.ravel())
    p, r, f, _ = precision_recall_fscore_support(y_true, pred, labels=[0, 1], zero_division=0)
    macro = precision_recall_fscore_support(y_true, pred, labels=[0, 1], average="macro", zero_division=0)[:3]
    weighted = precision_recall_fscore_support(y_true, pred, labels=[0, 1], average="weighted", zero_division=0)[:3]
    try:
        auc = float(roc_auc_score(y_true, proba)) if len(set(y_true)) == 2 else None
    except ValueError:
        auc = None
    return {
        "accuracy": float(accuracy_score(y_true, pred)),
        "malicious": {"precision": float(p[1]), "recall": float(r[1]), "f1": float(f[1])},
        "normal": {"precision": float(p[0]), "recall": float(r[0]), "f1": float(f[0])},
        "macro": dict(zip(("precision", "recall", "f1"), map(float, macro))),
        "weighted": dict(zip(("precision", "recall", "f1"), map(float, weighted))),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if (fn + tp) else 0.0,
        "confusion_matrix": [[tn, fp], [fn, tp]],  # rows: actual normal/malicious; cols: predicted
        "roc_auc": auc, "threshold": float(threshold), "n_samples": int(len(y_true)),
    }


def timed(fn, *args, **kwargs):
    t0 = time.perf_counter()
    out = fn(*args, **kwargs)
    return out, time.perf_counter() - t0
