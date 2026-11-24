"""Data inspection and cleaning helpers (no fitted state lives here)."""
import numpy as np
import pandas as pd


def missing_summary(df):
    counts = df.isna().sum()
    counts = counts[counts > 0]
    return {"total": int(counts.sum()), "by_column": {str(k): int(v) for k, v in counts.items()},
            "columns_affected": int(len(counts))}


def duplicate_count(df):
    return int(df.duplicated().sum())


def _numeric_like(series, threshold=0.95):
    """True for numeric dtypes, or text columns where >=95% of non-null values parse as numbers."""
    if pd.api.types.is_bool_dtype(series):
        return True
    if pd.api.types.is_numeric_dtype(series):
        return True
    non_null = series.dropna()
    if non_null.empty:
        return False
    parsed = pd.to_numeric(non_null, errors="coerce")
    return parsed.notna().mean() >= threshold


def infer_column_types(df, exclude=()):
    """Split columns into numeric and categorical lists."""
    numeric, categorical = [], []
    for col in df.columns:
        if col in exclude:
            continue
        (numeric if _numeric_like(df[col]) else categorical).append(col)
    return numeric, categorical


def column_overview(df, label_column=None):
    numeric, _ = infer_column_types(df)
    numeric = set(numeric)
    out = []
    for col in df.columns:
        out.append({"name": str(col), "kind": "numeric" if col in numeric else "categorical",
                    "dtype": str(df[col].dtype), "missing": int(df[col].isna().sum()),
                    "unique": int(df[col].nunique(dropna=True)), "is_label": col == label_column})
    return out


def coerce_frame(df, numeric_cols, categorical_cols):
    """Apply the training-time column typing to any frame (train/test/inference)."""
    out = pd.DataFrame(index=df.index)
    for col in numeric_cols:
        s = pd.to_numeric(df[col], errors="coerce").astype("float64")
        out[col] = s.replace([np.inf, -np.inf], np.nan)
    for col in categorical_cols:
        s = df[col]
        out[col] = s.where(s.isna(), s.astype(str).str.strip().str.lower()).astype(object)
    return out


def clean_frame(df, label_column, label_values, drop_duplicates=True):
    """Remove rows with a missing label and (optionally) exact duplicates.

    ``label_values`` is the binarised label aligned with ``df``. Returns
    (cleaned_df, cleaned_labels, stats).
    """
    stats = {"rows_before": int(len(df))}
    keep = label_values.notna()
    stats["missing_label_removed"] = int((~keep).sum())
    df, y = df[keep], label_values[keep].astype(int)
    stats["duplicates_removed"] = 0
    if drop_duplicates:
        dup = df.duplicated(keep="first")
        stats["duplicates_removed"] = int(dup.sum())
        df, y = df[~dup], y[~dup]
    stats["rows_after"] = int(len(df))
    return df.reset_index(drop=True), y.reset_index(drop=True), stats
