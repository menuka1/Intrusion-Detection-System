"""Categorical encoding, imputation and numerical scaling (fit on training data only)."""
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MinMaxScaler, OneHotEncoder, StandardScaler

SCALERS = {"standard": StandardScaler, "minmax": MinMaxScaler, "none": None}
MAX_CATEGORIES = 40  # rare categories collapse into one "infrequent" bucket


def build_column_transformer(numeric_cols, categorical_cols, scaling="standard"):
    if scaling not in SCALERS:
        raise ValueError(f"Unknown scaling '{scaling}'. Use one of {list(SCALERS)}.")
    transformers = []
    if numeric_cols:
        steps = [("impute", SimpleImputer(strategy="median"))]
        if SCALERS[scaling] is not None:
            steps.append(("scale", SCALERS[scaling]()))
        transformers.append(("num", Pipeline(steps), list(numeric_cols)))
    if categorical_cols:
        transformers.append(("cat", Pipeline([
            ("impute", SimpleImputer(strategy="most_frequent")),
            ("onehot", OneHotEncoder(handle_unknown="infrequent_if_exist", max_categories=MAX_CATEGORIES,
                                     sparse_output=False)),
        ]), list(categorical_cols)))
    if not transformers:
        raise ValueError("No usable feature columns remain after exclusions.")
    return ColumnTransformer(transformers, remainder="drop", verbose_feature_names_out=False)
