"""Feature selection applied after encoding; fitted on the training split only."""
import numpy as np
from sklearn.feature_selection import SelectKBest, f_classif, mutual_info_classif

METHODS = {"none": None, "f_classif": f_classif, "mutual_info": mutual_info_classif}


class FeatureSelector:
    """Drops zero-variance columns, then optionally keeps the k best scoring features."""

    def __init__(self, method="none", k=None, seed=42):
        if method not in METHODS:
            raise ValueError(f"Unknown feature selection method '{method}'.")
        self.method, self.k, self.seed = method, k, seed
        self.keep_idx_ = None
        self.scores_ = None
        self.names_in_ = None

    def fit(self, X, y, names):
        names = np.asarray(names)
        var_ok = np.nanvar(X, axis=0) > 0
        if not var_ok.any():
            raise ValueError("All features are constant after preprocessing.")
        idx = np.where(var_ok)[0]
        scores = np.zeros(len(names))
        if self.method != "none" and self.k and self.k < len(idx):
            fn = METHODS[self.method]
            if self.method == "mutual_info":
                sel = SelectKBest(lambda a, b: mutual_info_classif(a, b, random_state=self.seed), k=self.k)
            else:
                sel = SelectKBest(fn, k=self.k)
            sel.fit(X[:, idx], y)
            scores[idx] = np.nan_to_num(sel.scores_)
            idx = idx[np.sort(np.argsort(scores[idx])[::-1][: self.k])]
        elif self.method != "none":
            sel = SelectKBest(METHODS[self.method], k="all").fit(X[:, idx], y)
            scores[idx] = np.nan_to_num(sel.scores_)
        self.keep_idx_ = idx
        self.scores_ = scores
        self.names_in_ = names
        return self

    def transform(self, X):
        return X[:, self.keep_idx_]

    @property
    def selected_names(self):
        return [str(n) for n in self.names_in_[self.keep_idx_]]

    def ranking(self, top=20):
        order = np.argsort(self.scores_)[::-1][:top]
        return [{"feature": str(self.names_in_[i]), "score": float(self.scores_[i])} for i in order if self.scores_[i] > 0]
