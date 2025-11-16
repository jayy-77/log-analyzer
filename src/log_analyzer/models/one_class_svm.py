"""One-Class SVM wrapped to the AnomalyModel interface."""

from __future__ import annotations

import numpy as np
from sklearn.svm import OneClassSVM

from .base import AnomalyModel


class OneClassSVMModel(AnomalyModel):
    name = "one_class_svm"

    def __init__(self, nu: float = 0.05, kernel: str = "rbf", gamma: str = "scale"):
        self._model = OneClassSVM(nu=nu, kernel=kernel, gamma=gamma)
        self._lo: float | None = None
        self._hi: float | None = None

    def fit(self, X: np.ndarray) -> "OneClassSVMModel":
        # OCSVM is O(n^2). Subsample if the dataset is large.
        if len(X) > 20_000:
            rng = np.random.default_rng(42)
            idx = rng.choice(len(X), size=20_000, replace=False)
            self._model.fit(X[idx])
        else:
            self._model.fit(X)
        raw = -self._model.decision_function(X)
        self._lo, self._hi = float(raw.min()), float(raw.max())
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        raw = -self._model.decision_function(X)
        if self._lo is None:
            return raw
        denom = max(self._hi - self._lo, 1e-9)
        return np.clip((raw - self._lo) / denom, 0.0, 1.0)
