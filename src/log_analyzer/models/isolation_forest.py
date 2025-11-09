"""IsolationForest wrapped to the AnomalyModel interface."""

from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest

from .base import AnomalyModel


class IsolationForestModel(AnomalyModel):
    name = "isolation_forest"

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 200,
        max_samples: str | int = "auto",
        random_state: int = 42,
    ):
        self.contamination = contamination
        self._model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            max_samples=max_samples,
            random_state=random_state,
            n_jobs=-1,
        )
        self._score_min: float | None = None
        self._score_max: float | None = None

    def fit(self, X: np.ndarray) -> "IsolationForestModel":
        self._model.fit(X)
        # Calibrate to [0,1] on training data — sklearn's decision_function is
        # higher = more normal, so we flip and min-max normalize.
        raw = -self._model.decision_function(X)
        self._score_min = float(raw.min())
        self._score_max = float(raw.max())
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        raw = -self._model.decision_function(X)
        if self._score_min is None or self._score_max is None:
            return raw
        denom = max(self._score_max - self._score_min, 1e-9)
        return np.clip((raw - self._score_min) / denom, 0.0, 1.0)
