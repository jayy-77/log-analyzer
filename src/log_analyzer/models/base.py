"""Common interface for anomaly detection models."""

from __future__ import annotations

from abc import ABC, abstractmethod

import numpy as np


class AnomalyModel(ABC):
    """All detectors implement this so the training and serving code can
    treat them uniformly. `score` returns higher = more anomalous in
    [0, 1] (so threshold semantics are consistent across detectors)."""

    name: str = "abstract"

    @abstractmethod
    def fit(self, X: np.ndarray) -> "AnomalyModel":
        ...

    @abstractmethod
    def score(self, X: np.ndarray) -> np.ndarray:
        ...

    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        return (self.score(X) >= threshold).astype(int)
