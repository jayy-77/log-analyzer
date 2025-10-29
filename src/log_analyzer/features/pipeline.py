"""sklearn-compatible feature pipeline composition."""

from __future__ import annotations

from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .extractors import FeatureExtractor, FEATURE_NAMES


class _Extract:
    """Adapter that runs the FeatureExtractor inside a Pipeline."""

    def __init__(self):
        self._inner = FeatureExtractor()

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return self._inner.transform(X).values

    def fit_transform(self, X, y=None):
        return self.transform(X)

    def get_feature_names_out(self, _=None):
        return list(FEATURE_NAMES)


def build_feature_pipeline() -> Pipeline:
    """Per-row pipeline: parse → extract numeric features → standardize."""
    return Pipeline(
        steps=[
            ("extract", _Extract()),
            ("scale", StandardScaler()),
        ]
    )
