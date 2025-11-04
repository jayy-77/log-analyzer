"""Model registry: factory + persistence helpers.

The on-disk format is a joblib pickle of (model, metadata). MLflow handles
the catalog dimension separately — this registry is just the local layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import joblib

from .autoencoder import AutoencoderModel
from .base import AnomalyModel
from .isolation_forest import IsolationForestModel
from .one_class_svm import OneClassSVMModel


MODEL_REGISTRY: dict[str, Callable[..., AnomalyModel]] = {
    "isolation_forest": IsolationForestModel,
    "one_class_svm": OneClassSVMModel,
    "autoencoder": AutoencoderModel,
}


@dataclass
class ModelArtifact:
    model: AnomalyModel
    feature_names: list[str]
    metadata: dict = field(default_factory=dict)


def get_model(name: str, **kwargs) -> AnomalyModel:
    if name not in MODEL_REGISTRY:
        raise KeyError(
            f"unknown model {name!r}; available: {sorted(MODEL_REGISTRY)}"
        )
    return MODEL_REGISTRY[name](**kwargs)


def save_model(artifact: ModelArtifact, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, path)
    return path


def load_model(path: str | Path) -> ModelArtifact:
    return joblib.load(path)
