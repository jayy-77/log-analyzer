"""Training entrypoint — produces a serialized ModelArtifact."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from ..data import SyntheticLogGenerator
from ..features import FEATURE_NAMES, build_feature_pipeline
from ..models import MODEL_REGISTRY, get_model
from ..models.registry import ModelArtifact, save_model
from .evaluate import evaluate
from .mlflow_tracker import MLflowRun

log = logging.getLogger(__name__)


@dataclass
class TrainConfig:
    model_name: str = "isolation_forest"
    contamination: float = 0.05
    n_train: int = 10_000
    n_eval: int = 2_000
    anomaly_ratio: float = 0.05
    seed: int = 42
    artifact_path: str = "artifacts/model.joblib"
    mlflow_experiment: str = "log-analyzer"


def _entries_to_df(entries) -> pd.DataFrame:
    return pd.DataFrame([e.model_dump() for e in entries])


def train_model(cfg: TrainConfig) -> Path:
    if cfg.model_name not in MODEL_REGISTRY:
        raise KeyError(f"unknown model {cfg.model_name!r}")

    log.info("generating synthetic dataset n=%d (anomaly=%.2f)", cfg.n_train, cfg.anomaly_ratio)
    gen = SyntheticLogGenerator()
    gen.config.anomaly_ratio = cfg.anomaly_ratio
    gen.config.seed = cfg.seed
    train_entries = gen.generate(cfg.n_train)
    eval_entries = gen.generate(cfg.n_eval)

    train_df = _entries_to_df(train_entries)
    eval_df = _entries_to_df(eval_entries)

    pipe = build_feature_pipeline()
    X_train = pipe.fit_transform(train_df)
    X_eval = pipe.transform(eval_df)

    # Labels are inferred from synthetic 'info' tag for evaluation only.
    y_eval = (eval_df["info"] != "normal").astype(int).to_numpy()

    log.info("training model=%s on shape=%s", cfg.model_name, X_train.shape)
    kwargs = {}
    if cfg.model_name in ("isolation_forest", "one_class_svm"):
        kwargs["contamination" if cfg.model_name == "isolation_forest" else "nu"] = (
            cfg.contamination
        )
    model = get_model(cfg.model_name, **kwargs)
    model.fit(X_train)

    eval_scores = model.score(X_eval)
    metrics = evaluate(y_eval, eval_scores)
    log.info("eval metrics: %s", metrics)

    artifact = ModelArtifact(
        model=model,
        feature_names=list(FEATURE_NAMES),
        metadata={
            "model_name": cfg.model_name,
            "n_train": cfg.n_train,
            "metrics": metrics,
        },
    )
    # Note: we save the AnomalyModel only; the feature pipeline lives alongside
    # so the serving layer can rebuild it deterministically.
    path = save_model(artifact, cfg.artifact_path)
    save_model(
        ModelArtifact(model=pipe, feature_names=list(FEATURE_NAMES), metadata={"kind": "pipeline"}),
        Path(cfg.artifact_path).with_suffix(".pipeline.joblib"),
    )

    with MLflowRun(experiment=cfg.mlflow_experiment, run_name=cfg.model_name) as run:
        run.log_params(
            {
                "model_name": cfg.model_name,
                "n_train": cfg.n_train,
                "contamination": cfg.contamination,
                "anomaly_ratio": cfg.anomaly_ratio,
            }
        )
        run.log_metrics(metrics)
        run.log_artifact(path)

    return path
