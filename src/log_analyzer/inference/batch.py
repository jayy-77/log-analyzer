"""Batch scoring CLI helper."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from ..data import load_log_file
from ..models.registry import load_model


def batch_score(
    log_path: str | Path,
    model_path: str | Path,
    pipeline_path: str | Path,
    threshold: float = 0.7,
) -> pd.DataFrame:
    batch = load_log_file(log_path)
    df = pd.DataFrame([e.model_dump() for e in batch.entries])
    model = load_model(model_path).model
    pipeline = load_model(pipeline_path).model
    X = pipeline.transform(df)
    scores = model.score(np.asarray(X))
    df["score"] = scores
    df["decision"] = (scores >= threshold).astype(int)
    return df
