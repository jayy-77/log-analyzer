"""FastAPI inference service.

POST /score      single record → score + decision
POST /score/batch list of records → list of scores
GET  /healthz    liveness
GET  /metrics    prometheus exposition
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel
from starlette.responses import Response

from ..data.schema import LogEntry
from ..models.registry import load_model

_MODEL_PATH = os.environ.get("MODEL_PATH", "artifacts/model.joblib")
_PIPELINE_PATH = os.environ.get(
    "PIPELINE_PATH",
    str(Path(_MODEL_PATH).with_suffix(".pipeline.joblib")),
)
_THRESHOLD = float(os.environ.get("SCORE_THRESHOLD", "0.7"))

app = FastAPI(title="log-analyzer inference", version="0.2.0")

_score_count = Counter("log_analyzer_scored_total", "Records scored")
_anomaly_count = Counter("log_analyzer_anomaly_total", "Records flagged anomalous")
_latency = Histogram("log_analyzer_score_latency_seconds", "Score latency")

_artifact = None
_pipeline = None


def _load() -> None:
    global _artifact, _pipeline
    if _artifact is None:
        _artifact = load_model(_MODEL_PATH)
    if _pipeline is None:
        _pipeline = load_model(_PIPELINE_PATH).model


class ScoreRequest(BaseModel):
    entries: list[LogEntry]
    threshold: Optional[float] = None


class ScoreResponse(BaseModel):
    scores: list[float]
    decisions: list[int]
    threshold: float
    model_name: str


@app.on_event("startup")
def _startup() -> None:
    try:
        _load()
    except FileNotFoundError:
        # Model not yet trained — service stays up but /score will 503.
        pass


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "model_loaded": _artifact is not None}


@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest) -> ScoreResponse:
    if _artifact is None:
        _load()
    if _artifact is None:
        raise HTTPException(status_code=503, detail="model not loaded")

    df = pd.DataFrame([e.model_dump() for e in req.entries])
    with _latency.time():
        X = _pipeline.transform(df)
        scores = _artifact.model.score(np.asarray(X)).tolist()
    threshold = req.threshold if req.threshold is not None else _THRESHOLD
    decisions = [int(s >= threshold) for s in scores]
    _score_count.inc(len(scores))
    _anomaly_count.inc(sum(decisions))
    return ScoreResponse(
        scores=scores,
        decisions=decisions,
        threshold=threshold,
        model_name=_artifact.metadata.get("model_name", "unknown"),
    )
