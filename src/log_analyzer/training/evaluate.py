"""Offline evaluation: PR-AUC, ROC-AUC, precision@K, recall@K."""

from __future__ import annotations

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score


def evaluate(y_true: np.ndarray, scores: np.ndarray, k_pct: float = 0.05) -> dict[str, float]:
    """Return a small set of detector-friendly metrics.

    `precision_at_k` is the precision among the top-K% highest scores —
    the relevant metric when ops can only triage a fixed budget per day.
    """
    y_true = np.asarray(y_true).astype(int)
    scores = np.asarray(scores).astype(float)

    metrics: dict[str, float] = {}
    if y_true.sum() > 0 and y_true.sum() < len(y_true):
        metrics["pr_auc"] = float(average_precision_score(y_true, scores))
        metrics["roc_auc"] = float(roc_auc_score(y_true, scores))
    else:
        metrics["pr_auc"] = float("nan")
        metrics["roc_auc"] = float("nan")

    k = max(1, int(len(scores) * k_pct))
    top_idx = np.argsort(scores)[::-1][:k]
    metrics["precision_at_k"] = float(y_true[top_idx].mean())
    metrics["recall_at_k"] = (
        float(y_true[top_idx].sum() / y_true.sum()) if y_true.sum() > 0 else 0.0
    )
    metrics["k_pct"] = k_pct
    return metrics
