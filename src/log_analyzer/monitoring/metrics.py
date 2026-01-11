"""Prometheus metric registry used by the API and CLI."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram


def register_prometheus_metrics(namespace: str = "log_analyzer") -> dict:
    return {
        "scored": Counter(f"{namespace}_scored_total", "Records scored"),
        "anomalies": Counter(f"{namespace}_anomaly_total", "Records flagged anomalous"),
        "score_latency": Histogram(f"{namespace}_score_latency_seconds", "Score latency"),
        "drift_psi": Gauge(
            f"{namespace}_feature_drift_psi", "PSI per feature", ["feature"]
        ),
    }
