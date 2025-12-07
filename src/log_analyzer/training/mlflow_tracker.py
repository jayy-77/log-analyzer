"""Thin MLflow wrapper that no-ops gracefully when MLflow is absent.

The reason for the no-op path: training should still run in a fresh sandbox
with no tracking server. We don't want a missing dependency to break the
core pipeline — observability is opt-in.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

log = logging.getLogger(__name__)

try:
    import mlflow  # type: ignore

    _MLFLOW_AVAILABLE = True
except ImportError:  # pragma: no cover
    _MLFLOW_AVAILABLE = False


class MLflowRun:
    def __init__(self, experiment: str, run_name: str):
        self.experiment = experiment
        self.run_name = run_name
        self._active = False

    def __enter__(self):
        if not _MLFLOW_AVAILABLE:
            log.warning("mlflow not installed, skipping tracking")
            return self
        try:
            mlflow.set_experiment(self.experiment)
            mlflow.start_run(run_name=self.run_name)
            self._active = True
        except Exception as exc:  # pragma: no cover
            log.warning("mlflow tracking disabled: %s", exc)
        return self

    def __exit__(self, *args):
        if self._active:
            mlflow.end_run()

    def log_params(self, params: dict) -> None:
        if self._active:
            mlflow.log_params(params)

    def log_metrics(self, metrics: dict) -> None:
        if self._active:
            mlflow.log_metrics({k: v for k, v in metrics.items() if isinstance(v, (int, float))})

    def log_artifact(self, path: str | Path) -> None:
        if self._active:
            mlflow.log_artifact(str(path))


@contextmanager
def maybe_run(experiment: str, run_name: str) -> Iterator[MLflowRun]:
    with MLflowRun(experiment, run_name) as r:
        yield r
