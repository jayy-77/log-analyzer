"""Click-based CLI surface: train / evaluate / score / drift / generate."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import click
import numpy as np
import pandas as pd

from .data import SyntheticLogGenerator, load_log_file
from .features import build_feature_pipeline, FEATURE_NAMES
from .inference.batch import batch_score
from .monitoring.drift import report_drift
from .training import train_model
from .training.train import TrainConfig

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


@click.group()
def main() -> None:
    """log-analyzer command-line interface."""


@main.command("generate")
@click.option("--n", default=1_000, help="Number of synthetic log entries")
@click.option("--anomaly-ratio", default=0.05)
@click.option("--out", "out_path", type=click.Path(), default="logs/synthetic.log")
def generate(n: int, anomaly_ratio: float, out_path: str) -> None:
    """Write a synthetic firewall log file."""
    gen = SyntheticLogGenerator()
    gen.config.anomaly_ratio = anomaly_ratio
    entries = gen.generate(n)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        f.write("Date Time Action Protocol Src_IP Dst_IP Src_Port Dst_Port Size TCP_Flags Info\n")
        for e in entries:
            f.write(
                f"{e.timestamp:%Y-%m-%d} {e.timestamp:%H:%M:%S} {e.action} {e.protocol} "
                f"{e.src_ip} {e.dst_ip} {e.src_port or '-'} {e.dst_port or '-'} "
                f"{e.size or '-'} {e.tcp_flags or '-'} {e.info or '-'}\n"
            )
    click.echo(f"wrote {n} entries to {out}")


@main.command("train")
@click.option("--model", "model_name", default="isolation_forest")
@click.option("--n-train", default=10_000)
@click.option("--anomaly-ratio", default=0.05)
@click.option("--artifact", default="artifacts/model.joblib")
def train(model_name: str, n_train: int, anomaly_ratio: float, artifact: str) -> None:
    cfg = TrainConfig(
        model_name=model_name,
        n_train=n_train,
        anomaly_ratio=anomaly_ratio,
        artifact_path=artifact,
    )
    path = train_model(cfg)
    click.echo(f"model artifact: {path}")


@main.command("score")
@click.argument("log_file", type=click.Path(exists=True))
@click.option("--model", "model_path", default="artifacts/model.joblib")
@click.option("--pipeline", "pipeline_path", default="artifacts/model.pipeline.joblib")
@click.option("--threshold", default=0.7)
@click.option("--limit", default=20, help="Show only the top-N anomalies")
def score(log_file: str, model_path: str, pipeline_path: str, threshold: float, limit: int) -> None:
    df = batch_score(log_file, model_path, pipeline_path, threshold)
    top = df.sort_values("score", ascending=False).head(limit)
    click.echo(top[["timestamp", "src_ip", "dst_ip", "dst_port", "size", "score", "decision"]].to_string())


@main.command("drift")
@click.argument("baseline_log", type=click.Path(exists=True))
@click.argument("current_log", type=click.Path(exists=True))
def drift(baseline_log: str, current_log: str) -> None:
    pipeline = build_feature_pipeline()
    base_df = pd.DataFrame([e.model_dump() for e in load_log_file(baseline_log).entries])
    cur_df = pd.DataFrame([e.model_dump() for e in load_log_file(current_log).entries])
    X_base = np.asarray(pipeline.fit_transform(base_df))
    X_cur = np.asarray(pipeline.transform(cur_df))
    reports = report_drift(list(FEATURE_NAMES), X_base, X_cur)
    click.echo(json.dumps([r.__dict__ for r in reports], indent=2))


if __name__ == "__main__":
    main()
