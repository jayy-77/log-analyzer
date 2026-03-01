"""Streamlit UI — now a thin client of the log_analyzer package.

The original 100-line script that mixed parsing, training and UI is gone.
This file is just glue: parse log → call the training / batch-score CLIs
under the hood → render charts.
"""

from __future__ import annotations

import os
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st

from log_analyzer.data import load_log_file
from log_analyzer.features import build_feature_pipeline, FEATURE_NAMES
from log_analyzer.models import get_model
from log_analyzer.monitoring.drift import report_drift
from log_analyzer.training import train_model
from log_analyzer.training.train import TrainConfig

UPLOAD_FOLDER = Path("logs")
UPLOAD_FOLDER.mkdir(exist_ok=True)

st.set_page_config(page_title="Firewall Anomaly ML", layout="wide")
st.title("Firewall Anomaly Detection — MLE Pipeline")

with st.sidebar:
    st.header("Configuration")
    model_name = st.selectbox(
        "Model",
        options=["isolation_forest", "one_class_svm", "autoencoder"],
        index=0,
    )
    contamination = st.slider("Contamination / nu", 0.01, 0.20, 0.05)
    threshold = st.slider("Anomaly threshold", 0.0, 1.0, 0.7)
    n_train = st.number_input("Synthetic train samples", 1_000, 100_000, 10_000)
    st.caption("Threshold applies to scores returned by .score() (0–1 calibrated).")

uploaded_file = st.file_uploader("Upload a firewall log", type=["log"])

if uploaded_file is None:
    st.info("Upload a .log file (ABC Inc. column format).")
    st.stop()

target = UPLOAD_FOLDER / "uploaded.log"
target.write_bytes(uploaded_file.getbuffer())

batch = load_log_file(target)
st.success(f"Parsed {batch.parsed:,} entries ({batch.rejected:,} rejected)")
if not batch.entries:
    st.error("No parseable entries in the uploaded file.")
    st.stop()

df = pd.DataFrame([e.model_dump() for e in batch.entries])

st.subheader("Sample")
st.dataframe(df.head(10))

col1, col2, col3 = st.columns(3)
col1.metric("Records", len(df))
col2.metric("BLOCK rate", f"{(df['action'] == 'BLOCK').mean():.1%}")
col3.metric("Unique src IPs", df["src_ip"].nunique())

with st.spinner(f"Training {model_name} on synthetic data and scoring uploaded logs..."):
    cfg = TrainConfig(
        model_name=model_name,
        n_train=int(n_train),
        contamination=contamination,
        artifact_path="artifacts/streamlit_model.joblib",
    )
    train_model(cfg)

    from log_analyzer.models.registry import load_model

    model = load_model(cfg.artifact_path).model
    pipeline = load_model(Path(cfg.artifact_path).with_suffix(".pipeline.joblib")).model

    X = pipeline.transform(df)
    scores = model.score(np.asarray(X))
    df["score"] = scores
    df["decision"] = (scores >= threshold).astype(int)

st.subheader("Anomaly scores")
st.bar_chart(pd.Series(scores).rename("score"))

st.subheader("Top suspected anomalies")
top = df.sort_values("score", ascending=False).head(25)
st.dataframe(top[["timestamp", "action", "src_ip", "dst_ip", "dst_port", "size", "score", "decision"]])

st.subheader("Action breakdown")
st.bar_chart(df["action"].value_counts())

st.subheader("Top blocked destination ports")
st.bar_chart(df[df["action"] == "BLOCK"]["dst_port"].value_counts().head(10))

with st.expander("Drift report vs. synthetic baseline"):
    from log_analyzer.data import SyntheticLogGenerator

    gen = SyntheticLogGenerator()
    gen.config.anomaly_ratio = 0.0
    base = pd.DataFrame([e.model_dump() for e in gen.generate(5_000)])
    X_base = np.asarray(pipeline.transform(base))
    reports = report_drift(list(FEATURE_NAMES), X_base, np.asarray(X))
    st.dataframe(pd.DataFrame([r.__dict__ for r in reports]))
