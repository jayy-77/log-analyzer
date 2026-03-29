# Firewall Log Anomaly Detection — MLE Pipeline

[![CI](https://github.com/jayy-77/log-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/jayy-77/log-analyzer/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A full MLOps pipeline for detecting anomalies in firewall logs — from data
generation through training, evaluation, serving and drift monitoring.

## What's inside

```
src/log_analyzer/
├── data/         # log parsing, validation, synthetic generation
├── features/     # row- and window-level feature extraction
├── models/       # IsolationForest, One-Class SVM, Autoencoder, registry
├── training/     # train CLI + evaluation + MLflow tracking
├── inference/    # FastAPI service + batch CLI
├── monitoring/   # PSI / KS drift + Prometheus metrics
└── cli.py        # `log-analyzer` Click CLI
```

## Quick start

```bash
pip install -e .[dev]

# 1. Generate a synthetic log file with anomalies
log-analyzer generate --n 5000 --anomaly-ratio 0.05 --out logs/syn.log

# 2. Train any of the three models
log-analyzer train --model isolation_forest --n-train 20000
log-analyzer train --model one_class_svm
log-analyzer train --model autoencoder

# 3. Score an existing log
log-analyzer score logs/syn.log --threshold 0.7 --limit 20

# 4. Run the FastAPI inference service
uvicorn log_analyzer.inference.api:app --reload

# 5. Check feature drift between two log files
log-analyzer drift logs/baseline.log logs/today.log
```

## Streamlit UI

```bash
streamlit run streamlit_app.py
```

The Streamlit app is a thin client: it parses the upload, trains on
synthetic data via the package, and visualises anomaly scores and drift.

## Architecture

```
                        ┌──────────────────────────┐
                        │   synthetic generator    │
                        └────────────┬─────────────┘
                                     │
              ┌──────────────────────▼───────────────────────┐
              │  feature pipeline (extractor + StandardScaler) │
              └──────────────────────┬───────────────────────┘
                                     │
                ┌────────────────────┼───────────────────────┐
                ▼                    ▼                       ▼
        IsolationForest       One-Class SVM           Autoencoder (PyTorch)
                ▼                    ▼                       ▼
              ┌──────────────────────┴───────────────────────┐
              │           ModelArtifact (joblib + MLflow)    │
              └──────────────────────┬───────────────────────┘
                                     │
                ┌────────────────────┴───────────────────────┐
                ▼                                             ▼
       FastAPI inference                               batch scoring CLI
        + Prometheus
                ▼
             drift monitor (PSI + KS)
```

## Models

| Model | Strength | When to use |
|---|---|---|
| IsolationForest | Fast, handles mixed features, robust default | Production default |
| One-Class SVM | Captures tighter boundary on small data | < 20k records |
| Autoencoder | Captures non-linear structure | Rich features, more data |

All models implement the `AnomalyModel` interface and return scores in [0,1].

## Evaluation

- **PR-AUC** — main headline metric (anomalies are rare → ROC-AUC misleads)
- **ROC-AUC** — secondary
- **Precision@K** — what fraction of the top-K% flagged items are real anomalies?
- **Recall@K** — what fraction of real anomalies are in the top-K%?

## Drift detection

- **PSI** — banking-standard population stability index, per-feature
- **KS test** — non-parametric two-sample test, per-feature
- A feature is flagged when PSI ≥ 0.2 or KS p < 0.05

## CI

GitHub Actions runs ruff lint + pytest on Python 3.10 and 3.11 on every push.

## See also

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/MODEL_CARD.md](docs/MODEL_CARD.md)
