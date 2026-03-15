# Architecture

## Layers

### Data
- **`data/loader.py`** parses the ABC Inc. column format, returning `LogBatch(entries, parsed, rejected)`.
- **`data/schema.py`** uses pydantic for validation and normalization (uppercase actions, `-` → None).
- **`data/synthetic.py`** generates training data with controllable anomaly patterns: port scan, brute force, exfil, DDoS.

### Features
- Per-row: numeric, port categories, time-of-day, protocol flags, size buckets.
- Windowed: 7-feature aggregate that **matches the streaming Go processor** in [`redpanda-firewall-anomaly-detector`](../../redpanda-firewall-anomaly-detector) — same definition for train-serve symmetry.

### Models
All implement `AnomalyModel`:
- `fit(X)` → self
- `score(X)` → np.ndarray in [0, 1], higher = more anomalous
- `predict(X, threshold)` → 0/1

Calibration is done on the training set at fit time so threshold semantics are consistent across detector types.

### Training
1. Synthetic dataset generation (`SyntheticLogGenerator`)
2. Train/eval split
3. Feature pipeline fit_transform
4. Model fit
5. Eval on labelled synthetic anomalies → PR-AUC / ROC-AUC / precision@K / recall@K
6. Persist `(model, pipeline)` as joblib artifacts
7. Optional MLflow logging (params + metrics + artifact)

### Inference
- **FastAPI** service exposes `/score`, `/score/batch`, `/healthz`, `/metrics`
- **Prometheus** metrics: scored counter, anomaly counter, latency histogram, per-feature PSI gauge
- **Batch** CLI for one-shot scoring of large log files

### Monitoring
- PSI (banking-standard) and KS test per feature
- Drift report flags features with significant distribution shift
- The Streamlit UI surfaces the drift table next to the score chart

## Train-serve symmetry

The Go streaming processor in the sister repo extracts these 7 features in real time:

```
mean_value, std_dev, max_value, min_value,
percent_change, unique_ips, peak_to_mean_ratio
```

The Python `features.extractors.windowed_aggregate` function reproduces the
same math. A model trained here on the same feature schema can be served
behind that processor over HTTP (see the redpanda repo's `model_server`).

## Why these choices

- **pydantic** — schema is data-quality enforcement, not decoration
- **PyTorch over keras** — smaller install footprint, single-file model code
- **joblib + MLflow split** — joblib is the on-disk format, MLflow is the catalog; either can survive without the other
- **Click CLI** — argparse boilerplate was 30% of the original script
- **PSI threshold 0.2** — industry convention (<0.1 nothing, 0.1–0.25 moderate, >0.25 significant)
