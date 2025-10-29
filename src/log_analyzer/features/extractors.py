"""Per-row and windowed feature extraction.

Two complementary surfaces:
  - Per-row features (port category, size bucket, hour-of-day, etc.) used by
    point-anomaly detectors (Isolation Forest, OCSVM).
  - Windowed aggregate features (mean, std, unique IPs, peak-to-mean) that
    mirror the streaming Go processor's feature schema, so models trained
    here transfer there with no skew.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

# Single source of truth for feature column order. Keep in sync with
# `processor/firewall_anomaly_detector.go::extractFeatures`.
FEATURE_NAMES: tuple[str, ...] = (
    "size",
    "src_port",
    "dst_port",
    "is_well_known_port",
    "is_ephemeral_port",
    "hour",
    "minute_of_hour",
    "is_block",
    "is_tcp",
    "is_udp",
    "size_log",
    "size_bucket",
)

WINDOW_FEATURES: tuple[str, ...] = (
    "mean_value",
    "std_dev",
    "max_value",
    "min_value",
    "percent_change",
    "unique_ips",
    "peak_to_mean_ratio",
)


def _port_category(port: float) -> tuple[int, int]:
    if pd.isna(port):
        return 0, 0
    p = int(port)
    well_known = 1 if 0 < p <= 1023 else 0
    ephemeral = 1 if p >= 49152 else 0
    return well_known, ephemeral


@dataclass
class FeatureExtractor:
    """Stateless per-row feature builder.

    Accepts a DataFrame with the canonical column set produced by
    `data.loader.load_log_file` and returns a numeric DataFrame.
    """

    fillna_value: float = 0.0

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        out = pd.DataFrame(index=df.index)
        ts = pd.to_datetime(df["timestamp"], errors="coerce")
        size = pd.to_numeric(df.get("size"), errors="coerce")
        src_port = pd.to_numeric(df.get("src_port"), errors="coerce")
        dst_port = pd.to_numeric(df.get("dst_port"), errors="coerce")

        out["size"] = size.fillna(self.fillna_value)
        out["src_port"] = src_port.fillna(self.fillna_value)
        out["dst_port"] = dst_port.fillna(self.fillna_value)

        wk, ep = zip(*(_port_category(p) for p in dst_port))
        out["is_well_known_port"] = np.asarray(wk, dtype=float)
        out["is_ephemeral_port"] = np.asarray(ep, dtype=float)

        out["hour"] = ts.dt.hour.fillna(0).astype(float)
        out["minute_of_hour"] = ts.dt.minute.fillna(0).astype(float)

        action = df.get("action", pd.Series(dtype=str)).str.upper()
        out["is_block"] = action.isin(["BLOCK", "DROP", "DENY"]).astype(float)

        proto = df.get("protocol", pd.Series(dtype=str)).str.upper()
        out["is_tcp"] = (proto == "TCP").astype(float)
        out["is_udp"] = (proto == "UDP").astype(float)

        out["size_log"] = np.log1p(out["size"])
        # Coarse bucket: 0..7
        out["size_bucket"] = pd.cut(
            out["size"],
            bins=[-1, 64, 256, 1024, 1500, 10_000, 100_000, 1_000_000, np.inf],
            labels=False,
        ).astype(float)

        return out[list(FEATURE_NAMES)]


def windowed_aggregate(values: np.ndarray, last_mean: float, unique_ips: int) -> dict[str, float]:
    """Compute the 7-feature window aggregate that matches the Go processor.

    Centralizing this in Python gives the training side an identical
    feature definition; the Go side must keep its math in lockstep.
    """
    if len(values) == 0:
        return {k: 0.0 for k in WINDOW_FEATURES}
    mean = float(np.mean(values))
    std = float(np.std(values, ddof=1)) if len(values) > 1 else 0.0
    mx = float(np.max(values))
    mn = float(np.min(values))
    pct = ((mean - last_mean) / last_mean * 100.0) if last_mean > 0 else 0.0
    ptm = (mx / mean) if mean > 0 else 0.0
    return {
        "mean_value": mean,
        "std_dev": std,
        "max_value": mx,
        "min_value": mn,
        "percent_change": pct,
        "unique_ips": float(unique_ips),
        "peak_to_mean_ratio": ptm,
    }
