"""Data drift detection: Population Stability Index + Kolmogorov-Smirnov."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy.stats import ks_2samp


@dataclass
class DriftReport:
    feature: str
    psi: float
    ks_statistic: float
    ks_pvalue: float
    drift: bool


def psi(expected: np.ndarray, actual: np.ndarray, bins: int = 10) -> float:
    """Compute Population Stability Index.

    Rule-of-thumb thresholds (industry standard, not derived):
       < 0.10 = no significant shift
       0.10–0.25 = moderate shift, worth investigating
       > 0.25 = significant shift, retrain candidate
    """
    expected = np.asarray(expected, dtype=float)
    actual = np.asarray(actual, dtype=float)
    if len(expected) == 0 or len(actual) == 0:
        return 0.0
    quantiles = np.linspace(0, 1, bins + 1)
    cuts = np.quantile(expected, quantiles)
    cuts[0] = -np.inf
    cuts[-1] = np.inf
    exp_hist, _ = np.histogram(expected, bins=cuts)
    act_hist, _ = np.histogram(actual, bins=cuts)
    exp_pct = np.maximum(exp_hist / exp_hist.sum(), 1e-6)
    act_pct = np.maximum(act_hist / act_hist.sum(), 1e-6)
    return float(np.sum((act_pct - exp_pct) * np.log(act_pct / exp_pct)))


def ks_drift(expected: np.ndarray, actual: np.ndarray, alpha: float = 0.05) -> tuple[float, float, bool]:
    """Two-sample KS test. Returns (stat, p_value, is_drift)."""
    if len(expected) == 0 or len(actual) == 0:
        return 0.0, 1.0, False
    stat, p = ks_2samp(expected, actual)
    return float(stat), float(p), bool(p < alpha)


def report_drift(
    feature_names: list[str],
    expected: np.ndarray,
    actual: np.ndarray,
    psi_threshold: float = 0.2,
) -> list[DriftReport]:
    reports = []
    for i, name in enumerate(feature_names):
        col_exp = expected[:, i]
        col_act = actual[:, i]
        p = psi(col_exp, col_act)
        ks_stat, ks_p, ks_flag = ks_drift(col_exp, col_act)
        reports.append(
            DriftReport(
                feature=name,
                psi=p,
                ks_statistic=ks_stat,
                ks_pvalue=ks_p,
                drift=(p >= psi_threshold) or ks_flag,
            )
        )
    return reports
