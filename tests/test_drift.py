import numpy as np

from log_analyzer.monitoring.drift import ks_drift, psi, report_drift


def test_psi_no_drift_when_identical():
    rng = np.random.default_rng(0)
    x = rng.normal(size=5000)
    p = psi(x, x)
    assert p < 0.05


def test_psi_detects_shift():
    rng = np.random.default_rng(0)
    x = rng.normal(size=5000)
    y = rng.normal(loc=2.0, size=5000)
    assert psi(x, y) > 0.25


def test_ks_drift_pvalue_under_shift():
    rng = np.random.default_rng(0)
    x = rng.normal(size=2000)
    y = rng.normal(loc=1.5, size=2000)
    _, p, flag = ks_drift(x, y)
    assert p < 0.01 and flag is True


def test_report_drift_shape():
    rng = np.random.default_rng(0)
    a = rng.normal(size=(1000, 3))
    b = rng.normal(size=(1000, 3))
    reports = report_drift(["a", "b", "c"], a, b)
    assert len(reports) == 3
