import numpy as np
import pandas as pd

from log_analyzer.features import FEATURE_NAMES, build_feature_pipeline
from log_analyzer.features.extractors import FeatureExtractor, windowed_aggregate


def _toy_df() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "timestamp": "2024-10-01 12:34:56",
                "action": "ACCEPT",
                "protocol": "TCP",
                "src_ip": "192.168.1.1",
                "dst_ip": "10.0.0.1",
                "src_port": 54321,
                "dst_port": 80,
                "size": 1500,
                "tcp_flags": "ACK",
            },
            {
                "timestamp": "2024-10-01 12:35:00",
                "action": "BLOCK",
                "protocol": "UDP",
                "src_ip": "192.168.1.2",
                "dst_ip": "10.0.0.2",
                "src_port": 60000,
                "dst_port": 22,
                "size": 64,
                "tcp_flags": "SYN",
            },
        ]
    )


def test_extractor_columns():
    ext = FeatureExtractor()
    out = ext.transform(_toy_df())
    assert list(out.columns) == list(FEATURE_NAMES)
    assert len(out) == 2


def test_pipeline_runs_end_to_end():
    pipe = build_feature_pipeline()
    X = pipe.fit_transform(_toy_df())
    assert X.shape == (2, len(FEATURE_NAMES))


def test_windowed_aggregate_matches_definition():
    out = windowed_aggregate(np.array([10.0, 20.0, 30.0, 40.0, 50.0]), last_mean=25.0, unique_ips=3)
    assert out["mean_value"] == 30.0
    assert out["max_value"] == 50.0
    assert out["min_value"] == 10.0
    assert out["unique_ips"] == 3.0
    assert abs(out["peak_to_mean_ratio"] - 50 / 30) < 1e-9
    assert abs(out["percent_change"] - 20.0) < 1e-9


def test_windowed_aggregate_empty():
    out = windowed_aggregate(np.array([]), last_mean=0.0, unique_ips=0)
    assert all(v == 0.0 for v in out.values())
