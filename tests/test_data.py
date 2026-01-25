from datetime import datetime
from pathlib import Path

from log_analyzer.data import load_log_file, parse_log_line, SyntheticLogGenerator


def test_parse_valid_line():
    line = "2024-10-01 12:34:56 ACCEPT TCP 192.168.1.100 10.0.0.1 54321 80 1500 ACK info"
    entry = parse_log_line(line)
    assert entry is not None
    assert entry.action == "ACCEPT"
    assert entry.src_ip == "192.168.1.100"
    assert entry.dst_port == 80


def test_parse_rejects_short_line():
    assert parse_log_line("not enough columns here") is None


def test_synthetic_generator_anomaly_ratio():
    gen = SyntheticLogGenerator()
    gen.config.anomaly_ratio = 0.2
    entries = gen.generate(500)
    anomaly_share = sum(1 for e in entries if e.info != "normal") / len(entries)
    assert 0.05 < anomaly_share < 0.6  # noisy but bounded


def test_load_log_file_roundtrip(tmp_path: Path):
    p = tmp_path / "demo.log"
    p.write_text(
        "Date Time Action Protocol Src_IP Dst_IP Src_Port Dst_Port Size TCP_Flags Info\n"
        "2024-10-01 12:34:56 ACCEPT TCP 192.168.1.1 10.0.0.1 1024 80 1500 ACK ok\n"
        "garbage line that should be rejected\n"
    )
    batch = load_log_file(p)
    assert batch.parsed == 1
    assert batch.rejected >= 1
    assert batch.entries[0].timestamp.year == 2024
