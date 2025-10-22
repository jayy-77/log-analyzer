"""Synthetic firewall log generator with controllable anomaly injection.

Useful for: smoke tests, training under known-label conditions, and
benchmarking detectors against scripted attack patterns (port scan,
brute force, exfil burst, DDoS volume spike).
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterator

from .schema import LogEntry

_PROTOS = ("TCP", "UDP", "ICMP")
_ACTIONS_NORMAL = ("ACCEPT", "BLOCK")
_COMMON_PORTS = (22, 53, 80, 443, 3306, 5432, 6379, 8080)


@dataclass
class SyntheticConfig:
    """Knobs that control how the generator behaves."""

    base_rate_per_sec: float = 2.0
    anomaly_ratio: float = 0.05
    seed: int | None = 42


class SyntheticLogGenerator:
    """Generates synthetic firewall log entries.

    Patterns supported:
      - normal: realistic ACCEPT/BLOCK on common ports
      - port_scan: many distinct dst_ports from a single src_ip
      - brute_force: many SSH/RDP attempts to one dst_ip
      - exfil: large outbound size to single dst_ip
      - ddos: many source IPs hammering one dst_port
    """

    def __init__(self, config: SyntheticConfig | None = None):
        self.config = config or SyntheticConfig()
        self._rng = random.Random(self.config.seed)
        self._t = datetime(2025, 1, 1, 0, 0, 0)

    def _advance(self, seconds: float = 1.0) -> datetime:
        self._t += timedelta(seconds=seconds)
        return self._t

    def _rand_ip(self, subnet: str = "192.168") -> str:
        return f"{subnet}.{self._rng.randint(0, 255)}.{self._rng.randint(1, 254)}"

    def _normal(self) -> LogEntry:
        return LogEntry(
            timestamp=self._advance(self._rng.uniform(0.1, 1.0)),
            action=self._rng.choices(_ACTIONS_NORMAL, weights=(0.8, 0.2))[0],
            protocol=self._rng.choices(_PROTOS, weights=(0.7, 0.25, 0.05))[0],
            src_ip=self._rand_ip("192.168"),
            dst_ip=self._rand_ip("10"),
            src_port=self._rng.randint(1024, 65535),
            dst_port=self._rng.choice(_COMMON_PORTS),
            size=self._rng.randint(64, 1500),
            tcp_flags=self._rng.choice(("ACK", "SYN", "FIN", "RST")),
            info="normal",
        )

    def _port_scan(self, src: str, n: int = 30) -> list[LogEntry]:
        out = []
        for port in self._rng.sample(range(1, 1024), k=min(n, 1023)):
            out.append(
                LogEntry(
                    timestamp=self._advance(0.05),
                    action="BLOCK",
                    protocol="TCP",
                    src_ip=src,
                    dst_ip=self._rand_ip("10"),
                    src_port=self._rng.randint(40000, 60000),
                    dst_port=port,
                    size=64,
                    tcp_flags="SYN",
                    info="port_scan",
                )
            )
        return out

    def _brute_force(self, dst: str, n: int = 40) -> list[LogEntry]:
        return [
            LogEntry(
                timestamp=self._advance(0.2),
                action="BLOCK",
                protocol="TCP",
                src_ip=self._rand_ip("203.0"),
                dst_ip=dst,
                src_port=self._rng.randint(40000, 60000),
                dst_port=22,
                size=120,
                tcp_flags="RST",
                info="brute_force",
            )
            for _ in range(n)
        ]

    def _exfil(self, src: str, dst: str, n: int = 20) -> list[LogEntry]:
        return [
            LogEntry(
                timestamp=self._advance(0.5),
                action="ACCEPT",
                protocol="TCP",
                src_ip=src,
                dst_ip=dst,
                src_port=self._rng.randint(40000, 60000),
                dst_port=443,
                size=self._rng.randint(500_000, 5_000_000),
                tcp_flags="ACK",
                info="exfil",
            )
            for _ in range(n)
        ]

    def _ddos(self, dst: str, n: int = 200) -> list[LogEntry]:
        return [
            LogEntry(
                timestamp=self._advance(0.01),
                action="BLOCK",
                protocol="TCP",
                src_ip=self._rand_ip("203.0"),
                dst_ip=dst,
                src_port=self._rng.randint(1024, 65535),
                dst_port=80,
                size=64,
                tcp_flags="SYN",
                info="ddos",
            )
            for _ in range(n)
        ]

    def stream(self, n_total: int) -> Iterator[LogEntry]:
        """Yield n_total entries with anomalies sprinkled per config.anomaly_ratio."""
        anomaly_budget = int(n_total * self.config.anomaly_ratio)
        produced = 0
        while produced < n_total:
            if anomaly_budget > 0 and self._rng.random() < self.config.anomaly_ratio:
                kind = self._rng.choice(("port_scan", "brute_force", "exfil", "ddos"))
                if kind == "port_scan":
                    batch = self._port_scan(self._rand_ip("203.0"))
                elif kind == "brute_force":
                    batch = self._brute_force(self._rand_ip("10"))
                elif kind == "exfil":
                    batch = self._exfil(self._rand_ip("192.168"), self._rand_ip("203.0"))
                else:
                    batch = self._ddos(self._rand_ip("10"))
                for entry in batch:
                    if produced >= n_total:
                        return
                    yield entry
                    produced += 1
                anomaly_budget -= 1
            else:
                yield self._normal()
                produced += 1

    def generate(self, n_total: int) -> list[LogEntry]:
        return list(self.stream(n_total))
