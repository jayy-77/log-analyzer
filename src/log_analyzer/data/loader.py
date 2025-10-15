"""Parsing of firewall log lines into validated LogEntry records.

Supports the ABC Inc. column-aligned format used in the repo's sample data:
    DATE TIME ACTION PROTO SRC_IP DST_IP SRC_PORT DST_PORT SIZE FLAGS INFO

Lines with '-' as the placeholder for an optional field are accepted.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Iterable, Optional

from pydantic import ValidationError

from .schema import LogBatch, LogEntry

_SPLIT = re.compile(r" +")
log = logging.getLogger(__name__)


def parse_log_line(line: str) -> Optional[LogEntry]:
    """Parse a single line. Return None if the line is malformed."""
    parts = _SPLIT.split(line.strip())
    if len(parts) < 11:
        return None

    raw = {
        "timestamp": f"{parts[0]} {parts[1]}",
        "action": parts[2],
        "protocol": parts[3],
        "src_ip": parts[4],
        "dst_ip": parts[5],
        "src_port": parts[6],
        "dst_port": parts[7],
        "size": parts[8],
        "tcp_flags": parts[9],
        "info": " ".join(parts[10:]),
    }
    try:
        return LogEntry(**raw)
    except ValidationError as exc:
        log.debug("rejected line: %s (%s)", line[:60], exc)
        return None


def _iter_lines(source: Path | Iterable[str]) -> Iterable[str]:
    if isinstance(source, Path):
        with source.open("r", encoding="utf-8", errors="replace") as f:
            # skip header — the sample data has a single header line
            first = next(f, None)
            if first and not _looks_like_header(first):
                yield first
            yield from f
    else:
        yield from source


def _looks_like_header(line: str) -> bool:
    lower = line.lower()
    return "date" in lower and "src" in lower and "dst" in lower


def load_log_file(path: str | Path) -> LogBatch:
    """Load and validate a log file, returning a LogBatch.

    Counts both successful and rejected lines so we can report parse rate.
    """
    path = Path(path)
    entries: list[LogEntry] = []
    rejected = 0
    for line in _iter_lines(path):
        if not line.strip():
            continue
        entry = parse_log_line(line)
        if entry is None:
            rejected += 1
        else:
            entries.append(entry)
    return LogBatch(entries=entries, parsed=len(entries), rejected=rejected)
