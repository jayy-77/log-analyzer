"""Pydantic schemas for firewall log entries."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class LogEntry(BaseModel):
    """A single firewall log line in canonical form."""

    timestamp: datetime
    action: str = Field(pattern=r"^(ACCEPT|BLOCK|DROP|DENY|ALLOW)$")
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    size: Optional[int] = None
    tcp_flags: Optional[str] = None
    info: Optional[str] = None

    @field_validator("action", mode="before")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper() if isinstance(v, str) else v

    @field_validator("src_port", "dst_port", "size", mode="before")
    @classmethod
    def _none_for_dash(cls, v):
        if v in (None, "", "-"):
            return None
        return v


class LogBatch(BaseModel):
    """A validated batch of log entries plus parse statistics."""

    entries: list[LogEntry]
    parsed: int
    rejected: int

    @property
    def total(self) -> int:
        return self.parsed + self.rejected
