from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


Action = Literal["allow", "drop", "alert"]
Severity = Literal["low", "medium", "high"]


class PacketEvent(BaseModel):
    """Normalized packet observation flowing through the pipeline."""

    ts: float
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    proto: str = "OTHER"
    bytes: int = 0
    tls_sni: Optional[str] = None
    http_host: Optional[str] = None
    flags: list[str] = Field(default_factory=list)


class RuleMatch(BaseModel):
    src_cidr: Optional[str] = None
    dst_cidr: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    proto: Optional[str] = None
    sni_regex: Optional[str] = None
    host_regex: Optional[str] = None
    direction: Optional[Literal["internal", "external", "inbound", "outbound"]] = None


class Rule(BaseModel):
    name: str
    action: Action = "alert"
    severity: Severity = "medium"
    description: str = ""
    match: RuleMatch = Field(default_factory=RuleMatch)
    enabled: bool = True


class Alert(BaseModel):
    id: Optional[int] = None
    ts: float
    rule: str
    severity: Severity
    src_ip: str
    dst_ip: str
    proto: str
    detail: str = ""


class TopTalker(BaseModel):
    ip: str
    bytes: int
    packets: int


class ProtocolStat(BaseModel):
    proto: str
    bytes: int
    packets: int


class BandwidthPoint(BaseModel):
    ts: int
    bytes: int
    packets: int


class MetricsSnapshot(BaseModel):
    generated_at: float
    total_packets: int
    total_bytes: int
    dropped_packets: int
    alerts_count: int
    top_talkers: list[TopTalker]
    protocols: list[ProtocolStat]
    bandwidth: list[BandwidthPoint]
