"""Data models for PacketPulse network telemetry."""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any


@dataclass
class Hop:
    """Represents a single router hop in a network trajectory."""
    hop_num: int
    ip: Optional[str] = None
    hostname: Optional[str] = None
    rtt_ms: Optional[float] = None
    min_rtt_ms: Optional[float] = None
    max_rtt_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    loss_pct: float = 0.0
    lat: Optional[float] = None
    lon: Optional[float] = None
    city: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    is_destination: bool = False
    timed_out: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RouteTelemetry:
    """Complete route trajectory metadata and metrics."""
    target: str
    destination_ip: str
    hops: List[Hop] = field(default_factory=list)
    total_time_ms: float = 0.0
    avg_jitter_ms: float = 0.0
    packet_loss_pct: float = 0.0
    reached_destination: bool = False
    mode_used: str = "raw_icmp"  # 'raw_icmp', 'system_fallback', or 'simulated'

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
