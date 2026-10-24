"""Data structures and telemetry metrics models."""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any


@dataclass
class Hop:
    """Represents a single routing hop along the network transit path."""
    hop_num: int
    ip: Optional[str] = None
    rtt_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    city: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    asn: Optional[str] = None
    timed_out: bool = False
    is_destination: bool = False
    protocol: str = "ICMP"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TelemetryResult:
    """Aggregated route telemetry result across all hops."""
    target: str
    destination_ip: str
    hops: List[Hop] = field(default_factory=list)
    total_time_ms: float = 0.0
    reached_destination: bool = False

    @property
    def avg_jitter_ms(self) -> float:
        valid_jitters = [h.jitter_ms for h in self.hops if h.jitter_ms is not None]
        return round(sum(valid_jitters) / len(valid_jitters), 2) if valid_jitters else 0.0

    @property
    def packet_loss_pct(self) -> float:
        if not self.hops:
            return 0.0
        timeouts = sum(1 for h in self.hops if h.timed_out)
        return round((timeouts / len(self.hops)) * 100, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "destination_ip": self.destination_ip,
            "hops": [h.to_dict() for h in self.hops],
            "total_time_ms": self.total_time_ms,
            "reached_destination": self.reached_destination,
            "avg_jitter_ms": self.avg_jitter_ms,
            "packet_loss_pct": self.packet_loss_pct,
        }
