"""Unified high-level PacketPulse engine facade."""

from __future__ import annotations
from typing import Optional, Callable
from packetpulse.tracer import PacketTracer
from packetpulse.models import TelemetryResult, Hop


class PacketPulse:
    """Master network telemetry coordinator and stream manager."""

    def __init__(self, mode: str = "auto"):
        self.tracer = PacketTracer(mode=mode)

    @property
    def mode(self) -> str:
        return self.tracer.mode

    def trace(
        self,
        target: str = "google.com",
        max_hops: int = 20,
        timeout: float = 1.5,
        inter_packet_delay: float = 0.05,
        on_hop: Optional[Callable[[Hop], None]] = None,
    ) -> TelemetryResult:
        """Dispatches traceroute scan with real-time hop stream."""
        return self.tracer.trace(
            target=target,
            max_hops=max_hops,
            timeout=timeout,
            inter_packet_delay=inter_packet_delay,
            on_hop=on_hop,
        )
