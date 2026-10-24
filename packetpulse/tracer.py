"""Core network traceroute engine: raw ICMP sockets, system subprocess fallback, and mock telemetry."""

from __future__ import annotations
import socket
import select
import time
import os
import subprocess
import re
from typing import List, Optional, Callable

from packetpulse.models import Hop, TelemetryResult
from packetpulse.protocols import ICMPPacket
from packetpulse.geoip import GeoIPResolver
from packetpulse.security import validate_target, validate_hops, validate_delay


# High-fidelity realistic transoceanic simulated route (Delhi -> Mumbai -> Singapore -> Tokyo -> California)
SIMULATED_HOPS_DATA = [
    {"ip": "192.168.1.1", "city": "New Delhi", "country": "India", "country_code": "IN", "lat": 28.6139, "lon": 77.2090, "asn": "Local Gateway / Optical ONT", "base_rtt": 1.8},
    {"ip": "182.79.128.4", "city": "Delhi Metro", "country": "India", "country_code": "IN", "lat": 28.7041, "lon": 77.1025, "asn": "AS9498 Bharti Airtel Ltd.", "base_rtt": 4.6},
    {"ip": "180.87.36.12", "city": "Mumbai Landing Station", "country": "India", "country_code": "IN", "lat": 18.9220, "lon": 72.8347, "asn": "AS4755 Tata Communications (SMW-4)", "base_rtt": 19.4},
    {"ip": "180.87.12.98", "city": "Penang Subsea Cable Branch", "country": "Malaysia", "country_code": "MY", "lat": 5.4164, "lon": 100.3327, "asn": "AS4755 Submarine Cable System", "base_rtt": 38.2},
    {"ip": "202.160.240.11", "city": "Singapore Equinix SG1", "country": "Singapore", "country_code": "SG", "lat": 1.3521, "lon": 103.8198, "asn": "AS24482 Equinix Singapore Hub", "base_rtt": 52.1},
    {"ip": "62.115.112.5", "city": "Hong Kong HKIX", "country": "Hong Kong", "country_code": "HK", "lat": 22.3193, "lon": 114.1694, "asn": "AS1299 Arelion Global Backbone", "base_rtt": 78.4},
    {"ip": "129.250.3.44", "city": "Tokyo Equinix TY2", "country": "Japan", "country_code": "JP", "lat": 35.6762, "lon": 139.6503, "asn": "AS2914 NTT America / Pacific Crossing (PC-1)", "base_rtt": 112.8},
    {"ip": "129.250.2.19", "city": "Mid-Pacific Transoceanic Cable", "country": "Pacific Ocean", "country_code": "OC", "lat": 25.0000, "lon": -170.0000, "asn": "FASTER Transpacific Optical Network", "base_rtt": 145.2},
    {"ip": "4.69.152.1", "city": "San Jose BBP", "country": "United States", "country_code": "US", "lat": 37.3382, "lon": -121.8863, "asn": "AS3356 Lumen Technologies", "base_rtt": 172.6},
    {"ip": "142.250.160.1", "city": "Mountain View HQ", "country": "United States", "country_code": "US", "lat": 37.4056, "lon": -122.0775, "asn": "AS15169 Google LLC Edge Cluster", "base_rtt": 178.9},
]


class PacketTracer:
    """Wire-level network packet tracer with raw socket, system, and simulated backbones."""

    def __init__(self, mode: str = "auto"):
        self.mode = mode
        self.resolver = GeoIPResolver()
        self.raw_available = self._check_raw_socket()

    def _check_raw_socket(self) -> bool:
        """Verifies if the process has permissions to create raw AF_INET/SOCK_RAW sockets."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.close()
            return True
        except (PermissionError, OSError):
            return False

    def _resolve_target(self, target: str) -> str:
        """Resolves target hostname to IPv4 address with security validation."""
        target = validate_target(target)
        try:
            return socket.gethostbyname(target)
        except socket.gaierror as e:
            raise ValueError(f"Could not resolve target host '{target}': {e}")

    def trace(
        self,
        target: str,
        max_hops: int = 20,
        timeout: float = 1.5,
        inter_packet_delay: float = 0.05,
        on_hop: Optional[Callable[[Hop], None]] = None,
    ) -> TelemetryResult:
        """Executes a trace across network hops with live callbacks."""
        target = validate_target(target)
        max_hops = validate_hops(max_hops)
        inter_packet_delay = validate_delay(inter_packet_delay)

        if self.mode == "simulated" or (self.mode == "auto" and not self.raw_available and not self._has_system_traceroute()):
            return self._trace_simulated(target, max_hops, on_hop)

        if self.raw_available and self.mode in ("auto", "raw"):
            return self._trace_raw_socket(target, max_hops, timeout, inter_packet_delay, on_hop)

        # Fallback to system traceroute execution
        return self._trace_system_fallback(target, max_hops, timeout, on_hop)

    def _trace_simulated(
        self,
        target: str,
        max_hops: int,
        on_hop: Optional[Callable[[Hop], None]] = None,
    ) -> TelemetryResult:
        """Generates realistic telemetry for testing and instant visualization."""
        dest_ip = "142.250.160.1" if "google" in target else ("1.1.1.1" if "cloudflare" in target else "8.8.8.8")
        hops: List[Hop] = []
        start_time = time.time()
        prev_rtt = 0.0

        num_hops = min(len(SIMULATED_HOPS_DATA), max_hops)
        for i in range(num_hops):
            raw = SIMULATED_HOPS_DATA[i]
            is_dest = (i == num_hops - 1)
            # Add microsecond jitter variance
            jitter_variance = ((hash(f"{target}-{i}") % 30) - 15) / 10.0
            rtt = max(1.0, raw["base_rtt"] + jitter_variance)
            jitter = abs(rtt - prev_rtt) if prev_rtt > 0 else 0.0
            prev_rtt = rtt

            hop = Hop(
                hop_num=i + 1,
                ip=dest_ip if is_dest else raw["ip"],
                rtt_ms=round(rtt, 2),
                jitter_ms=round(jitter, 2),
                city=raw["city"],
                country=raw["country"],
                country_code=raw["country_code"],
                lat=raw["lat"],
                lon=raw["lon"],
                asn=raw["asn"],
                is_destination=is_dest,
                protocol="ICMP/Echo",
            )
            hops.append(hop)
            if on_hop:
                on_hop(hop)
            time.sleep(0.04)

        total_time = (time.time() - start_time) * 1000
        return TelemetryResult(
            target=target,
            destination_ip=dest_ip,
            hops=hops,
            total_time_ms=round(total_time, 2),
            reached_destination=True,
        )

    def _trace_raw_socket(
        self,
        target: str,
        max_hops: int,
        timeout: float,
        inter_packet_delay: float,
        on_hop: Optional[Callable[[Hop], None]] = None,
    ) -> TelemetryResult:
        """Executes ICMP TTL stepping via raw AF_INET/SOCK_RAW sockets."""
        dest_ip = self._resolve_target(target)
        hops: List[Hop] = []
        reached_destination = False
        start_time = time.time()
        prev_rtt = 0.0

        for ttl in range(1, max_hops + 1):
            hop_ip = None
            rtt_ms = None
            timed_out = False

            # Create raw ICMP send & receive sockets
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            recv_sock.settimeout(timeout)
            recv_sock.bind(("", 0))

            packet_obj = ICMPPacket(sequence=ttl)
            packet_bytes = packet_obj.serialize()

            t_send = time.perf_counter()
            try:
                send_sock.sendto(packet_bytes, (dest_ip, 0))
                ready = select.select([recv_sock], [], [], timeout)
                if ready[0]:
                    recv_data, addr = recv_sock.recvfrom(1024)
                    t_recv = time.perf_counter()
                    hop_ip = addr[0]
                    rtt_ms = (t_recv - t_send) * 1000
                else:
                    timed_out = True
            except socket.timeout:
                timed_out = True
            except OSError:
                timed_out = True
            finally:
                send_sock.close()
                recv_sock.close()

            if timed_out or not hop_ip:
                hop = Hop(
                    hop_num=ttl,
                    ip=None,
                    rtt_ms=None,
                    jitter_ms=None,
                    timed_out=True,
                )
            else:
                geo = self.resolver.resolve(hop_ip)
                is_dest = (hop_ip == dest_ip)
                jitter = abs(rtt_ms - prev_rtt) if prev_rtt > 0 else 0.0
                prev_rtt = rtt_ms

                hop = Hop(
                    hop_num=ttl,
                    ip=hop_ip,
                    rtt_ms=round(rtt_ms, 2),
                    jitter_ms=round(jitter, 2),
                    city=geo.get("city", "Unknown"),
                    country=geo.get("country", "Unknown"),
                    country_code=geo.get("country_code", "--"),
                    lat=geo.get("lat", 0.0),
                    lon=geo.get("lon", 0.0),
                    asn=geo.get("asn", "Unknown"),
                    is_destination=is_dest,
                    protocol="ICMP/Echo",
                )
                if is_dest:
                    reached_destination = True

            hops.append(hop)
            if on_hop:
                on_hop(hop)

            if reached_destination:
                break

            time.sleep(inter_packet_delay)

        total_time = (time.time() - start_time) * 1000
        return TelemetryResult(
            target=target,
            destination_ip=dest_ip,
            hops=hops,
            total_time_ms=round(total_time, 2),
            reached_destination=reached_destination,
        )

    def _has_system_traceroute(self) -> bool:
        """Checks if system traceroute or tracepath utility is installed."""
        for cmd in ["traceroute", "tracepath"]:
            try:
                subprocess.run([cmd, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
            except (FileNotFoundError, PermissionError):
                continue
        return False

    def _trace_system_fallback(
        self,
        target: str,
        max_hops: int,
        timeout: float,
        on_hop: Optional[Callable[[Hop], None]] = None,
    ) -> TelemetryResult:
        """Parses output from system traceroute or tracepath when unprivileged."""
        dest_ip = self._resolve_target(target)
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(int(timeout)), dest_ip]

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except FileNotFoundError:
            return self._trace_simulated(target, max_hops, on_hop)

        hops: List[Hop] = []
        reached_dest = False
        start_time = time.time()
        prev_rtt = 0.0

        for line in proc.stdout:
            line = line.strip()
            if not line or line.startswith("traceroute"):
                continue

            parts = line.split()
            if len(parts) >= 2 and parts[0].isdigit():
                hop_num = int(parts[0])
                if parts[1] == "*":
                    hop = Hop(hop_num=hop_num, timed_out=True)
                else:
                    ip = parts[1]
                    # Parse RTT ms
                    rtt_match = re.search(r"([\d\.]+)\s*ms", line)
                    rtt_ms = float(rtt_match.group(1)) if rtt_match else 10.0
                    jitter = abs(rtt_ms - prev_rtt) if prev_rtt > 0 else 0.0
                    prev_rtt = rtt_ms

                    geo = self.resolver.resolve(ip)
                    is_dest = (ip == dest_ip)
                    if is_dest:
                        reached_dest = True

                    hop = Hop(
                        hop_num=hop_num,
                        ip=ip,
                        rtt_ms=round(rtt_ms, 2),
                        jitter_ms=round(jitter, 2),
                        city=geo.get("city", "Unknown"),
                        country=geo.get("country", "Unknown"),
                        country_code=geo.get("country_code", "--"),
                        lat=geo.get("lat", 0.0),
                        lon=geo.get("lon", 0.0),
                        asn=geo.get("asn", "Unknown"),
                        is_destination=is_dest,
                    )

                hops.append(hop)
                if on_hop:
                    on_hop(hop)

        proc.wait()
        total_time = (time.time() - start_time) * 1000
        return TelemetryResult(
            target=target,
            destination_ip=dest_ip,
            hops=hops,
            total_time_ms=round(total_time, 2),
            reached_destination=reached_dest,
        )
