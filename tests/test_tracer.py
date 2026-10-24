"""Unit tests for PacketPulse protocols, checksums, and tracer engine using standard unittest."""

import unittest
import struct

from packetpulse.protocols import (
    calculate_checksum,
    build_icmp_echo_packet,
    parse_icmp_response,
    ICMP_ECHO_REQUEST,
    ICMP_TIME_EXCEEDED,
)
from packetpulse.geoip import is_private_ip, resolve_geoip
from packetpulse.models import Hop, RouteTelemetry
from packetpulse.engine import PacketPulse


class TestPacketPulse(unittest.TestCase):

    def test_calculate_checksum(self):
        # Checksum of 0 bytes should be 0xFFFF
        self.assertEqual(calculate_checksum(b"\x00\x00"), 0xFFFF)
        
        # Checksum with odd byte count
        data = b"\x08\x00\x00\x00\x01\x02\x03"
        chk1 = calculate_checksum(data)
        self.assertTrue(0 <= chk1 <= 0xFFFF)

        # Build packet and test RFC 1071 verification (checksum of complete packet is 0)
        packet = build_icmp_echo_packet(identifier=0x1234, seq=1, payload=b"EchoPayload")
        self.assertEqual(calculate_checksum(packet), 0)

    def test_build_icmp_echo_packet(self):
        packet = build_icmp_echo_packet(identifier=1234, seq=42, payload=b"TestData")
        self.assertEqual(len(packet), 8 + len(b"TestData"))
        
        icmp_type, code, chksum, ident, seq = struct.unpack("!BBHHH", packet[:8])
        self.assertEqual(icmp_type, ICMP_ECHO_REQUEST)
        self.assertEqual(code, 0)
        self.assertEqual(ident, 1234)
        self.assertEqual(seq, 42)

    def test_parse_icmp_response(self):
        # Too short
        self.assertEqual(parse_icmp_response(b"\x00" * 10), (-1, -1, None, None))

        # Synthetic IP header (20 bytes) + ICMP Echo Reply (8 bytes)
        ip_header = b"\x45" + (b"\x00" * 19)  # Version 4, IHL 5 (20 bytes)
        icmp_header = struct.pack("!BBHHH", 0, 0, 0, 999, 1)
        raw_packet = ip_header + icmp_header
        
        icmp_type, code, ident, seq = parse_icmp_response(raw_packet)
        self.assertEqual(icmp_type, 0)
        self.assertEqual(code, 0)
        self.assertEqual(ident, 999)
        self.assertEqual(seq, 1)

    def test_is_private_ip(self):
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertTrue(is_private_ip("172.16.0.1"))
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("1.1.1.1"))

    def test_resolve_geoip(self):
        # Public seed IP
        lat, lon, city, country, asn = resolve_geoip("1.1.1.1")
        self.assertEqual(city, "San Francisco")
        self.assertIn("Cloudflare", asn)
        self.assertIsNotNone(lat)
        self.assertIsNotNone(lon)

        # Private IP
        plat, plon, pcity, pcountry, pasn = resolve_geoip("192.168.1.1")
        self.assertTrue("Private" in pcountry or "Internal" in pcity)

    def test_models_to_dict(self):
        hop = Hop(hop_num=1, ip="1.1.1.1", rtt_ms=12.4, city="SF")
        d = hop.to_dict()
        self.assertEqual(d["hop_num"], 1)
        self.assertEqual(d["ip"], "1.1.1.1")
        self.assertEqual(d["rtt_ms"], 12.4)

    def test_engine_simulated_trace(self):
        engine = PacketPulse(mode="simulated")
        telemetry = engine.trace(target="google.com", max_hops=5)
        
        self.assertEqual(len(telemetry.hops), 5)
        self.assertEqual(telemetry.target, "google.com")
        self.assertEqual(telemetry.hops[0].hop_num, 1)
        self.assertEqual(telemetry.hops[0].ip, "192.168.1.1")
        self.assertTrue(telemetry.total_time_ms > 0)


if __name__ == "__main__":
    unittest.main()
