"""Binary wire protocol serialization, RFC 1071 checksums, and raw packet frames."""

from __future__ import annotations
import struct
import os
import time


def internet_checksum(data: bytes) -> int:
    """Calculate the RFC 1071 16-bit one's complement Internet Checksum.

    Handles odd-length byte buffers safely with zero padding.
    """
    if len(data) % 2 != 0:
        data += b"\x00"

    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    checksum = ~checksum & 0xFFFF
    return checksum


class ICMPPacket:
    """ICMP Echo Request (Type 8) frame builder and deserializer."""

    ICMP_ECHO_REQUEST = 8
    ICMP_ECHO_REPLY = 0
    ICMP_TIME_EXCEEDED = 11

    def __init__(self, packet_id: int | None = None, sequence: int = 1, payload: bytes | None = None):
        self.packet_id = (packet_id or (os.getpid() & 0xFFFF)) & 0xFFFF
        self.sequence = sequence & 0xFFFF
        self.payload = payload or (b"PACKETPULSE" + struct.pack("!d", time.time()))

    def serialize(self) -> bytes:
        """Packs ICMP header + payload with valid 16-bit RFC 1071 checksum."""
        # Header without checksum: Type (8), Code (0), Checksum (0), ID, Sequence
        header_dummy = struct.pack("!BBHHH", self.ICMP_ECHO_REQUEST, 0, 0, self.packet_id, self.sequence)
        dummy_packet = header_dummy + self.payload

        chk = internet_checksum(dummy_packet)
        # Re-pack with valid checksum
        header = struct.pack("!BBHHH", self.ICMP_ECHO_REQUEST, 0, chk, self.packet_id, self.sequence)
        return header + self.payload

    @staticmethod
    def parse_reply(data: bytes) -> dict:
        """Unpacks an incoming IPv4 raw packet frame and extracts ICMP payload metadata."""
        if len(data) < 20:
            raise ValueError(f"Packet too short for IPv4 header: {len(data)} bytes")

        # First byte: Version & IHL
        ihl = (data[0] & 0x0F) * 4
        if len(data) < ihl + 8:
            raise ValueError("Buffer truncated: cannot parse ICMP header")

        icmp_raw = data[ihl:ihl + 8]
        icmp_type, icmp_code, checksum, p_id, seq = struct.unpack("!BBHHH", icmp_raw)

        inner_id = p_id
        inner_seq = seq

        # If Time Exceeded (Type 11), the original packet IP+ICMP is appended inside payload
        if icmp_type == 11 and len(data) >= ihl + 8 + 20 + 8:
            inner_ip_offset = ihl + 8
            inner_ihl = (data[inner_ip_offset] & 0x0F) * 4
            inner_icmp_offset = inner_ip_offset + inner_ihl
            if len(data) >= inner_icmp_offset + 8:
                _, _, _, inner_id, inner_seq = struct.unpack("!BBHHH", data[inner_icmp_offset:inner_icmp_offset + 8])

        return {
            "type": icmp_type,
            "code": icmp_code,
            "checksum": checksum,
            "id": inner_id,
            "sequence": inner_seq,
            "payload": data[ihl + 8:],
        }
