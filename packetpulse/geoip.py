"""In-memory GeoIP and Autonomous System (ASN) coordinate resolution engine."""

from __future__ import annotations
import json
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

# Offline seed cache for major global backbones and cloud edge infrastructures
SEED_GEO_TABLE: Dict[str, Dict[str, Any]] = {
    # Public Anycast DNS / CDNs
    "1.1.1.1": {"country": "Australia", "country_code": "AU", "city": "Sydney", "lat": -33.8688, "lon": 151.2093, "asn": "AS13335 Cloudflare, Inc."},
    "1.0.0.1": {"country": "Australia", "country_code": "AU", "city": "Sydney", "lat": -33.8688, "lon": 151.2093, "asn": "AS13335 Cloudflare, Inc."},
    "8.8.8.8": {"country": "United States", "country_code": "US", "city": "Mountain View", "lat": 37.4056, "lon": -122.0775, "asn": "AS15169 Google LLC"},
    "8.8.4.4": {"country": "United States", "country_code": "US", "city": "Mountain View", "lat": 37.4056, "lon": -122.0775, "asn": "AS15169 Google LLC"},
    "9.9.9.9": {"country": "United States", "country_code": "US", "city": "Berkeley", "lat": 37.8715, "lon": -122.2730, "asn": "AS19281 Quad9"},
    "208.67.222.222": {"country": "United States", "country_code": "US", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194, "asn": "AS36692 OpenDNS LLC"},

    # Global Tier-1 Telecommunications Hubs & Landing Points
    "62.115.0.0": {"country": "Sweden", "country_code": "SE", "city": "Stockholm", "lat": 59.3293, "lon": 18.0686, "asn": "AS1299 Arelion (Telia Carrier)"},
    "129.250.0.0": {"country": "Japan", "country_code": "JP", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503, "asn": "AS2914 NTT Communications"},
    "180.87.0.0": {"country": "India", "country_code": "IN", "city": "Mumbai", "lat": 18.9220, "lon": 72.8347, "asn": "AS4755 Tata Communications"},
    "154.54.0.0": {"country": "United States", "country_code": "US", "city": "Washington D.C.", "lat": 38.9072, "lon": -77.0369, "asn": "AS174 Cogent Communications"},
    "4.69.0.0": {"country": "United States", "country_code": "US", "city": "Denver", "lat": 39.7392, "lon": -104.9903, "asn": "AS3356 Lumen Technologies (Level 3)"},
    "195.66.224.0": {"country": "United Kingdom", "country_code": "GB", "city": "London", "lat": 51.5074, "lon": -0.1278, "asn": "AS13030 LINX Internet Exchange"},
    "80.81.192.0": {"country": "Germany", "country_code": "DE", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "asn": "AS6695 DE-CIX Frankfurt"},
    "202.160.240.0": {"country": "Singapore", "country_code": "SG", "city": "Singapore", "lat": 1.3521, "lon": 103.8198, "asn": "AS24482 Equinix Singapore"},
}


class GeoIPResolver:
    """High-speed in-memory cached GeoIP and ASN resolution engine."""

    def __init__(self, offline_mode: bool = False):
        self.offline_mode = offline_mode
        self._cache: Dict[str, Dict[str, Any]] = dict(SEED_GEO_TABLE)

    def is_private_ip(self, ip: str) -> bool:
        """Returns True if IP is in RFC 1918 or Loopback private address spaces."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            b0, b1 = int(parts[0]), int(parts[1])
            if b0 == 10:
                return True
            if b0 == 172 and (16 <= b1 <= 31):
                return True
            if b0 == 192 and b1 == 168:
                return True
            if b0 == 127:
                return True
        except ValueError:
            return False
        return False

    def resolve(self, ip: str) -> Dict[str, Any]:
        """Resolves an IPv4 address to its geographic coordinates and ASN info."""
        if not ip or ip == "*":
            return {"country": "Unknown", "country_code": "--", "city": "Unknown", "lat": 0.0, "lon": 0.0, "asn": "Unknown"}

        if self.is_private_ip(ip):
            return {
                "country": "Local LAN",
                "country_code": "LAN",
                "city": "Private Gateway",
                "lat": 28.6139,
                "lon": 77.2090,
                "asn": "RFC 1918 Private Network",
            }

        if ip in self._cache:
            return self._cache[ip]

        # Check prefix match in seed table
        ip_parts = ip.split(".")
        if len(ip_parts) == 4:
            prefix_2 = f"{ip_parts[0]}.{ip_parts[1]}.0.0"
            if prefix_2 in self._cache:
                return self._cache[prefix_2]

        if self.offline_mode:
            return {
                "country": "Global Internet",
                "country_code": "NET",
                "city": "Transit Hop",
                "lat": 30.0,
                "lon": -20.0,
                "asn": "Tier-1 Transit Backbone",
            }

        # Query lightweight unauthenticated public GeoIP endpoint
        try:
            req = urllib.request.Request(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,as",
                headers={"User-Agent": "PacketPulse/1.0"},
            )
            with urllib.request.urlopen(req, timeout=1.2) as response:
                data = json.loads(response.read().decode("utf-8"))
                if data.get("status") == "success":
                    result = {
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", "--"),
                        "city": data.get("city", "Unknown"),
                        "lat": float(data.get("lat", 0.0)),
                        "lon": float(data.get("lon", 0.0)),
                        "asn": data.get("as", "Unknown ASN"),
                    }
                    self._cache[ip] = result
                    return result
        except Exception:
            pass

        # Fallback coordinate
        fallback = {
            "country": "Transit Backbone",
            "country_code": "NET",
            "city": "Subsea Optical Repeater",
            "lat": 35.0,
            "lon": -40.0,
            "asn": "Global Fiber Route",
        }
        self._cache[ip] = fallback
        return fallback
