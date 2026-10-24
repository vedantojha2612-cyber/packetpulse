"""PacketPulse Web HUD Server: REST API & 3D WebGL Earth Visualizer."""

from __future__ import annotations
import http.server
import json
import os
import socketserver
import sys
import urllib.parse
from typing import Dict, Any

from .engine import PacketPulse
from .security import validate_target, validate_hops, validate_delay, validate_mode

WEB_DIR = os.path.join(os.path.dirname(__file__), "..", "web")
if not os.path.exists(WEB_DIR):
    WEB_DIR = os.path.join(os.path.dirname(__file__), "web")

PRESET_TARGETS = [
    {"name": "Google DNS (Mountain View)", "target": "8.8.8.8", "region": "US West"},
    {"name": "Cloudflare Edge (San Francisco)", "target": "1.1.1.1", "region": "US West"},
    {"name": "Tokyo Equinix IX", "target": "tokyo.packetpulse.internal", "region": "Asia East"},
    {"name": "London Telehouse", "target": "london.packetpulse.internal", "region": "Europe West"},
    {"name": "Frankfurt DE-CIX", "target": "frankfurt.packetpulse.internal", "region": "Europe Central"},
    {"name": "Sydney Global Transit", "target": "sydney.packetpulse.internal", "region": "Oceania"},
]


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Multi-threaded HTTP server for high-concurrency Web HUD and REST endpoints."""
    daemon_threads = True
    allow_reuse_address = True


class PacketPulseHTTPHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP handler serving the WebGL HUD and REST APIs with security hardening."""

    def __init__(*args, **kwargs):
        self = args[0]
        super(PacketPulseHTTPHandler, self).__init__(*args, directory=WEB_DIR, **kwargs)

    def end_headers(self):
        """Inject OWASP security response headers."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:;"
        )
        super().end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/api/presets":
            self._send_json(PRESET_TARGETS)
            return

        if path == "/api/trace":
            raw_target = query.get("target", ["google.com"])[0]
            raw_mode = query.get("mode", ["simulated"])[0]
            raw_hops = query.get("max_hops", ["18"])[0]
            raw_delay = query.get("delay", ["0.05"])[0]

            # Input validation and sanitization
            try:
                target = validate_target(raw_target)
            except ValueError as ve:
                self._send_json({"error": f"Invalid target: {str(ve)}"}, status=400)
                return

            mode = validate_mode(raw_mode, default="simulated")
            max_hops = validate_hops(raw_hops, default=18)
            delay = validate_delay(raw_delay, default=0.05)

            try:
                engine = PacketPulse(mode=mode, hop_delay=delay)
                telemetry = engine.trace(target=target, max_hops=max_hops, timeout=1.2)
                self._send_json(telemetry.to_dict())
            except Exception as e:
                self._send_json({"error": "Failed to complete trace request"}, status=500)
            return

        if path == "/api/status":
            self._send_json({
                "status": "online",
                "service": "PacketPulse 3D WebGL Telemetry",
                "engine_version": "0.2.0",
                "security_hardened": True,
            })
            return

        # Serve static files securely from WEB_DIR
        super().do_GET()

    def _send_json(self, data: Any, status: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Silence verbose standard logging
        pass


def start_web_server(port: int = 8080, host: str = "0.0.0.0", open_browser: bool = False):
    """Launch the Web HUD HTTP server."""
    with ThreadedHTTPServer((host, port), PacketPulseHTTPHandler) as httpd:
        print(f"\033[92m✔ PacketPulse 3D WebGL HUD active on http://localhost:{port}\033[0m")
        print(f"\033[90mPress Ctrl+C to terminate web server.\033[0m")
        if open_browser:
            import webbrowser
            webbrowser.open(f"http://localhost:{port}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down web server.")


if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    start_web_server(port=p)
