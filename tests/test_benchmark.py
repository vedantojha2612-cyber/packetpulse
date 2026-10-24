"""Unit and regression tests for PerformanceBenchmarker."""

import unittest
from packetpulse.benchmark import PerformanceBenchmarker, percentile


class TestPerformanceBenchmarker(unittest.TestCase):
    """Verify performance benchmarking, percentile calculations, and stress tests."""

    def setUp(self):
        self.bm = PerformanceBenchmarker(verbose=False)

    def test_percentile_calculation(self):
        data = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0]
        self.assertEqual(percentile(data, 50), 55.0)
        self.assertAlmostEqual(percentile(data, 90), 91.0, places=1)
        self.assertAlmostEqual(percentile(data, 99), 99.1, places=1)

    def test_protocols_micro_benchmark(self):
        res = self.bm.benchmark_protocols(iterations=500)
        self.assertIn("checksum_ops_sec", res)
        self.assertIn("packet_build_ops_sec", res)
        self.assertIn("geoip_cache_ops_sec", res)
        self.assertGreater(res["checksum_ops_sec"], 10000)

    def test_concurrency_stress_benchmark(self):
        res = self.bm.benchmark_concurrency(concurrency_levels=[1, 5], requests_per_level=10)
        self.assertIn("5_workers", res)
        tier = res["5_workers"]
        self.assertEqual(tier["errors"], 0)
        self.assertLess(tier["p95_ms"], 50.0)

    def test_memory_leak_detection(self):
        res = self.bm.benchmark_memory_leaks(test_runs=15)
        self.assertFalse(res["leak_detected"])
        self.assertLess(res["net_leak_bytes"], 50000)

    def test_frontend_bundle_profiling(self):
        res = self.bm.benchmark_frontend_bundles()
        self.assertIn("assets", res)
        self.assertIn("index.html", res["assets"])
        self.assertGreater(res["overall_compression_pct"], 50.0)


if __name__ == "__main__":
    unittest.main()
