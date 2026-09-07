"""
Unit tests for hash algorithm speed benchmarking module.
"""

import json
import unittest
import tempfile
from pathlib import Path

from cyberhash.benchmark.engine import (
    benchmark_algorithm,
    run_benchmark,
    BenchmarkResultItem,
    FAST_BENCHMARK_ALGORITHMS,
    CRYPT_ALGORITHMS
)


class TestBenchmarkEngine(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_benchmark_fast_algorithm(self):
        result = benchmark_algorithm("MD5", duration_seconds=0.1)

        self.assertIsInstance(result, BenchmarkResultItem)
        self.assertEqual(result.algorithm, "MD5")
        self.assertGreater(result.operations, 0)
        self.assertGreater(result.elapsed, 0.0)
        self.assertGreater(result.ops_per_sec, 0.0)

    def test_benchmark_crypt_algorithm_raises(self):
        # BCRYPT must never be benchmarked using raw hashlib assumptions
        with self.assertRaises(ValueError):
            benchmark_algorithm("BCRYPT", duration_seconds=0.1)

    def test_run_benchmark_single_algo(self):
        results = run_benchmark(target_algo="SHA256", duration_per_algo=0.1)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].algorithm, "SHA256")
        self.assertGreater(results[0].operations, 0)

    def test_run_benchmark_all_fast_algos(self):
        # Short duration per algorithm for testing speed
        results = run_benchmark(duration_per_algo=0.02)

        self.assertGreater(len(results), 0)
        algo_names = [r.algorithm for r in results]
        self.assertIn("MD5", algo_names)
        self.assertIn("SHA256", algo_names)

    def test_run_benchmark_crypt_algo_skipped(self):
        results = run_benchmark(target_algo="BCRYPT", duration_per_algo=0.1)
        self.assertEqual(len(results), 0)

    def test_run_benchmark_export(self):
        export_file = self.dir_path / "bench.json"
        results = run_benchmark(
            target_algo="MD5",
            duration_per_algo=0.1,
            export_path=str(export_file)
        )

        self.assertEqual(len(results), 1)
        self.assertTrue(export_file.exists())

        with open(export_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["algorithm"], "MD5")
        self.assertIn("ops_per_sec", data[0])


if __name__ == "__main__":
    unittest.main()
