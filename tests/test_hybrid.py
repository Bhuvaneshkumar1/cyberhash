"""
Unit tests for hybrid dictionary + mask attack engine.
"""

import tempfile
import unittest
from pathlib import Path
from cyberhash.attacks.hybrid import generate_hybrid_candidates, run_hybrid_attack


class TestHybridAttack(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_generate_hybrid_candidates_suffix(self):
        cands = list(generate_hybrid_candidates("pass", "?d?d", mode="suffix", max_per_word=100))
        self.assertEqual(len(cands), 100)
        self.assertIn("pass00", cands)
        self.assertIn("pass99", cands)

    def test_generate_hybrid_candidates_prefix(self):
        cands = list(generate_hybrid_candidates("word", "?d", mode="prefix", max_per_word=10))
        self.assertEqual(len(cands), 10)
        self.assertIn("0word", cands)
        self.assertIn("9word", cands)

    def test_generate_hybrid_candidates_max_limit(self):
        cands = list(generate_hybrid_candidates("word", "?d?d", mode="suffix", max_per_word=5))
        self.assertEqual(len(cands), 5)

    def test_run_hybrid_attack_suffix_match(self):
        f1 = self.temp_path / "wl.txt"
        f1.write_text("admin\nwelcome\n")

        # md5("admin12") = 1844156d4166d94387f1a4ad031ca5fa
        res = run_hybrid_attack(
            wordlist_paths=[f1],
            mask="?d?d",
            target_hash="1844156d4166d94387f1a4ad031ca5fa",
            algos=["MD5"],
            mode="suffix",
            max_per_word=100
        )

        self.assertTrue(res.found)
        self.assertEqual(res.candidate, "admin12")
        self.assertEqual(res.algorithm, "MD5")

    def test_run_hybrid_attack_prefix_match(self):
        f1 = self.temp_path / "wl.txt"
        f1.write_text("admin\n")

        # md5("12admin") = f8def8bcecb2e7925a2b42d60d202deb
        res = run_hybrid_attack(
            wordlist_paths=[f1],
            mask="?d?d",
            target_hash="f8def8bcecb2e7925a2b42d60d202deb",
            algos=["MD5"],
            mode="prefix",
            max_per_word=100
        )

        self.assertTrue(res.found)
        self.assertEqual(res.candidate, "12admin")


if __name__ == "__main__":
    unittest.main()
