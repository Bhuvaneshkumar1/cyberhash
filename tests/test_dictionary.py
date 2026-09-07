"""
Unit tests for streaming dictionary attack engine and AttackResult.
"""

import tempfile
import unittest
from pathlib import Path
from cyberhash.attacks.dictionary import (
    AttackResult,
    stream_wordlists,
    run_dictionary_attack
)


class TestDictionaryAttack(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_attack_result_structure(self):
        res = AttackResult(found=True, candidate="password", algorithm="MD5", tested=10, elapsed=0.5)
        self.assertTrue(res.found)
        self.assertEqual(res.candidate, "password")
        self.assertEqual(res.algorithm, "MD5")
        self.assertEqual(res.tested, 10)
        self.assertEqual(res.elapsed, 0.5)

    def test_stream_wordlists_single(self):
        f1 = self.temp_path / "w1.txt"
        f1.write_text("apple\nbanana\ncherry\n")

        words = list(stream_wordlists([f1]))
        self.assertEqual(words, ["apple", "banana", "cherry"])

    def test_stream_wordlists_multiple_and_deduplicate(self):
        f1 = self.temp_path / "w1.txt"
        f1.write_text("apple\nbanana\n")

        f2 = self.temp_path / "w2.txt"
        f2.write_text("banana\ncherry\ndate\n")

        words = list(stream_wordlists([f1, f2], deduplicate=True))
        self.assertEqual(words, ["apple", "banana", "cherry", "date"])

    def test_run_dictionary_attack_match(self):
        # target: md5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
        f1 = self.temp_path / "wl.txt"
        f1.write_text("admin\npassword\nwelcome\n")

        result = run_dictionary_attack(
            wordlist_paths=[f1],
            target_hash="5f4dcc3b5aa765d61d8327deb882cf99",
            algos=["MD5"],
            threads=2
        )

        self.assertTrue(result.found)
        self.assertEqual(result.candidate, "password")
        self.assertEqual(result.algorithm, "MD5")
        self.assertGreater(result.tested, 0)

    def test_run_dictionary_attack_no_match(self):
        f1 = self.temp_path / "wl.txt"
        f1.write_text("admin\nwelcome\n")

        result = run_dictionary_attack(
            wordlist_paths=[f1],
            target_hash="5f4dcc3b5aa765d61d8327deb882cf99",
            algos=["MD5"],
            threads=2
        )

        self.assertFalse(result.found)
        self.assertIsNone(result.candidate)


if __name__ == "__main__":
    unittest.main()
