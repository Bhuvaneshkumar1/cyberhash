"""
Unit tests for wordlist analysis and statistics module.
"""

import gzip
import unittest
import tempfile
from pathlib import Path

from cyberhash.wordlists.statistics import get_wordlist_info, get_wordlist_stats


class TestWordlistStatistics(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_get_wordlist_info_plain_text(self):
        wl_file = self.dir_path / "sample.txt"
        # Content: 6 total lines: 3 words, 1 duplicate, 2 empty lines
        lines = [
            "password123",  # mixed, len 11
            "123456",       # numeric-only, len 6
            "",             # empty line 1
            "password123",  # duplicate mixed, len 11
            "admin",        # alphabetic-only, len 5
            "",             # empty line 2
        ]
        wl_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        info = get_wordlist_info(wl_file)

        self.assertTrue(info["exists"])
        self.assertEqual(info["line_count"], 6)
        self.assertEqual(info["empty_lines"], 2)
        self.assertEqual(info["unique_count"], 3)  # password123, 123456, admin
        self.assertEqual(info["duplicate_count"], 1)
        self.assertEqual(info["min_length"], 5)   # "admin"
        self.assertEqual(info["max_length"], 11)  # "password123"
        self.assertEqual(info["numeric_only_count"], 1)     # "123456"
        self.assertEqual(info["alphabetic_only_count"], 1)  # "admin"
        self.assertEqual(info["mixed_count"], 2)            # "password123" x 2
        self.assertFalse(info["is_compressed"])

        # Average length: (11 + 6 + 11 + 5) / 4 = 33 / 4 = 8.25
        self.assertEqual(info["average_length"], 8.25)

    def test_get_wordlist_info_gzip(self):
        gz_file = self.dir_path / "sample.txt.gz"
        lines = ["123", "abc", "a1b2"]
        with gzip.open(gz_file, "wt", encoding="utf-8") as f:
            f.write("\n".join(lines))

        info = get_wordlist_info(gz_file)

        self.assertTrue(info["exists"])
        self.assertTrue(info["is_compressed"])
        self.assertEqual(info["line_count"], 3)
        self.assertEqual(info["unique_count"], 3)
        self.assertEqual(info["duplicate_count"], 0)
        self.assertEqual(info["numeric_only_count"], 1)
        self.assertEqual(info["alphabetic_only_count"], 1)
        self.assertEqual(info["mixed_count"], 1)

    def test_get_wordlist_info_nonexistent_file(self):
        missing_file = self.dir_path / "nonexistent.txt"
        info = get_wordlist_info(missing_file)

        self.assertFalse(info["exists"])
        self.assertEqual(info["line_count"], 0)
        self.assertEqual(info["file_size"], 0)


if __name__ == "__main__":
    unittest.main()
