"""
Unit tests for batch hash processing module.
"""

import json
import unittest
import tempfile
from pathlib import Path

from cyberhash.core.batch import run_batch_processing, process_single_hash


class TestBatchProcessing(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

        # Create a sample wordlist
        self.wordlist_file = self.dir_path / "words.txt"
        self.wordlist_file.write_text("hello\npassword\nadmin\nsecret\n123456\n", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_process_single_hash_found(self):
        # MD5 for "hello" = 5d41402abc4b2a76b9719d911017c592
        # Wordlist contains: hello, password, admin, secret, 123456
        md5_hash = "5d41402abc4b2a76b9719d911017c592"
        res = process_single_hash(
            target_hash=md5_hash,
            wordlist_paths=[self.wordlist_file]
        )

        self.assertEqual(res.status, "found")
        self.assertEqual(res.candidate, "hello")
        self.assertEqual(res.algorithm.lower(), "md5")

    def test_process_single_hash_invalid(self):
        res = process_single_hash(
            target_hash="invalid_hash_string!",
            wordlist_paths=[self.wordlist_file]
        )
        self.assertEqual(res.status, "invalid")

    def test_process_single_hash_unsupported(self):
        # 10 chars is valid format hex string, but no supported algorithm matches length 10
        res = process_single_hash(
            target_hash="1234567890",
            wordlist_paths=[self.wordlist_file]
        )
        self.assertEqual(res.status, "unsupported")

    def test_run_batch_processing_file(self):
        hash_file = self.dir_path / "targets.txt"
        hashes = [
            "# Comment line to ignore",
            "",  # empty line to ignore
            "5d41402abc4b2a76b9719d911017c592",  # MD5 of "password" -> found
            "21232f297a57a5a743894a0e4a801fc3",  # MD5 of "admin" -> found
            "00000000000000000000000000000000",  # MD5 -> not found
            "invalid_hash!!!",                  # -> invalid
            "1234567890",                        # -> unsupported
        ]
        hash_file.write_text("\n".join(hashes) + "\n", encoding="utf-8")

        export_json_path = self.dir_path / "batch_out.json"

        results = run_batch_processing(
            hash_file_path=hash_file,
            wordlist_paths=[self.wordlist_file],
            export_path=str(export_json_path)
        )

        self.assertEqual(len(results), 5)
        statuses = [r.status for r in results]
        self.assertEqual(statuses.count("found"), 2)
        self.assertEqual(statuses.count("not_found"), 1)
        self.assertEqual(statuses.count("invalid"), 1)
        self.assertEqual(statuses.count("unsupported"), 1)

        # Verify JSON export
        self.assertTrue(export_json_path.exists())
        with open(export_json_path, "r", encoding="utf-8") as f:
            exported_data = json.load(f)
        self.assertEqual(len(exported_data), 5)


if __name__ == "__main__":
    unittest.main()
