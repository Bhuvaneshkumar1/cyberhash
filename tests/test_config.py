"""
Unit tests for CyberHash platform-independent configuration management system.
"""

import json
import unittest
import tempfile
from pathlib import Path

from cyberhash.config import (
    CyberHashConfig,
    load_config,
    save_config,
)


class TestConfigSystem(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_default_config_instance(self):
        cfg = CyberHashConfig()
        self.assertEqual(cfg.threads, 4)
        self.assertEqual(cfg.rule_depth, 1)
        self.assertEqual(cfg.output_format, "table")
        self.assertIsNone(cfg.default_wordlist)
        self.assertFalse(cfg.quiet)
        self.assertFalse(cfg.verbose)
        self.assertTrue(cfg.logging)

    def test_load_missing_config_returns_default(self):
        missing_file = self.dir_path / "nonexistent.json"
        cfg = load_config(missing_file)

        # Missing config is normal and returns default
        self.assertEqual(cfg.threads, 4)
        self.assertEqual(cfg.rule_depth, 1)

    def test_load_valid_config_json(self):
        config_file = self.dir_path / "cyberhash.json"
        valid_data = {
            "threads": 8,
            "rule_depth": 3,
            "output_format": "json",
            "quiet": True,
            "verbose": False,
            "logging": False,
            "default_wordlist": "/tmp/custom_words.txt"
        }
        config_file.write_text(json.dumps(valid_data), encoding="utf-8")

        cfg = load_config(config_file)
        self.assertEqual(cfg.threads, 8)
        self.assertEqual(cfg.rule_depth, 3)
        self.assertEqual(cfg.output_format, "json")
        self.assertTrue(cfg.quiet)
        self.assertFalse(cfg.logging)
        self.assertEqual(cfg.default_wordlist, "/tmp/custom_words.txt")

    def test_load_invalid_json_raises_clear_error(self):
        config_file = self.dir_path / "invalid.json"
        config_file.write_text("{broken_json: True, missing_quotes}", encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            load_config(config_file)
        self.assertIn("Invalid JSON", str(ctx.exception))

    def test_load_invalid_option_types_raises_error(self):
        config_file = self.dir_path / "bad_types.json"
        config_file.write_text(json.dumps({"threads": -5}), encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            load_config(config_file)
        self.assertIn("threads", str(ctx.exception))

    def test_save_config_atomic(self):
        config_file = self.dir_path / "saved_config.json"
        cfg = CyberHashConfig(threads=16, rule_depth=4, verbose=True)

        success = save_config(cfg, config_file)
        self.assertTrue(success)
        self.assertTrue(config_file.exists())

        loaded_cfg = load_config(config_file)
        self.assertEqual(loaded_cfg.threads, 16)
        self.assertEqual(loaded_cfg.rule_depth, 4)
        self.assertTrue(loaded_cfg.verbose)


if __name__ == "__main__":
    unittest.main()
