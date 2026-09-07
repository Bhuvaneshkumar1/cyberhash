"""
Comprehensive unit tests for Rule Engine v2.
"""

import tempfile
import unittest
from pathlib import Path

from cyberhash.attacks.rules import (
    RuleEngine,
    transform_lowercase,
    transform_uppercase,
    transform_capitalize,
    transform_titlecase,
    transform_reverse,
    transform_append_digits,
    transform_prepend_digits,
    transform_append_symbols,
    transform_prepend_symbols,
    transform_leetspeak,
    transform_substitute,
    transform_year_suffix,
    transform_numeric_suffixes,
    transform_password_suffixes
)


class TestRuleEngineV2(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. Tests for every individual transformation rule
    def test_transform_lowercase(self):
        self.assertEqual(transform_lowercase("PASSWORD"), "password")

    def test_transform_uppercase(self):
        self.assertEqual(transform_uppercase("password"), "PASSWORD")

    def test_transform_capitalize(self):
        self.assertEqual(transform_capitalize("password"), "Password")

    def test_transform_titlecase(self):
        self.assertEqual(transform_titlecase("hello world"), "Hello World")

    def test_transform_reverse(self):
        self.assertEqual(transform_reverse("password"), "drowssap")

    def test_transform_append_digits(self):
        res = transform_append_digits("password")
        self.assertIn("password123", res)

    def test_transform_prepend_digits(self):
        res = transform_prepend_digits("password")
        self.assertIn("123password", res)

    def test_transform_append_symbols(self):
        res = transform_append_symbols("password")
        self.assertIn("password!", res)

    def test_transform_prepend_symbols(self):
        res = transform_prepend_symbols("password")
        self.assertIn("!password", res)

    def test_transform_leetspeak(self):
        res = transform_leetspeak("password")
        self.assertIn("p@$$w0rd", res)

    def test_transform_substitute(self):
        res = transform_substitute("password")
        self.assertIn("p@ssword", res)

    def test_transform_year_suffix(self):
        res = transform_year_suffix("password")
        self.assertIn("password2024", res)

    def test_transform_numeric_suffixes(self):
        res = transform_numeric_suffixes("password")
        self.assertIn("password123", res)

    def test_transform_password_suffixes(self):
        res = transform_password_suffixes("password")
        self.assertIn("password123!", res)

    # 2. Tests for rule combinations
    def test_rule_combination_depth_2(self):
        engine = RuleEngine(depth=2)
        mutations = engine.generate_mutations("password")
        self.assertIn("Password", mutations)
        self.assertTrue(any("Password" in m for m in mutations))

    # 3. Tests ensuring duplicate candidates are removed & original not duplicated
    def test_candidate_deduplication(self):
        engine = RuleEngine(depth=1)
        mutations = engine.generate_mutations("password")
        self.assertNotIn("password", mutations)  # Original word excluded
        self.assertEqual(len(mutations), len(set(mutations)))  # Fully unique

    # 4. Tests ensuring rule-depth limits work
    def test_rule_depth_limits(self):
        engine1 = RuleEngine(depth=1)
        res1 = engine1.generate_mutations("password")

        engine2 = RuleEngine(depth=2)
        res2 = engine2.generate_mutations("password")

        self.assertGreater(len(res2), len(res1))

    # 5. Tests for rules file parsing and error handling
    def test_rules_file_valid(self):
        rules_file = self.temp_path / "valid_rules.txt"
        rules_file.write_text("lowercase\ncapitalize\nleetspeak\n")

        engine = RuleEngine(rules_file=rules_file)
        self.assertEqual(engine.enabled_rule_names, ["lowercase", "capitalize", "leetspeak"])

    def test_rules_file_invalid_path(self):
        invalid_path = self.temp_path / "non_existent.txt"
        with self.assertRaises(ValueError):
            RuleEngine(rules_file=invalid_path)

    def test_rules_file_empty(self):
        empty_file = self.temp_path / "empty_rules.txt"
        empty_file.write_text("# Only comments\n")
        with self.assertRaises(ValueError):
            RuleEngine(rules_file=empty_file)


if __name__ == "__main__":
    unittest.main()
