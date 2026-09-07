"""
Unit tests for mask attack engine.
"""

import unittest
from cyberhash.attacks.mask import (
    validate_mask,
    calculate_mask_combinations,
    mask_attack_generator,
    run_mask_attack
)


class TestMaskAttack(unittest.TestCase):

    def test_validate_mask_valid(self):
        self.assertTrue(validate_mask("?l?l?l?d?d"))
        self.assertTrue(validate_mask("?u?s?d"))
        self.assertTrue(validate_mask("simple_numeric"))  # Preset
        self.assertTrue(validate_mask("admin?d?d"))

    def test_validate_mask_invalid(self):
        self.assertFalse(validate_mask(""))
        self.assertFalse(validate_mask("?x?y"))
        self.assertFalse(validate_mask("?"))

    def test_calculate_mask_combinations(self):
        self.assertEqual(calculate_mask_combinations("?d?d"), 100)
        self.assertEqual(calculate_mask_combinations("?l"), 26)
        self.assertEqual(calculate_mask_combinations("?u"), 26)
        self.assertEqual(calculate_mask_combinations("?s"), 8)

    def test_mask_attack_generator(self):
        cands = list(mask_attack_generator("?d?d"))
        self.assertEqual(len(cands), 100)
        self.assertIn("00", cands)
        self.assertIn("99", cands)

    def test_run_mask_attack_match(self):
        # md5("12") = c20ad4d76fe97759aa27a0c99bff6710
        res = run_mask_attack("?d?d", "c20ad4d76fe97759aa27a0c99bff6710", ["MD5", "NTLM"])
        self.assertTrue(res.found)
        self.assertEqual(res.candidate, "12")
        self.assertEqual(res.algorithm, "MD5")

    def test_run_mask_attack_no_match(self):
        res = run_mask_attack("?d", "c20ad4d76fe97759aa27a0c99bff6710", ["MD5"])
        self.assertFalse(res.found)


if __name__ == "__main__":
    unittest.main()
