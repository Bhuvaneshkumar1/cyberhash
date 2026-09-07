"""
Unit tests for detector module.
"""

import unittest
from cyberhash.core.detector import (
    validate_hash,
    identify_hash,
    detect_candidates,
    is_crypt_hash
)


class TestDetector(unittest.TestCase):

    def test_validate_hash(self):
        # Hex hashes
        self.assertTrue(validate_hash("5f4dcc3b5aa765d61d8327deb882cf99"))
        self.assertTrue(validate_hash("5F4DCC3B5AA765D61D8327DEB882CF99"))
        # Crypt hashes
        self.assertTrue(validate_hash("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"))
        self.assertTrue(validate_hash("$1$q652Y.Vb$p4K.2H2J12J/Y.E9hQ/M/1"))
        self.assertTrue(validate_hash("$5$rounds=5000$toolongsecret$g.R15D2V2W155X9a79.T2V22X/"))
        self.assertTrue(validate_hash("$6$rounds=5000$toolongsecret$r8/Y1.Y2Z2W155X9a79.T2V22X/"))
        # Invalid
        self.assertFalse(validate_hash("not_a_hash_g!"))

    def test_is_crypt_hash(self):
        self.assertTrue(is_crypt_hash("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"))
        self.assertTrue(is_crypt_hash("$1$salt$hash"))
        self.assertTrue(is_crypt_hash("$5$salt$hash"))
        self.assertTrue(is_crypt_hash("$6$salt$hash"))
        self.assertFalse(is_crypt_hash("5f4dcc3b5aa765d61d8327deb882cf99"))

    def test_identify_hash(self):
        self.assertEqual(identify_hash("5f4dcc3b5aa765d61d8327deb882cf99"), "MD5 / NTLM")
        self.assertEqual(identify_hash("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"), "SHA1")
        self.assertEqual(identify_hash("$2a$10$abcdefghijklmnopqrstuu"), "BCRYPT")
        self.assertEqual(identify_hash("$1$q652Y.Vb$p4K.2H2J12J/Y.E9hQ/M/1"), "MD5CRYPT")

    def test_detect_candidates_ambiguity(self):
        # 32 chars -> MD5, NTLM
        self.assertEqual(detect_candidates("5f4dcc3b5aa765d61d8327deb882cf99"), ["MD5", "NTLM"])
        # 40 chars -> SHA1
        self.assertEqual(detect_candidates("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"), ["SHA1"])
        # 64 chars -> SHA256, SHA3-256
        self.assertEqual(detect_candidates("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"), ["SHA256", "SHA3-256"])
        # Crypt candidate resolution
        self.assertEqual(detect_candidates("$2a$10$xyz"), ["BCRYPT"])
        self.assertEqual(detect_candidates("$1$salt$hash"), ["MD5-CRYPT"])
        self.assertEqual(detect_candidates("$5$salt$hash"), ["SHA256-CRYPT"])
        self.assertEqual(detect_candidates("$6$salt$hash"), ["SHA512-CRYPT"])


if __name__ == "__main__":
    unittest.main()
