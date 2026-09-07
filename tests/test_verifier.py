"""
Unit tests for verifier module supporting hex and crypt hashes.
"""

import unittest
from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt
from cyberhash.core.verifier import check_word, auto_check_word, extended_check_word


class TestVerifier(unittest.TestCase):

    def test_check_word_hex_md5(self):
        res = check_word("password", "5f4dcc3b5aa765d61d8327deb882cf99", "MD5")
        self.assertIsNotNone(res)
        if res:
            algo, word, method, shift = res
            self.assertEqual(algo, "MD5")
            self.assertEqual(word, "password")
            self.assertEqual(method, "Direct")

    def test_check_word_hex_case_insensitive(self):
        res = check_word("password", "5F4DCC3B5AA765D61D8327DEB882CF99", "MD5")
        self.assertIsNotNone(res)
        if res:
            self.assertEqual(res[1], "password")

    def test_check_word_crypt_bcrypt(self):
        hash_val = "$2b$12$JFTJlqpg3LNhpBr1ql5L1utNZ2bWmjjShiwoPIsJjhddUsQl2QmDq"
        res = check_word("password", hash_val, "BCRYPT")
        self.assertIsNotNone(res)
        if res:
            algo, word, method, shift = res
            self.assertEqual(algo, "BCRYPT")
            self.assertEqual(word, "password")
            self.assertEqual(method, "Crypt Match")

    def test_check_word_crypt_md5_crypt(self):
        hash_val = md5_crypt.hash("password")
        res = check_word("password", hash_val, "MD5-CRYPT")
        self.assertIsNotNone(res)
        if res:
            self.assertEqual(res[2], "Crypt Match")

    def test_auto_check_word(self):
        res = auto_check_word("password", "5f4dcc3b5aa765d61d8327deb882cf99", ["MD5", "NTLM"])
        self.assertIsNotNone(res)
        if res:
            algo, word, method, shift = res
            self.assertEqual(algo, "MD5")
            self.assertEqual(word, "password")

    def test_extended_check_word_hex(self):
        target = "482c811da5d5b4bc6d497ffa98491e38" # md5("password123")
        res = extended_check_word("password", target, "MD5")
        self.assertIsNotNone(res)
        if res:
            algo, word, method, shift = res
            self.assertEqual(algo, "MD5")
            self.assertIn("password", word)


if __name__ == "__main__":
    unittest.main()
