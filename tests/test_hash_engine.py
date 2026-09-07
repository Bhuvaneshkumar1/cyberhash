"""
Unit tests for hash computation engine supporting hex and passlib crypt hashes.
"""

import unittest
from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt
from cyberhash.core.hash_engine import (
    compute_hash,
    verify_crypt_hash,
    normalize_algorithm
)


class TestHashEngine(unittest.TestCase):

    def test_normalize_algorithm(self):
        self.assertEqual(normalize_algorithm("md5"), "MD5")
        self.assertEqual(normalize_algorithm("sha-256"), "SHA256")
        self.assertEqual(normalize_algorithm("sha3_256"), "SHA3-256")
        self.assertEqual(normalize_algorithm("bcrypt"), "BCRYPT")
        self.assertEqual(normalize_algorithm("md5crypt"), "MD5-CRYPT")
        self.assertEqual(normalize_algorithm("sha256-crypt"), "SHA256-CRYPT")
        self.assertEqual(normalize_algorithm("sha512crypt"), "SHA512-CRYPT")

    def test_compute_hash_md5(self):
        # md5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
        res = compute_hash(b"password", "MD5")
        self.assertEqual(res, "5f4dcc3b5aa765d61d8327deb882cf99")

    def test_compute_hash_sha1(self):
        # sha1("password") = 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
        res = compute_hash(b"password", "SHA1")
        self.assertEqual(res, "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")

    def test_compute_hash_sha256(self):
        # sha256("password") = 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
        res = compute_hash(b"password", "SHA256")
        self.assertEqual(res, "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8")

    def test_compute_hash_sha512(self):
        # sha512("password")
        res = compute_hash(b"password", "SHA512")
        self.assertEqual(
            res,
            "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
        )

    def test_compute_hash_sha3_256(self):
        # sha3_256("password")
        res = compute_hash(b"password", "SHA3-256")
        self.assertEqual(res, "c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484")

    def test_compute_hash_ntlm(self):
        # ntlm("password") = 8846f7eaee8fb117ad06bdd830b7586c
        res = compute_hash(b"password", "NTLM")
        self.assertEqual(res, "8846f7eaee8fb117ad06bdd830b7586c")

    def test_verify_crypt_hash_bcrypt_static(self):
        # Pre-calculated bcrypt test vector for "password"
        bcrypt_hash = "$2b$12$JFTJlqpg3LNhpBr1ql5L1utNZ2bWmjjShiwoPIsJjhddUsQl2QmDq"
        self.assertTrue(verify_crypt_hash("password", bcrypt_hash, "BCRYPT"))
        self.assertFalse(verify_crypt_hash("wrongpass", bcrypt_hash, "BCRYPT"))

    def test_verify_crypt_hash_md5_crypt(self):
        hash_val = md5_crypt.hash("password")
        self.assertTrue(verify_crypt_hash("password", hash_val, "MD5-CRYPT"))
        self.assertFalse(verify_crypt_hash("wrongpass", hash_val, "MD5-CRYPT"))

    def test_verify_crypt_hash_sha256_crypt(self):
        hash_val = sha256_crypt.hash("password")
        self.assertTrue(verify_crypt_hash("password", hash_val, "SHA256-CRYPT"))
        self.assertFalse(verify_crypt_hash("wrongpass", hash_val, "SHA256-CRYPT"))

    def test_verify_crypt_hash_sha512_crypt(self):
        hash_val = sha512_crypt.hash("password")
        self.assertTrue(verify_crypt_hash("password", hash_val, "SHA512-CRYPT"))
        self.assertFalse(verify_crypt_hash("wrongpass", hash_val, "SHA512-CRYPT"))

    def test_unsupported_algorithm_raises_error(self):
        with self.assertRaises(ValueError):
            compute_hash(b"test", "UNKNOWN_ALGO")

    def test_crypt_algo_in_compute_hash_raises_error(self):
        with self.assertRaises(ValueError):
            compute_hash(b"password", "BCRYPT")


if __name__ == "__main__":
    unittest.main()
