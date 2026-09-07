"""
Core hashing engine for hex digests and crypt verification.
"""

import base64
import hashlib
import zlib
from typing import Optional, List, Tuple
from passlib.hash import nthash

try:
    from passlib.hash import bcrypt as passlib_bcrypt, md5_crypt, sha256_crypt, sha512_crypt
    PASSLIB_AVAILABLE = True
except ImportError:
    PASSLIB_AVAILABLE = False

try:
    import bcrypt as native_bcrypt
except ImportError:
    native_bcrypt = None


# Map normalized algorithm names
ALGO_NORM_MAP = {
    "MD5": "MD5",
    "NTLM": "NTLM",
    "SHA1": "SHA1",
    "SHA-1": "SHA1",
    "SHA224": "SHA224",
    "SHA-224": "SHA224",
    "SHA256": "SHA256",
    "SHA-256": "SHA256",
    "SHA384": "SHA384",
    "SHA-384": "SHA384",
    "SHA512": "SHA512",
    "SHA-512": "SHA512",
    "SHA3_224": "SHA3-224",
    "SHA3-224": "SHA3-224",
    "SHA3_256": "SHA3-256",
    "SHA3-256": "SHA3-256",
    "SHA3_384": "SHA3-384",
    "SHA3-384": "SHA3-384",
    "SHA3_512": "SHA3-512",
    "SHA3-512": "SHA3-512",
    "SHA512_224": "SHA512-224",
    "SHA512-224": "SHA512-224",
    "SHA512/224": "SHA512-224",
    "SHAKE128": "SHAKE128",
    "SHAKE256": "SHAKE256",
    "CRC32": "CRC32",
    "BCRYPT": "BCRYPT",
    "MD5CRYPT": "MD5-CRYPT",
    "MD5-CRYPT": "MD5-CRYPT",
    "SHA256CRYPT": "SHA256-CRYPT",
    "SHA256-CRYPT": "SHA256-CRYPT",
    "SHA512CRYPT": "SHA512-CRYPT",
    "SHA512-CRYPT": "SHA512-CRYPT"
}


def normalize_algorithm(algo: str) -> str:
    """
    Normalize algorithm name to uppercase canonical string representation.

    :param algo: Input algorithm string.
    :return: Normalized algorithm string.
    """
    clean = algo.strip().upper()
    return ALGO_NORM_MAP.get(clean, clean)


def compute_hash(data: bytes, algo: str, hash_length: Optional[int] = None) -> str:
    """
    Compute lowercase hex digest for given binary data and algorithm string.

    :param data: Raw binary bytes to hash.
    :param algo: Name of algorithm (e.g. 'MD5', 'SHA256', 'NTLM').
    :param hash_length: Optional length for extendable-output algorithms.
    :return: Lowercase hex string digest.
    :raises ValueError: If algorithm is unsupported or crypt-format.
    """
    norm_algo = normalize_algorithm(algo)

    if norm_algo in ("BCRYPT", "MD5-CRYPT", "SHA256-CRYPT", "SHA512-CRYPT"):
        raise ValueError(f"Crypt algorithm '{norm_algo}' cannot be calculated as raw hex. Use verifier routines.")

    if norm_algo == "MD5":
        return hashlib.md5(data).hexdigest()
    elif norm_algo == "SHA1":
        return hashlib.sha1(data).hexdigest()
    elif norm_algo == "SHA224":
        return hashlib.sha224(data).hexdigest()
    elif norm_algo == "SHA256":
        return hashlib.sha256(data).hexdigest()
    elif norm_algo == "SHA384":
        return hashlib.sha384(data).hexdigest()
    elif norm_algo == "SHA512":
        return hashlib.sha512(data).hexdigest()
    elif norm_algo == "SHA3-224":
        return hashlib.sha3_224(data).hexdigest()
    elif norm_algo == "SHA3-256":
        return hashlib.sha3_256(data).hexdigest()
    elif norm_algo == "SHA3-384":
        return hashlib.sha3_384(data).hexdigest()
    elif norm_algo == "SHA3-512":
        return hashlib.sha3_512(data).hexdigest()
    elif norm_algo == "SHA512-224":
        try:
            return hashlib.new("sha512_224", data).hexdigest()
        except ValueError:
            raise ValueError("SHA512/224 is not supported on this Python environment.")
    elif norm_algo == "SHAKE256":
        length = hash_length if hash_length is not None else 64
        return hashlib.shake_256(data).hexdigest(length // 2)
    elif norm_algo == "SHAKE128":
        length = hash_length if hash_length is not None else 64
        return hashlib.shake_128(data).hexdigest(length // 2)
    elif norm_algo == "CRC32":
        return format(zlib.crc32(data) & 0xffffffff, "08x")
    elif norm_algo == "NTLM":
        return nthash.hash(data.decode(errors="ignore")).lower()
    else:
        raise ValueError(f"Unsupported algorithm: '{algo}'")


def verify_crypt_hash(word: str, target_hash: str, algo: str) -> bool:
    """
    Verify password candidate against a crypt-format hash using Passlib/native backends.

    :param word: Candidate password word.
    :param target_hash: Target crypt hash string.
    :param algo: Algorithm identifier.
    :return: True if match, False otherwise.
    """
    norm_algo = normalize_algorithm(algo)

    if norm_algo == "BCRYPT":
        if native_bcrypt is not None:
            try:
                return native_bcrypt.checkpw(word.encode("utf-8"), target_hash.encode("utf-8"))
            except Exception:
                pass

    if not PASSLIB_AVAILABLE:
        return False

    try:
        if norm_algo == "BCRYPT":
            return passlib_bcrypt.verify(word, target_hash)
        elif norm_algo == "MD5-CRYPT":
            return md5_crypt.verify(word, target_hash)
        elif norm_algo == "SHA256-CRYPT":
            return sha256_crypt.verify(word, target_hash)
        elif norm_algo == "SHA512-CRYPT":
            return sha512_crypt.verify(word, target_hash)
    except Exception:
        return False

    return False


def base64_hash(data: bytes, algo: str, hash_length: Optional[int] = None) -> str:
    """
    Encode data with base64 first, then compute target hash digest.

    :param data: Raw binary bytes.
    :param algo: Target algorithm.
    :param hash_length: Optional hash length.
    :return: Lowercase hex digest string.
    """
    encoded = base64.b64encode(data)
    return compute_hash(encoded, algo, hash_length)


def rot13(data: bytes) -> bytes:
    """
    Apply ROT13 substitution cipher to input bytes.

    :param data: Binary input text.
    :return: Transformed binary text.
    """
    result: List[str] = []
    text = data.decode(errors="ignore")
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - 97 + 13) % 26 + 97))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - 65 + 13) % 26 + 65))
        else:
            result.append(c)
    return "".join(result).encode()


def caesar_variants(word: bytes) -> List[Tuple[int, bytes]]:
    """
    Generate all 25 Caesar shift variants for a given binary word.

    :param word: Original binary word.
    :return: List of tuples containing (shift_amount, shifted_bytes).
    """
    variants: List[Tuple[int, bytes]] = []
    text = word.decode(errors="ignore")
    for shift in range(1, 26):
        out: List[str] = []
        for c in text:
            if 'a' <= c <= 'z':
                out.append(chr((ord(c) - 97 + shift) % 26 + 97))
            elif 'A' <= c <= 'Z':
                out.append(chr((ord(c) - 65 + shift) % 26 + 65))
            else:
                out.append(c)
        variants.append((shift, "".join(out).encode()))
    return variants
