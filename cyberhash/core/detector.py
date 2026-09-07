"""
Hash format validation and fingerprint detection engine.
"""

import re
from typing import Optional, List
from cyberhash.config import HASH_SIGNATURES


def validate_hash(hash_value: str) -> bool:
    """
    Validate whether a string is a valid hexadecimal hash string or crypt hash string.

    :param hash_value: Hash string to validate.
    :return: True if valid hex or crypt format, False otherwise.
    """
    clean_hash = hash_value.strip()
    if is_crypt_hash(clean_hash):
        return True
    return bool(re.fullmatch(r"[a-fA-F0-9]+", clean_hash))


def is_crypt_hash(hash_value: str) -> bool:
    """
    Check whether a target hash string uses crypt-format signature prefixes ($2a$, $1$, $5$, $6$).

    :param hash_value: Hash string to check.
    :return: True if crypt format, False otherwise.
    """
    clean = hash_value.strip()
    for sig in HASH_SIGNATURES:
        if re.match(sig["regex"], clean):
            return True
    return False


def identify_hash(hash_value: str) -> str:
    """
    Identify hash type/fingerprint based on structure, regex, or length.

    :param hash_value: Target hash string.
    :return: Friendly identification name string.
    """
    clean = hash_value.strip()

    # Structure / prefix signature detection
    for sig in HASH_SIGNATURES:
        if re.match(sig["regex"], clean):
            return sig["name"].upper()

    # Hex charset length detection
    if re.fullmatch(r"[a-fA-F0-9]+", clean):
        length = len(clean)
        if length == 32:
            return "MD5 / NTLM"
        elif length == 40:
            return "SHA1"
        elif length == 56:
            return "SHA224 / SHA3-224 / SHA512-224"
        elif length == 64:
            return "SHA256 / SHA3-256"
        elif length == 96:
            return "SHA384 / SHA3-384"
        elif length == 128:
            return "SHA512 / SHA3-512"

    # Base64 charset detection
    if re.fullmatch(r"[A-Za-z0-9+/=]+", clean):
        return "BASE64 ENCODED DATA"

    return "UNKNOWN"


def detect_candidates(hash_value: str) -> List[str]:
    """
    Detect all candidate algorithm strings for a given hash value.

    :param hash_value: Target hash string.
    :return: List of candidate algorithm strings.
    """
    clean = hash_value.strip()

    # 1. Crypt format matches
    if clean.startswith(("$2a$", "$2b$", "$2y$")):
        return ["BCRYPT"]
    elif clean.startswith("$1$"):
        return ["MD5-CRYPT"]
    elif clean.startswith("$5$"):
        return ["SHA256-CRYPT"]
    elif clean.startswith("$6$"):
        return ["SHA512-CRYPT"]

    # 2. Hex length candidate resolution
    length = len(clean)
    if length == 32:
        return ["MD5", "NTLM"]
    elif length == 40:
        return ["SHA1"]
    elif length == 56:
        return ["SHA224", "SHA3-224", "SHA512-224"]
    elif length == 64:
        return ["SHA256", "SHA3-256"]
    elif length == 96:
        return ["SHA384", "SHA3-384"]
    elif length == 128:
        return ["SHA512", "SHA3-512"]

    return []


def detect_algorithm(hash_value: str) -> Optional[str]:
    """
    Legacy helper returning first detected algorithm.
    """
    candidates = detect_candidates(hash_value)
    return candidates[0] if candidates else None
