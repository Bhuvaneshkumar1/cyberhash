"""
Word verification and match detection module supporting hex and crypt hashes.
"""

import logging
from typing import Optional, Tuple, List, Union
from cyberhash.core.hash_engine import (
    compute_hash,
    base64_hash,
    rot13,
    caesar_variants,
    verify_crypt_hash,
    normalize_algorithm
)
from cyberhash.core.detector import is_crypt_hash
from cyberhash.attacks.rules import apply_rules, mutations


def check_word(
    word: str, target_hash: str, algo: str
) -> Optional[Tuple[str, str, str, Optional[int]]]:
    """
    Check a word against a target hash using a single algorithm across various transformations.

    :param word: Candidate password word.
    :param target_hash: Target hex or crypt hash string.
    :param algo: Target algorithm string.
    :return: 4-tuple of (algo, matched_word, method, shift) or None if no match.
    """
    norm_algo = normalize_algorithm(algo)
    clean_target = target_hash.strip()
    data = word.encode()

    # Route crypt-format hashes directly to Passlib verification
    if is_crypt_hash(clean_target) or norm_algo in ("BCRYPT", "MD5-CRYPT", "SHA256-CRYPT", "SHA512-CRYPT"):
        if verify_crypt_hash(word, clean_target, norm_algo):
            return (norm_algo, word, "Crypt Match", None)
        return None

    # Hexadecimal hash comparisons (case-insensitive)
    target_hex = clean_target.lower()
    hash_len = len(target_hex)

    try:
        # Direct check
        if compute_hash(data, norm_algo, hash_len).lower() == target_hex:
            return (norm_algo, word, "Direct", None)

        # Base64 check
        if base64_hash(data, norm_algo, hash_len).lower() == target_hex:
            return (norm_algo, word, "Base64", None)

        # ROT13 check
        r13 = rot13(data)
        if compute_hash(r13, norm_algo, hash_len).lower() == target_hex:
            return (norm_algo, word, "ROT13", None)

        # Caesar shift check
        for shift, val in caesar_variants(data):
            if compute_hash(val, norm_algo, hash_len).lower() == target_hex:
                return (norm_algo, word, "Caesar", shift)

        # Mutation check
        for m in mutations(data):
            if compute_hash(m, norm_algo, hash_len).lower() == target_hex:
                return (norm_algo, m.decode(errors="ignore"), "Mutation", None)

    except Exception as e:
        logging.debug(f"Error checking word '{word}' with algo '{norm_algo}': {e}")

    return None


def auto_check_word(
    word: str, target_hash: str, algos: List[str]
) -> Optional[Tuple[str, str, str, Optional[int]]]:
    """
    Check candidate word directly against multiple possible algorithms.

    :param word: Candidate password word.
    :param target_hash: Target hash string.
    :param algos: List of candidate algorithm names.
    :return: 4-tuple of (algo, word, method, shift) or None.
    """
    clean_target = target_hash.strip()
    target_hex = clean_target.lower()
    data = word.encode()
    hash_len = len(target_hex)

    for algo in algos:
        norm_algo = normalize_algorithm(algo)
        try:
            if is_crypt_hash(clean_target) or norm_algo in ("BCRYPT", "MD5-CRYPT", "SHA256-CRYPT", "SHA512-CRYPT"):
                if verify_crypt_hash(word, clean_target, norm_algo):
                    return (norm_algo, word, "Crypt Match", None)
            else:
                if compute_hash(data, norm_algo, hash_len).lower() == target_hex:
                    return (norm_algo, word, "Auto", None)
        except Exception as e:
            logging.debug(f"Auto check failed for algo '{algo}': {e}")

    return None


def extended_check_word(
    word: str, target_hash: str, algos: Union[str, List[str]]
) -> Optional[Tuple[str, str, str, Optional[int]]]:
    """
    Perform extended verification including rule engine mutations. Handles single or multiple algos.

    :param word: Candidate password word.
    :param target_hash: Target hash string.
    :param algos: Algorithm string or list of algorithm strings.
    :return: 4-tuple of (algo, matched_word, method, shift) or None.
    """
    algo_list = [algos] if isinstance(algos, str) else algos

    for algo in algo_list:
        norm_algo = normalize_algorithm(algo)
        res = check_word(word, target_hash, norm_algo)
        if res:
            return res

        for mutated in apply_rules(word):
            data = mutated.encode()
            clean_target = target_hash.strip()
            target_hex = clean_target.lower()
            hash_len = len(target_hex)
            try:
                if is_crypt_hash(clean_target) or norm_algo in ("BCRYPT", "MD5-CRYPT", "SHA256-CRYPT", "SHA512-CRYPT"):
                    if verify_crypt_hash(mutated, clean_target, norm_algo):
                        return (norm_algo, mutated, "Rule Mutation (Crypt)", None)
                else:
                    if compute_hash(data, norm_algo, hash_len).lower() == target_hex:
                        return (norm_algo, mutated, "Rule Mutation", None)
            except Exception as e:
                logging.debug(f"Extended check failed for mutated word '{mutated}': {e}")

    return None
