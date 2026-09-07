"""
Algorithm resolution module mapping target hashes to algorithm candidates.
"""

from typing import List, Optional
from cyberhash.core.hash_engine import normalize_algorithm
from cyberhash.core.detector import detect_candidates


def possible_algorithms(hash_value: str) -> List[str]:
    """
    Determine possible algorithm candidates for a given target hash.

    :param hash_value: Target hash string.
    :return: List of candidate algorithm names.
    """
    return detect_candidates(hash_value)


def resolve_algorithms(args_algo: Optional[str], target_hash: str) -> List[str]:
    """
    Resolve algorithms given user override or target hash length/format.

    - When --algo is explicitly supplied: return only the requested normalized algorithm.
    - When --algo is omitted: return all compatible candidate algorithms where ambiguity exists.

    :param args_algo: User supplied algorithm override flag.
    :param target_hash: Target hash string.
    :return: List of resolved normalized algorithm candidate strings.
    """
    if args_algo:
        return [normalize_algorithm(args_algo)]

    return detect_candidates(target_hash)
