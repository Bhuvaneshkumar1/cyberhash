"""
Wordlist statistics and information utility module.
"""

import os
import platform
from pathlib import Path
from typing import Dict, Any, Optional

from cyberhash.wordlists.manager import open_wordlist


def get_wordlist_info(
    file_path: Path,
    source_label: str = "unknown",
    target_os: Optional[str] = None
) -> Dict[str, Any]:
    """
    Compute comprehensive wordlist metadata by streaming the file line-by-line.

    Calculates:
    - file_size (bytes)
    - line_count
    - unique_count
    - duplicate_count
    - empty_lines
    - average_length
    - min_length
    - max_length
    - numeric_only_count
    - alphabetic_only_count
    - mixed_count

    :param file_path: Path object to wordlist.
    :param source_label: Source label string.
    :param target_os: Target OS name override.
    :return: Dictionary containing wordlist metadata and statistics.
    """
    path_obj = Path(file_path)

    if not path_obj.exists():
        return {
            "path": str(path_obj),
            "file_size": 0,
            "size_bytes": 0,
            "line_count": 0,
            "unique_count": 0,
            "unique_entries": 0,
            "duplicate_count": 0,
            "empty_lines": 0,
            "average_length": 0.0,
            "min_length": 0,
            "max_length": 0,
            "numeric_only_count": 0,
            "alphabetic_only_count": 0,
            "mixed_count": 0,
            "is_compressed": False,
            "platform": target_os or platform.system(),
            "source": source_label,
            "exists": False
        }

    size_bytes = os.path.getsize(path_obj)
    is_compressed = path_obj.suffix.lower() == ".gz"

    line_count = 0
    empty_lines = 0
    non_empty_count = 0
    total_char_len = 0
    min_length: Optional[int] = None
    max_length: Optional[int] = None

    numeric_only_count = 0
    alphabetic_only_count = 0
    mixed_count = 0

    seen_hashes = set()

    try:
        with open_wordlist(path_obj) as f:
            for raw_line in f:
                line_count += 1
                word = raw_line.rstrip("\r\n")

                if not word:
                    empty_lines += 1
                    continue

                non_empty_count += 1
                w_len = len(word)
                total_char_len += w_len

                if min_length is None or w_len < min_length:
                    min_length = w_len
                if max_length is None or w_len > max_length:
                    max_length = w_len

                if word.isdigit():
                    numeric_only_count += 1
                elif word.isalpha():
                    alphabetic_only_count += 1
                else:
                    mixed_count += 1

                seen_hashes.add(hash(word))
    except Exception:
        pass

    unique_count = len(seen_hashes)
    duplicate_count = non_empty_count - unique_count
    avg_len = (total_char_len / non_empty_count) if non_empty_count > 0 else 0.0

    return {
        "path": str(path_obj.resolve()),
        "file_size": size_bytes,
        "size_bytes": size_bytes,
        "line_count": line_count,
        "unique_count": unique_count,
        "unique_entries": unique_count,
        "duplicate_count": duplicate_count,
        "empty_lines": empty_lines,
        "average_length": round(avg_len, 2),
        "min_length": min_length if min_length is not None else 0,
        "max_length": max_length if max_length is not None else 0,
        "numeric_only_count": numeric_only_count,
        "alphabetic_only_count": alphabetic_only_count,
        "mixed_count": mixed_count,
        "is_compressed": is_compressed,
        "platform": target_os or platform.system(),
        "source": source_label,
        "exists": True
    }


def get_wordlist_stats(file_path: Path) -> Dict[str, Any]:
    """
    Get statistics dictionary for a wordlist file.

    :param file_path: Path object to wordlist.
    :return: Dictionary with wordlist stats.
    """
    return get_wordlist_info(file_path)
