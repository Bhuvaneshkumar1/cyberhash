"""
Mask attack generation, validation, and multi-algorithm execution module.
"""

import time
import logging
import itertools
from typing import Generator, List, Optional
from cyberhash.config import MASK_SETS, MASK_PRESETS
from cyberhash.core.verifier import auto_check_word
from cyberhash.attacks.dictionary import AttackResult
from cyberhash.output.console import display_result, console


def validate_mask(mask: str) -> bool:
    """
    Validate mask pattern string or preset name before execution.

    :param mask: Mask string pattern (e.g. '?d?d?d?d') or preset key ('simple_numeric').
    :return: True if valid mask or preset, False otherwise.
    """
    if not mask:
        return False

    # Preset lookup
    if mask in MASK_PRESETS:
        return True

    i = 0
    valid_tokens = set(MASK_SETS.keys())
    while i < len(mask):
        if mask[i] == "?":
            if i + 1 < len(mask):
                token = mask[i:i + 2]
                if token in valid_tokens:
                    i += 2
                    continue
                else:
                    return False
            else:
                return False
        i += 1

    return True


def parse_mask_parts(mask: str) -> List[str]:
    """
    Parse mask pattern string or preset name into list of character sets / literal chars.

    :param mask: Mask pattern string or preset name.
    :return: List of character set strings.
    """
    pattern = MASK_PRESETS.get(mask, mask)
    parts: List[str] = []
    i = 0
    while i < len(pattern):
        if pattern[i] == "?" and i + 1 < len(pattern):
            token = pattern[i:i + 2]
            if token in MASK_SETS:
                parts.append(MASK_SETS[token])
                i += 2
                continue
        parts.append(pattern[i])
        i += 1
    return parts


def calculate_mask_combinations(mask: str) -> int:
    """
    Calculate the total number of candidate combinations for a given mask pattern or preset.

    :param mask: Mask string pattern or preset name.
    :return: Integer total candidate count search space size.
    """
    if not validate_mask(mask):
        return 0

    parts = parse_mask_parts(mask)
    if not parts:
        return 0

    total = 1
    for part in parts:
        total *= len(part)
    return total


def mask_attack_generator(mask: str) -> Generator[str, None, None]:
    """
    Generate password candidate strings according to mask pattern or preset name.

    :param mask: Mask string pattern or preset name.
    :return: Generator yielding candidate password strings.
    """
    parts = parse_mask_parts(mask)
    for combo in itertools.product(*parts):
        yield "".join(combo)


def run_mask_attack(
    mask: str,
    target_hash: str,
    algos: List[str]
) -> AttackResult:
    """
    Execute mask attack for target hash testing candidates against ALL resolved algorithms.

    :param mask: Mask string pattern or preset name.
    :param target_hash: Target hex or crypt hash string.
    :param algos: List of all candidate algorithm strings to test against.
    :return: Structured AttackResult object.
    """
    start_time = time.time()

    if not validate_mask(mask):
        console.print(f"[red]Invalid mask pattern or preset name: '{mask}'[/red]")
        return AttackResult(found=False, elapsed=time.time() - start_time)

    actual_pattern = MASK_PRESETS.get(mask, mask)
    total_combinations = calculate_mask_combinations(mask)

    console.print(f"[yellow][*] Running mask attack: {actual_pattern}[/yellow]")
    console.print(f"[cyan][+] Estimated search space:[/cyan] {total_combinations:,} candidates")

    tested_count = 0

    try:
        for candidate in mask_attack_generator(mask):
            tested_count += 1
            res = auto_check_word(candidate, target_hash, algos)
            if res:
                elapsed = time.time() - start_time
                matched_algo, matched_word, method, shift = res
                display_result(
                    word=matched_word,
                    algo=matched_algo,
                    method="Mask Attack",
                    shift=shift,
                    start_time=start_time,
                    count=tested_count
                )
                return AttackResult(
                    found=True,
                    candidate=matched_word,
                    algorithm=matched_algo,
                    method="Mask Attack",
                    tested=tested_count,
                    elapsed=elapsed
                )
    except KeyboardInterrupt:
        console.print("\n[yellow][*] Mask attack interrupted by user.[/yellow]")

    elapsed = time.time() - start_time
    cps = tested_count / elapsed if elapsed > 0 else 0.0

    console.print("[red][-] Mask attack failed[/red]")
    console.print(f"[yellow]Candidates tested:[/yellow] {tested_count}")
    console.print(f"[yellow]Elapsed time:[/yellow] {elapsed:.2f}s")
    console.print(f"[yellow]Speed:[/yellow] {int(cps)} candidates/sec")

    return AttackResult(
        found=False,
        tested=tested_count,
        elapsed=elapsed
    )
