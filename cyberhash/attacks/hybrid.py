"""
Hybrid attack engine combining dictionary wordlist candidates with mask patterns.
"""

import time
import logging
from pathlib import Path
from typing import Optional, List, Generator
from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait
from rich.progress import Progress

from cyberhash.core.verifier import auto_check_word
from cyberhash.attacks.mask import validate_mask, mask_attack_generator, calculate_mask_combinations
from cyberhash.attacks.dictionary import AttackResult, stream_wordlists
from cyberhash.output.console import display_result, console


def generate_hybrid_candidates(
    word: str,
    mask: str,
    mode: str = "suffix",
    max_per_word: int = 1000
) -> Generator[str, None, None]:
    """
    Generate hybrid candidate combinations combining word with mask patterns.

    :param word: Base wordlist candidate string.
    :param mask: Mask string pattern or preset name.
    :param mode: Combination mode ('suffix' = word+mask, 'prefix' = mask+word, 'both' = both).
    :param max_per_word: Maximum mask variations per base word.
    :yield: Hybrid password candidate strings.
    """
    if not validate_mask(mask):
        return

    count = 0
    mode_clean = mode.lower().strip()

    for mask_cand in mask_attack_generator(mask):
        if mode_clean in ("suffix", "both"):
            yield f"{word}{mask_cand}"
            count += 1
            if count >= max_per_word:
                break

        if mode_clean in ("prefix", "both"):
            yield f"{mask_cand}{word}"
            count += 1
            if count >= max_per_word:
                break


def run_hybrid_attack(
    wordlist_paths: List[Path],
    mask: str,
    target_hash: str,
    algos: List[str],
    mode: str = "suffix",
    max_per_word: int = 1000,
    max_total_candidates: int = 500000,
    threads: int = 4
) -> AttackResult:
    """
    Execute hybrid dictionary + mask attack testing candidates against ALL resolved algorithms.

    :param wordlist_paths: List of Path objects to wordlists.
    :param mask: Target mask string or preset.
    :param target_hash: Target hex or crypt hash string.
    :param algos: List of all candidate algorithm strings to test against.
    :param mode: Combination mode ('suffix', 'prefix', or 'both').
    :param max_per_word: Maximum mask variations per word.
    :param max_total_candidates: Ceiling on total hybrid candidates generated.
    :param threads: Number of worker threads.
    :return: Structured AttackResult object.
    """
    start_time = time.time()

    if not validate_mask(mask):
        console.print(f"[red]Invalid mask pattern or preset for hybrid attack: '{mask}'[/red]")
        return AttackResult(found=False, elapsed=time.time() - start_time)

    existing_paths = [p for p in wordlist_paths if p.exists()]
    if not existing_paths:
        console.print("[red]No valid wordlist files supplied for hybrid attack.[/red]")
        return AttackResult(found=False, elapsed=time.time() - start_time)

    mask_combinations = calculate_mask_combinations(mask)
    console.print(f"[yellow][*] Running hybrid attack ({mode} mode, mask: '{mask}')[/yellow]")
    console.print(f"[cyan][+] Mask combinations per word:[/cyan] {mask_combinations:,} (capped at {max_per_word}/word)")

    tested_count = 0

    def process_hybrid_word(word: str):
        for candidate in generate_hybrid_candidates(word, mask, mode, max_per_word):
            res = auto_check_word(candidate, target_hash, algos)
            if res:
                return res
        return None

    max_bounded_futures = max(1, threads * 2)

    try:
        with Progress() as progress:
            task = progress.add_task("Hybrid Scanning", total=None)
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {}
                word_stream = stream_wordlists(existing_paths, deduplicate=len(existing_paths) > 1)

                for word in word_stream:
                    if tested_count >= max_total_candidates:
                        console.print(f"[yellow][*] Reached max total candidate limit ({max_total_candidates:,}).[/yellow]")
                        break

                    fut = executor.submit(process_hybrid_word, word)
                    futures[fut] = word
                    tested_count += min(mask_combinations, max_per_word)
                    progress.update(task, advance=1)

                    if len(futures) >= max_bounded_futures:
                        done, _ = wait(futures.keys(), return_when=FIRST_COMPLETED)
                        for f in done:
                            res = f.result()
                            del futures[f]
                            if res:
                                elapsed = time.time() - start_time
                                matched_algo, matched_word, method, shift = res
                                display_result(
                                    word=matched_word,
                                    algo=matched_algo,
                                    method=f"Hybrid Attack ({mode})",
                                    shift=shift,
                                    start_time=start_time,
                                    count=tested_count
                                )
                                return AttackResult(
                                    found=True,
                                    candidate=matched_word,
                                    algorithm=matched_algo,
                                    method=f"Hybrid Attack ({mode})",
                                    tested=tested_count,
                                    elapsed=elapsed
                                )

                # Drain remaining futures
                for f in list(futures.keys()):
                    res = f.result()
                    if res:
                        elapsed = time.time() - start_time
                        matched_algo, matched_word, method, shift = res
                        display_result(
                            word=matched_word,
                            algo=matched_algo,
                            method=f"Hybrid Attack ({mode})",
                            shift=shift,
                            start_time=start_time,
                            count=tested_count
                        )
                        return AttackResult(
                            found=True,
                            candidate=matched_word,
                            algorithm=matched_algo,
                            method=f"Hybrid Attack ({mode})",
                            tested=tested_count,
                            elapsed=elapsed
                        )

    except KeyboardInterrupt:
        console.print("\n[yellow][*] Hybrid attack interrupted by user.[/yellow]")

    elapsed = time.time() - start_time
    cps = tested_count / elapsed if elapsed > 0 else 0.0

    console.print("[red][-] Hybrid attack failed[/red]")
    console.print(f"[yellow]Candidates tested:[/yellow] {tested_count}")
    console.print(f"[yellow]Elapsed time:[/yellow] {elapsed:.2f}s")
    console.print(f"[yellow]Speed:[/yellow] {int(cps)} candidates/sec")

    return AttackResult(
        found=False,
        tested=tested_count,
        elapsed=elapsed
    )
