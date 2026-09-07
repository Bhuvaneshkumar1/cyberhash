"""
Clean, streaming multi-wordlist dictionary attack engine with bounded worker pools.
"""

import time
import logging
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List, Set, Generator
from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait
from rich.progress import Progress

from cyberhash.core.verifier import auto_check_word
from cyberhash.attacks.rules import RuleEngine
from cyberhash.session.manager import SessionManager
from cyberhash.wordlists.manager import open_wordlist
from cyberhash.output.console import display_result, console


@dataclass
class AttackResult:
    """
    Consistent result object returned by attack routines.
    """
    found: bool
    candidate: Optional[str] = None
    algorithm: Optional[str] = None
    method: Optional[str] = None
    rule: Optional[str] = None
    tested: int = 0
    elapsed: float = 0.0


def stream_wordlists(
    wordlist_paths: List[Path],
    deduplicate: bool = True,
    max_dedup_cache: int = 500000
) -> Generator[str, None, None]:
    """
    Stream candidate words sequentially across one or more wordlists safely handling UTF-8 byte errors.

    :param wordlist_paths: List of Path objects to wordlists.
    :param deduplicate: Whether to filter out duplicate candidate words across files.
    :param max_dedup_cache: Maximum cache limit for deduplication set.
    :yield: Stripped non-empty candidate word strings.
    """
    seen: Set[str] = set()

    for path in wordlist_paths:
        if not path.exists():
            logging.warning(f"Wordlist file not found: {path}")
            continue

        try:
            with open_wordlist(path) as f:
                for line in f:
                    word = line.strip()
                    if not word:
                        continue

                    if deduplicate:
                        if word in seen:
                            continue
                        if len(seen) < max_dedup_cache:
                            seen.add(word)

                    yield word
        except Exception as e:
            logging.error(f"Error reading wordlist '{path}': {e}")


def run_dictionary_attack(
    wordlist_paths: List[Path],
    target_hash: str,
    algos: List[str],
    threads: int = 4,
    use_rules: bool = False,
    rules_only: bool = False,
    rule_engine: Optional[RuleEngine] = None,
    session_mgr: Optional[SessionManager] = None
) -> AttackResult:
    """
    Run dictionary attack across single or multiple wordlists with bounded worker pool queues.

    :param wordlist_paths: List of Path objects to wordlist files.
    :param target_hash: Target hex or crypt hash string.
    :param algos: List of candidate algorithms.
    :param threads: Number of worker threads.
    :param use_rules: Whether to run rule-based mutations alongside base word.
    :param rules_only: Whether to check ONLY rule-generated candidates.
    :param rule_engine: Optional RuleEngine v2 instance.
    :param session_mgr: Optional SessionManager instance for checkpointing.
    :return: Structured AttackResult instance.
    """
    start_time = time.time()
    tested_count = 0
    engine = rule_engine or RuleEngine(depth=1)

    existing_paths = [p for p in wordlist_paths if p.exists()]
    if not existing_paths:
        console.print("[red]No valid wordlist files supplied or found.[/red]")
        return AttackResult(found=False, elapsed=time.time() - start_time)

    def process_word_candidates(word: str):
        candidates: List[str] = []
        if not rules_only:
            candidates.append(word)

        if use_rules or rules_only:
            candidates.extend(engine.generate_mutations(word))

        for cand in candidates:
            res = auto_check_word(cand, target_hash, algos)
            if res:
                return res
        return None

    max_bounded_futures = max(1, threads * 2)

    try:
        with Progress() as progress:
            task = progress.add_task("Scanning", total=None)
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {}
                word_stream = stream_wordlists(existing_paths, deduplicate=len(existing_paths) > 1)

                for i, word in enumerate(word_stream):
                    if session_mgr:
                        session_mgr.set_current_state(i, existing_paths[0], target_hash)

                    fut = executor.submit(process_word_candidates, word)
                    futures[fut] = word
                    tested_count += 1
                    progress.update(task, advance=1)

                    if session_mgr and tested_count % 5000 == 0:
                        session_mgr.save_session(i, existing_paths[0], target_hash)

                    # Maintain bounded work queue (max_workers * 2)
                    if len(futures) >= max_bounded_futures:
                        done, _ = wait(futures.keys(), return_when=FIRST_COMPLETED)
                        for f in done:
                            res = f.result()
                            del futures[f]
                            if res:
                                elapsed = time.time() - start_time
                                algo, matched_word, method, shift = res
                                safe_word = matched_word.replace("\n", "").replace("\r", "")
                                logging.info(f"FOUND {safe_word}")
                                
                                result_obj = AttackResult(
                                    found=True,
                                    candidate=matched_word,
                                    algorithm=algo,
                                    method=method,
                                    rule=None,
                                    tested=tested_count,
                                    elapsed=elapsed
                                )
                                display_result(
                                    word=matched_word,
                                    algo=algo,
                                    method=method,
                                    shift=shift,
                                    start_time=start_time,
                                    count=tested_count
                                )
                                if session_mgr:
                                    session_mgr.clear_session()
                                return result_obj

                # Drain remaining in-flight futures
                for f in list(futures.keys()):
                    res = f.result()
                    if res:
                        elapsed = time.time() - start_time
                        algo, matched_word, method, shift = res
                        safe_word = matched_word.replace("\n", "").replace("\r", "")
                        logging.info(f"FOUND {safe_word}")
                        
                        result_obj = AttackResult(
                            found=True,
                            candidate=matched_word,
                            algorithm=algo,
                            method=method,
                            rule=None,
                            tested=tested_count,
                            elapsed=elapsed
                        )
                        display_result(
                            word=matched_word,
                            algo=algo,
                            method=method,
                            shift=shift,
                            start_time=start_time,
                            count=tested_count
                        )
                        if session_mgr:
                            session_mgr.clear_session()
                        return result_obj

    except KeyboardInterrupt:
        console.print("\n[yellow][*] Attack interrupted by user.[/yellow]")

    elapsed = time.time() - start_time
    cps = tested_count / elapsed if elapsed > 0 else 0.0

    console.print("[red][-] Hash not found[/red]")
    console.print(f"[yellow]Candidates tested:[/yellow] {tested_count}")
    console.print(f"[yellow]Elapsed time:[/yellow] {elapsed:.2f}s")
    console.print(f"[yellow]Speed:[/yellow] {int(cps)} candidates/sec")
    logging.info("Hash not found")

    return AttackResult(
        found=False,
        tested=tested_count,
        elapsed=elapsed
    )
