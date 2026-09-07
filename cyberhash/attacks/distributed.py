"""
Multi-process distributed cracking attack module with transparent gzip support.
"""

import os
import time
from pathlib import Path
from multiprocessing import Process, Queue
from typing import List, Tuple, Optional

from cyberhash.core.verifier import extended_check_word
from cyberhash.wordlists.manager import open_wordlist
from cyberhash.output.console import display_result, console


def split_wordlist(file_path: Path, workers: int) -> List[Tuple[int, int]]:
    """
    Split wordlist file into byte offset ranges for worker processes.

    :param file_path: Path object to wordlist.
    :param workers: Number of worker processes.
    :return: List of (start_byte, end_byte) tuple offsets.
    """
    size = os.path.getsize(file_path)
    chunk = size // workers
    ranges: List[Tuple[int, int]] = []
    start = 0

    for i in range(workers):
        end = start + chunk
        if i == workers - 1:
            end = size
        ranges.append((start, end))
        start = end

    return ranges


def _process_worker(
    res_queue: Queue,
    file_path: Path,
    start: int,
    end: int,
    target_hash: str,
    algo: str
) -> None:
    """
    Worker function executed in separate process to search a byte range chunk.
    """
    try:
        with open_wordlist(file_path) as f:
            if start != 0 and hasattr(f, "seek"):
                try:
                    f.seek(start)
                    f.readline()
                except Exception:
                    pass

            while True:
                if hasattr(f, "tell"):
                    try:
                        if f.tell() >= end:
                            break
                    except Exception:
                        pass

                line = f.readline()
                if not line:
                    break

                word = line.strip()
                if not word:
                    continue

                res = extended_check_word(word, target_hash, algo)
                if res:
                    res_queue.put(res)
                    return
    except Exception:
        pass


def distributed_attack(
    wordlist_path: Path,
    target_hash: str,
    algo: str,
    workers: int
) -> bool:
    """
    Split wordlist work across multiple worker processes.

    :param wordlist_path: Path object to wordlist file.
    :param target_hash: Target hash string.
    :param algo: Target algorithm string.
    :param workers: Number of worker processes.
    :return: True if match found, False otherwise.
    """
    start_time = time.time()
    console.print(f"[yellow][*] Distributed attack with {workers} workers[/yellow]")

    if not wordlist_path.exists():
        console.print(f"[red]Wordlist file not found: {wordlist_path}[/red]")
        return False

    ranges = split_wordlist(wordlist_path, workers)
    queue: Queue = Queue()
    processes: List[Process] = []

    for start, end in ranges:
        p = Process(
            target=_process_worker,
            args=(queue, wordlist_path, start, end, target_hash, algo)
        )
        p.start()
        processes.append(p)

    found_result: Optional[Tuple[str, str, str, Optional[int]]] = None

    try:
        while any(p.is_alive() for p in processes):
            if not queue.empty():
                found_result = queue.get()
                break
            time.sleep(0.05)

        if not found_result and not queue.empty():
            found_result = queue.get()
    finally:
        for p in processes:
            if p.is_alive():
                p.terminate()
            p.join()

    if found_result:
        algo_matched, word, method, shift = found_result
        display_result(
            word=word,
            algo=algo_matched,
            method=method,
            shift=shift,
            start_time=start_time,
            count=0
        )
        return True

    console.print("[red][-] Distributed attack completed: Hash not found[/red]")
    return False
