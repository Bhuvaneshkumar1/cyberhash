"""
Hash algorithm speed benchmarking engine with precision counters, crypt isolation, and export capabilities.
"""

import time
import logging
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Union

from cyberhash.core.hash_engine import compute_hash, normalize_algorithm
from cyberhash.output.console import console
from cyberhash.output.exporter import export_result
from rich.table import Table

# List of fast hashing algorithms supported by compute_hash
FAST_BENCHMARK_ALGORITHMS = [
    "MD5",
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "NTLM",
    "CRC32",
]

# Crypt algorithms that require password verification backends rather than hashlib
CRYPT_ALGORITHMS = [
    "BCRYPT",
    "MD5-CRYPT",
    "SHA256-CRYPT",
    "SHA512-CRYPT",
]


@dataclass
class BenchmarkResultItem:
    """
    Data model representing benchmark metrics for a single algorithm.
    """
    algorithm: str
    operations: int
    elapsed: float
    ops_per_sec: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def benchmark_algorithm(algo: str, duration_seconds: float = 1.0) -> BenchmarkResultItem:
    """
    Measure hash performance for a single fast algorithm over duration_seconds.

    :param algo: Algorithm name string.
    :param duration_seconds: Time budget in seconds.
    :return: BenchmarkResultItem dataclass object.
    :raises ValueError: If algorithm is a slow crypt format.
    """
    norm_algo = normalize_algorithm(algo)

    if norm_algo in CRYPT_ALGORITHMS:
        raise ValueError(f"Crypt algorithm '{norm_algo}' cannot be benchmarked using raw hash loop.")

    sample_bytes = b"cyberhash_benchmark_candidate_string"
    start_time = time.perf_counter()
    ops = 0

    while (time.perf_counter() - start_time) < duration_seconds:
        compute_hash(sample_bytes, norm_algo)
        ops += 1

    elapsed = time.perf_counter() - start_time
    ops_per_sec = ops / elapsed if elapsed > 0 else 0.0

    return BenchmarkResultItem(
        algorithm=norm_algo,
        operations=ops,
        elapsed=round(elapsed, 4),
        ops_per_sec=round(ops_per_sec, 2)
    )


def run_benchmark(
    target_algo: Optional[str] = None,
    duration_per_algo: float = 1.0,
    export_path: Optional[Union[str, Path]] = None
) -> List[BenchmarkResultItem]:
    """
    Run speed benchmark for specified algorithm or all supported fast algorithms.

    :param target_algo: Optional single algorithm name to benchmark.
    :param duration_per_algo: Duration in seconds to run each algorithm test.
    :param export_path: Optional destination path for JSON/CSV/TXT export.
    :return: List of BenchmarkResultItem dataclasses.
    """
    if target_algo:
        norm_target = normalize_algorithm(target_algo)
        if norm_target in CRYPT_ALGORITHMS:
            console.print(f"[yellow][!] Crypt algorithm '{norm_target}' skipped (use fast algorithms for raw throughput benchmark).[/yellow]")
            return []
        algos = [norm_target]
    else:
        algos = FAST_BENCHMARK_ALGORITHMS

    console.print(f"[cyan][*] Starting CyberHash benchmark ({duration_per_algo:.1f}s per algorithm)...[/cyan]")

    results: List[BenchmarkResultItem] = []

    for algo in algos:
        try:
            res = benchmark_algorithm(algo, duration_seconds=duration_per_algo)
            results.append(res)
        except Exception as e:
            logging.warning(f"Failed to benchmark algorithm '{algo}': {e}")

    # Render Rich Output Table
    table = Table(title="CYBERHASH ALGORITHM BENCHMARK")
    table.add_column("Algorithm", style="cyan")
    table.add_column("Operations", style="magenta")
    table.add_column("Elapsed (s)", style="white")
    table.add_column("Speed (ops/sec)", style="bold green")

    for r in results:
        table.add_row(
            r.algorithm,
            f"{r.operations:,}",
            f"{r.elapsed:.2f}s",
            f"{r.ops_per_sec:,.2f} ops/s"
        )

    console.print(table)

    if export_path:
        payloads = [r.to_dict() for r in results]
        export_result(output_path=export_path, payload=payloads)
        console.print(f"[green][+] Benchmark results exported to:[/green] {export_path}")

    return results
