"""
Batch hash processing module for multi-target execution with error isolation and status reporting.
"""

import time
import logging
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

from cyberhash.core.detector import validate_hash
from cyberhash.core.resolver import resolve_algorithms
from cyberhash.attacks.dictionary import run_dictionary_attack
from cyberhash.attacks.mask import run_mask_attack
from cyberhash.attacks.hybrid import run_hybrid_attack
from cyberhash.attacks.rules import RuleEngine
from cyberhash.output.console import console
from cyberhash.output.exporter import export_result
from rich.table import Table


@dataclass
class BatchTargetResult:
    """
    Data model representing execution outcome for a single target hash in a batch run.
    """
    target_hash: str
    status: str  # "found", "not_found", "unsupported", "invalid"
    algorithm: str
    candidate: Optional[str]
    method: str
    tested: int
    elapsed: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def process_single_hash(
    target_hash: str,
    wordlist_paths: List[Path],
    algo_override: Optional[str] = None,
    mask: Optional[str] = None,
    hybrid: bool = False,
    hybrid_mode: str = "suffix",
    hybrid_max_per_word: int = 1000,
    use_rules: bool = False,
    rules_only: bool = False,
    rule_engine: Optional[RuleEngine] = None,
    threads: int = 4
) -> BatchTargetResult:
    """
    Process a single target hash within a batch run with exception safety.

    :return: BatchTargetResult object.
    """
    clean_hash = target_hash.strip().lower()

    if not validate_hash(clean_hash):
        return BatchTargetResult(
            target_hash=clean_hash,
            status="invalid",
            algorithm="None",
            candidate=None,
            method="validation",
            tested=0,
            elapsed=0.0
        )

    algos = resolve_algorithms(algo_override, clean_hash)
    if not algos:
        return BatchTargetResult(
            target_hash=clean_hash,
            status="unsupported",
            algorithm="Unknown",
            candidate=None,
            method="resolution",
            tested=0,
            elapsed=0.0
        )

    start_time = time.time()
    try:
        if hybrid:
            if not mask:
                mask = "?d?d"
            res = run_hybrid_attack(
                wordlist_paths=wordlist_paths,
                mask=mask,
                target_hash=clean_hash,
                algos=algos,
                mode=hybrid_mode,
                max_per_word=hybrid_max_per_word,
                threads=threads
            )
        elif mask:
            res = run_mask_attack(mask, clean_hash, algos)
        else:
            res = run_dictionary_attack(
                wordlist_paths=wordlist_paths,
                target_hash=clean_hash,
                algos=algos,
                threads=threads,
                use_rules=use_rules,
                rules_only=rules_only,
                rule_engine=rule_engine
            )

        elapsed = time.time() - start_time
        if res.found:
            return BatchTargetResult(
                target_hash=clean_hash,
                status="found",
                algorithm=res.algorithm or algos[0],
                candidate=res.candidate,
                method=res.method or ("hybrid" if hybrid else ("mask" if mask else "dictionary")),
                tested=res.tested,
                elapsed=elapsed
            )
        else:
            return BatchTargetResult(
                target_hash=clean_hash,
                status="not_found",
                algorithm=algos[0],
                candidate=None,
                method=res.method or ("hybrid" if hybrid else ("mask" if mask else "dictionary")),
                tested=res.tested,
                elapsed=elapsed
            )
    except Exception as e:
        logging.error(f"Error processing batch target hash '{clean_hash}': {e}")
        return BatchTargetResult(
            target_hash=clean_hash,
            status="not_found",
            algorithm=algos[0] if algos else "Unknown",
            candidate=None,
            method="error",
            tested=0,
            elapsed=time.time() - start_time
        )


def run_batch_processing(
    hash_file_path: Path,
    wordlist_paths: List[Path],
    algo_override: Optional[str] = None,
    mask: Optional[str] = None,
    hybrid: bool = False,
    hybrid_mode: str = "suffix",
    hybrid_max_per_word: int = 1000,
    use_rules: bool = False,
    rules_only: bool = False,
    rule_engine: Optional[RuleEngine] = None,
    threads: int = 4,
    export_path: Optional[str] = None
) -> List[BatchTargetResult]:
    """
    Sequentially process target hashes from a file, reporting status for each item and supporting export.

    :param hash_file_path: Path object to text file containing one hash per line.
    :param wordlist_paths: List of Path objects to wordlists.
    :param export_path: Target export path string (optional).
    :return: List of BatchTargetResult objects.
    """
    if not hash_file_path.exists():
        console.print(f"[red]Batch hash file not found: {hash_file_path}[/red]")
        return []

    target_hashes: List[str] = []
    with open(hash_file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                target_hashes.append(stripped)

    console.print(f"[cyan][*] Loaded {len(target_hashes)} target hashes from batch file.[/cyan]")

    results: List[BatchTargetResult] = []
    found_count = 0
    not_found_count = 0
    unsupported_count = 0
    invalid_count = 0

    for idx, target in enumerate(target_hashes, 1):
        console.print(f"[yellow][*] Processing target {idx}/{len(target_hashes)}: {target[:12]}...[/yellow]")
        res = process_single_hash(
            target_hash=target,
            wordlist_paths=wordlist_paths,
            algo_override=algo_override,
            mask=mask,
            hybrid=hybrid,
            hybrid_mode=hybrid_mode,
            hybrid_max_per_word=hybrid_max_per_word,
            use_rules=use_rules,
            rules_only=rules_only,
            rule_engine=rule_engine,
            threads=threads
        )
        results.append(res)

        if res.status == "found":
            found_count += 1
            console.print(f"[green]  [+] FOUND! Password: '{res.candidate}' ({res.algorithm})[/green]")
        elif res.status == "invalid":
            invalid_count += 1
            console.print("[red]  [-] INVALID HASH FORMAT[/red]")
        elif res.status == "unsupported":
            unsupported_count += 1
            console.print("[yellow]  [-] UNSUPPORTED ALGORITHM[/yellow]")
        else:
            not_found_count += 1
            console.print("[red]  [-] NOT FOUND[/red]")

    # Display Summary Table
    table = Table(title="BATCH CRACKING SUMMARY")
    table.add_column("Index", style="cyan")
    table.add_column("Target Hash", style="yellow")
    table.add_column("Status", style="bold")
    table.add_column("Algorithm", style="green")
    table.add_column("Candidate", style="bold green")
    table.add_column("Tested", style="magenta")
    table.add_column("Time", style="white")

    for idx, res in enumerate(results, 1):
        status_colored = res.status
        if res.status == "found":
            status_colored = f"[green]{res.status}[/green]"
        elif res.status == "invalid":
            status_colored = f"[red]{res.status}[/red]"
        elif res.status == "unsupported":
            status_colored = f"[yellow]{res.status}[/yellow]"
        else:
            status_colored = f"[red]{res.status}[/red]"

        table.add_row(
            str(idx),
            res.target_hash[:14] + ("..." if len(res.target_hash) > 14 else ""),
            status_colored,
            res.algorithm,
            res.candidate or "-",
            str(res.tested),
            f"{res.elapsed:.2f}s"
        )

    console.print(table)

    console.print(
        f"[bold white]Batch Totals:[/bold white] "
        f"[green]Found: {found_count}[/green] | "
        f"[red]Not Found: {not_found_count}[/red] | "
        f"[yellow]Unsupported: {unsupported_count}[/yellow] | "
        f"[red]Invalid: {invalid_count}[/red]"
    )

    if export_path:
        batch_payloads = [r.to_dict() for r in results]
        export_result(output_path=export_path, payload=batch_payloads)
        console.print(f"[green][+] Exported batch results to:[/green] {export_path}")

    return results
