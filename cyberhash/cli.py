"""
Main command-line interface entry point for CyberHash.
"""

import sys
import time
import logging
import argparse
from pathlib import Path
from typing import Optional, List
from rich.table import Table

from cyberhash import __version__ as APP_VERSION
from cyberhash.config import load_config, CyberHashConfig
from cyberhash.core.detector import validate_hash, identify_hash
from cyberhash.core.resolver import resolve_algorithms
from cyberhash.attacks.dictionary import run_dictionary_attack
from cyberhash.attacks.mask import run_mask_attack
from cyberhash.attacks.hybrid import run_hybrid_attack
from cyberhash.attacks.distributed import distributed_attack
from cyberhash.attacks.rules import RuleEngine
from cyberhash.session.manager import SessionManager, generate_stable_session_id
from cyberhash.wordlists.manager import resolve_wordlist, ensure_sample_wordlist, load_wordlist
from cyberhash.wordlists.statistics import get_wordlist_info
from cyberhash.benchmark.engine import run_benchmark
from cyberhash.output.console import render_banner, console
from cyberhash.output.exporter import export_result
from cyberhash.utils.platform import clear_terminal
from cyberhash.utils.logging import setup_logging


def main(args_list: Optional[List[str]] = None) -> None:
    """
    CLI main execution routine.

    :param args_list: Optional argument string list for testing or direct invocation.
    """
    parser = argparse.ArgumentParser(
        description="Cyber Hash Analyzer - High Performance Hash Analysis & Verification Platform",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # 1. Target & Input Options
    g_target = parser.add_argument_group("Target & Input Options")
    g_target.add_argument("--hash", help="Single target hash string to analyze/verify")
    g_target.add_argument("--hash-file", help="Path to text file containing target hashes (one per line)")
    g_target.add_argument("--algo", help="Manually specify target hash algorithm (e.g., MD5, SHA256)")

    # 2. Wordlist Options
    g_wordlist = parser.add_argument_group("Wordlist Options")
    g_wordlist.add_argument("--wordlist", help="Custom single wordlist file path")
    g_wordlist.add_argument("--wordlists", nargs="+", help="Multiple wordlist file paths")
    g_wordlist.add_argument("--wordlist-info", nargs="?", const=True, help="Display metadata & statistics for wordlist (optional path)")
    g_wordlist.add_argument("--stats", action="store_true", help="Display statistics for target wordlist")
    g_wordlist.add_argument("--generate-wordlist", action="store_true", help="Generate bundled sample wordlist and output path")

    # 3. Attack & Mutation Options
    g_attack = parser.add_argument_group("Attack & Mutation Options")
    g_attack.add_argument("--mask", help="Mask pattern string (e.g. '?l?l?d?d') or preset name")
    g_attack.add_argument("--hybrid", action="store_true", help="Enable hybrid dictionary + mask attack mode")
    g_attack.add_argument("--hybrid-mode", choices=["suffix", "prefix", "both"], default="suffix", help="Hybrid mask positioning (default: suffix)")
    g_attack.add_argument("--hybrid-max-per-word", type=int, default=1000, help="Maximum mask variations per word (default: 1000)")
    g_attack.add_argument("--rules", action="store_true", help="Enable rule engine password mutations")
    g_attack.add_argument("--rules-only", action="store_true", help="Run only rule-mutated candidates")
    g_attack.add_argument("--rules-file", help="Path to custom rule transformation text file")
    g_attack.add_argument("--rule-depth", type=int, default=None, help="Composition depth for rule engine (default: 1)")

    # 4. Performance & Distributed
    g_perf = parser.add_argument_group("Performance & Distributed Options")
    g_perf.add_argument("--threads", type=int, default=None, help="Number of worker threads (default: 4)")
    g_perf.add_argument("--distributed", type=int, help="Number of multi-process worker processes")

    # 5. Session Management
    g_session = parser.add_argument_group("Session Management Options")
    g_session.add_argument("--resume", action="store_true", help="Resume state for current target hash")
    g_session.add_argument("--session-id", help="Explicit session ID to checkpoint or resume")
    g_session.add_argument("--session-list", action="store_true", help="List all stored saved session checkpoints")
    g_session.add_argument("--session-resume", help="Resume specific saved session checkpoint by ID")
    g_session.add_argument("--session-delete", help="Delete specific saved session checkpoint by ID")
    g_session.add_argument("--session-clear", action="store_true", help="Clear all stored session checkpoint files")

    # 6. Benchmarking Options
    g_bench = parser.add_argument_group("Benchmarking Options")
    g_bench.add_argument("--benchmark", action="store_true", help="Run algorithm performance benchmark")
    g_bench.add_argument("--benchmark-duration", type=float, default=1.0, help="Time budget in seconds per algorithm test (default: 1.0)")

    # 7. Output & Formatting Options
    g_out = parser.add_argument_group("Output & Formatting Options")
    g_out.add_argument("--export", help="Output file path for saving crack/batch results (.json, .csv, .txt)")
    g_out.add_argument("--quiet", action="store_true", help="Suppress non-essential console logs and banner")
    g_out.add_argument("--verbose", action="store_true", help="Enable verbose execution output")
    g_out.add_argument("--debug", action="store_true", help="Enable debug logging output")
    g_out.add_argument("--no-color", action="store_true", help="Disable ANSI color styling in console output")

    # 8. Configuration & Information
    g_config = parser.add_argument_group("Configuration & Information Options")
    g_config.add_argument("--config", help="Path to custom JSON configuration file")
    g_config.add_argument("--show-config", action="store_true", help="Display active configuration settings")
    g_config.add_argument("--version", action="store_true", help="Display CyberHash version and exit")

    args = parser.parse_args(args_list)

    # Global Option: --version
    if args.version:
        console.print(f"CyberHash v{APP_VERSION}")
        return

    # Global Option: --no-color
    if args.no_color:
        console.no_color = True

    # Global Logging Setup
    log_level = logging.DEBUG if args.debug else (logging.INFO if args.verbose else logging.WARNING)
    setup_logging(level=log_level)

    # Argument Conflict Validation
    if args.quiet and args.verbose:
        parser.error("Cannot specify both --quiet and --verbose")

    if args.hash and args.hash_file:
        parser.error("Cannot specify both --hash and --hash-file")

    if args.hybrid and not args.mask:
        parser.error("Hybrid attack mode requires a mask pattern (--mask)")

    # Strict Path Existence Validation (No Silent Fallback!)
    if args.config and not Path(args.config).exists():
        parser.error(f"Configuration file not found: {args.config}")

    if args.hash_file and not Path(args.hash_file).exists():
        parser.error(f"Batch hash file not found: {args.hash_file}")

    if args.rules_file and not Path(args.rules_file).exists():
        parser.error(f"Rules file not found: {args.rules_file}")

    if args.wordlist and not Path(args.wordlist).exists():
        parser.error(f"Wordlist file not found: {args.wordlist}")

    if args.wordlists:
        for wp in args.wordlists:
            if not Path(wp).exists():
                parser.error(f"Wordlist file not found: {wp}")

    if not args.quiet:
        clear_terminal()
        render_banner()

    # Load Configuration
    try:
        cfg = load_config(args.config)
    except ValueError as e:
        console.print(f"[red]Configuration Error:[/red] {e}")
        sys.exit(1)

    # Apply Configuration Overrides
    if args.quiet:
        cfg.quiet = True
    if args.verbose:
        cfg.verbose = True
    if args.threads is not None:
        cfg.threads = args.threads
    if args.rule_depth is not None:
        cfg.rule_depth = args.rule_depth

    # Flag: --show-config
    if args.show_config:
        table = Table(title="ACTIVE CONFIGURATION")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Threads", str(cfg.threads))
        table.add_row("Default Wordlist", str(cfg.default_wordlist or "-"))
        table.add_row("Rule Depth", str(cfg.rule_depth))
        table.add_row("Output Format", cfg.output_format)
        table.add_row("Quiet", str(cfg.quiet))
        table.add_row("Verbose", str(cfg.verbose))
        table.add_row("Logging", str(cfg.logging))
        table.add_row("Session Directory", str(cfg.session_directory or "-"))
        console.print(table)
        return

    # Flag: --generate-wordlist
    if args.generate_wordlist:
        sample_path = ensure_sample_wordlist()
        if not cfg.quiet:
            console.print(f"[green][+] Sample wordlist generated at:[/green] {sample_path}")
        return

    # Flag: --benchmark
    if args.benchmark:
        run_benchmark(
            target_algo=args.algo,
            duration_per_algo=args.benchmark_duration,
            export_path=args.export
        )
        return

    session_mgr = SessionManager()

    # CLI Command: --session-list
    if args.session_list:
        sessions = session_mgr.list_sessions()
        if not sessions:
            console.print("[yellow]No stored session checkpoints found.[/yellow]")
            return

        table = Table(title="STORED SESSIONS")
        table.add_column("Session ID", style="cyan")
        table.add_column("Target Hash", style="yellow")
        table.add_column("Mode", style="green")
        table.add_column("Tested", style="magenta")
        table.add_column("Last Updated", style="white")

        for s in sessions:
            updated_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s.updated_at))
            table.add_row(
                s.session_id,
                s.target_hash[:12] + "...",
                s.attack_mode,
                str(s.candidates_tested),
                updated_str
            )
        console.print(table)
        return

    # CLI Command: --session-delete SESSION_ID
    if args.session_delete:
        success = session_mgr.delete_session(args.session_delete)
        if success:
            console.print(f"[green][+] Session '{args.session_delete}' deleted successfully.[/green]")
        else:
            console.print(f"[red][-] Session '{args.session_delete}' not found or could not be deleted.[/red]")
        return

    # CLI Command: --session-clear
    if args.session_clear:
        count = session_mgr.clear_all_sessions()
        console.print(f"[green][+] Cleared {count} stored session checkpoint files.[/green]")
        return

    # Handle --session-resume or --resume
    resume_target_id = args.session_resume or args.session_id
    if args.resume and not resume_target_id and args.hash:
        resume_target_id = generate_stable_session_id(args.hash, "hybrid" if args.hybrid else ("mask" if args.mask else "dictionary"))

    if resume_target_id:
        resumed_session_data = session_mgr.load_session(resume_target_id)
        if resumed_session_data:
            if not cfg.quiet:
                console.print(f"[green][+] Resuming session '{resumed_session_data.session_id}'[/green]")
            args.hash = resumed_session_data.target_hash
            if resumed_session_data.algorithms:
                args.algo = resumed_session_data.algorithms[0]
            if resumed_session_data.wordlist_paths:
                args.wordlists = resumed_session_data.wordlist_paths
            args.mask = resumed_session_data.mask
        else:
            console.print(f"[red][-] Saved session '{resume_target_id}' not found.[/red]")
            sys.exit(1)

    # Resolve target wordlist paths
    wordlist_paths: List[Path] = []
    if args.wordlists:
        for wp in args.wordlists:
            wordlist_paths.append(Path(wp))
        if not cfg.quiet:
            console.print(f"[green][+] Wordlist source : user supplied ({len(wordlist_paths)} files)[/green]")
    elif args.wordlist:
        wordlist_paths.append(Path(args.wordlist))

    # Flag: --wordlist-info / --stats
    if args.wordlist_info or args.stats:
        target_info_path: Optional[Path] = None
        if isinstance(args.wordlist_info, str):
            target_info_path = Path(args.wordlist_info)
        elif wordlist_paths:
            target_info_path = wordlist_paths[0]
        else:
            target_info_path = resolve_wordlist(None)[0]

        source_label = "user supplied" if (isinstance(args.wordlist_info, str) or args.wordlist or args.wordlists) else resolve_wordlist(None)[1]
        info = get_wordlist_info(target_info_path, source_label)

        table = Table(title="WORDLIST ANALYSIS & STATISTICS")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("File Path", info["path"])
        table.add_row("File Size", f"{info['file_size']} bytes")
        table.add_row("Line Count", str(info["line_count"]))
        table.add_row("Unique Count", str(info["unique_count"]))
        table.add_row("Duplicate Count", str(info["duplicate_count"]))
        table.add_row("Empty Lines", str(info["empty_lines"]))
        table.add_row("Average Length", f"{info['average_length']:.2f}")
        table.add_row("Minimum Length", str(info["min_length"]))
        table.add_row("Maximum Length", str(info["max_length"]))
        table.add_row("Numeric-Only Count", str(info["numeric_only_count"]))
        table.add_row("Alphabetic-Only Count", str(info["alphabetic_only_count"]))
        table.add_row("Mixed Count", str(info["mixed_count"]))
        table.add_row("Compressed (.gz)", "Yes" if info["is_compressed"] else "No")
        table.add_row("Platform", info["platform"])

        console.print(table)
        return

    # Handle Batch Hash Mode (--hash-file)
    if args.hash_file:
        if not wordlist_paths:
            wordlist_paths.append(load_wordlist(None))

        rules_file_path = Path(args.rules_file) if args.rules_file else None
        try:
            rule_engine = RuleEngine(depth=cfg.rule_depth, rules_file=rules_file_path)
        except ValueError as e:
            console.print(f"[red]Rule Engine Error:[/red] {e}")
            sys.exit(1)

        from cyberhash.core.batch import run_batch_processing
        run_batch_processing(
            hash_file_path=Path(args.hash_file),
            wordlist_paths=wordlist_paths,
            algo_override=args.algo,
            mask=args.mask,
            hybrid=args.hybrid,
            hybrid_mode=args.hybrid_mode,
            hybrid_max_per_word=args.hybrid_max_per_word,
            use_rules=args.rules,
            rules_only=args.rules_only,
            rule_engine=rule_engine,
            threads=cfg.threads,
            export_path=args.export
        )
        return

    if not args.hash:
        parser.error("one of the arguments --hash or --hash-file is required")

    target_hash = args.hash.lower()

    if not validate_hash(target_hash):
        console.print("[red]Invalid hash format[/red]")
        sys.exit(1)

    fingerprint = identify_hash(target_hash)
    if not cfg.quiet:
        console.print(f"[cyan][*] Hash fingerprint:[/cyan] {fingerprint}")

    algos = resolve_algorithms(args.algo, target_hash)
    if not algos:
        console.print("[red]Unable to determine possible algorithms[/red]")
        sys.exit(1)

    if not cfg.quiet:
        console.print(f"[yellow][*] Possible algorithms:[/yellow] {', '.join(algos)}")

    # Setup active SessionManager instance
    attack_mode_name = "hybrid" if args.hybrid else ("mask" if args.mask else "dictionary")
    active_session_mgr = SessionManager(
        session_id=resume_target_id,
        target_hash=target_hash,
        algorithms=algos,
        wordlist_paths=wordlist_paths,
        attack_mode=attack_mode_name,
        mask=args.mask
    )
    active_session_mgr.setup_interrupt_handler()

    effective_threads = cfg.threads
    effective_rule_depth = cfg.rule_depth

    # Initialize Rule Engine v2
    rules_file_path = Path(args.rules_file) if args.rules_file else None
    try:
        rule_engine = RuleEngine(
            depth=effective_rule_depth,
            rules_file=rules_file_path
        )
    except ValueError as e:
        console.print(f"[red]Rule Engine Error:[/red] {e}")
        sys.exit(1)

    # Hybrid Attack Mode
    if args.hybrid:
        if not wordlist_paths:
            wordlist_paths.append(load_wordlist(None))

        res = run_hybrid_attack(
            wordlist_paths=wordlist_paths,
            mask=args.mask,
            target_hash=target_hash,
            algos=algos,
            mode=args.hybrid_mode,
            max_per_word=args.hybrid_max_per_word,
            threads=effective_threads
        )
        if args.export:
            export_result(
                output_path=args.export,
                algorithm=res.algorithm or algos[0],
                candidate=res.candidate,
                method=res.method or "hybrid",
                tested=res.tested,
                elapsed=res.elapsed
            )
            if not cfg.quiet:
                console.print(f"[green][+] Exported results to:[/green] {args.export}")

        if res.found:
            active_session_mgr.delete_session()
            return

    # Mask Attack Mode
    if args.mask and not args.hybrid:
        res = run_mask_attack(args.mask, target_hash, algos)
        if args.export:
            export_result(
                output_path=args.export,
                algorithm=res.algorithm or algos[0],
                candidate=res.candidate,
                method=res.method or "mask",
                tested=res.tested,
                elapsed=res.elapsed
            )
            if not cfg.quiet:
                console.print(f"[green][+] Exported results to:[/green] {args.export}")

        if res.found:
            active_session_mgr.delete_session()
            return

    if not wordlist_paths:
        wordlist_paths.append(load_wordlist(None))

    # Distributed Mode
    if args.distributed:
        success = distributed_attack(wordlist_paths[0], target_hash, algos[0], args.distributed)
        if args.export:
            export_result(
                output_path=args.export,
                algorithm=algos[0],
                candidate=None,
                method="distributed",
                tested=0,
                elapsed=0.0
            )
            if not cfg.quiet:
                console.print(f"[green][+] Exported results to:[/green] {args.export}")

        if success:
            active_session_mgr.delete_session()
            return

    # Dictionary & Rule Attack Mode
    res = run_dictionary_attack(
        wordlist_paths=wordlist_paths,
        target_hash=target_hash,
        algos=algos,
        threads=effective_threads,
        use_rules=args.rules,
        rules_only=args.rules_only,
        rule_engine=rule_engine,
        session_mgr=active_session_mgr
    )
    if args.export:
        export_result(
            output_path=args.export,
            algorithm=res.algorithm or algos[0],
            candidate=res.candidate,
            method=res.method or "dictionary",
            tested=res.tested,
            elapsed=res.elapsed
        )
        if not cfg.quiet:
            console.print(f"[green][+] Exported results to:[/green] {args.export}")

    if res.found:
        active_session_mgr.delete_session()


if __name__ == "__main__":
    main()
