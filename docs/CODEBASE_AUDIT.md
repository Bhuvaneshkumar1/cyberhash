# 🔐 CyberHash — Codebase Audit Report

## 1. Executive Summary

This document provides a comprehensive codebase audit of the **CyberHash** repository prior to architectural refactoring. Every Python source file, configuration file, documentation file, and directory was inspected.

- **Repository**: `https://github.com/Bhuvaneshkumar1/cyberhash`
- **Audit Date**: September 7, 2026
- **Auditor**: Antigravity AI (Google DeepMind)
- **Scope**: Codebase structure, CLI capabilities, runtime stability, platform compatibility, algorithm detection, session handling, attack engines, dependencies, and test suite baseline.

---

## 2. Inspected Files Inventory

| File Path | Description | Lines | Size (Bytes) |
| --- | --- | --- | --- |
| [`cyberhash.py`](file:///d:/cyberhash/cyberhash.py) | Main CLI application, hash engine, attack modes, session handling, UI | 756 | 21,997 |
| [`setup.py`](file:///d:/cyberhash/setup.py) | Package configuration and entry point definitions | 19 | 356 |
| [`requirements.txt`](file:///d:/cyberhash/requirements.txt) | Project Python dependencies | 5 | 45 |
| [`README.md`](file:///d:/cyberhash/README.md) | User documentation and CLI manual | 277 | 5,110 |
| [`wordlists/default_wordlist.txt`](file:///d:/cyberhash/wordlists/default_wordlist.txt) | Bundled fallback wordlist | 65 | 608 |

---

## 3. Current Architecture

CyberHash is structured as a monolithic single-file CLI application (`cyberhash.py`) with entry point binding in `setup.py`.

```
cyberhash/
├── cyberhash.py           # Core Application Logic (Monolith)
│   ├── Logging & UI       # Rich console logging, Figlet banner, ANSI terminal clear
│   ├── Session System     # JSON-based checkpointing & interrupt signal handlers
│   ├── Detection Engine   # Length & regex based hash identification & algorithm resolution
│   ├── Attack Engines     # Dictionary, Rule Engine, Mask Attack, Caesar, ROT13, Base64
│   ├── Multiprocessing    # Distributed worker chunking & ThreadPoolExecutor engine
│   └── Main CLI Runner    # argparse CLI entry point
├── setup.py               # setuptools config (console_scripts: cyberhash=cyberhash:main)
├── requirements.txt       # Dependencies (rich, pyfiglet, passlib, pycryptodome, crcmod)
├── README.md              # Documentation
└── wordlists/
    └── default_wordlist.txt
```

### Architectural Highlights & Component Interconnections
1. **CLI Layer (`main`)**: Uses `argparse` to parse command-line flags (`--hash`, `--wordlist`, `--threads`, `--rules`, `--mask`, `--resume`, `--distributed`, `--benchmark`, `--algo`).
2. **Hash Identification & Resolution**: Uses `identify_hash` and `resolve_algorithms` to determine candidate hash types based on hash length or regex patterns.
3. **Attack Engines**:
   - **Direct & Encoding**: Checks raw string, Base64, ROT13, Caesar shifts (1-25).
   - **Mutation Engine**: Appends/prepends numbers and symbols to dictionary words.
   - **Rule Engine**: Secondary mutation set (`apply_rules`).
   - **Mask Engine**: Evaluates custom format strings (`?d`, `?l`, `?u`, `?s`).
   - **Distributed Engine**: Splits wordlist file into byte ranges for child `multiprocessing.Process` workers.
4. **Execution Layer**: Utilizes `concurrent.futures.ThreadPoolExecutor` for multi-threaded dictionary lookups.

---

## 4. Current CLI Commands

CyberHash is invoked via the `cyberhash` entry point (or `python cyberhash.py`).

| Command / Flag | Syntax Example | Stated Purpose | Status / Defect Note |
| --- | --- | --- | --- |
| `--hash` | `cyberhash --hash 5f4dcc3b5aa765d61d8327deb882cf99` | Target hash value (Required) | Functional |
| `--wordlist` | `cyberhash --hash <hash> --wordlist dict.txt` | Custom wordlist path | Functional |
| `--threads` | `cyberhash --hash <hash> --threads 8` | Thread pool worker count (Default: 4) | Functional |
| `--rules` | `cyberhash --hash <hash> --rules` | Enable rule-based password mutations | **CRITICAL BUG**: Crashes on match due to tuple unpacking mismatch & type error |
| `--mask` | `cyberhash --hash <hash> --mask ?d?d?d?d` | Custom mask attack pattern | **DEFECT**: Works for literal masks, but mask presets (`simple_numeric`, etc.) are dead code |
| `--resume` | `cyberhash --hash <hash> --resume` | Resume interrupted session | **CRITICAL BUG**: Fails to load session due to timestamped session filenames |
| `--distributed` | `cyberhash --hash <hash> --distributed 4` | Multi-process worker splitting | **CRITICAL BUG**: Crashes on match with `NameError` (`start` undefined) & premature join |
| `--benchmark` | `cyberhash --hash <hash> --benchmark` | Run hashing speed benchmark | **DEFECT**: Benchmark runs but does not exit; proceeds to scan wordlist |
| `--algo` | `cyberhash --hash <hash> --algo MD5` | Manually specify target algorithm | Functional when specified, incompatible when list returned |

---

## 5. Baseline Test Suite Results

- **Test Suite Framework**: `pytest` / `unittest`
- **Execution Command**: `python -m pytest` / `python -m unittest discover`
- **Tests Discovered**: 0
- **Tests Executed**: 0
- **Baseline Result**: **NO EXISTING TESTS PRESENT IN REPOSITORY**

> [!NOTE]
> The repository currently lacks any unit or integration tests (`tests/` directory is absent). Running `pytest` confirms `0 items collected`.

---

## 6. Discovered Defects & Vulnerabilities Analysis

The audit uncovered **11 defects** spanning critical runtime crashes, broken CLI parameters, dead code, duplicated logic, and dependency problems.

### Defect Matrix

| ID | Affected File / Function | Category | Severity | Summary of Defect | Recommended Correction |
| --- | --- | --- | --- | --- | --- |
| **DEF-01** | [`cyberhash.py:L75`](file:///d:/cyberhash/cyberhash.py#L75)<br>[`cyberhash.py:L98`](file:///d:/cyberhash/cyberhash.py#L98)<br>[`cyberhash.py:L307`](file:///d:/cyberhash/cyberhash.py#L307) | Broken `--resume` / Session Handling | **HIGH** | `SESSION_FILE` incorporates runtime `time.time()` at startup. Resuming in a new process generates a new timestamp, so `load_session()` checks a non-existent filename and never restores session state. | Use a fixed session file name (e.g. `.cyberhash_session.json`) or search for existing `session_*.json` files. |
| **DEF-02** | [`cyberhash.py:L739`](file:///d:/cyberhash/cyberhash.py#L739)<br>[`cyberhash.py:L209`](file:///d:/cyberhash/cyberhash.py#L209) | Runtime Crash / Broken `--rules` | **HIGH** | `auto_check_word` returns 4 items (`algo, word, method, shift`), but `extended_check_word` returns 3 items (`method, word, shift`). `main()` attempts `algo, w, method, shift = res`, raising `ValueError: not enough values to unpack` on match. | Standardize all check function return values to 4-tuples `(algo, word, method, shift)`. |
| **DEF-03** | [`cyberhash.py:L166`](file:///d:/cyberhash/cyberhash.py#L166)<br>[`cyberhash.py:L725`](file:///d:/cyberhash/cyberhash.py#L725)<br>[`cyberhash.py:L490`](file:///d:/cyberhash/cyberhash.py#L490) | Type Incompatibility / Crash | **HIGH** | `resolve_algorithms` returns a `list` of strings (e.g. `['MD5', 'NTLM']`). `main()` passes this `list` to `extended_check_word` and `compute_hash`. `compute_hash` compares `algo == 'MD5'`, which fails for a `list` and raises `ValueError: Unsupported algorithm`. | Pass a single algorithm string or iterate over algorithm list within worker routines. |
| **DEF-04** | [`cyberhash.py:L706`](file:///d:/cyberhash/cyberhash.py#L706) | Runtime Crash / Broken `--distributed` | **HIGH** | Line 706 calls `result(word, algo[0], method, shift, start, tested)` on distributed match, but `start` and `tested` are only initialized at line 708. Triggers `NameError: name 'start' is not defined`. | Move `start = time.time()` and counter initialization prior to execution blocks. |
| **DEF-05** | [`cyberhash.py:L416`](file:///d:/cyberhash/cyberhash.py#L416) | Process Deadlock / Orphan Workers | **HIGH** | `p.join(timeout=0.1)` in `distributed_attack` waits only 100ms per worker. Workers taking longer are abandoned as background orphans while main returns `None` immediately. | Properly await worker process completion or use `multiprocessing.Pool` with result queues. |
| **DEF-06** | [`cyberhash.py:L690`](file:///d:/cyberhash/cyberhash.py#L690) | Control Flow / Broken `--benchmark` | **MEDIUM** | Passing `--benchmark` executes `benchmark()`, but `main()` does not exit; it proceeds into wordlist loading and cracking execution. | Add `sys.exit(0)` or `return` immediately following benchmark completion. |
| **DEF-07** | [`cyberhash.py:L181`](file:///d:/cyberhash/cyberhash.py#L181)<br>[`cyberhash.py:L559`](file:///d:/cyberhash/cyberhash.py#L559) | Code Duplication & Performance | **MEDIUM** | Both `apply_rules()` and `mutations()` define identical string/byte transformations. `check_word` calls `mutations()` and `extended_check_word` calls `apply_rules()`, causing exponential redundant hash calculations. | Consolidate mutation logic into a single rule engine module. |
| **DEF-08** | [`cyberhash.py:L228`](file:///d:/cyberhash/cyberhash.py#L228)<br>[`cyberhash.py:L474`](file:///d:/cyberhash/cyberhash.py#L474) | Dead Code | **LOW** | `MASK_PRESETS` dictionary is defined but never referenced in mask attack. `detect_algorithm()` is defined but never invoked (superseded by `possible_algorithms`). | Remove dead code or integrate preset lookup into mask attack CLI parser. |
| **DEF-09** | [`requirements.txt:L4-5`](file:///d:/cyberhash/requirements.txt#L4-5)<br>[`setup.py:L11-12`](file:///d:/cyberhash/setup.py#L11-12) | Dependency Inflation | **LOW** | `pycryptodome` and `crcmod` are declared as dependencies in `requirements.txt` and `setup.py`, but neither is imported in the codebase (`zlib.crc32` is used). | Remove unused dependencies from `requirements.txt` and `setup.py`. |
| **DEF-10** | [`cyberhash.py:L430`](file:///d:/cyberhash/cyberhash.py#L430)<br>[`cyberhash.py:L490`](file:///d:/cyberhash/cyberhash.py#L490) | Unhandled Algorithm Signatures | **MEDIUM** | `HASH_SIGNATURES` detects `bcrypt`, `sha512crypt`, `sha256crypt`, `md5crypt`, but `compute_hash` contains no handler for these, raising `ValueError: Unsupported algorithm`. | Add crypt algorithm handlers or restrict detection to supported hash types. |
| **DEF-11** | [`cyberhash.py:L38`](file:///d:/cyberhash/cyberhash.py#L38)<br>[`cyberhash.py:L124`](file:///d:/cyberhash/cyberhash.py#L124)<br>[`cyberhash.py:L584`](file:///d:/cyberhash/cyberhash.py#L584) | Platform Incompatibilities | **LOW** | `signal.SIGTSTP` is Linux-only (handled by try-except); ANSI clear code `\033[2J\033[H` lacks native Windows cmd support; hardcoded `/usr/share/wordlists/` Linux paths fail silently on Windows. | Implement cross-platform console clearing (`rich` / `os.name`), clean signal handling, and pathlib path resolution. |

---

## 7. Recommended Action Plan

Before implementing architectural refactoring or new attack capabilities:
1. **Fix Critical Runtime Crashes**: Resolve DEF-01 through DEF-06 to ensure existing CLI flags (`--rules`, `--resume`, `--distributed`, `--benchmark`, `--mask`) function reliably without raising exceptions.
2. **Establish Test Suite**: Create comprehensive unit tests in a `tests/` directory covering:
   - Hash identification (`identify_hash`, `possible_algorithms`)
   - Hash calculation (`compute_hash` for MD5, SHA1, SHA256, NTLM, etc.)
   - Encoding transforms (Base64, ROT13, Caesar shifts)
   - Rule mutations and mask pattern generation
   - Session load/save state serialization
3. **Clean Up Dependencies & Dead Code**: Purge unused dependencies (`pycryptodome`, `crcmod`) and unreferenced functions/constants.
