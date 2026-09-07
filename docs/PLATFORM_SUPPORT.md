# CyberHash Platform Support & Compatibility Matrix

**Version**: v1.0.0  
**Supported Operating Systems**: Windows (10/11), Linux (Kernel 4.x+), macOS (11+ Big Sur / Monterey / Ventura / Sonoma / Sequoia).  

---

## Executive Platform Support Summary

CyberHash is engineered to be strictly platform-independent, relying on Python standard library abstractions and `pathlib.Path` for cross-platform file system operations, terminal styling, thread management, and multi-process execution.

CyberHash requires **no administrator or root privileges** on any platform and stores configuration, sessions, and sample wordlists in user-space application data directories.

---

## Detailed Platform Matrix

| Platform | Application Data Location | Default Wordlist Strategy | Hardware & Signal Capabilities | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Windows** | `%LOCALAPPDATA%\.cyberhash\` | **generated sample wordlist** (`sample_wordlist.txt`) | Multi-threaded execution, multi-process (`multiprocessing` spawn), `SIGINT` atomic session saving. | FULLY SUPPORTED |
| **Linux** | `~/.cyberhash/` | **rockyou.txt / rockyou.txt.gz when available** (fallback to generated sample wordlist) | Multi-threaded execution, multi-process fork/spawn, transparent gzip reading, `SIGINT`/`SIGTERM` session saving. | FULLY SUPPORTED |
| **macOS** | `~/.cyberhash/` | **generated sample wordlist fallback** (`sample_wordlist.txt`) | Multi-threaded execution, multi-process spawn, POSIX signal handling, `SIGINT` atomic session saving. | FULLY SUPPORTED |

---

## Verified Platform Checklist (16 Criteria)

### 1. `pathlib` Usage
- **Verification**: `pathlib.Path` is used exclusively across all core components (`config.py`, `wordlists/manager.py`, `session/manager.py`, `output/exporter.py`, `cli.py`, `core/batch.py`, `attacks/distributed.py`).
- **Support Status**: Confirmed across Windows, Linux, and macOS.

### 2. No Hardcoded Windows Separators
- **Verification**: Verified zero hardcoded backslash (`\`) string paths in source code. All path joins use `Path` division (`/`) or `Path` method calls, ensuring cross-platform separator compatibility.
- **Support Status**: Confirmed across all platforms.

### 3. No Linux-Only Imports
- **Verification**: Audited all module imports. Un-guarded Linux-only OS modules (`termios`, `syslog`, `fcntl`, `pwd`, `grp`) are absent.
- **Support Status**: Confirmed.

### 4. No Windows-Only Imports
- **Verification**: Audited all module imports. Un-guarded Windows-only C-bindings or API modules (`win32api`, `win32con`, `msvcrt`) are absent.
- **Support Status**: Confirmed.

### 5. No Administrator Requirement
- **Verification**: Application settings, stored sessions, logs, and sample wordlists are saved in user-writable application data directories (`%LOCALAPPDATA%` or `~/.cyberhash`).
- **Support Status**: Operates fully under non-privileged standard user accounts.

### 6. Correct Application-Data / Session Paths
- **Windows**: `%LOCALAPPDATA%\.cyberhash\sessions\`
- **Linux**: `~/.cyberhash/sessions/`
- **macOS**: `~/.cyberhash/sessions/`
- **Support Status**: Confirmed platform-specific user directory resolution via `get_app_data_dir()`.

### 7. Windows Sample Wordlist Generation
- **Verification**: Automatically generates a deterministic 20-word sample wordlist (`sample_wordlist.txt`) at `%LOCALAPPDATA%\.cyberhash\sample_wordlist.txt` when no `--wordlist` argument is supplied.
- **Support Status**: Confirmed and tested.

### 8. Linux `rockyou.txt` Discovery
- **Verification**: Automatically searches standard system wordlist locations on Linux:
  - `/usr/share/wordlists/rockyou.txt`
  - `/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt`
- **Support Status**: Confirmed and tested via path mocks.

### 9. Linux `rockyou.txt.gz` Support
- **Verification**: Supports transparent reading of compressed gzip wordlists without prior manual extraction:
  - `/usr/share/wordlists/rockyou.txt.gz`
  - `/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.gz`
- **Support Status**: Confirmed using `open_wordlist()` context manager streaming.

### 10. macOS Sample Fallback
- **Verification**: On macOS, CyberHash checks for user-supplied wordlists and gracefully falls back to creating and using the sample wordlist at `~/.cyberhash/sample_wordlist.txt`.
- **Support Status**: Confirmed and tested via macOS platform mocks.

### 11. UTF-8 Handling
- **Verification**: File reads and writes explicitly enforce `encoding="utf-8"` with `errors="ignore"` or `errors="replace"`, ensuring non-UTF-8 binary bytes do not crash the application.
- **Support Status**: Confirmed across plain text, `.gz`, JSON, CSV, and TXT files.

### 12. Rich Terminal Behavior
- **Verification**: Uses `rich.console`, `rich.table`, `rich.progress` for responsive table layouts, banners, and progress updates. Supports `--no-color` for non-ANSI terminals and automated logging pipelines.
- **Support Status**: Confirmed.

### 13. Threading Capabilities
- **Verification**: `ThreadPoolExecutor` worker pool execution in `run_dictionary_attack()` and `run_hybrid_attack()`. Configurable via `--threads N`.
- **Support Status**: Confirmed across Windows, Linux, and macOS.

### 14. Multiprocessing Capabilities
- **Verification**: `distributed_attack()` splits wordlist byte ranges across `multiprocessing.Process` workers with queue-based result collection and `try...finally` process cleanup.
- **Support Status**: Confirmed across Windows, Linux, and macOS.

### 15. Session Persistence & Ctrl+C Recovery
- **Verification**: `SessionManager` provides atomic `.tmp` state file replacement, ID generation, listing, deletion, clearing, and cross-platform `SIGINT` signal handlers.
- **Support Status**: Confirmed across Windows, Linux, and macOS.

### 16. Export Paths
- **Verification**: `export_result()` automatically formats and exports attack results to `.json`, `.csv`, `.txt`, or `.log` files, automatically creating missing parent directories on all platforms.
- **Support Status**: Confirmed.
