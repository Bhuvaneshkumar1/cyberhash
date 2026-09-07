"""
Platform-independent wordlist loading and resolution module.
"""

import os
import sys
import gzip
import platform
from pathlib import Path
from contextlib import contextmanager
from typing import Optional, List, Tuple, Generator, TextIO

from cyberhash.output.console import console

# Deterministic sample password list for demonstration and testing
SAMPLE_PASSWORDS: List[str] = [
    "password",
    "Password",
    "password123",
    "admin",
    "admin123",
    "welcome",
    "letmein",
    "qwerty",
    "test",
    "test123",
    "123456",
    "12345678",
    "login",
    "cyberhash",
    "master",
    "p@ssword",
    "administrator",
    "iloveyou",
    "sunshine",
    "princess"
]


def get_app_data_dir() -> Path:
    """
    Get user-level application data directory for storing app data without admin privileges.

    :return: Path object to user data directory.
    """
    home = Path.home()
    if platform.system() == "Windows":
        local_app_data = os.getenv("LOCALAPPDATA")
        if local_app_data:
            base_dir = Path(local_app_data)
        else:
            base_dir = home / "AppData" / "Local"
    else:
        base_dir = home

    app_dir = base_dir / ".cyberhash"
    app_dir.mkdir(parents=True, exist_ok=True)
    return app_dir


def ensure_sample_wordlist() -> Path:
    """
    Deterministically generate sample wordlist if it does not already exist.

    :return: Path object to generated sample wordlist file.
    """
    app_dir = get_app_data_dir()
    sample_file = app_dir / "sample_wordlist.txt"

    if not sample_file.exists():
        with open(sample_file, "w", encoding="utf-8") as f:
            for word in SAMPLE_PASSWORDS:
                f.write(f"{word}\n")

    return sample_file


@contextmanager
def open_wordlist(file_path: Path) -> Generator[TextIO, None, None]:
    """
    Context manager to open plain text or gzip compressed wordlist files.

    :param file_path: Path object to target wordlist.
    :yield: TextIO stream interface for reading lines.
    """
    if file_path.suffix.lower() == ".gz":
        f = gzip.open(file_path, "rt", encoding="utf-8", errors="ignore")
    else:
        f = open(file_path, "r", encoding="utf-8", errors="ignore")

    try:
        yield f
    finally:
        f.close()


def resolve_wordlist(
    user_path: Optional[str] = None,
    current_os: Optional[str] = None
) -> Tuple[Path, str]:
    """
    Resolve wordlist file path based on user input, system OS, or sample generator.

    :param user_path: Optional user-supplied path string (--wordlist).
    :param current_os: Optional OS override string (for testing).
    :return: Tuple of (Path object, source_description_string).
    """
    target_os = current_os or platform.system()

    # Priority 1: User-supplied wordlist
    if user_path:
        path = Path(user_path)
        if path.exists():
            return (path, "user supplied")
        else:
            console.print(f"[red]User wordlist not found: {user_path}[/red]")
            sys.exit(1)

    # Priority 2: Linux system rockyou search
    if target_os == "Linux":
        linux_candidate_paths: List[Path] = [
            Path("/usr/share/wordlists/rockyou.txt"),
            Path("/usr/share/wordlists/rockyou.txt.gz"),
            Path("/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt"),
            Path("/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.gz")
        ]
        for candidate in linux_candidate_paths:
            if candidate.exists():
                return (candidate, "system rockyou")

    # Priority 3: Generated sample wordlist (Windows, macOS, or Linux without rockyou)
    sample_path = ensure_sample_wordlist()
    return (sample_path, "generated sample")


def load_wordlist(
    user_path: Optional[str] = None,
    current_os: Optional[str] = None
) -> Path:
    """
    Legacy wrapper for wordlist resolution returning Path object and printing source.

    :param user_path: Optional user-supplied path string.
    :param current_os: Optional OS string override.
    :return: Resolved Path object.
    """
    path, source_label = resolve_wordlist(user_path, current_os)
    console.print(f"[green][+] Wordlist source : {source_label}[/green]")
    return path
