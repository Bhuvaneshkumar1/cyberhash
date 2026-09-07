"""
Global configuration constants, models, and platform-independent settings for CyberHash.
"""

import json
import logging
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, Union

from cyberhash.wordlists.manager import get_app_data_dir

# Default paths using pathlib.Path
BASE_DIR: Path = Path(__file__).resolve().parent.parent
DEFAULT_WORDLIST_PATH: Path = BASE_DIR / "wordlists" / "default_wordlist.txt"
SESSION_FILE_PATH: Path = Path("cyberhash_session.json")
LOGS_DIR: Path = Path("logs")

# Mask attack token mappings
MASK_SETS: Dict[str, str] = {
    "?l": "abcdefghijklmnopqrstuvwxyz",
    "?u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "?d": "0123456789",
    "?s": "!@#$%^&*"
}

# Mask attack presets
MASK_PRESETS: Dict[str, str] = {
    "simple_numeric": "?d?d?d?d",
    "common_password": "?l?l?l?l?d?d",
    "capital_word_number": "?u?l?l?l?l?d?d",
    "word_year": "?l?l?l?l?d?d?d?d",
    "admin_style": "admin?d?d"
}

# Regex signatures for algorithm identification
HASH_SIGNATURES = [
    {"name": "bcrypt", "regex": r"^\$2[aby]\$\d+\$.*"},
    {"name": "sha512crypt", "regex": r"^\$6\$.*"},
    {"name": "sha256crypt", "regex": r"^\$5\$.*"},
    {"name": "md5crypt", "regex": r"^\$1\$.*"},
]


@dataclass
class CyberHashConfig:
    """
    Data model representing CyberHash runtime settings.
    """
    threads: int = 4
    default_wordlist: Optional[str] = None
    rule_depth: int = 1
    output_format: str = "table"
    quiet: bool = False
    verbose: bool = False
    logging: bool = True
    session_directory: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CyberHashConfig":
        threads = data.get("threads", 4)
        if not isinstance(threads, int) or threads <= 0:
            raise ValueError(f"Invalid 'threads' configuration value: {threads} (must be a positive integer)")

        rule_depth = data.get("rule_depth", 1)
        if not isinstance(rule_depth, int) or rule_depth < 1:
            raise ValueError(f"Invalid 'rule_depth' configuration value: {rule_depth} (must be an integer >= 1)")

        quiet = data.get("quiet", False)
        if not isinstance(quiet, bool):
            raise ValueError(f"Invalid 'quiet' configuration value: {quiet} (must be boolean)")

        verbose = data.get("verbose", False)
        if not isinstance(verbose, bool):
            raise ValueError(f"Invalid 'verbose' configuration value: {verbose} (must be boolean)")

        log_setting = data.get("logging", True)
        if not isinstance(log_setting, bool):
            raise ValueError(f"Invalid 'logging' configuration value: {log_setting} (must be boolean)")

        output_format = str(data.get("output_format", "table"))
        default_wordlist = data.get("default_wordlist")
        if default_wordlist is not None:
            default_wordlist = str(default_wordlist)

        session_directory = data.get("session_directory")
        if session_directory is not None:
            session_directory = str(session_directory)

        return cls(
            threads=threads,
            default_wordlist=default_wordlist,
            rule_depth=rule_depth,
            output_format=output_format,
            quiet=quiet,
            verbose=verbose,
            logging=log_setting,
            session_directory=session_directory
        )


def resolve_default_config_path() -> Optional[Path]:
    """
    Search standard default config file locations in current dir and user home app data.

    :return: Path object if found, None otherwise.
    """
    cwd_config = Path.cwd() / "cyberhash.json"
    if cwd_config.exists():
        return cwd_config

    user_config = get_app_data_dir() / "cyberhash.json"
    if user_config.exists():
        return user_config

    return None


def load_config(config_path: Optional[Union[str, Path]] = None) -> CyberHashConfig:
    """
    Load configuration from JSON file or return default configuration if missing.

    :param config_path: Optional custom Path to configuration file.
    :return: CyberHashConfig object.
    :raises ValueError: If config file exists but contains invalid JSON or invalid option types.
    """
    target_path: Optional[Path] = None

    if config_path:
        target_path = Path(config_path)
    else:
        target_path = resolve_default_config_path()

    if not target_path or not target_path.exists():
        # Missing configuration file is normal
        return CyberHashConfig()

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("Configuration file content must be a JSON object.")
            return CyberHashConfig.from_dict(data)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in configuration file '{target_path}': {e}")
    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise ValueError(f"Failed to load configuration file '{target_path}': {e}")


def save_config(config: CyberHashConfig, target_path: Union[str, Path]) -> bool:
    """
    Save configuration instance to JSON file atomically.

    :param config: CyberHashConfig instance.
    :param target_path: Output file path.
    :return: True if saved, False otherwise.
    """
    path_obj = Path(target_path)
    temp_obj = path_obj.with_suffix(".tmp")
    try:
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        with open(temp_obj, "w", encoding="utf-8") as f:
            json.dump(config.to_dict(), f, indent=2)
        temp_obj.replace(path_obj)
        return True
    except Exception as e:
        logging.error(f"Failed to save configuration to '{target_path}': {e}")
        if temp_obj.exists():
            try:
                temp_obj.unlink()
            except Exception:
                pass
        return False
