"""
Logging configuration utility for CyberHash.
"""

import logging
import time
from pathlib import Path
from typing import Optional
from cyberhash.config import LOGS_DIR

def setup_logging(logs_dir: Optional[Path] = None, level: int = logging.INFO) -> Path:
    """
    Initialize logging configuration writing to a timestamped log file.

    :param logs_dir: Optional directory path to store logs. Defaults to config.LOGS_DIR.
    :param level: Logging level threshold integer (default: logging.INFO).
    :return: Path to the log file created.
    """
    target_dir = logs_dir or LOGS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    
    log_file = target_dir / f"hashscan_{int(time.time())}.log"
    
    logging.basicConfig(
        filename=str(log_file),
        level=level,
        format="%(asctime)s - %(message)s",
        force=True
    )
    return log_file
