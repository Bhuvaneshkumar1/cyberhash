"""
Cross-platform system and terminal utility functions.
"""

import os
import shutil
import signal
import sys
from typing import Callable, Any

def clear_terminal() -> None:
    """
    Clear the terminal screen in a cross-platform compatible manner.
    """
    if os.name == 'nt':
        os.system('cls')
    else:
        print("\033[2J\033[H", end="")

def get_terminal_width(default: int = 80) -> int:
    """
    Get the current terminal width in columns.

    :param default: Default width if terminal size cannot be retrieved.
    :return: Number of columns in terminal.
    """
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return default

def register_interrupt_handler(handler: Callable[[int, Any], None]) -> None:
    """
    Register signal handlers for SIGINT and SIGTERM safely across platforms.

    :param handler: Function to call on interrupt signal.
    """
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
    if hasattr(signal, 'SIGTSTP'):
        try:
            signal.signal(signal.SIGTSTP, handler)
        except (AttributeError, ValueError):
            pass
