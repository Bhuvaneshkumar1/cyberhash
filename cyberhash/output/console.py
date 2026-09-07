"""
Rich console UI rendering and result table display module.
"""

import time
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align

try:
    from pyfiglet import Figlet
except ImportError:
    Figlet = None

from cyberhash.utils.platform import get_terminal_width

console = Console()


def render_banner() -> None:
    """
    Render centered ASCII CyberHash banner and information panel.
    """
    width = get_terminal_width()

    if Figlet is not None:
        try:
            fig = Figlet(font="slant")
            title = fig.renderText("CyberHash")
            centered_title = "\n".join(line.center(width) for line in title.splitlines())
            console.print(f"[cyan]{centered_title}[/cyan]")
        except Exception:
            console.print(Align.center("[bold cyan]CyberHash[/bold cyan]"))
    else:
        console.print(Align.center("[bold cyan]CyberHash[/bold cyan]"))

    panel_text = (
        "[bold yellow]Cyber Hash Analyzer v3.0[/bold yellow]\n"
        "[white]Professional Hash Analysis Utility[/white]"
    )

    console.print(
        Align.center(
            Panel(
                Align.center(panel_text),
                border_style="cyan",
                width=max(20, width - 10)
            )
        )
    )


def display_result(
    word: str,
    algo: str,
    method: str,
    shift: Optional[int],
    start_time: float,
    count: int
) -> None:
    """
    Display structured result table when a match is found.

    :param word: Cracked password text.
    :param algo: Algorithm name string.
    :param method: Attack/encoding method used.
    :param shift: Caesar shift amount if applicable.
    :param start_time: Execution start timestamp.
    :param count: Total words tested.
    """
    table = Table(title="HASH CRACK RESULT")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Word", word)
    table.add_row("Algorithm", algo)
    table.add_row("Method", method)

    if shift is not None:
        table.add_row("Shift", str(shift))

    table.add_row("Words Tested", str(count))
    table.add_row("Runtime", f"{time.time() - start_time:.2f}s")

    console.print(table)
