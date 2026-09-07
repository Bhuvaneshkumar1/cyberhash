"""
Human-readable text result export utility.
"""

from pathlib import Path
from typing import Dict, Any, Union, List


def export_txt(data: Union[Dict[str, Any], List[Dict[str, Any]]], output_path: Path) -> bool:
    """
    Export cracking result dictionary or list of dictionaries to a human-readable TXT file.

    :param data: Dictionary or list of dictionaries containing crack results.
    :param output_path: Target Path object.
    :return: True if successful, False otherwise.
    """
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        items = data if isinstance(data, list) else [data]
        lines = [
            "==================================================",
            "CyberHash Analysis Results",
            "==================================================",
        ]
        for idx, item in enumerate(items, 1):
            lines.extend([
                f"--- Item {idx} ---",
                f"Target Hash: {item.get('target_hash', '-')}",
                f"Status     : {item.get('status', '-')}",
                f"Algorithm  : {item.get('algorithm', 'Unknown')}",
                f"Candidate  : {item.get('candidate', 'None')}",
                f"Method     : {item.get('method', 'Unknown')}",
                f"Tested     : {item.get('tested', 0)}",
                f"Elapsed    : {item.get('elapsed', 0.0):.2f}s",
                ""
            ])
        lines.append("==================================================")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return True
    except Exception:
        return False

