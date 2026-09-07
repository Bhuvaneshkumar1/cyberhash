"""
CSV result export utility.
"""

import csv
from pathlib import Path
from typing import Dict, Any, Union, List


def export_csv(data: Union[Dict[str, Any], List[Dict[str, Any]]], output_path: Path) -> bool:
    """
    Export cracking result dictionary or list of dictionaries to a CSV file.

    :param data: Dictionary or list of dictionaries containing crack results.
    :param output_path: Target Path object.
    :return: True if successful, False otherwise.
    """
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        rows = data if isinstance(data, list) else [data]
        if not rows:
            return False

        fieldnames = list(rows[0].keys())
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        return True
    except Exception:
        return False

