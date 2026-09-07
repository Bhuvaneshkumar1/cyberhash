"""
JSON result export utility.
"""

import json
from pathlib import Path
from typing import Dict, Any, Union, List


def export_json(data: Union[Dict[str, Any], List[Dict[str, Any]]], output_path: Path) -> bool:
    """
    Export cracking result dictionary or list of dictionaries to a JSON file.

    :param data: Dictionary or list of dictionaries containing crack results.
    :param output_path: Target Path object.
    :return: True if successful, False otherwise.
    """
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception:
        return False
