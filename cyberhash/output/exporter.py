"""
Unified result export manager supporting automatic format detection (JSON, CSV, TXT).
"""

import time
from pathlib import Path
from typing import Dict, Any, Union, Optional, List

from cyberhash import __version__ as APP_VERSION
from cyberhash.output.json_export import export_json
from cyberhash.output.csv_export import export_csv
from cyberhash.output.txt_export import export_txt


def format_export_payload(
    algorithm: Optional[str] = None,
    candidate: Optional[str] = None,
    method: Optional[str] = None,
    tested: int = 0,
    elapsed: float = 0.0,
    tool_name: str = "CyberHash",
    version: str = APP_VERSION,
    timestamp: Optional[str] = None
) -> Dict[str, Any]:
    """
    Format standard result dictionary payload adhering strictly to required schema.

    :return: Formatted dictionary payload.
    """
    if timestamp is None:
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    return {
        "tool": tool_name,
        "version": version,
        "algorithm": algorithm or "Unknown",
        "candidate": candidate if candidate is not None else "None",
        "method": method or "Unknown",
        "tested": tested,
        "elapsed": round(elapsed, 4),
        "timestamp": timestamp,
    }


def export_result(
    output_path: Union[str, Path],
    algorithm: Optional[str] = None,
    candidate: Optional[str] = None,
    method: Optional[str] = None,
    tested: int = 0,
    elapsed: float = 0.0,
    payload: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = None
) -> bool:
    """
    Export attack results to specified path, automatically selecting format from file extension.

    :param output_path: Destination file path string or Path object.
    :param algorithm: Hashing algorithm name.
    :param candidate: Cracked candidate password or None.
    :param method: Attack method string.
    :param tested: Number of candidate items tested.
    :param elapsed: Seconds spent on search.
    :param payload: Pre-formatted payload dictionary or list of dictionaries (optional).
    :return: True if export succeeds, False otherwise.
    """
    target_path = Path(output_path)

    if payload is None:
        payload = format_export_payload(
            algorithm=algorithm,
            candidate=candidate,
            method=method,
            tested=tested,
            elapsed=elapsed
        )

    ext = target_path.suffix.lower()

    if ext == ".json":
        return export_json(payload, target_path)
    elif ext == ".csv":
        return export_csv(payload, target_path)
    else:
        # Default to TXT for .txt, .log, or unrecognised extensions
        return export_txt(payload, target_path)

