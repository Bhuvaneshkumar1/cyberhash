"""
Unit and integration tests for result export utilities (JSON, CSV, TXT).
"""

import json
import csv
import pytest
from pathlib import Path

from cyberhash.output.json_export import export_json
from cyberhash.output.csv_export import export_csv
from cyberhash.output.txt_export import export_txt
from cyberhash.output.exporter import export_result, format_export_payload


@pytest.fixture
def sample_payload():
    return format_export_payload(
        algorithm="md5",
        candidate="password123",
        method="dictionary",
        tested=500,
        elapsed=1.234,
        timestamp="2026-09-07T20:30:00Z"
    )


def test_json_export_schema(tmp_path, sample_payload):
    json_file = tmp_path / "result.json"
    success = export_json(sample_payload, json_file)

    assert success
    assert json_file.exists()

    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data.get("tool") == "CyberHash"
    assert "version" in data
    assert data.get("algorithm") == "md5"
    assert data.get("candidate") == "password123"
    assert data.get("method") == "dictionary"
    assert data.get("tested") == 500
    assert data.get("elapsed") == 1.234
    assert data.get("timestamp") == "2026-09-07T20:30:00Z"


def test_csv_export_schema(tmp_path, sample_payload):
    csv_file = tmp_path / "result.csv"
    success = export_csv(sample_payload, csv_file)

    assert success
    assert csv_file.exists()

    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) == 1
    row = rows[0]
    assert row.get("tool") == "CyberHash"
    assert row.get("algorithm") == "md5"
    assert row.get("candidate") == "password123"
    assert row.get("method") == "dictionary"
    assert row.get("tested") == "500"


def test_txt_export_format(tmp_path, sample_payload):
    txt_file = tmp_path / "result.txt"
    success = export_txt(sample_payload, txt_file)

    assert success
    assert txt_file.exists()

    content = txt_file.read_text(encoding="utf-8")
    assert "CyberHash Analysis Result" in content
    assert "Algorithm  : md5" in content
    assert "Candidate  : password123" in content
    assert "Method     : dictionary" in content


def test_export_result_auto_dispatch(tmp_path):
    # Nested directory creation & Auto JSON
    json_path = tmp_path / "nested" / "auto.json"
    assert export_result(json_path, algorithm="sha256", candidate="admin", method="mask", tested=10, elapsed=0.5)
    assert json_path.exists()

    # Auto CSV
    csv_path = tmp_path / "auto.csv"
    assert export_result(csv_path, algorithm="sha256", candidate="admin", method="mask", tested=10, elapsed=0.5)
    assert csv_path.exists()

    # Auto TXT
    txt_path = tmp_path / "auto.txt"
    assert export_result(txt_path, algorithm="sha256", candidate="admin", method="mask", tested=10, elapsed=0.5)
    assert txt_path.exists()
