"""
Comprehensive unit and integration tests for platform-independent wordlist management system.
"""

import gzip
import pytest
from pathlib import Path
from unittest.mock import patch

from cyberhash.wordlists.manager import (
    resolve_wordlist,
    ensure_sample_wordlist,
    open_wordlist,
    get_app_data_dir,
    load_wordlist
)
from cyberhash.wordlists.statistics import get_wordlist_info


def test_windows_path_behavior_and_sample_gen(tmp_path):
    """Test Windows platform resolution automatically generates sample wordlist in app data dir."""
    with patch("cyberhash.wordlists.manager.get_app_data_dir", return_value=tmp_path):
        path, source = resolve_wordlist(user_path=None, current_os="Windows")
        assert source == "generated sample"
        assert path.exists()
        assert path.name == "sample_wordlist.txt"


def test_linux_path_behavior_rockyou_txt():
    """Test Linux platform detection locating system rockyou.txt (mocked)."""
    target = Path("/usr/share/wordlists/rockyou.txt")
    with patch.object(Path, "exists", autospec=True) as mock_exists:
        mock_exists.side_effect = lambda self: self == target
        path, source = resolve_wordlist(user_path=None, current_os="Linux")
        assert source == "system rockyou"
        assert path == target


def test_linux_path_behavior_rockyou_gz():
    """Test Linux platform detection locating system rockyou.txt.gz (mocked)."""
    target = Path("/usr/share/wordlists/rockyou.txt.gz")
    with patch.object(Path, "exists", autospec=True) as mock_exists:
        mock_exists.side_effect = lambda self: self == target
        path, source = resolve_wordlist(user_path=None, current_os="Linux")
        assert source == "system rockyou"
        assert path == target


def test_macos_fallback_sample_gen(tmp_path):
    """Test macOS platform fallback to sample wordlist."""
    with patch("cyberhash.wordlists.manager.get_app_data_dir", return_value=tmp_path):
        path, source = resolve_wordlist(user_path=None, current_os="Darwin")
        assert source == "generated sample"
        assert path.exists()


def test_user_supplied_wordlist_priority(tmp_path):
    """Test that user-supplied --wordlist always takes top priority regardless of OS."""
    user_file = tmp_path / "custom.txt"
    user_file.write_text("custompass\n", encoding="utf-8")

    path, source = resolve_wordlist(user_path=str(user_file), current_os="Linux")
    assert source == "user supplied"
    assert path == user_file


def test_missing_user_wordlist(tmp_path):
    """Test that missing user wordlist exits with error code 1."""
    non_existent = str(tmp_path / "does_not_exist.txt")
    with pytest.raises(SystemExit) as exc_info:
        resolve_wordlist(user_path=non_existent)
    assert exc_info.value.code == 1


def test_gzip_transparent_reading(tmp_path):
    """Test opening and reading .gz compressed wordlist files transparently."""
    gz_file = tmp_path / "test.txt.gz"
    content = "word1\nword2\nword3\n"
    with gzip.open(gz_file, "wt", encoding="utf-8") as f:
        f.write(content)

    lines = []
    with open_wordlist(gz_file) as f:
        for line in f:
            lines.append(line.strip())

    assert lines == ["word1", "word2", "word3"]


def test_corrupted_gzip_wordlist_handling(tmp_path):
    """Test malformed gzip wordlist handling without application crash."""
    corrupt_gz = tmp_path / "corrupt.txt.gz"
    corrupt_gz.write_bytes(b"NOT_A_GZIP_FILE_HEADER_12345")

    with open_wordlist(corrupt_gz) as f:
        with pytest.raises(Exception):
            list(f)


def test_load_wordlist_legacy_wrapper(tmp_path):
    """Test load_wordlist legacy wrapper."""
    with patch("cyberhash.wordlists.manager.get_app_data_dir", return_value=tmp_path):
        p = load_wordlist(current_os="Windows")
        assert p.exists()
