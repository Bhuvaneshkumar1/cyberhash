"""
Unit and integration tests for CyberHash session manager module and interrupt recovery.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch

from cyberhash.session.manager import (
    SessionManager,
    SessionData,
    generate_stable_session_id,
    get_sessions_dir,
)


@pytest.fixture
def temp_sessions_dir(tmp_path):
    sessions_dir = tmp_path / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    with patch("cyberhash.session.manager.get_sessions_dir", return_value=sessions_dir):
        yield sessions_dir


def test_generate_stable_session_id():
    hash1 = "5d41402abc4b2a76b9719d911017c592"
    id1 = generate_stable_session_id(hash1, "dictionary")
    id2 = generate_stable_session_id(hash1, "dictionary")
    id3 = generate_stable_session_id(hash1, "mask")

    assert id1.startswith("sess_5d4140_dictionary_")
    assert id1 == id2, "Stable session ID should be deterministic"
    assert id1 != id3, "Different attack modes should yield different session IDs"


def test_save_and_load_session(temp_sessions_dir):
    mgr = SessionManager(
        target_hash="5d41402abc4b2a76b9719d911017c592",
        algorithms=["md5"],
        wordlist_paths=[Path("/tmp/words.txt")],
        attack_mode="dictionary",
        rule_config={"rules_enabled": True, "depth": 2},
        mask=None,
    )
    mgr.set_state(position=500, candidates_tested=1500, elapsed_time=12.5)

    saved = mgr.save_session()
    assert saved

    expected_file = temp_sessions_dir / f"{mgr.session_id}.json"
    assert expected_file.exists()

    loaded_data = mgr.load_session()
    assert loaded_data is not None
    assert loaded_data.session_id == mgr.session_id
    assert loaded_data.target_hash == "5d41402abc4b2a76b9719d911017c592"
    assert loaded_data.algorithms == ["md5"]
    assert loaded_data.current_position == 500
    assert loaded_data.candidates_tested == 1500
    assert loaded_data.elapsed_time == 12.5
    assert loaded_data.attack_mode == "dictionary"
    assert loaded_data.rule_config == {"rules_enabled": True, "depth": 2}


def test_path_traversal_sanitization(temp_sessions_dir):
    """Test path traversal attempts in session IDs are sanitized safely."""
    mgr = SessionManager(target_hash="test_hash")
    malicious_id = "../../../etc/passwd"
    file_path = mgr.get_session_file(malicious_id)
    assert file_path.parent == temp_sessions_dir
    assert ".." not in file_path.name


def test_load_corrupted_session_file(temp_sessions_dir):
    mgr = SessionManager(target_hash="test_hash")
    session_file = mgr.get_session_file(mgr.session_id)

    # Write invalid corrupted JSON
    with open(session_file, "w", encoding="utf-8") as f:
        f.write("{invalid_json: true, missing_quotes}")

    # Loading corrupt session should return None safely without raising an exception
    loaded = mgr.load_session()
    assert loaded is None


def test_list_sessions(temp_sessions_dir):
    mgr1 = SessionManager(target_hash="hash_one", attack_mode="dictionary")
    mgr1.set_state(position=10, candidates_tested=10, elapsed_time=1.0)
    mgr1.save_session()

    mgr2 = SessionManager(target_hash="hash_two", attack_mode="mask")
    mgr2.set_state(position=20, candidates_tested=50, elapsed_time=2.0)
    mgr2.save_session()

    # Write a corrupted file in sessions_dir to ensure list_sessions skips it cleanly
    corrupt_file = temp_sessions_dir / "corrupt_session.json"
    corrupt_file.write_text("corrupted content", encoding="utf-8")

    sessions = mgr1.list_sessions()
    assert len(sessions) == 2
    session_ids = [s.session_id for s in sessions]
    assert mgr1.session_id in session_ids
    assert mgr2.session_id in session_ids


def test_delete_session(temp_sessions_dir):
    mgr = SessionManager(target_hash="hash_to_delete")
    mgr.save_session()

    assert mgr.get_session_file(mgr.session_id).exists()

    deleted = mgr.delete_session()
    assert deleted
    assert not mgr.get_session_file(mgr.session_id).exists()

    # Attempt deleting already deleted session
    deleted_again = mgr.delete_session()
    assert not deleted_again


def test_clear_all_sessions(temp_sessions_dir):
    mgr1 = SessionManager(target_hash="hash_a")
    mgr1.save_session()

    mgr2 = SessionManager(target_hash="hash_b")
    mgr2.save_session()

    assert len(list(temp_sessions_dir.glob("*.json"))) == 2

    cleared_count = mgr1.clear_all_sessions()
    assert cleared_count == 2
    assert len(list(temp_sessions_dir.glob("*.json"))) == 0


def test_setup_interrupt_handler(temp_sessions_dir):
    """Test interrupt handler registration."""
    mgr = SessionManager(target_hash="hash_interrupt")
    with patch("cyberhash.session.manager.register_interrupt_handler") as mock_reg:
        mgr.setup_interrupt_handler()
        assert mock_reg.called
