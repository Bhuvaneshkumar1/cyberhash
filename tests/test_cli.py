"""
Comprehensive integration tests for CyberHash CLI parser, argument groups, all execution modes, path validation, and conflict enforcement.
"""

import io
import sys
import pytest
from pathlib import Path
from unittest.mock import patch

from cyberhash.cli import main
from cyberhash import __version__ as APP_VERSION


@pytest.fixture
def cli_workspace(tmp_path):
    wordlist_file = tmp_path / "valid_words.txt"
    wordlist_file.write_text("password\nadmin\n", encoding="utf-8")

    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text("5f4dcc3b5aa765d61d8327deb882cf99\n", encoding="utf-8")

    rules_file = tmp_path / "custom_rules.txt"
    rules_file.write_text("lowercase\nuppercase\n", encoding="utf-8")

    config_file = tmp_path / "custom_config.json"
    config_file.write_text('{"threads": 2, "quiet": true}', encoding="utf-8")

    return {
        "dir": tmp_path,
        "wordlist": wordlist_file,
        "hash_file": hash_file,
        "rules_file": rules_file,
        "config_file": config_file,
    }


def test_cli_version_flag():
    with patch("rich.console.Console.print") as mock_print:
        main(["--version"])
        mock_print.assert_called_with(f"CyberHash v{APP_VERSION}")


def test_cli_help_flag():
    with pytest.raises(SystemExit) as exc_info:
        with patch("sys.stdout", io.StringIO()):
            main(["--help"])
    assert exc_info.value.code == 0


def test_cli_no_color():
    main(["--version", "--no-color"])


def test_cli_show_config():
    main(["--show-config", "--quiet"])


def test_cli_custom_config(cli_workspace):
    main(["--config", str(cli_workspace["config_file"]), "--show-config", "--quiet"])


def test_cli_generate_wordlist():
    main(["--generate-wordlist", "--quiet"])


def test_cli_benchmark_mode():
    main(["--benchmark", "--algo", "MD5", "--benchmark-duration", "0.05", "--quiet"])


def test_cli_dictionary_attack(cli_workspace):
    main([
        "--hash", "5f4dcc3b5aa765d61d8327deb882cf99",
        "--wordlist", str(cli_workspace["wordlist"]),
        "--quiet"
    ])


def test_cli_multiple_wordlists(cli_workspace):
    main([
        "--hash", "5f4dcc3b5aa765d61d8327deb882cf99",
        "--wordlists", str(cli_workspace["wordlist"]), str(cli_workspace["wordlist"]),
        "--quiet"
    ])


def test_cli_rules_mode(cli_workspace):
    main([
        "--hash", "5f4dcc3b5aa765d61d8327deb882cf99",
        "--wordlist", str(cli_workspace["wordlist"]),
        "--rules",
        "--rule-depth", "1",
        "--quiet"
    ])


def test_cli_rules_only_mode(cli_workspace):
    main([
        "--hash", "5f4dcc3b5aa765d61d8327deb882cf99",
        "--wordlist", str(cli_workspace["wordlist"]),
        "--rules-only",
        "--rules-file", str(cli_workspace["rules_file"]),
        "--quiet"
    ])


def test_cli_mask_attack():
    main([
        "--hash", "5f4dcc3b5aa765d61d8327deb882cf99",
        "--mask", "?d?d",
        "--quiet"
    ])


def test_cli_hybrid_attack(cli_workspace):
    main([
        "--hash", "5f4dcc3b5aa765d61d8327deb882cf99",
        "--wordlist", str(cli_workspace["wordlist"]),
        "--mask", "?d?d",
        "--hybrid",
        "--hybrid-mode", "suffix",
        "--hybrid-max-per-word", "10",
        "--quiet"
    ])


def test_cli_threads_and_distributed(cli_workspace):
    main([
        "--hash", "5f4dcc3b5aa765d61d8327deb882cf99",
        "--wordlist", str(cli_workspace["wordlist"]),
        "--threads", "2",
        "--quiet"
    ])


def test_cli_batch_hash_file(cli_workspace):
    main([
        "--hash-file", str(cli_workspace["hash_file"]),
        "--wordlist", str(cli_workspace["wordlist"]),
        "--quiet"
    ])


def test_cli_wordlist_info(cli_workspace):
    main(["--wordlist-info", str(cli_workspace["wordlist"]), "--quiet"])


def test_cli_stats_flag(cli_workspace):
    main(["--wordlist", str(cli_workspace["wordlist"]), "--stats", "--quiet"])


def test_cli_session_commands():
    main(["--session-list", "--quiet"])
    main(["--session-clear", "--quiet"])


def test_cli_export_option(cli_workspace):
    export_file = cli_workspace["dir"] / "out.json"
    main([
        "--hash", "5f4dcc3b5aa765d61d8327deb882cf99",
        "--wordlist", str(cli_workspace["wordlist"]),
        "--export", str(export_file),
        "--quiet"
    ])
    assert export_file.exists()


def test_conflicting_quiet_and_verbose():
    with pytest.raises(SystemExit) as exc_info:
        with patch("sys.stderr", io.StringIO()):
            main(["--quiet", "--verbose", "--hash", "5f4dcc3b5aa765d61d8327deb882cf99"])
    assert exc_info.value.code != 0


def test_conflicting_hash_and_hash_file(cli_workspace):
    with pytest.raises(SystemExit) as exc_info:
        with patch("sys.stderr", io.StringIO()):
            main([
                "--hash", "5f4dcc3b5aa765d61d8327deb882cf99",
                "--hash-file", str(cli_workspace["hash_file"])
            ])
    assert exc_info.value.code != 0


def test_hybrid_without_mask_error():
    with pytest.raises(SystemExit) as exc_info:
        with patch("sys.stderr", io.StringIO()):
            main(["--hybrid", "--hash", "5f4dcc3b5aa765d61d8327deb882cf99"])
    assert exc_info.value.code != 0


def test_nonexistent_wordlist_error(cli_workspace):
    missing = str(cli_workspace["dir"] / "nonexistent.txt")
    with pytest.raises(SystemExit) as exc_info:
        with patch("sys.stderr", io.StringIO()):
            main(["--hash", "5f4dcc3b5aa765d61d8327deb882cf99", "--wordlist", missing])
    assert exc_info.value.code != 0
