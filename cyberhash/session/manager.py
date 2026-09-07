"""
Robust session management for CyberHash checkpoints and recovery.
"""

import os
import sys
import json
import time
import logging
import platform
import hashlib
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any

from cyberhash import __version__ as APP_VERSION
from cyberhash.wordlists.manager import get_app_data_dir
from cyberhash.output.console import console
from cyberhash.utils.platform import register_interrupt_handler


@dataclass
class SessionData:
    """
    Data model representing a stored cracking session state.
    """
    session_id: str
    target_hash: str
    algorithms: List[str]
    wordlist_paths: List[str]
    attack_mode: str
    rule_config: Dict[str, Any]
    mask: Optional[str]
    current_position: int
    candidates_tested: int
    elapsed_time: float
    created_at: float
    updated_at: float
    app_version: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionData":
        return cls(
            session_id=data.get("session_id", ""),
            target_hash=data.get("target_hash", ""),
            algorithms=data.get("algorithms", []),
            wordlist_paths=data.get("wordlist_paths", []),
            attack_mode=data.get("attack_mode", "dictionary"),
            rule_config=data.get("rule_config", {}),
            mask=data.get("mask"),
            current_position=data.get("current_position", 0),
            candidates_tested=data.get("candidates_tested", 0),
            elapsed_time=data.get("elapsed_time", 0.0),
            created_at=data.get("created_at", time.time()),
            updated_at=data.get("updated_at", time.time()),
            app_version=data.get("app_version", APP_VERSION)
        )


def get_sessions_dir() -> Path:
    """
    Get path to stored sessions directory within app data dir (~/.cyberhash/sessions/).

    :return: Path object to sessions directory.
    """
    sessions_dir = get_app_data_dir() / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    return sessions_dir


def generate_stable_session_id(target_hash: str, attack_mode: str = "dictionary") -> str:
    """
    Generate a stable, deterministic session identifier based on target hash and attack mode.

    :param target_hash: Target hash string.
    :param attack_mode: Attack mode name string.
    :return: Stable session ID string.
    """
    clean_hash = target_hash.strip().lower()
    hash_digest = hashlib.md5(f"{clean_hash}_{attack_mode}".encode()).hexdigest()[:8]
    prefix = clean_hash[:6] if len(clean_hash) >= 6 else clean_hash
    return f"sess_{prefix}_{attack_mode}_{hash_digest}"


class SessionManager:
    """
    Manages atomic session persistence, loading, listing, deletion, and interrupt recovery.
    """

    def __init__(
        self,
        session_id: Optional[str] = None,
        target_hash: Optional[str] = None,
        algorithms: Optional[List[str]] = None,
        wordlist_paths: Optional[List[Path]] = None,
        attack_mode: str = "dictionary",
        rule_config: Optional[Dict[str, Any]] = None,
        mask: Optional[str] = None
    ):
        self.sessions_dir: Path = get_sessions_dir()

        if target_hash:
            self.session_id: str = session_id or generate_stable_session_id(target_hash, attack_mode)
        else:
            self.session_id: str = session_id or "sess_default"

        self.target_hash: str = target_hash or ""
        self.algorithms: List[str] = algorithms or []
        self.wordlist_paths: List[str] = [str(p) for p in (wordlist_paths or [])]
        self.attack_mode: str = attack_mode
        self.rule_config: Dict[str, Any] = rule_config or {}
        self.mask: Optional[str] = mask

        self.current_position: int = 0
        self.candidates_tested: int = 0
        self.elapsed_time: float = 0.0
        self.created_at: float = time.time()
        self.start_time: float = time.time()

    def set_state(
        self,
        position: int,
        candidates_tested: int,
        elapsed_time: Optional[float] = None
    ) -> None:
        """
        Update current in-memory progress metrics.

        :param position: Current item index in wordlist.
        :param candidates_tested: Total candidates tested so far.
        :param elapsed_time: Total elapsed execution seconds.
        """
        self.current_position = position
        self.candidates_tested = candidates_tested
        if elapsed_time is not None:
            self.elapsed_time = elapsed_time
        else:
            self.elapsed_time = time.time() - self.start_time

    def set_current_state(self, position: int, wordlist_path: Any = None, target_hash: str = "") -> None:
        """Compatibility alias for set_state."""
        self.set_state(position=position, candidates_tested=position)
        if target_hash and not self.target_hash:
            self.target_hash = target_hash

    def get_session_file(self, session_id: str) -> Path:
        """
        Get file Path for a given session ID, ensuring path traversal protection.

        :param session_id: Session identifier string.
        :return: Path object to json session file.
        """
        clean_id = Path(session_id).name.replace(".json", "")
        clean_id = "".join(c for c in clean_id if c.isalnum() or c in ("_", "-"))
        if not clean_id:
            clean_id = "sess_default"
        return self.sessions_dir / f"{clean_id}.json"

    def save_session(self, position: Optional[int] = None, wordlist_path: Any = None, target_hash: str = "") -> bool:
        """
        Atomically write session data to JSON file via temporary file replacement.

        :return: True if saved successfully, False otherwise.
        """
        if position is not None:
            self.current_position = position
        session_file = self.get_session_file(self.session_id)
        temp_file = session_file.with_suffix(".tmp")

        now = time.time()
        data = SessionData(
            session_id=self.session_id,
            target_hash=self.target_hash,
            algorithms=self.algorithms,
            wordlist_paths=self.wordlist_paths,
            attack_mode=self.attack_mode,
            rule_config=self.rule_config,
            mask=self.mask,
            current_position=self.current_position,
            candidates_tested=self.candidates_tested,
            elapsed_time=self.elapsed_time,
            created_at=self.created_at,
            updated_at=now,
            app_version=APP_VERSION
        )

        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(data.to_dict(), f, indent=2)

            # Atomic replace
            temp_file.replace(session_file)
            return True
        except Exception as e:
            logging.error(f"Failed atomic session save for '{self.session_id}': {e}")
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except Exception:
                    pass
            return False

    def load_session(self, session_id: Optional[str] = None) -> Optional[SessionData]:
        """
        Safely load session data from disk, handling corrupted files gracefully.

        :param session_id: Session ID to load, defaults to current session_id.
        :return: SessionData object or None if invalid or missing.
        """
        target_id = session_id or self.session_id
        session_file = self.get_session_file(target_id)

        if not session_file.exists():
            return None

        try:
            with open(session_file, "r", encoding="utf-8") as f:
                content = json.load(f)
                return SessionData.from_dict(content)
        except Exception as e:
            logging.warning(f"Corrupted or invalid session file '{session_file}': {e}")
            return None

    def delete_session(self, session_id: Optional[str] = None) -> bool:
        """
        Delete a stored session checkpoint file.

        :param session_id: Session ID to delete.
        :return: True if deleted, False otherwise.
        """
        target_id = session_id or self.session_id
        session_file = self.get_session_file(target_id)

        if session_file.exists():
            try:
                session_file.unlink()
                return True
            except Exception as e:
                logging.error(f"Failed to delete session '{target_id}': {e}")
        return False

    def clear_session(self) -> bool:
        """Alias for delete_session."""
        return self.delete_session()

    def clear_all_sessions(self) -> int:
        """
        Delete all stored session checkpoint files.

        :return: Number of session files deleted.
        """
        count = 0
        for f in self.sessions_dir.glob("*.json"):
            try:
                f.unlink()
                count += 1
            except Exception as e:
                logging.error(f"Failed to delete '{f}': {e}")
        return count

    def list_sessions(self) -> List[SessionData]:
        """
        List all active valid session checkpoints stored on disk.

        :return: List of SessionData objects sorted by updated_at timestamp.
        """
        sessions: List[SessionData] = []
        for f in self.sessions_dir.glob("*.json"):
            try:
                with open(f, "r", encoding="utf-8") as file:
                    data = json.load(file)
                    sessions.append(SessionData.from_dict(data))
            except Exception as e:
                logging.warning(f"Skipping corrupt session file '{f}': {e}")

        sessions.sort(key=lambda s: s.updated_at, reverse=True)
        return sessions

    def setup_interrupt_handler(self) -> None:
        """
        Register cross-platform Ctrl+C / SIGINT signal handler to save current session atomically.
        """
        def handle_interrupt(sig: int, frame: Any) -> None:
            console.print("\n[yellow][*] Interrupt detected. Atomically saving session...[/yellow]")
            success = self.save_session()
            if success:
                console.print(f"[green][+] Session '{self.session_id}' saved successfully.[/green]")
            else:
                console.print("[red][-] Failed to save session checkpoint.[/red]")
            sys.exit(0)

        register_interrupt_handler(handle_interrupt)
