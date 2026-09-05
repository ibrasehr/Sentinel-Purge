"""
Sentinel-Purge Audit Trail Logger
Module: erasure.audit_trail

Live, step-by-step audit event emitter for sanitization and erasure operations.
Records each execution step (authorization, file operations, outcomes)
with ISO 8601 timestamps to:
  1. An in-memory list (for API responses / real-time UI feeds)
  2. An append-only JSON-Lines file (forensic-grade persistent log)
"""

from __future__ import annotations

import datetime
import json
import os
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# Default log output directory
DEFAULT_LOG_DIR = "audit_logs"
DEFAULT_LOG_FILE = "erasure_audit.jsonl"


@dataclass
class AuditEntry:
    """A single audit trail event."""
    timestamp: str
    action: str
    target_file: str
    operator: str
    detail: str
    success: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


class AuditTrail:
    """
    In-process audit event emitter.

    Thread-safe. Maintains an ordered list of AuditEntry objects for the
    current session and simultaneously appends each entry to a JSONL log file.
    """

    # Canonical action constants
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAILURE = "AUTH_FAILURE"
    CLEAR_START = "CLEAR_START"
    CLEAR_OK = "CLEAR_OK"
    PURGE_START = "PURGE_START"
    PURGE_OK = "PURGE_OK"
    ERROR = "ERROR"

    def __init__(
        self,
        log_dir: str | Path = DEFAULT_LOG_DIR,
        log_filename: str = DEFAULT_LOG_FILE,
    ) -> None:
        self._entries: List[AuditEntry] = []
        self._lock = threading.Lock()

        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / log_filename

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(
        self,
        action: str,
        target_file: str,
        detail: str,
        success: bool,
        operator: str = "web_user",
    ) -> AuditEntry:
        """
        Record a new audit event.

        Args:
            action:      One of the class-level action constants.
            target_file: Filesystem path of the target file.
            detail:      Human-readable description of what happened.
            success:     Whether this step succeeded.
            operator:    Identity of the actor (default 'web_user').

        Returns:
            The newly created AuditEntry.
        """
        entry = AuditEntry(
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            action=action,
            target_file=target_file,
            operator=operator,
            detail=detail,
            success=success,
        )

        with self._lock:
            self._entries.append(entry)
            self._persist(entry)

        return entry

    def get_entries(self) -> List[Dict[str, Any]]:
        """Return all recorded entries as a list of dicts (safe for JSON serialization)."""
        with self._lock:
            return [e.to_dict() for e in self._entries]

    def clear(self) -> None:
        """Clear the in-memory log (does NOT erase the JSONL file)."""
        with self._lock:
            self._entries.clear()

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _persist(self, entry: AuditEntry) -> None:
        """Append a single entry to the JSONL log file."""
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(entry.to_json() + "\n")
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            # Never let logging failures crash the main operation
            pass
