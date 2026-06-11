"""Append-only JSONL audit log with size-based rotation.

Every tool call — read or write — is recorded: tool, sanitized identifier
arguments, scope/approval decisions, redaction counts, truncation. Bodies are
never logged, so the audit log itself can never become a secret store.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_MAX_BYTES = 10 * 1024 * 1024
_BACKUPS = 3


class AuditLog:
    def __init__(self, path: Path, max_bytes: int = _MAX_BYTES, backups: int = _BACKUPS):
        self._path = path
        self._max_bytes = max_bytes
        self._backups = backups
        self._lock = threading.Lock()

    def _rotate_if_needed(self) -> None:
        try:
            if self._path.stat().st_size < self._max_bytes:
                return
        except FileNotFoundError:
            return
        for i in range(self._backups - 1, 0, -1):
            src = self._path.with_suffix(f".jsonl.{i}")
            if src.exists():
                src.rename(self._path.with_suffix(f".jsonl.{i + 1}"))
        self._path.rename(self._path.with_suffix(".jsonl.1"))

    def write(self, event: str, **fields: Any) -> None:
        record = {"ts": datetime.now(UTC).isoformat(), "event": event, **fields}
        line = json.dumps(record, sort_keys=True, default=str)
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._rotate_if_needed()
            with self._path.open("a") as fh:
                fh.write(line + "\n")

    def log_call(self, tool: str, **fields: Any) -> None:
        self.write("tool_call", tool=tool, **fields)

    def log_denied(self, tool: str, **fields: Any) -> None:
        self.write("write_denied", tool=tool, **fields)

    def log_pending(self, tool: str, **fields: Any) -> None:
        self.write("write_pending", tool=tool, **fields)

    def log_approved(self, tool: str, **fields: Any) -> None:
        self.write("write_approved", tool=tool, **fields)

    def log_error(self, tool: str, error: str, **fields: Any) -> None:
        self.write("tool_error", tool=tool, error=error, **fields)
