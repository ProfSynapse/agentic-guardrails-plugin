"""No-persistence compatibility boundary for host-managed activity history.

Claude and Codex task history is the human activity log. Guardrails therefore
does not keep a second command/event ledger. These functions intentionally do
not inspect or modify ``AGW_HOME`` or any legacy audit/quarantine artifacts.
"""
from __future__ import annotations

from dataclasses import dataclass


SCHEMA = "agw-audit-disabled"
VERSION = 0
ACTIVE_NAME = ""
KEY_NAME = ""
QUARANTINE_DIR = ""
ALLOWED_OUTPUT_KEYS = frozenset()


@dataclass(frozen=True)
class AuditStatus:
    ok: bool = True
    code: str = "host-history"


_STATUS = AuditStatus()


def build_record(_kind="", _data=None):
    """Return no record because command/event persistence is disabled."""
    return None


def log(_kind="", _data=None) -> AuditStatus:
    """Compatibility no-op; host task history remains the activity record."""
    return _STATUS


def status() -> AuditStatus:
    return _STATUS


def tail(_limit=50) -> list:
    """No command-level history is available from Guardrails."""
    return []


__all__ = [
    "ACTIVE_NAME", "ALLOWED_OUTPUT_KEYS", "AuditStatus", "KEY_NAME",
    "QUARANTINE_DIR", "SCHEMA", "VERSION", "build_record", "log", "status",
    "tail",
]
