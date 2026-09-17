"""No-persistence compatibility boundary for host-managed activity history.

Claude and Codex task history is the human activity log. Guardrails therefore
does not keep a second command/event ledger. These functions intentionally do
not inspect or modify ``AGW_HOME`` or any legacy audit/quarantine artifacts.
"""
from __future__ import annotations

from collections import namedtuple


SCHEMA = "agw-audit-disabled"
VERSION = 0
ACTIVE_NAME = ""
KEY_NAME = ""
QUARANTINE_DIR = ""
ALLOWED_OUTPUT_KEYS = frozenset()


# A namedtuple rather than a dataclass: this module is imported on every hook
# call and dataclasses pulls in inspect (about a dozen milliseconds) for a
# two-field record that never changes.
AuditStatus = namedtuple("AuditStatus", ("ok", "code"))
AuditStatus.__new__.__defaults__ = (True, "host-history")


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
