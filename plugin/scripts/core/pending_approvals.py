"""Pending-approval records: the one-use handshake between PreToolUse and
PostToolUse that turns "the user approved this ask" into session memory.

PreToolUse writes a privacy-minimal record for an ASK it may later memoize;
PostToolUse consumes it. On nearly every PostToolUse call there is no record,
and that answer has to be cheap: this module needs only os, json, hashlib and
time, so the adapter can check the gate before it loads the engine, the store
or the prompt renderers. ``core.approvals`` re-exports these names.
"""
import hashlib
import json
import os
import time
from _thread import get_ident

PENDING_SECONDS = 120


def _host_event_id(payload: dict) -> str:
    return str(payload.get("event_id") or payload.get("invocation_id") or
               payload.get("tool_use_id") or "")


def _identity_hash(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()


def approval_identity(memo_key: str, policy_revision: str) -> str:
    """One-way, revision-bound identity for a resource approval."""
    material = f"agw-pending-approval-v1\0{policy_revision}\0{memo_key}"
    return _identity_hash(material)


def _pending_path(payload: dict, session_id: str) -> str:
    event_id = _host_event_id(payload)
    if not event_id or not session_id:
        return ""
    home = os.environ.get("AGW_HOME") or os.path.join(os.path.expanduser("~"), ".agw")
    directory = os.path.join(home, "pending-approvals")
    os.makedirs(directory, exist_ok=True)
    key = _identity_hash(f"{session_id}\0{event_id}")
    return os.path.join(directory, key + ".json")


def record_pending_approval(payload: dict, session_id: str, memo_key: str,
                            policy_revision: str, operation_fingerprint: str) -> bool:
    """Persist a privacy-minimal pre-hook candidate for one post-hook consume."""
    path = _pending_path(payload, session_id)
    if not path or not memo_key or not policy_revision or not operation_fingerprint:
        return False
    record = {
        "session_hash": _identity_hash(session_id),
        "event_hash": _identity_hash(_host_event_id(payload)),
        "approval_identity": approval_identity(memo_key, policy_revision),
        "policy_revision": policy_revision,
        "operation_fingerprint": operation_fingerprint,
        "created_at": time.time(),
    }
    temp = path + f".{os.getpid()}.{get_ident()}.tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        json.dump(record, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)
    return True


def consume_pending_approval(payload: dict, session_id: str):
    """Atomically consume one matching, unexpired pending approval record."""
    path = _pending_path(payload, session_id)
    if not path or not os.path.exists(path):
        return None
    consuming = path + f".{os.getpid()}.{get_ident()}.consuming"
    try:
        os.replace(path, consuming)
    except OSError:
        return None
    try:
        with open(consuming, encoding="utf-8") as handle:
            record = json.load(handle)
        if time.time() - float(record.get("created_at", 0)) > PENDING_SECONDS:
            return None
        if record.get("session_hash") != _identity_hash(session_id):
            return None
        if record.get("event_hash") != _identity_hash(_host_event_id(payload)):
            return None
        if not record.get("policy_revision") or not record.get("approval_identity"):
            return None
        return record
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None
    finally:
        try:
            os.unlink(consuming)
        except OSError:
            pass
