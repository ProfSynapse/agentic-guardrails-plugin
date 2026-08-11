"""Stable, presentation-neutral contracts for recovery receipts and plans."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping


PRESENT = "PRESENT"
ABSENT = "ABSENT"
COMMITTED = "COMMITTED"


def canonical_sha256(value: Mapping[str, Any]) -> str:
    """Hash a JSON object using one deterministic representation."""
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def bind_plan_hash(plan: Mapping[str, Any], field: str = "plan_sha256") -> dict:
    """Return a copy of *plan* bound to all fields except the hash field."""
    bound = dict(plan)
    bound.pop(field, None)
    bound[field] = canonical_sha256(bound)
    return bound


def plan_hash_valid(plan: Mapping[str, Any], field: str = "plan_sha256") -> bool:
    """Return whether a plan still matches its embedded canonical hash."""
    expected = str(plan.get(field) or "")
    if not expected:
        return False
    unbound = dict(plan)
    unbound.pop(field, None)
    return canonical_sha256(unbound) == expected


def recovery_receipt_fields(
    *,
    target: str,
    state: str,
    artifact: str,
    transaction_id: str,
    recovery_record_kind: str,
    recovery_record_state: str,
    undo_transaction_id: str = "",
) -> dict:
    """Serialize recovery meaning without relying on legacy state terminology."""
    target_existed_before = state == PRESENT
    preimage_captured = bool(target_existed_before and artifact)
    committed = recovery_record_state == COMMITTED
    rollback_available = bool(
        transaction_id
        and committed
        and (
            (recovery_record_kind == "archive" and preimage_captured)
            or (recovery_record_kind == "absent_tombstone" and state == ABSENT)
        )
    )
    return {
        "target": target,
        "target_existed_before": target_existed_before,
        "preimage_captured": preimage_captured,
        "rollback_available": rollback_available,
        "recovery_record_kind": recovery_record_kind,
        "recovery_record_state": recovery_record_state,
        "transaction_id": transaction_id,
        "undo_argv": (
            ["agw", "undo", "--transaction", undo_transaction_id or transaction_id]
            if rollback_available else []
        ),
    }
