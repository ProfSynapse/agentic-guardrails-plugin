"""Stable, presentation-neutral contracts for recovery receipts and plans."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

from . import outcomes


PRESENT = "PRESENT"
ABSENT = "ABSENT"
COMMITTED = "COMMITTED"

PUBLICATION_ROLLBACK_CONTRACT = "publication-rollback/v1"
PUBLICATION_ROLLBACK_CAPTURE_PREFIX = PUBLICATION_ROLLBACK_CONTRACT + ":"
UNRESOLVED_PREPARED_PUBLICATION = "unresolved_prepared_publication"
ACTIVE_PUBLICATION_ROLLBACK = "active_publication_rollback"
MAX_PUBLICATION_ROLLBACK_MEMBERS = 64
MAX_PUBLICATION_ROLLBACK_MANIFEST_BYTES = 64 * 1024
PUBLICATION_TERMINAL_STATES = frozenset({
    "COMMITTED", "ROLLED_BACK", "NEEDS_ATTENTION",
})
PUBLICATION_BINDING_FIELDS = (
    "operations", "atomicity", "visibility", "plan_sha256",
    "parent_plan_id", "parent_plan_sha256", "claim_id",
)
PUBLICATION_TERMINAL_FIELDS = frozenset({
    "op", "transaction_id", "prepared_transaction_id", "state", "operations",
    "atomicity", "visibility", "process_outcome", "contract_outcome",
    "precondition_outcome", "policy_outcome", "environment_outcome",
    "publication_outcome", "operation_outcome", "outcome", "recovered",
    "plan_sha256", "recovery_state", "outcome_known", "outcome_source",
    "parent_plan_id", "parent_plan_sha256", "claim_id", "error",
    "rollback_errors", "rolled_back", "schema_version", "ts", "timestamp_ns",
})

_TRANSACTION_ID_RE = re.compile(r"[0-9a-f]{32}")


def canonical_sha256(value: Mapping[str, Any]) -> str:
    """Hash a JSON object using one deterministic representation."""
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def exact_transaction_id(value: object, *, field: str = "transaction id") -> str:
    """Return one canonical 32-hex identifier or refuse it."""
    identifier = str(value or "")
    if not _TRANSACTION_ID_RE.fullmatch(identifier):
        raise ValueError(f"{field} must be exactly 32 lowercase hexadecimal characters")
    return identifier


def publication_rollback_capture_group(prepared_transaction_id: object) -> str:
    """Bind a displaced archive to one prepared publication."""
    return PUBLICATION_ROLLBACK_CAPTURE_PREFIX + exact_transaction_id(
        prepared_transaction_id, field="prepared transaction id"
    )


def _publication_member_derivation(
    purpose: str,
    prepared_transaction_id: object,
    member_number: object,
    target_identity: object,
) -> str:
    prepared = exact_transaction_id(
        prepared_transaction_id, field="prepared transaction id"
    )
    try:
        number = int(member_number)
    except (TypeError, ValueError) as exc:
        raise ValueError("publication member number must be an integer") from exc
    identity = str(target_identity or "")
    if number < 1 or number > MAX_PUBLICATION_ROLLBACK_MEMBERS:
        raise ValueError("publication member number is outside the recovery bound")
    if not identity:
        raise ValueError("publication target identity is required")
    return canonical_sha256({
        "contract": PUBLICATION_ROLLBACK_CONTRACT,
        "purpose": purpose,
        "prepared_transaction_id": prepared,
        "member_number": number,
        "target_identity": identity,
    })[:32]


def publication_displaced_transaction_id(
    prepared_transaction_id: object,
    member_number: object,
    target_identity: object,
) -> str:
    """Derive the stable archive id for one displaced published state."""
    return _publication_member_derivation(
        "displaced-archive", prepared_transaction_id, member_number, target_identity
    )


def publication_restore_token(
    prepared_transaction_id: object,
    member_number: object,
    target_identity: object,
) -> str:
    """Derive the stable basename token for one restore staging file."""
    return _publication_member_derivation(
        "restore-stage", prepared_transaction_id, member_number, target_identity
    )


def publication_terminal_transaction_id(
    prepared_transaction_id: object, terminal_state: object
) -> str:
    """Derive one domain-separated terminal transaction identifier."""
    prepared = exact_transaction_id(
        prepared_transaction_id, field="prepared transaction id"
    )
    state = str(terminal_state or "")
    if state not in PUBLICATION_TERMINAL_STATES:
        raise ValueError("publication terminal state is not recognized")
    payload = (
        "agw-publication-terminal/v1\0" + prepared + "\0" + state
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:32]


def publication_terminal_valid(prepared: Mapping[str, Any],
                               terminal: Mapping[str, Any]) -> bool:
    """Authenticate one terminal against its exact canonical PREPARED record."""
    if set(terminal) - PUBLICATION_TERMINAL_FIELDS:
        return False
    if "schema_version" in terminal and (
            isinstance(terminal["schema_version"], bool)
            or terminal["schema_version"] != 1):
        return False
    if "ts" in terminal and not isinstance(terminal["ts"], str):
        return False
    if "timestamp_ns" in terminal and (
            isinstance(terminal["timestamp_ns"], bool)
            or not isinstance(terminal["timestamp_ns"], int)
            or terminal["timestamp_ns"] <= 0):
        return False
    state = str(terminal.get("state") or "")
    if state not in PUBLICATION_TERMINAL_STATES:
        return False
    try:
        transaction_id = exact_transaction_id(
            terminal.get("transaction_id"), field="publication terminal id"
        )
    except ValueError:
        return False
    if terminal.get("prepared_transaction_id") != prepared.get("transaction_id"):
        return False
    if any((field in terminal) != (field in prepared)
           or terminal.get(field) != prepared.get(field)
           for field in PUBLICATION_BINDING_FIELDS):
        return False
    expected_publication = {
        "COMMITTED": "committed", "ROLLED_BACK": "rolled_back",
        "NEEDS_ATTENTION": "needs_attention",
    }[state]
    recovered = terminal.get("recovered")
    if not isinstance(recovered, bool):
        return False
    expected_operation = "success" if state == "COMMITTED" or (
        recovered and state == "ROLLED_BACK"
    ) else "process_failed"
    required = {
        "op": "file-transaction-state", "recovery_state": state,
        "process_outcome": "not_applicable", "contract_outcome": "not_evaluated",
        "precondition_outcome": "satisfied", "policy_outcome": "allowed",
        "environment_outcome": "ready", "publication_outcome": expected_publication,
        "operation_outcome": expected_operation, "outcome": expected_operation,
        "outcome_known": True, "outcome_source": "live_evaluation",
    }
    if any(terminal.get(field) != value for field, value in required.items()):
        return False
    if "rolled_back" in terminal \
            and terminal.get("rolled_back") is not (state == "ROLLED_BACK"):
        return False
    return not recovered or transaction_id == publication_terminal_transaction_id(
        prepared["transaction_id"], state
    )


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
        "recovery_state": recovery_record_state,
        "transaction_id": transaction_id,
        "undo_argv": (
            ["agw", "undo", "--transaction", undo_transaction_id or transaction_id]
            if rollback_available else []
        ),
    }


def outcome_fields(record: Mapping[str, Any]) -> dict:
    """Project operation axes without conflating recovery with success."""
    return outcomes.project_record(record)
