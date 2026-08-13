"""Activity-aware, fail-closed retention for the recovery store.

This module deliberately has no dependency on :mod:`core.store`.  ``store`` can
therefore expose these functions as a facade while retaining ownership of the
process-wide lock.  Planning is read-only.  Applying a plan requires the exact
reviewed hash, re-inventories the store, and can only remove transaction ids
that appeared in that plan.
"""
from __future__ import annotations

from contextlib import nullcontext
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import shutil
import stat
import time
import uuid

from . import archive_transactions as archive_tx
from . import recovery_contracts
from . import retention_policy


SCHEMA_VERSION = 1
PLAN_OPERATION = "retention-plan"
PLAN_TTL_NS = 15 * 60 * 1_000_000_000
DAY_NS = 24 * 60 * 60 * 1_000_000_000
RECENT_DAYS = 7
ACTIVE_DAYS = 30
KEEP_NEWEST_ACTIVE = 3
MAX_CANDIDATES = 256
MAX_RECLAIM_BYTES = 1 << 30
DEFAULT_HIGH_WATER = 0.90
DEFAULT_LOW_WATER = 0.80
MAX_INVENTORY_RECORDS = 100_000
MAX_WALK_NODES = 250_000

_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _meaningful_publication_identity(value) -> tuple[int, int, int, int] | None:
    if not isinstance(value, (list, tuple)) or len(value) != 4 \
            or any(isinstance(item, bool) or not isinstance(item, int)
                   for item in value):
        return None
    identity = tuple(value)
    device, inode, size, modified_ns = identity
    if device < 0 or inode <= 0 or size < 0 or modified_ns <= 0:
        return None
    return identity


def _publication_terminal_valid(prepared: dict, terminal: dict) -> bool:
    return recovery_contracts.publication_terminal_valid(prepared, terminal)

ELIGIBLE_CLASS = "mutation_preimage"
PROTECTED_CLASSES = frozenset({
    "manual_snapshot",
    "safety_archive",
    "evidence",
    "evidence_or_quarantine",
    "legacy",
    "legacy_unclassified",
})
KNOWN_CLASSES = frozenset({ELIGIBLE_CLASS}) | PROTECTED_CLASSES

PREPARED = "PREPARED"
STAGED = "STAGED"
PURGED = "PURGED"


class RetentionError(RuntimeError):
    """Base class for retention refusal and recovery errors."""


class InventoryIncompleteError(RetentionError):
    """The store could not be inventoried authoritatively."""


class InvalidPlanError(RetentionError):
    """A plan was malformed, expired, tampered with, or for another store."""


class StalePlanError(RetentionError):
    """A reviewed candidate no longer has its plan-bound identity."""


class SimulatedCrash(RuntimeError):
    """Test-only interruption at a durable retention boundary."""


def migrate_legacy_cache_records(home: str, *, protected_days: int = RECENT_DAYS
                                 ) -> dict:
    """Classify only legacy records with an exact trusted producer signature.

    Unknown records remain protected.  This migration never infers from a
    filename or age and never changes an artifact; it only adds retention
    metadata to committed copy transactions produced by known mutation paths.
    """
    migrated = []
    protected_ns = max(0, int(protected_days)) * DAY_NS
    for item in archive_tx.discover(home):
        record = item.get("record")
        if not isinstance(record, dict) or record.get("retention_class"):
            continue
        if record.get("kind") != "archive" \
                or record.get("state") != archive_tx.COMMITTED \
                or record.get("mode") != "copy" \
                or str(record.get("artifact_state") or "PRESENT") != "PRESENT":
            continue
        actor = str(record.get("actor") or "")
        reason = str(record.get("reason") or "")
        trusted_hook = (
            actor == "guardrails-hook"
            and reason.startswith("verified pre-image before ")
            and bool(record.get("policy_revision"))
        )
        trusted_office = (
            actor.startswith("agw office ")
            and reason.startswith("pre-image before agw office ")
        )
        if not (trusted_hook or trusted_office):
            continue
        created = max(0, int(record.get("created_at_ns") or 0))
        archive_tx.update(
            home, record["transaction_id"],
            retention_class=ELIGIBLE_CLASS,
            protected_until_ns=created + protected_ns,
            capture_group_id=str(record.get("capture_group_id") or "legacy"),
            artifact_state="PRESENT",
            retention_migrated_from="legacy_trusted_producer",
        )
        migrated.append(record["transaction_id"])
    return {
        "migrated": len(migrated),
        "transaction_ids": migrated,
        "protected_days": max(0, int(protected_days)),
    }


def _canonical(path: str) -> str:
    return archive_tx.canonical_path(os.path.abspath(str(path)))


def _archive_root(home: str) -> str:
    return os.path.abspath(os.path.join(home, "archive"))


def _retention_root(home: str) -> str:
    return os.path.abspath(os.path.join(home, "retention"))


def _within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath((os.path.abspath(path), os.path.abspath(root))) \
            == os.path.abspath(root)
    except (OSError, ValueError):
        return False


def _safe_artifact_path(home: str, path: str) -> bool:
    """Require a literal, non-link artifact rooted in this store's archive."""
    if not path or not os.path.isabs(path):
        return False
    root = _archive_root(home)
    absolute = os.path.abspath(path)
    if absolute == root or not _within(absolute, root):
        return False
    try:
        root_info = os.lstat(root)
        info = os.lstat(absolute)
    except OSError:
        return False
    if stat.S_ISLNK(root_info.st_mode) or stat.S_ISLNK(info.st_mode):
        return False
    # A parent reparse/symlink must not redirect a manifest outside the store.
    return _within(os.path.realpath(absolute), os.path.realpath(root))


def _lstat_identity(path: str) -> dict:
    info = os.lstat(path)
    return {
        "dev": getattr(info, "st_dev", None),
        "ino": getattr(info, "st_ino", None),
        "mode": int(info.st_mode),
        "size": int(getattr(info, "st_size", 0) or 0),
        "mtime_ns": int(getattr(info, "st_mtime_ns", 0) or 0),
        "ctime_ns": int(getattr(info, "st_ctime_ns", 0) or 0),
    }


def _allocated_bytes(path: str, *, node_budget: list[int]) -> int:
    """Count allocated bytes without following links, bounded by node_budget."""
    total = 0
    pending = [path]
    while pending:
        current = pending.pop()
        node_budget[0] -= 1
        if node_budget[0] < 0:
            raise InventoryIncompleteError("inventory filesystem node limit exceeded")
        info = os.lstat(current)
        blocks = getattr(info, "st_blocks", None)
        total += int(blocks * 512 if isinstance(blocks, int) and blocks > 0
                     else getattr(info, "st_size", 0) or 0)
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            with os.scandir(current) as entries:
                pending.extend(entry.path for entry in entries)
    return total


def _json_hash(value) -> str:
    return recovery_contracts.canonical_sha256(value)


def _file_hash(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_hash(record: dict) -> str:
    return _json_hash(record)


def store_identity(home: str) -> dict:
    """Return a stable identity for one concrete recovery-store directory."""
    absolute = os.path.abspath(home)
    os.makedirs(absolute, exist_ok=True)
    info = os.stat(absolute, follow_symlinks=False)
    identity = {
        "canonical_home": _canonical(absolute),
        "dev": getattr(info, "st_dev", None),
        "ino": getattr(info, "st_ino", None),
    }
    return {**identity, "store_id": _json_hash(identity)}


def _timestamp_ns(record: dict) -> int:
    for field in ("activity_at_ns", "timestamp_ns", "created_at_ns"):
        try:
            value = int(record.get(field) or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value
    raw = str(record.get("ts") or "").strip()
    if not raw:
        return 0
    for candidate in (raw, raw.replace("T", " ")):
        try:
            value = datetime.fromisoformat(candidate)
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return int(value.timestamp() * 1_000_000_000)
        except ValueError:
            pass
    try:
        value = datetime.strptime(raw, "%Y-%m-%dT%H-%M-%S").replace(
            tzinfo=timezone.utc
        )
        return int(value.timestamp() * 1_000_000_000)
    except ValueError:
        return 0


def _successful_activity_record(record: dict) -> bool:
    operation = str(record.get("op") or "")
    state = str(record.get("state") or "")
    if operation.endswith("-failed") or operation == "file-transaction-prepared":
        return False
    if operation == "file-transaction-state":
        return state == "COMMITTED"
    if state and state not in {"COMMITTED", "SUCCESS", "SUCCEEDED"}:
        return False
    return operation in {
        "file-mutation", "file-transaction", "transaction-undo", "restore",
        "archive", "write", "edit", "apply-plan", "run",
    }


def _activity_paths(record: dict):
    for field in ("src", "path", "target"):
        value = record.get(field)
        if isinstance(value, str) and value:
            yield value
    for item in record.get("operations") or ():
        if not isinstance(item, dict):
            continue
        for field in ("src", "path", "target"):
            value = item.get(field)
            if isinstance(value, str) and value:
                yield value


def _read_oplog(home: str) -> tuple[list[dict], list[str]]:
    path = os.path.join(home, "oplog.jsonl")
    if not os.path.exists(path):
        return [], []
    records, errors = [], []
    try:
        with open(path, encoding="utf-8") as handle:
            for number, raw in enumerate(handle, 1):
                if not raw.strip():
                    continue
                try:
                    value = json.loads(raw)
                    if not isinstance(value, dict):
                        raise ValueError("record is not an object")
                    records.append(value)
                except (json.JSONDecodeError, ValueError) as exc:
                    errors.append(f"oplog line {number}: {exc}")
    except OSError as exc:
        errors.append(f"oplog unreadable: {exc}")
    return records, errors


def _discover_manifests(home: str, max_records: int) -> tuple[list[dict], list[str]]:
    """Read authoritative manifests with a hard record bound."""
    root = os.path.join(home, "transactions")
    if not os.path.isdir(root):
        return [], []
    found, errors = [], []
    seen = 0
    try:
        with os.scandir(root) as entries:
            names = sorted(entry.name for entry in entries
                           if entry.name.endswith(".json"))
    except OSError as exc:
        return [], [f"transaction directory unreadable: {exc}"]
    for name in names:
        seen += 1
        if seen > max(0, int(max_records)):
            errors.append("inventory transaction record limit exceeded")
            break
        path = os.path.join(root, name)
        try:
            with open(path, encoding="utf-8") as handle:
                record = json.load(handle)
            if not isinstance(record, dict):
                raise ValueError("manifest is not an object")
            found.append({"path": path, "record": record, "error": ""})
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            found.append({"path": path, "record": None, "error": str(exc)})
    return found, errors


def activity_index(archive_records: list[dict], activity_records: list[dict]) -> dict:
    """Latest successful activity per source, including refreshed references.

    A source's current lstat mtime extends activity only when it is newer than
    durable AGW activity.  ``last_referenced_at_ns`` lets a safely deduplicated
    preimage reflect its most recent use rather than its original creation.
    """
    activity = {}
    for record in activity_records:
        if not _successful_activity_record(record):
            continue
        stamp = _timestamp_ns(record)
        if stamp <= 0:
            continue
        for path in _activity_paths(record):
            key = _canonical(path)
            activity[key] = max(activity.get(key, 0), stamp)
    for record in archive_records:
        source = str(record.get("src") or "")
        if not source:
            continue
        key = _canonical(source)
        try:
            referenced = int(record.get("last_referenced_at_ns") or 0)
        except (TypeError, ValueError):
            referenced = 0
        activity[key] = max(activity.get(key, 0), referenced)
        try:
            current_mtime = int(os.stat(source, follow_symlinks=False).st_mtime_ns)
        except OSError:
            current_mtime = 0
        activity[key] = max(activity.get(key, 0), current_mtime)
    return activity


def _publication_recovery_pins(
        manifest_records: list[dict], activity_records: list[dict]
        ) -> tuple[dict[str, set[str]], list[str], set[str]]:
    """Derive conservative pins using only bounded inventory evidence.

    This is not Slice 2's live-target authentication.  It validates enough of
    the immutable PREPARED/snapshot relationship to prevent retention from
    reclaiming a possible rollback dependency.  Ambiguity makes the inventory
    incomplete instead of guessing that an artifact is unneeded.
    """
    errors = []
    pins: dict[str, set[str]] = {}
    manifests = {
        str(record.get("transaction_id") or ""): record
        for record in manifest_records
        if str(record.get("transaction_id") or "")
    }
    prepared_by_id = {}
    changed_members_by_prepared = {}
    terminal_by_id = {}
    ambiguous_prepared = set()
    for record in activity_records:
        operation = str(record.get("op") or "")
        if operation == "file-transaction-prepared":
            if record.get("atomicity") != "recoverable-set" \
                    or record.get("visibility") != "per-file-sequential":
                continue
            transaction_id = str(record.get("transaction_id") or "")
            try:
                recovery_contracts.exact_transaction_id(
                    transaction_id, field="prepared transaction id"
                )
            except ValueError:
                errors.append("prepared publication has an invalid identity")
                continue
            prior = prepared_by_id.get(transaction_id)
            if prior is not None and recovery_contracts.canonical_sha256(prior) \
                    != recovery_contracts.canonical_sha256(record):
                errors.append(
                    f"prepared publication is ambiguous: {transaction_id}"
                )
                ambiguous_prepared.add(transaction_id)
                continue
            if prior is None:
                prepared_by_id[transaction_id] = record
        elif operation == "file-transaction-state":
            transaction_id = str(record.get("prepared_transaction_id") or "")
            if not transaction_id:
                continue
            try:
                recovery_contracts.exact_transaction_id(
                    transaction_id, field="prepared transaction id"
                )
            except ValueError:
                errors.append("publication terminal has an invalid identity")
                continue
            terminal_by_id.setdefault(transaction_id, []).append(record)

    unresolved = set()
    resolved = set()
    resolved_states = {}
    for transaction_id, prepared in prepared_by_id.items():
        if transaction_id in ambiguous_prepared:
            unresolved.add(transaction_id)
            continue
        terminals = terminal_by_id.get(transaction_id, [])
        if prepared.get("state") != "PREPARED":
            errors.append(f"prepared publication state is invalid: {transaction_id}")
            unresolved.add(transaction_id)
            continue
        if not _SHA256_RE.fullmatch(str(prepared.get("plan_sha256") or "")):
            errors.append(f"prepared publication plan binding is invalid: {transaction_id}")
            unresolved.add(transaction_id)
            continue
        operations = prepared.get("operations")
        if not isinstance(operations, list) or not operations \
                or len(operations) > recovery_contracts.MAX_PUBLICATION_ROLLBACK_MEMBERS:
            errors.append(f"prepared publication members are invalid: {transaction_id}")
            continue
        snapshot_ids = []
        changed_members = []
        seen_targets = set()
        valid = True
        for expected_number, member in enumerate(operations, 1):
            if not isinstance(member, dict) or member.get("number") != expected_number:
                valid = False
                break
            target = str(member.get("path") or "")
            if not target or os.path.abspath(target) != target:
                valid = False
                break
            target_identity = _canonical(target)
            if target_identity in seen_targets:
                valid = False
                break
            seen_targets.add(target_identity)
            before = str(member.get("before_hash") or "")
            after = str(member.get("after_hash") or "")
            changed = bool(member.get("changed"))
            if before != "absent" and not _SHA256_RE.fullmatch(before):
                valid = False
                break
            if not _SHA256_RE.fullmatch(after):
                valid = False
                break
            snapshot_id = str(member.get("snapshot_transaction_id") or "")
            if not changed:
                if before != after or snapshot_id:
                    valid = False
                    break
                continue
            after_identity = _meaningful_publication_identity(
                member.get("candidate_identity")
            )
            if after_identity is None or after_identity[2] < 0:
                valid = False
                break
            try:
                recovery_contracts.exact_transaction_id(
                    snapshot_id, field="snapshot transaction id"
                )
            except ValueError:
                valid = False
                break
            snapshot = manifests.get(snapshot_id)
            if not snapshot or snapshot.get("state") != archive_tx.COMMITTED \
                    or _canonical(snapshot.get("src") or "") != target_identity \
                    or snapshot.get("source_identity") != target_identity:
                valid = False
                break
            if before == "absent":
                if snapshot.get("kind") != "absent_tombstone":
                    valid = False
                    break
            elif snapshot.get("kind") != "archive" \
                    or snapshot.get("sha256") != before:
                valid = False
                break
            snapshot_ids.append(snapshot_id)
            changed_members.append({
                "number": expected_number,
                "target": target,
                "target_identity": target_identity,
                "after_sha256": after,
                "after_identity": after_identity,
            })
        if not valid:
            errors.append(f"prepared publication evidence is incomplete: {transaction_id}")
            unresolved.add(transaction_id)
            continue
        if terminals:
            terminal_hashes = {
                recovery_contracts.canonical_sha256(item) for item in terminals
            }
            terminal_states = {str(item.get("state") or "") for item in terminals}
            if len(terminal_hashes) != 1 or len(terminal_states) != 1 \
                    or not all(_publication_terminal_valid(prepared, item)
                               for item in terminals):
                errors.append(
                    f"publication terminal evidence is invalid: {transaction_id}"
                )
                unresolved.add(transaction_id)
            else:
                resolved.add(transaction_id)
                resolved_states[transaction_id] = next(iter(terminal_states))
        else:
            unresolved.add(transaction_id)
        changed_members_by_prepared[transaction_id] = changed_members
        if transaction_id in unresolved:
            for snapshot_id in snapshot_ids:
                pins.setdefault(snapshot_id, set()).add(
                    recovery_contracts.UNRESOLVED_PREPARED_PUBLICATION
                )

    prefix = recovery_contracts.PUBLICATION_ROLLBACK_CAPTURE_PREFIX
    for record in manifest_records:
        binding = str(record.get("capture_group_id") or "")
        if not binding.startswith(prefix):
            continue
        prepared_id = binding[len(prefix):]
        try:
            recovery_contracts.exact_transaction_id(
                prepared_id, field="publication rollback binding"
            )
        except ValueError:
            errors.append("publication rollback archive has an invalid binding")
            continue
        if prepared_id not in prepared_by_id:
            errors.append(
                f"publication rollback archive has no prepared record: {prepared_id}"
            )
            continue
        members = changed_members_by_prepared.get(prepared_id)
        if members is None:
            # A resolved publication no longer needs a pin. Its terminal record
            # is sufficient to release retention even if legacy PREPARED
            # evidence cannot satisfy the newer linkage contract.
            if prepared_id in resolved:
                continue
            errors.append(
                f"publication rollback archive has unauthenticated members: {prepared_id}"
            )
            continue
        matching = []
        for member in members:
            expected_id = recovery_contracts.publication_displaced_transaction_id(
                prepared_id, member["number"], member["target_identity"]
            )
            if expected_id == str(record.get("transaction_id") or ""):
                matching.append(member)
        if len(matching) != 1:
            errors.append(
                f"publication rollback archive member is ambiguous: {prepared_id}"
            )
            continue
        member = matching[0]
        if record.get("kind") != "archive" \
                or record.get("mode") != "move" \
                or record.get("actor") != "guardrails-recovery" \
                or record.get("retention_class") != ELIGIBLE_CLASS \
                or _canonical(record.get("src") or "") \
                    != member["target_identity"] \
                or record.get("source_identity") != member["target_identity"] \
                or record.get("sha256") != member["after_sha256"] \
                or tuple(record.get("recovery_source_identity") or ()) \
                    != member["after_identity"]:
            errors.append(
                f"publication rollback archive binding is inconsistent: {prepared_id}"
            )
            continue
        if prepared_id in resolved \
                and resolved_states.get(prepared_id) != "ROLLED_BACK":
            errors.append(
                f"publication rollback archive conflicts with terminal: {prepared_id}"
            )
            for snapshot_id in (
                    str(item.get("snapshot_transaction_id") or "")
                    for item in prepared_by_id[prepared_id].get("operations") or ()):
                if snapshot_id:
                    pins.setdefault(snapshot_id, set()).add(
                        recovery_contracts.UNRESOLVED_PREPARED_PUBLICATION
                    )
            pins.setdefault(str(record.get("transaction_id") or ""), set()).add(
                recovery_contracts.ACTIVE_PUBLICATION_ROLLBACK
            )
            continue
        if prepared_id in unresolved:
            pins.setdefault(str(record.get("transaction_id") or ""), set()).add(
                recovery_contracts.ACTIVE_PUBLICATION_ROLLBACK
            )
    resolved_captures = set()
    for record in manifest_records:
        transaction_id = str(record.get("transaction_id") or "")
        binding = str(record.get("capture_group_id") or "")
        if binding.startswith(prefix) \
                and resolved_states.get(binding[len(prefix):]) == "ROLLED_BACK" \
                and transaction_id not in pins:
            # Only records that passed the exact-member loop above are eligible.
            prepared_id = binding[len(prefix):]
            members = changed_members_by_prepared.get(prepared_id, ())
            if any(
                recovery_contracts.publication_displaced_transaction_id(
                    prepared_id, member["number"], member["target_identity"]
                ) == transaction_id
                and record.get("kind") == "archive"
                and record.get("mode") == "move"
                and record.get("actor") == "guardrails-recovery"
                and record.get("retention_class") == ELIGIBLE_CLASS
                and _canonical(record.get("src") or "") == member["target_identity"]
                and record.get("source_identity") == member["target_identity"]
                and record.get("sha256") == member["after_sha256"]
                and tuple(record.get("recovery_source_identity") or ())
                    == member["after_identity"]
                for member in members
            ):
                resolved_captures.add(transaction_id)
    return pins, errors, resolved_captures


def inventory(home: str, *, activity_records: list[dict] | None = None,
              max_records: int = MAX_INVENTORY_RECORDS,
              max_walk_nodes: int = MAX_WALK_NODES) -> dict:
    """Inventory authoritative transactions without treating unknowns as safe.

    ``complete`` is false for corrupt manifests, identity mismatches, unsafe or
    missing artifact paths, malformed activity records, and record-count or
    filesystem-node bound exhaustion.  Callers must not apply retention from an
    incomplete inventory.
    """
    home = os.path.abspath(home)
    identity = store_identity(home)
    discovered, errors = _discover_manifests(home, max_records)
    unclassified = []
    records = []
    manifest_records = []
    node_budget = [max(0, int(max_walk_nodes))]
    for item in discovered:
        record = item.get("record")
        path = str(item.get("path") or "")
        if item.get("error") or not isinstance(record, dict):
            errors.append(f"corrupt transaction manifest: {path}")
            continue
        manifest_records.append(record)
        transaction_id = str(record.get("transaction_id") or "")
        expected_name = transaction_id + ".json"
        if not transaction_id or os.path.basename(path) != expected_name:
            errors.append(f"transaction manifest identity mismatch: {path}")
            continue
        if record.get("kind") != "archive":
            # Tombstones and future non-artifact records are not reclaimable.
            continue
        classification = str(record.get("retention_class") or "")
        if classification not in KNOWN_CLASSES:
            unclassified.append(transaction_id)
        state = str(record.get("state") or "")
        destination = str(record.get("dest") or "")
        candidate = {
            "transaction_id": transaction_id,
            "source": str(record.get("src") or ""),
            "source_identity": str(record.get("source_identity") or ""),
            "artifact": destination,
            "mode": str(record.get("mode") or ""),
            "state": state,
            "retention_class": classification or "unclassified",
            "created_at_ns": int(record.get("created_at_ns") or 0),
            "last_referenced_at_ns": int(record.get("last_referenced_at_ns") or 0),
            "protected_until_ns": int(record.get("protected_until_ns") or 0),
            "version": int(record.get("version") or 0),
            "artifact_kind": str(record.get("artifact_kind") or ""),
            "sha256": str(record.get("sha256") or ""),
            "logical_bytes": int(record.get("size") or 0),
            "manifest_sha256": _manifest_hash(record),
            "available": False,
            "allocated_bytes": 0,
            "lstat_identity": {},
            "protection_reasons": [],
        }
        if state != archive_tx.COMMITTED:
            candidate["protection_reasons"].append("noncommitted")
            records.append(candidate)
            continue
        if str(record.get("artifact_state") or "PRESENT") != "PRESENT":
            candidate["protection_reasons"].append("artifact_not_present")
            records.append(candidate)
            continue
        if not os.path.lexists(destination):
            # The recovery point is already unavailable. Keep the manifest as
            # evidence and exclude it, but do not let one missing protected
            # artifact prevent safe reclamation of unrelated verified cache.
            candidate["protection_reasons"].append("missing_artifact")
            errors.append(f"missing artifact: {transaction_id}")
            records.append(candidate)
            continue
        if not _safe_artifact_path(home, destination):
            candidate["protection_reasons"].append("unsafe_artifact_path")
            errors.append(f"unsafe artifact path: {transaction_id}")
            records.append(candidate)
            continue
        try:
            candidate["lstat_identity"] = _lstat_identity(destination)
            candidate["allocated_bytes"] = _allocated_bytes(
                destination, node_budget=node_budget
            )
            candidate["available"] = True
        except (OSError, InventoryIncompleteError) as exc:
            candidate["protection_reasons"].append("unreadable_artifact")
            errors.append(f"artifact inventory failed for {transaction_id}: {exc}")
        records.append(candidate)

    if activity_records is None:
        activity_records, activity_errors = _read_oplog(home)
        errors.extend(activity_errors)
    else:
        activity_errors = []
        for number, record in enumerate(activity_records, 1):
            if not isinstance(record, dict):
                activity_errors.append(f"activity record {number} is not an object")
        errors.extend(activity_errors)
        activity_records = [item for item in activity_records if isinstance(item, dict)]

    recovery_pins, recovery_errors, resolved_captures = _publication_recovery_pins(
        manifest_records, activity_records
    )
    errors.extend(recovery_errors)
    for candidate in records:
        candidate["protection_reasons"].extend(
            sorted(recovery_pins.get(candidate["transaction_id"], ()))
        )
        candidate["resolved_publication_rollback"] = (
            candidate["transaction_id"] in resolved_captures
        )

    activity = activity_index(manifest_records, activity_records)
    fingerprint_payload = {
        "records": sorted(records, key=lambda value: value["transaction_id"]),
        "activity": sorted(activity.items()),
        "errors": errors,
        "unclassified": sorted(unclassified),
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "store_identity": identity,
        "complete": not any(
            not error.startswith("missing artifact:") for error in errors
        ),
        "errors": errors,
        "unclassified_transaction_ids": sorted(unclassified),
        "records": records,
        "activity_by_source": activity,
        "known_allocated_bytes": sum(item["allocated_bytes"] for item in records),
        "inventory_sha256": _json_hash(fingerprint_payload),
    }


def _utc_day(timestamp_ns: int) -> str:
    return datetime.fromtimestamp(timestamp_ns / 1_000_000_000,
                                  tz=timezone.utc).strftime("%Y-%m-%d")


def protection_map(snapshot: dict, *, now_ns: int | None = None,
                   policy: retention_policy.RetentionPolicy | None = None
                   ) -> dict[str, list[str]]:
    """Return deterministic protection reasons for every inventoried record."""
    now_ns = int(now_ns or time.time_ns())
    recent_days = (policy.min_protected_age_days if policy else RECENT_DAYS)
    inactive_days = (policy.inactive_collapse_age_days if policy else ACTIVE_DAYS)
    protected = {item["transaction_id"]: list(item["protection_reasons"])
                 for item in snapshot["records"]}
    by_source = {}
    for item in snapshot["records"]:
        transaction_id = item["transaction_id"]
        reasons = protected[transaction_id]
        if item["mode"] == "move" \
                and not item.get("resolved_publication_rollback"):
            reasons.append("move_archive")
        if item["retention_class"] != ELIGIBLE_CLASS:
            reasons.append("retention_class")
        if item["state"] != archive_tx.COMMITTED or not item["available"]:
            reasons.append("not_usable")
        if item["protected_until_ns"] > now_ns:
            reasons.append("active_hold")
        if now_ns - item["created_at_ns"] <= recent_days * DAY_NS:
            reasons.append("recent_generation")
        if item["available"]:
            by_source.setdefault(_canonical(item["source"]), []).append(item)

    for source, items in by_source.items():
        items.sort(key=lambda item: (
            item["created_at_ns"], item["version"], item["transaction_id"]
        ), reverse=True)
        activity_at = int(snapshot["activity_by_source"].get(source) or 0)
        active = activity_at > 0 and now_ns - activity_at <= inactive_days * DAY_NS
        newest_count = KEEP_NEWEST_ACTIVE if active else 1
        for item in items[:newest_count]:
            protected[item["transaction_id"]].append(
                "newest_active" if active else "newest_inactive"
            )
        if active:
            daily = {}
            for item in items:
                age = now_ns - item["created_at_ns"]
                if age <= recent_days * DAY_NS or age > inactive_days * DAY_NS:
                    continue
                day = _utc_day(item["created_at_ns"])
                daily.setdefault(day, item)
            for item in daily.values():
                protected[item["transaction_id"]].append("daily_generation")

    return {transaction_id: sorted(set(reasons))
            for transaction_id, reasons in protected.items()}


def select_candidates(snapshot: dict, bytes_to_free: int, *,
                      now_ns: int | None = None,
                      max_candidates: int = MAX_CANDIDATES,
                      max_reclaim_bytes: int = MAX_RECLAIM_BYTES,
                      policy: retention_policy.RetentionPolicy | None = None
                      ) -> list[dict]:
    """Select a bounded, deterministic subset only from explicit preimages."""
    if not snapshot.get("complete"):
        return []
    required = max(0, int(bytes_to_free or 0))
    if required <= 0:
        return []
    if policy is not None:
        max_candidates = policy.max_candidates
        max_reclaim_bytes = policy.max_reclaim_bytes
    protected = protection_map(snapshot, now_ns=now_ns, policy=policy)
    eligible = [
        item for item in snapshot["records"]
        if not protected[item["transaction_id"]]
    ]
    # Eligibility already encodes recency/activity guarantees. Within that
    # safe set, reclaim larger artifacts first so the bounded candidate count
    # removes fewer recovery points and reaches useful headroom sooner.
    eligible.sort(key=lambda item: (
        -item["allocated_bytes"], item["created_at_ns"],
        item["version"], item["transaction_id"],
    ))
    selected = []
    reclaimed = 0
    count_limit = max(0, min(int(max_candidates), MAX_CANDIDATES))
    byte_limit = max(0, min(int(max_reclaim_bytes), MAX_RECLAIM_BYTES))
    for item in eligible:
        if len(selected) >= count_limit or reclaimed >= required:
            break
        size = int(item["allocated_bytes"])
        if selected and reclaimed + size > byte_limit:
            break
        if not selected and size > byte_limit:
            # One large artifact still cannot exceed the explicit per-pass cap.
            continue
        selected.append({
            field: item[field] for field in (
                "transaction_id", "source", "source_identity", "artifact",
                "retention_class", "created_at_ns", "last_referenced_at_ns",
                "protected_until_ns", "version", "artifact_kind", "sha256",
                "logical_bytes", "allocated_bytes", "manifest_sha256",
                "lstat_identity",
            )
        })
        reclaimed += size
    return selected


def build_plan(home: str, max_bytes: int | None = None, *,
               policy: retention_policy.RetentionPolicy | None = None,
               current_bytes: int | None = None,
               now_ns: int | None = None,
               activity_records: list[dict] | None = None,
               high_water: float = DEFAULT_HIGH_WATER,
               low_water: float = DEFAULT_LOW_WATER,
               max_candidates: int = MAX_CANDIDATES,
               max_reclaim_bytes: int = MAX_RECLAIM_BYTES,
               max_records: int = MAX_INVENTORY_RECORDS,
               max_walk_nodes: int = MAX_WALK_NODES) -> dict:
    """Create a 15-minute, hash-bound plan.  This function never mutates data."""
    now_ns = int(now_ns or time.time_ns())
    if policy is None:
        maximum = int(max_bytes or 0)
        policy = retention_policy.RetentionPolicy(
            max_bytes=maximum,
            high_water_bytes=int(maximum * high_water) if maximum else 0,
            low_water_bytes=int(maximum * low_water) if maximum else 0,
            min_protected_age_days=RECENT_DAYS,
            inactive_collapse_age_days=ACTIVE_DAYS,
            max_candidates=min(max(1, int(max_candidates)), MAX_CANDIDATES),
            max_reclaim_bytes=min(max(1, int(max_reclaim_bytes)),
                                  MAX_RECLAIM_BYTES),
        )
    else:
        maximum = int(policy.max_bytes)
    if maximum < 0:
        raise ValueError("max_bytes cannot be negative")
    if not 0 < low_water < high_water <= 1:
        raise ValueError("watermarks must satisfy 0 < low < high <= 1")
    snapshot = inventory(
        home, activity_records=activity_records, max_records=max_records,
        max_walk_nodes=max_walk_nodes,
    )
    current = (int(snapshot["known_allocated_bytes"])
               if current_bytes is None else int(current_bytes))
    if current < snapshot["known_allocated_bytes"] or current < 0:
        raise ValueError(
            "current_bytes cannot be negative or below inventoried artifact bytes"
        )
    state = retention_policy.classify_retention_state(policy, current)
    high_bytes = policy.high_water_bytes
    target_bytes = policy.low_water_bytes
    pressure = state.prune_recommended
    required = state.reclaim_target_bytes
    # Unknown/legacy records are individually protected.  Their presence may
    # prevent reaching the target, but must not prevent safe classified cache
    # entries from being reclaimed.
    applicable = bool(snapshot["complete"])
    candidates = select_candidates(
        snapshot, required, now_ns=now_ns, max_candidates=max_candidates,
        max_reclaim_bytes=max_reclaim_bytes, policy=policy,
    ) if applicable else []
    planned = sum(item["allocated_bytes"] for item in candidates)
    plan = {
        "schema_version": SCHEMA_VERSION,
        "operation": PLAN_OPERATION,
        "plan_id": uuid.uuid4().hex,
        "created_at_ns": now_ns,
        "expires_at_ns": now_ns + PLAN_TTL_NS,
        "store_identity": snapshot["store_identity"],
        "inventory_sha256": snapshot["inventory_sha256"],
        "inventory_complete": snapshot["complete"],
        "inventory_errors": snapshot["errors"],
        "unclassified_transaction_ids": snapshot["unclassified_transaction_ids"],
        "applicable": applicable,
        "budget_bytes": maximum,
        "high_water_bytes": high_bytes,
        "target_bytes": target_bytes,
        "current_bytes": current,
        "inventoried_artifact_bytes": snapshot["known_allocated_bytes"],
        "under_pressure": pressure,
        "bytes_to_free": required,
        "planned_reclaim_bytes": planned,
        "projected_bytes": max(0, current - planned),
        "capacity_satisfied_by_plan": planned >= required,
        "policy": policy.as_dict(),
        "retention_state": state.as_dict(),
        "max_candidates": min(policy.max_candidates, MAX_CANDIDATES),
        "max_reclaim_bytes": min(policy.max_reclaim_bytes,
                                 MAX_RECLAIM_BYTES),
        "candidates": candidates,
    }
    return recovery_contracts.bind_plan_hash(plan)


def plan_hash_valid(plan: dict) -> bool:
    return recovery_contracts.plan_hash_valid(plan)


def _journal_dir(home: str) -> str:
    path = os.path.join(_retention_root(home), "transactions")
    os.makedirs(path, exist_ok=True)
    return path


def _staging_dir(home: str, plan_id: str) -> str:
    path = os.path.join(_retention_root(home), "staging", plan_id)
    os.makedirs(path, exist_ok=True)
    return path


def _journal_path(home: str, plan_id: str) -> str:
    return os.path.join(_journal_dir(home), plan_id + ".json")


def _persist_json(path: str, value: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temp = path + "." + uuid.uuid4().hex + ".tmp"
    with open(temp, "x", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)
    try:
        fd = os.open(os.path.dirname(path), os.O_RDONLY |
                     getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def load_journal(home: str, plan_id: str) -> dict:
    with open(_journal_path(home, plan_id), encoding="utf-8") as handle:
        return json.load(handle)


class _RetentionLock:
    """A no-steal lock; store facade should normally supply its global lock."""

    def __init__(self, home: str):
        self.path = os.path.join(_retention_root(home), "retention.lock")
        self.fd = None

    def __enter__(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        try:
            self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(self.fd, uuid.uuid4().hex.encode("ascii"))
        except FileExistsError as exc:
            raise RetentionError("another retention operation is active") from exc
        return self

    def __exit__(self, *_exc):
        if self.fd is not None:
            os.close(self.fd)
        try:
            os.unlink(self.path)
        except OSError:
            pass


def _lock_context(home: str, lock_context):
    if lock_context is None:
        return _RetentionLock(home)
    return lock_context if hasattr(lock_context, "__enter__") else lock_context()


def _validate_plan(plan: dict, expected_plan_hash: str, home: str, now_ns: int):
    if not expected_plan_hash or expected_plan_hash != plan.get("plan_sha256"):
        raise InvalidPlanError("the exact reviewed plan hash is required")
    if not plan_hash_valid(plan):
        raise InvalidPlanError("retention plan hash is invalid")
    plan_id = str(plan.get("plan_id") or "")
    if plan.get("operation") != PLAN_OPERATION or len(plan_id) != 32 \
            or any(char not in "0123456789abcdef" for char in plan_id):
        raise InvalidPlanError("not a retention plan")
    if int(plan.get("expires_at_ns") or 0) < now_ns:
        raise InvalidPlanError("retention plan has expired")
    if plan.get("store_identity") != store_identity(home):
        raise InvalidPlanError("retention plan belongs to a different store")
    if not plan.get("inventory_complete") or not plan.get("applicable"):
        raise InventoryIncompleteError("retention plan inventory was not applicable")
    candidates = plan.get("candidates") or ()
    if not isinstance(candidates, list) or len(candidates) > MAX_CANDIDATES:
        raise InvalidPlanError("retention plan exceeds its candidate bound")
    transaction_ids = [str(item.get("transaction_id") or "")
                       for item in candidates if isinstance(item, dict)]
    if len(transaction_ids) != len(candidates) or len(set(transaction_ids)) \
            != len(transaction_ids):
        raise InvalidPlanError("retention plan candidate identities are invalid")
    if any(len(value) != 32 or any(char not in "0123456789abcdef" for char in value)
           for value in transaction_ids):
        raise InvalidPlanError("retention plan candidate identity is invalid")
    if any(item.get("retention_class") != ELIGIBLE_CLASS for item in candidates):
        raise InvalidPlanError("retention plan contains a protected class")
    if sum(max(0, int(item.get("allocated_bytes") or 0)) for item in candidates) \
            > MAX_RECLAIM_BYTES:
        raise InvalidPlanError("retention plan exceeds its reclaim-byte bound")


def _candidate_metadata_equal(planned: dict, current: dict) -> bool:
    fields = (
        "transaction_id", "source", "source_identity", "artifact",
        "retention_class", "created_at_ns", "last_referenced_at_ns",
        "protected_until_ns", "version", "artifact_kind", "sha256",
        "logical_bytes", "allocated_bytes", "manifest_sha256", "lstat_identity",
    )
    return all(planned.get(field) == current.get(field) for field in fields)


def _candidate_artifact_identity_equal(planned: dict, current: dict) -> bool:
    """Fields that may not change even when a new activity hold is added."""
    fields = (
        "transaction_id", "source", "source_identity", "artifact",
        "retention_class", "created_at_ns", "version", "artifact_kind",
        "sha256", "logical_bytes", "allocated_bytes", "lstat_identity",
    )
    return all(planned.get(field) == current.get(field) for field in fields)


def _verify_artifact(candidate: dict):
    expected = (candidate["artifact_kind"], candidate["sha256"],
                candidate["logical_bytes"])
    actual = archive_tx.artifact_fingerprint(candidate["artifact"])
    # Link recovery artifacts are ordinary metadata files in the store.
    if candidate["artifact_kind"] == "link-metadata" and actual[0] == "file":
        actual = ("link-metadata", actual[1], actual[2])
    if actual != expected:
        raise StalePlanError(
            f"artifact fingerprint changed: {candidate['transaction_id']}"
        )


def _mark_manifest_purged(home: str, entry: dict, plan_id: str,
                          purged_at_ns: int):
    record = archive_tx.load(home, entry["transaction_id"])
    if str(record.get("artifact_state") or "PRESENT") == "PURGED" \
            and record.get("retention_plan_id") == plan_id:
        return
    archive_tx.update(
        home, entry["transaction_id"], artifact_state="PURGED",
        retention_plan_id=plan_id, purged_at_ns=purged_at_ns,
        purged_artifact_sha256=entry["sha256"],
        purged_artifact_bytes=entry["allocated_bytes"],
    )


def _remove_staged(path: str):
    info = os.lstat(path)
    if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
        shutil.rmtree(path)
    else:
        os.unlink(path)


def _finish_staged(home: str, journal: dict, *, crash_after: str | None = None) -> dict:
    path = _journal_path(home, journal["plan_id"])
    for index, entry in enumerate(journal["entries"]):
        staged = entry["staged_artifact"]
        if not entry.get("purged"):
            if os.path.lexists(staged):
                _remove_staged(staged)
            elif os.path.lexists(entry["artifact"]):
                raise RetentionError("staged artifact unexpectedly returned to archive")
            entry["purged"] = True
            entry["purged_at_ns"] = time.time_ns()
            _persist_json(path, journal)
            if crash_after == "PURGED_ITEM" and index == 0:
                raise SimulatedCrash("simulated crash after PURGED_ITEM")
        _mark_manifest_purged(
            home, entry, journal["plan_id"], entry["purged_at_ns"]
        )
    journal["state"] = PURGED
    journal["purged_at_ns"] = time.time_ns()
    _persist_json(path, journal)
    try:
        os.rmdir(os.path.dirname(journal["entries"][0]["staged_artifact"]))
    except (OSError, IndexError):
        pass
    return journal


def apply_plan(home: str, plan: dict, *, expected_plan_hash: str,
               now_ns: int | None = None, activity_records: list[dict] | None = None,
               policy: retention_policy.RetentionPolicy | None = None,
               lock_context=None, crash_after: str | None = None) -> dict:
    """Apply only still-eligible reviewed candidates through a durable journal.

    ``lock_context`` may be a context manager or zero-argument factory supplied
    by ``store``.  Without one, a conservative no-steal retention lock is used.
    """
    home = os.path.abspath(home)
    now_ns = int(now_ns or time.time_ns())
    _validate_plan(plan, expected_plan_hash, home, now_ns)
    with _lock_context(home, lock_context):
        fresh = inventory(home, activity_records=activity_records)
        if not fresh["complete"]:
            raise InventoryIncompleteError("current retention inventory is incomplete")
        current_by_id = {item["transaction_id"]: item for item in fresh["records"]}
        if policy is None:
            raw_policy = plan.get("policy") or {}
            def _policy_value(name: str, fallback: int) -> int:
                return int(raw_policy[name]) if name in raw_policy else fallback

            policy = retention_policy.RetentionPolicy(
                max_bytes=_policy_value("max_bytes", 0),
                high_water_bytes=_policy_value("high_water_bytes", 0),
                low_water_bytes=_policy_value("low_water_bytes", 0),
                min_protected_age_days=_policy_value(
                    "min_protected_age_days", RECENT_DAYS
                ),
                inactive_collapse_age_days=_policy_value(
                    "inactive_collapse_age_days", ACTIVE_DAYS
                ),
                max_candidates=_policy_value("max_candidates", MAX_CANDIDATES),
                max_reclaim_bytes=_policy_value(
                    "max_reclaim_bytes", MAX_RECLAIM_BYTES
                ),
            )
        elif policy.as_dict() != plan.get("policy"):
            raise InvalidPlanError("retention policy differs from the reviewed plan")
        protected = protection_map(fresh, now_ns=now_ns, policy=policy)
        selected, skipped = [], []
        for planned in plan.get("candidates") or ():
            transaction_id = planned.get("transaction_id")
            current = current_by_id.get(transaction_id)
            if current is None:
                raise StalePlanError(f"planned candidate changed: {transaction_id}")
            reasons = protected[transaction_id]
            if not _candidate_metadata_equal(planned, current):
                # A refreshed last-reference/protection hold may only shrink the
                # reviewed set.  All artifact-bound fields must remain exact.
                if _candidate_artifact_identity_equal(planned, current) and reasons:
                    skipped.append({
                        "transaction_id": transaction_id,
                        "reasons": sorted(set(reasons + ["activity_metadata_changed"])),
                    })
                    continue
                raise StalePlanError(f"planned candidate changed: {transaction_id}")
            if reasons:
                skipped.append({"transaction_id": transaction_id, "reasons": reasons})
                continue
            if not _safe_artifact_path(home, current["artifact"]):
                raise StalePlanError(f"unsafe candidate path: {transaction_id}")
            if _lstat_identity(current["artifact"]) != planned["lstat_identity"]:
                raise StalePlanError(f"candidate identity changed: {transaction_id}")
            _verify_artifact(current)
            selected.append(current)

        plan_ids = [item.get("transaction_id") for item in plan.get("candidates") or ()]
        if any(item["transaction_id"] not in plan_ids for item in selected):
            raise InvalidPlanError("apply attempted to expand the reviewed candidate set")
        journal = {
            "schema_version": SCHEMA_VERSION,
            "kind": "retention",
            "plan_id": plan["plan_id"],
            "plan_sha256": expected_plan_hash,
            "store_identity": plan["store_identity"],
            "state": PREPARED,
            "created_at_ns": now_ns,
            "inventory_changed": fresh["inventory_sha256"]
                != plan["inventory_sha256"],
            "skipped": skipped,
            "entries": [],
        }
        staging = _staging_dir(home, plan["plan_id"])
        for item in selected:
            staged = os.path.join(
                staging, item["transaction_id"] + "__" +
                os.path.basename(item["artifact"])
            )
            journal["entries"].append({**item, "staged_artifact": staged,
                                       "staged": False, "purged": False})
        journal_path = _journal_path(home, plan["plan_id"])
        _persist_json(journal_path, journal)
        if crash_after == PREPARED:
            raise SimulatedCrash("simulated crash after PREPARED")

        try:
            for index, entry in enumerate(journal["entries"]):
                os.replace(entry["artifact"], entry["staged_artifact"])
                entry["staged"] = True
                _persist_json(journal_path, journal)
                if crash_after == "STAGED_ITEM" and index == 0:
                    raise SimulatedCrash("simulated crash after STAGED_ITEM")
        except SimulatedCrash:
            raise
        except Exception:
            # No bytes have been purged yet; restore all successfully staged items.
            for entry in reversed(journal["entries"]):
                if entry.get("staged") and os.path.lexists(entry["staged_artifact"]) \
                        and not os.path.lexists(entry["artifact"]):
                    os.replace(entry["staged_artifact"], entry["artifact"])
                    entry["staged"] = False
            _persist_json(journal_path, journal)
            raise
        journal["state"] = STAGED
        _persist_json(journal_path, journal)
        if crash_after == STAGED:
            raise SimulatedCrash("simulated crash after STAGED")
        journal = _finish_staged(home, journal, crash_after=crash_after)
        return {
            "plan_id": plan["plan_id"],
            "state": journal["state"],
            "purged_transaction_ids": [entry["transaction_id"]
                                       for entry in journal["entries"]],
            "skipped": skipped,
            "planned_candidates": len(plan.get("candidates") or ()),
            "purged_candidates": len(journal["entries"]),
            "reclaimed_bytes": sum(entry["allocated_bytes"]
                                   for entry in journal["entries"]),
            "inventory_changed": journal["inventory_changed"],
        }


def recover_journal(home: str, plan_id: str, *, lock_context=None) -> dict:
    """Recover one interrupted retention apply idempotently."""
    home = os.path.abspath(home)
    with _lock_context(home, lock_context):
        journal = load_journal(home, plan_id)
        if journal.get("store_identity") != store_identity(home):
            raise RetentionError("retention journal belongs to a different store")
        state = journal.get("state")
        if state == PURGED:
            return journal
        if state == PREPARED:
            # Staging was not committed, so restore every staged artifact.
            for entry in reversed(journal.get("entries") or ()):
                staged = entry["staged_artifact"]
                original = entry["artifact"]
                if os.path.lexists(staged):
                    if os.path.lexists(original):
                        raise RetentionError("both staged and original artifacts exist")
                    os.replace(staged, original)
                entry["staged"] = False
            journal["recovered_at_ns"] = time.time_ns()
            journal["recovery_action"] = "rolled_back_staging"
            _persist_json(_journal_path(home, plan_id), journal)
            return journal
        if state == STAGED:
            return _finish_staged(home, journal)
        raise RetentionError(f"unknown retention journal state: {state}")
