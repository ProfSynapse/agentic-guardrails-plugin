"""Crash-resumable rollback for authenticated PREPARED publications.

The journal stores only progress.  Static recovery evidence is re-derived from
the hash-bound PREPARED oplog record on every entry.
"""
from __future__ import annotations

from contextlib import ExitStack, nullcontext
import hashlib
import json
import os
import re
import secrets
import stat
import time
from typing import Callable, Mapping

from core import archive_transactions as archive_tx, recovery_contracts, store
import file_ops
import path_safety


SCHEMA = "agw-publication-rollback/v1"
MAX_MEMBERS = recovery_contracts.MAX_PUBLICATION_ROLLBACK_MEMBERS
MAX_MANIFEST_BYTES = recovery_contracts.MAX_PUBLICATION_ROLLBACK_MANIFEST_BYTES

ACTIVE = "ACTIVE"
BLOCKED = "BLOCKED"
ROLLED_BACK = "ROLLED_BACK"
TRANSACTION_STATES = {ACTIVE, BLOCKED, ROLLED_BACK}

ALREADY_BEFORE = "ALREADY_BEFORE"
CAPTURE_INTENT = "CAPTURE_INTENT"
RESTORE_INTENT = "RESTORE_INTENT"
STAGE_ALLOCATE_INTENT = "STAGE_ALLOCATE_INTENT"
STAGE_OWNED = "STAGE_OWNED"
STAGE_READY = "STAGE_READY"
RESTORED = "RESTORED"
MEMBER_STATES = {
    ALREADY_BEFORE, CAPTURE_INTENT, RESTORE_INTENT, STAGE_ALLOCATE_INTENT,
    STAGE_OWNED, STAGE_READY, RESTORED,
}

_TOP_KEYS = {
    "schema", "prepared_transaction_id", "prepared_sha256", "plan_sha256",
    "state", "revision", "created_at_ns", "updated_at_ns", "members",
    "blocked", "manifest_sha256",
}
_MEMBER_KEYS = {"number", "state", "stage_basename", "stage_identity"}
_BLOCKED_KEYS = {"code", "member"}
_BLOCK_CODE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}")
_HASH_RE = re.compile(r"[0-9a-f]{64}")
_TEMP_RE = re.compile(r"([0-9a-f]{32})\.([1-9][0-9]*)\.([0-9a-f]{32})\.tmp")


class RecoveryEvidenceError(ValueError):
    """PREPARED evidence cannot authorize rollback before journaling."""


class RecoveryManifestError(ValueError):
    """An existing recovery journal is corrupt or does not match PREPARED."""


def _manifest_dir() -> str:
    return os.path.join(store.agw_home_path(), "publication-recovery")


def manifest_path(prepared_transaction_id: str) -> str:
    identifier = recovery_contracts.exact_transaction_id(
        prepared_transaction_id, field="prepared transaction id",
    )
    return os.path.join(_manifest_dir(), identifier + ".json")


def _manifest_temp_dir() -> str:
    return os.path.join(_manifest_dir(), ".tmp")


def _bound_manifest(record: Mapping) -> dict:
    bound = dict(record)
    bound.pop("manifest_sha256", None)
    bound["manifest_sha256"] = recovery_contracts.canonical_sha256(bound)
    return bound


def _serialized(record: Mapping) -> bytes:
    return json.dumps(
        record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _flush_directory(path: str) -> None:
    flags = getattr(os, "O_DIRECTORY", 0) | os.O_RDONLY
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _persist(record: Mapping) -> dict:
    """Atomically replace one bounded manifest and advance its revision once."""
    previous = int(record.get("revision") or 0)
    now = time.time_ns()
    updated = dict(record)
    updated["revision"] = previous + 1
    updated["created_at_ns"] = int(updated.get("created_at_ns") or now)
    updated["updated_at_ns"] = max(now, updated["created_at_ns"])
    updated = _bound_manifest(updated)
    payload = _serialized(updated)
    if len(payload) > MAX_MANIFEST_BYTES:
        raise RecoveryManifestError("publication recovery manifest exceeds 64 KiB")
    with store.Lock("publication-recovery-manifest-store", timeout=30.0):
        directory = _manifest_dir()
        temporary_dir = _manifest_temp_dir()
        os.makedirs(temporary_dir, exist_ok=True)
        if os.path.islink(temporary_dir) or not os.path.isdir(temporary_dir):
            raise RecoveryManifestError(
                "publication recovery temp directory is unsafe"
            )
        with os.scandir(temporary_dir) as iterator:
            if next(iterator, None) is not None:
                raise RecoveryManifestError(
                    "publication recovery temp store was not reconciled"
                )
        destination = manifest_path(updated["prepared_transaction_id"])
        name = (f"{updated['prepared_transaction_id']}.{updated['revision']}."
                f"{secrets.token_hex(16)}.tmp")
        temporary = os.path.join(temporary_dir, name)
        with open(temporary, "xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        _flush_directory(directory)
    return updated


def _read_manifest_file(
    path: str, prepared: Mapping, *, validation_path: str = "",
) -> dict:
    size = os.path.getsize(path)
    if size <= 0 or size > MAX_MANIFEST_BYTES:
        raise RecoveryManifestError("publication recovery manifest size is invalid")
    try:
        with open(path, encoding="utf-8") as handle:
            record = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RecoveryManifestError(
            "publication recovery manifest could not be authenticated"
        ) from exc
    return _validate_manifest(record, prepared, validation_path or path)


def _reconcile_manifest_temps_locked(prepared: Mapping) -> None:
    directory = _manifest_temp_dir()
    if not os.path.lexists(directory):
        return
    if os.path.islink(directory) or not os.path.isdir(directory):
        raise RecoveryManifestError("publication recovery temp directory is unsafe")
    with os.scandir(directory) as iterator:
        entries = []
        for entry in iterator:
            entries.append(entry)
            if len(entries) > 1:
                break
    if len(entries) > 1:
        raise RecoveryManifestError("publication recovery temp store is ambiguous")
    if not entries:
        return
    entry = entries[0]
    match = _TEMP_RE.fullmatch(entry.name)
    info = entry.stat(follow_symlinks=False)
    if not match or entry.is_symlink() or not stat.S_ISREG(info.st_mode) \
            or match.group(1) != prepared["transaction_id"] \
            or int(info.st_size) > MAX_MANIFEST_BYTES:
        raise RecoveryManifestError("publication recovery temp is unknown or unsafe")
    destination = manifest_path(prepared["transaction_id"])
    current = load_manifest(prepared)
    expected_revision = int(current.get("revision") or 0) + 1 if current else 1
    if int(match.group(2)) != expected_revision:
        raise RecoveryManifestError("publication recovery temp revision is invalid")
    if info.st_size:
        try:
            candidate = _read_manifest_file(
                entry.path, prepared, validation_path=destination,
            )
        except RecoveryManifestError:
            candidate = None
        if candidate is not None and candidate["revision"] == expected_revision:
            os.replace(entry.path, destination)
            _flush_directory(_manifest_dir())
            return
    os.unlink(entry.path)


def _reconcile_manifest_temps(prepared: Mapping) -> None:
    with store.Lock("publication-recovery-manifest-store", timeout=30.0):
        _reconcile_manifest_temps_locked(prepared)


def _validate_manifest(record: object, prepared: Mapping, path: str) -> dict:
    if not isinstance(record, Mapping) or set(record) != _TOP_KEYS:
        raise RecoveryManifestError("publication recovery manifest fields are invalid")
    identifier = recovery_contracts.exact_transaction_id(
        record.get("prepared_transaction_id"), field="prepared transaction id",
    )
    if os.path.abspath(path) != os.path.abspath(manifest_path(identifier)):
        raise RecoveryManifestError("publication recovery filename is invalid")
    if record.get("schema") != SCHEMA or record.get("state") not in TRANSACTION_STATES:
        raise RecoveryManifestError("publication recovery schema or state is invalid")
    if identifier != prepared.get("transaction_id"):
        raise RecoveryManifestError("publication recovery identifies another transaction")
    if record.get("prepared_sha256") != recovery_contracts.canonical_sha256(prepared) \
            or record.get("plan_sha256") != prepared.get("plan_sha256"):
        raise RecoveryManifestError("publication recovery PREPARED binding is invalid")
    revision = record.get("revision")
    created = record.get("created_at_ns")
    updated = record.get("updated_at_ns")
    if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0
           for value in (revision, created, updated)) or updated < created:
        raise RecoveryManifestError("publication recovery revision or timestamps are invalid")
    if not _HASH_RE.fullmatch(str(record.get("manifest_sha256") or "")) \
            or _bound_manifest(record) != dict(record):
        raise RecoveryManifestError("publication recovery manifest hash is invalid")
    members = record.get("members")
    expected_count = len(prepared.get("operations") or [])
    if not isinstance(members, list) or not 1 <= len(members) <= MAX_MEMBERS \
            or len(members) != expected_count:
        raise RecoveryManifestError("publication recovery members are invalid")
    for number, member in enumerate(members, 1):
        if not isinstance(member, Mapping) or set(member) != _MEMBER_KEYS \
                or member.get("number") != number \
                or member.get("state") not in MEMBER_STATES:
            raise RecoveryManifestError("publication recovery member state is invalid")
        basename = member.get("stage_basename")
        identity = member.get("stage_identity")
        state = member["state"]
        if not isinstance(basename, str) or os.path.basename(basename) != basename \
                or (basename and not re.fullmatch(
                    r"\.agw-publication-rollback-[0-9a-f]{32}\.restore", basename
                )):
            raise RecoveryManifestError("publication recovery stage basename is invalid")
        if identity is not None:
            try:
                store._publication_stage_identity(identity)
            except Exception as exc:
                raise RecoveryManifestError(
                    "publication recovery stage identity is invalid"
                ) from exc
        if state in {ALREADY_BEFORE, CAPTURE_INTENT, RESTORE_INTENT, RESTORED} \
                and (basename or identity is not None):
            raise RecoveryManifestError("publication recovery member has premature stage data")
        if state == STAGE_ALLOCATE_INTENT and (not basename or identity is not None):
            raise RecoveryManifestError("stage allocation intent fields are invalid")
        if state in {STAGE_OWNED, STAGE_READY} and (not basename or identity is None):
            raise RecoveryManifestError("owned publication stage fields are invalid")
    blocked = record.get("blocked")
    if blocked is not None:
        if not isinstance(blocked, Mapping) or set(blocked) != _BLOCKED_KEYS \
                or not _BLOCK_CODE_RE.fullmatch(str(blocked.get("code") or "")):
            raise RecoveryManifestError("publication recovery blocked reason is invalid")
        member = blocked.get("member")
        if isinstance(member, bool) or not isinstance(member, int) \
                or member < 0 or member > len(members):
            raise RecoveryManifestError("publication recovery blocked member is invalid")
    if record.get("state") == BLOCKED and blocked is None:
        raise RecoveryManifestError("blocked publication recovery lacks a reason")
    if record.get("state") != BLOCKED and blocked is not None:
        raise RecoveryManifestError("non-blocked publication recovery has a blocked reason")
    member_states = {member["state"] for member in members}
    if record.get("state") == ROLLED_BACK \
            and not member_states <= {ALREADY_BEFORE, RESTORED}:
        raise RecoveryManifestError("rolled-back publication has incomplete members")
    if len(_serialized(record)) > MAX_MANIFEST_BYTES:
        raise RecoveryManifestError("publication recovery manifest exceeds 64 KiB")
    return dict(record)


def load_manifest(prepared: Mapping) -> dict | None:
    path = manifest_path(str(prepared.get("transaction_id") or ""))
    try:
        size = os.path.getsize(path)
    except FileNotFoundError:
        return None
    return _read_manifest_file(path, prepared)


def _absolute_recorded_path(value: object, label: str) -> str:
    raw = str(value or "")
    if not raw or "\x00" in raw or any(character in raw for character in "*?["):
        raise RecoveryEvidenceError(f"{label} is not a literal path")
    path = os.path.abspath(os.path.expanduser(raw))
    if raw != path:
        raise RecoveryEvidenceError(f"{label} is not normalized and absolute")
    return path


def _hash(value: object, label: str, *, absent: bool = False) -> str:
    digest = str(value or "")
    if absent and digest == "absent":
        return digest
    if not _HASH_RE.fullmatch(digest):
        raise RecoveryEvidenceError(f"{label} is not a lowercase SHA-256")
    return digest


def _candidate_identity(value: object) -> tuple[int, int, int, int]:
    try:
        return store._meaningful_ordinary_file_identity(value)
    except Exception as exc:
        raise RecoveryEvidenceError("prepared candidate identity is not meaningful") from exc


def authenticate_prepared(prepared: Mapping) -> list[dict]:
    """Authenticate static PREPARED evidence without reading candidates/stages."""
    if not isinstance(prepared, Mapping):
        raise RecoveryEvidenceError("prepared publication record is invalid")
    identifier = recovery_contracts.exact_transaction_id(
        prepared.get("transaction_id"), field="prepared transaction id",
    )
    if prepared.get("op") != "file-transaction-prepared" \
            or prepared.get("state") != "PREPARED" \
            or prepared.get("atomicity") != "recoverable-set" \
            or prepared.get("visibility") != "per-file-sequential" \
            or not _HASH_RE.fullmatch(str(prepared.get("plan_sha256") or "")):
        raise RecoveryEvidenceError("prepared publication envelope is invalid")
    operations = prepared.get("operations")
    if not isinstance(operations, list) or not 1 <= len(operations) <= MAX_MEMBERS:
        raise RecoveryEvidenceError("prepared publication member count is invalid")
    members = []
    identities = set()
    for number, item in enumerate(operations, 1):
        if not isinstance(item, Mapping) or item.get("number") != number:
            raise RecoveryEvidenceError("prepared publication numbering is invalid")
        target = _absolute_recorded_path(item.get("path"), "prepared target")
        candidate = _absolute_recorded_path(
            item.get("candidate"), "prepared candidate",
        )
        for path in (target, candidate):
            identity = path_safety.identify(path).unicode_key
            if identity in identities:
                raise RecoveryEvidenceError("prepared recovery paths are not distinct")
            identities.add(identity)
        before = _hash(item.get("before_hash"), "prepared before hash", absent=True)
        after = _hash(item.get("after_hash"), "prepared after hash")
        changed = item.get("changed")
        if changed not in (0, 1, False, True):
            raise RecoveryEvidenceError("prepared changed marker is invalid")
        changed = bool(changed)
        if not changed and before != after:
            raise RecoveryEvidenceError("unchanged prepared member has distinct hashes")
        member = {
            "number": number, "path": target, "candidate": candidate,
            "candidate_identity": _candidate_identity(item.get("candidate_identity")),
            "before_sha256": before, "after_sha256": after,
            "changed": changed,
            "snapshot_transaction_id": str(item.get("snapshot_transaction_id") or ""),
            "record": dict(item), "prepared_transaction_id": identifier,
        }
        if changed:
            try:
                recovery_contracts.exact_transaction_id(
                    member["snapshot_transaction_id"],
                    field="snapshot transaction id",
                )
            except Exception as exc:
                raise RecoveryEvidenceError(
                    "changed prepared member has an invalid snapshot transaction id"
                ) from exc
            try:
                member["snapshot"] = store._verified_snapshot(member)
            except Exception as exc:
                raise RecoveryEvidenceError(str(exc)) from exc
            if member["snapshot"].get("kind") == "archive":
                raw_destination = str(member["snapshot"].get("dest") or "")
                destination = os.path.abspath(raw_destination) if raw_destination else ""
                archive_root = os.path.abspath(
                    os.path.join(store.agw_home(), "archive")
                )
                try:
                    inside = bool(destination) and os.path.commonpath(
                        (archive_root, destination)
                    ) == archive_root
                except (OSError, ValueError):
                    inside = False
                if not inside:
                    raise RecoveryEvidenceError(
                        "prepared recovery snapshot is outside the authenticated archive root"
                    )
        elif member["snapshot_transaction_id"]:
            raise RecoveryEvidenceError("unchanged prepared member has a snapshot")
        members.append(member)
    return members


def _current_label(path: str) -> str:
    value = file_ops._current_hash(path)
    return value or "absent"


def classify_member(member: Mapping) -> str:
    actual = _current_label(member["path"])
    if actual == member["before_sha256"]:
        return "before"
    if actual != member["after_sha256"]:
        return "other"
    if os.path.lexists(member["candidate"]):
        return "other"
    try:
        identity = store._current_ordinary_file_identity(member["path"])
    except Exception:
        return "other"
    return "after" if identity == member["candidate_identity"] else "other"


def inspect(prepared: Mapping) -> dict:
    members = authenticate_prepared(prepared)
    classified = []
    for member in members:
        try:
            state = classify_member(member)
            error = ""
        except Exception as exc:
            state, error = "unknown", str(exc)
        classified.append({
            "number": member["number"], "path": member["path"],
            "classification": state,
            "actual_hash": (
                member["before_sha256"] if state == "before"
                else member["after_sha256"] if state == "after" else ""
            ),
            "error": error,
            "before_hash": member["before_sha256"],
            "after_hash": member["after_sha256"],
        })
    states = {item["classification"] for item in classified}
    overall = next(iter(states)) if len(states) == 1 else (
        "mixed" if states <= {"before", "after"} else "ambiguous"
    )
    return {"classification": overall, "members": classified}


def preflight(prepared: Mapping, action: str) -> None:
    """Perform the complete unlocked read-only recovery preflight."""
    members = authenticate_prepared(prepared)
    manifest = load_manifest(prepared)
    if action == "finalize-observed":
        states = [classify_member(member) for member in members]
        if any(state not in {"before", "after"} for state in states):
            raise RecoveryEvidenceError("prepared target state is ambiguous")
        if manifest is not None:
            raise file_ops.PreparedFinalizeAfterRollbackStarted(
                "rollback intent already exists for this prepared transaction",
                {"transaction_id": prepared["transaction_id"],
                 "recovery_state": manifest["state"]},
            )
        return
    if manifest is None:
        states = [classify_member(member) for member in members]
        if any(state not in {"before", "after"} for state in states):
            raise RecoveryEvidenceError("prepared target state is ambiguous")
    else:
        _validate_progress_observations(members, manifest)


def _lock_name(path: str) -> tuple[str, str]:
    identity = path_safety.identify(path).native_key
    digest = hashlib.sha256(identity.encode("utf-8", "replace")).hexdigest()[:32]
    return identity, "file-" + digest


def _lock_paths(members: list[dict]) -> list[tuple[str, str]]:
    return sorted(
        {_lock_name(member[key]) for member in members for key in ("path", "candidate")}
    )


def _locked_authoritative_prepared(
    prepared: Mapping, authority_reader: Callable[[], tuple[Mapping, object]] | None,
) -> tuple[dict, object]:
    """Recheck authority after path locks without expanding the held lock set."""
    if authority_reader is None:
        return dict(prepared), None
    authoritative, terminal = authority_reader()
    if terminal is not None:
        return dict(prepared), terminal
    original_members = authenticate_prepared(prepared)
    fresh_members = authenticate_prepared(authoritative)
    if recovery_contracts.canonical_sha256(authoritative) \
            != recovery_contracts.canonical_sha256(prepared) \
            or _lock_paths(fresh_members) != _lock_paths(original_members):
        raise RecoveryEvidenceError(
            "authoritative PREPARED publication changed while recovery waited for path locks"
        )
    return dict(authoritative), None


def _initial_manifest(prepared: Mapping, states: list[str]) -> dict:
    return {
        "schema": SCHEMA,
        "prepared_transaction_id": prepared["transaction_id"],
        "prepared_sha256": recovery_contracts.canonical_sha256(prepared),
        "plan_sha256": prepared["plan_sha256"],
        "state": ACTIVE,
        "revision": 0,
        "created_at_ns": 0,
        "updated_at_ns": 0,
        "members": [
            {"number": number, "state": (
                ALREADY_BEFORE if state == "before" else CAPTURE_INTENT
            ), "stage_basename": "", "stage_identity": None}
            for number, state in enumerate(states, 1)
        ],
        "blocked": None,
        "manifest_sha256": "",
    }


def _set_member(
    manifest: dict, number: int, state: str, *, stage_basename: str | None = None,
    stage_identity: dict | None | object = ...,
) -> dict:
    previous = manifest["members"][number - 1]["state"]
    legal = {
        CAPTURE_INTENT: {RESTORE_INTENT, RESTORED},
        RESTORE_INTENT: {STAGE_ALLOCATE_INTENT, RESTORED},
        STAGE_ALLOCATE_INTENT: {STAGE_OWNED},
        STAGE_OWNED: {STAGE_READY},
        STAGE_READY: {RESTORED},
    }
    if state not in legal.get(previous, set()):
        raise RecoveryManifestError("publication recovery member state regression")
    changed = dict(manifest)
    changed["members"] = [dict(member) for member in manifest["members"]]
    changed["members"][number - 1]["state"] = state
    if stage_basename is not None:
        changed["members"][number - 1]["stage_basename"] = stage_basename
    if stage_identity is not ...:
        changed["members"][number - 1]["stage_identity"] = stage_identity
    if state == RESTORED:
        changed["members"][number - 1]["stage_basename"] = ""
        changed["members"][number - 1]["stage_identity"] = None
    return _persist(changed)


def _block(manifest: dict, code: str, member: int) -> dict:
    changed = dict(manifest)
    changed["state"] = BLOCKED
    changed["blocked"] = {"code": code, "member": member}
    return _persist(changed)


def _activate(manifest: dict) -> dict:
    if manifest.get("state") != BLOCKED:
        raise RecoveryManifestError("only a blocked recovery can be reactivated")
    changed = dict(manifest)
    changed["state"] = ACTIVE
    changed["blocked"] = None
    return _persist(changed)


def _raise_blocked(manifest: Mapping, message: str) -> None:
    raise file_ops.PreparedRecoveryBlocked(message, {
        "transaction_id": manifest["prepared_transaction_id"],
        "recovery_state": BLOCKED,
        "blocked": manifest.get("blocked"),
        "manifest_revision": manifest.get("revision"),
        "publication_outcome": "needs_attention",
        "operation_outcome": "process_failed", "outcome": "process_failed",
        "outcome_known": True,
    })


def _revalidate(prepared: Mapping) -> tuple[list[dict], list[str]]:
    members = authenticate_prepared(prepared)
    states = [classify_member(member) for member in members]
    if any(state not in {"before", "after"} for state in states):
        raise RecoveryEvidenceError("prepared target state is ambiguous")
    return members, states


def _validate_progress_observations(
    members: list[dict], manifest: Mapping,
) -> list[str]:
    states = [classify_member(member) for member in members]
    for member, journal_member, live in zip(members, manifest["members"], states):
        progress = journal_member["state"]
        target_exists = os.path.lexists(member["path"])
        valid = (
            (progress in {ALREADY_BEFORE, RESTORED} and live == "before")
            or (progress == CAPTURE_INTENT and (
                live in {"before", "after"} or not target_exists
            ))
            or (progress == RESTORE_INTENT and (
                live == "before" or not target_exists
            ))
            or (progress in {
                STAGE_ALLOCATE_INTENT, STAGE_OWNED, STAGE_READY,
            } and (live == "before" or not target_exists))
        )
        if not valid:
            raise RecoveryEvidenceError(
                f"member {member['number']} is inconsistent with durable recovery intent"
            )
        if progress == STAGE_ALLOCATE_INTENT:
            observed = store._inspect_publication_restore_stage_locked(
                member["path"], journal_member["stage_basename"],
            )
            if observed.get("state") != "ABSENT" and not (
                observed.get("kind") == "file" and observed.get("size") == 0
            ):
                raise RecoveryEvidenceError(
                    f"member {member['number']} allocation stage is unsafe"
                )
        elif progress in {STAGE_OWNED, STAGE_READY}:
            observed = store._inspect_publication_restore_stage_locked(
                member["path"], journal_member["stage_basename"],
            )
            stage_may_be_consumed = progress == STAGE_READY and live == "before"
            if observed.get("state") == "ABSENT" and stage_may_be_consumed:
                continue
            expected = store._publication_stage_identity(
                journal_member["stage_identity"]
            )
            if observed.get("state") != "PRESENT" \
                    or observed.get("kind") != "file" \
                    or observed.get("identity") != expected:
                raise RecoveryEvidenceError(
                    f"member {member['number']} owned stage is unsafe"
                )
    return states


def _derived_archive_record(member: Mapping) -> dict | None:
    transaction_id = recovery_contracts.publication_displaced_transaction_id(
        member["prepared_transaction_id"], member["number"],
        archive_tx.canonical_path(member["path"]),
    )
    try:
        return archive_tx.load(store.agw_home(), transaction_id)
    except FileNotFoundError:
        return None


def _authenticated_capture(member: Mapping) -> dict | None:
    record = _derived_archive_record(member)
    if record is None:
        return None
    transaction_id = recovery_contracts.publication_displaced_transaction_id(
        member["prepared_transaction_id"], member["number"],
        archive_tx.canonical_path(member["path"]),
    )
    capture_group = recovery_contracts.publication_rollback_capture_group(
        member["prepared_transaction_id"]
    )
    if record.get("state") != archive_tx.COMMITTED \
            or not store._publication_displaced_record_matches(
                record, member["path"], transaction_id, capture_group,
                member["after_sha256"], member["candidate_identity"],
            ):
        return None
    entry = archive_tx.entry_from_record(record)
    return record if archive_tx.entry_is_verified(
        store.agw_home(), entry, member["path"],
    ) else None


def _remaining_capture_bytes(
    members: list[dict], manifest: Mapping, live_states: list[str],
) -> int:
    incoming = 0
    for member, journal_member, live in zip(
            members, manifest["members"], live_states):
        if journal_member["state"] != CAPTURE_INTENT or live == "before":
            continue
        if _authenticated_capture(member) is None:
            incoming += member["candidate_identity"][2]
    return incoming


def _allocate_stage_basename(member: Mapping) -> str:
    for _attempt in range(4):
        basename = f".agw-publication-rollback-{secrets.token_hex(16)}.restore"
        observed = store._inspect_publication_restore_stage_locked(
            member["path"], basename,
        )
        if observed.get("state") == "ABSENT":
            return basename
    raise RecoveryEvidenceError(
        "publication restore stage allocation exhausted collision attempts"
    )


def _owned_or_allocated_stage(member: Mapping, journal_member: Mapping) -> dict:
    basename = journal_member["stage_basename"]
    observed = store._inspect_publication_restore_stage_locked(
        member["path"], basename,
    )
    if observed.get("state") == "ABSENT":
        return store._create_publication_restore_stage_locked(
            member["path"], basename,
        )
    if observed.get("kind") == "file" and observed.get("size") == 0:
        return store._publication_stage_identity(observed.get("identity"))
    raise RecoveryEvidenceError(
        "publication restore allocation intent found a nonempty or unsafe stage"
    )


def _require_journal_stage(member: Mapping, journal_member: Mapping) -> dict:
    expected = store._publication_stage_identity(journal_member["stage_identity"])
    observed = store._inspect_publication_restore_stage_locked(
        member["path"], journal_member["stage_basename"],
    )
    if observed.get("state") != "PRESENT" or observed.get("kind") != "file" \
            or observed.get("identity") != expected:
        raise RecoveryEvidenceError(
            "publication restore stage no longer matches journal ownership"
        )
    return expected


def rollback(
    prepared: Mapping, *, transaction_lock_held: bool = False,
    terminal_writer: Callable[[str], dict] | None = None,
    authority_reader: Callable[[], tuple[Mapping, object]] | None = None,
) -> dict:
    """Restore every exact after-state member, resuming from durable intent."""
    # Complete read-only preflight.  This creates neither locks nor directories.
    preflight_members = authenticate_prepared(prepared)
    existing = load_manifest(prepared)
    if existing is None:
        preflight_states = [classify_member(member) for member in preflight_members]
        if any(state not in {"before", "after"} for state in preflight_states):
            raise RecoveryEvidenceError("prepared target state is ambiguous")
    else:
        # A trusted journal requires authoritative under-lock reconciliation;
        # an unlocked observation cannot decide whether BLOCKED may resume or
        # whether ACTIVE must transition durably to BLOCKED.
        preflight_states = []
    transaction_id = prepared["transaction_id"]
    with ExitStack() as locks:
        locks.enter_context(
            nullcontext() if transaction_lock_held else
            store.Lock("publication-recovery-" + transaction_id, timeout=10.0)
        )
        for _identity, name in _lock_paths(preflight_members):
            locks.enter_context(store.Lock(name, timeout=10.0))
        prepared, winner = _locked_authoritative_prepared(
            prepared, authority_reader,
        )
        if winner is not None:
            return {"state": winner.get("state"), "manifest": existing,
                    "members": preflight_members, "terminal": winner}
        locks.enter_context(store.Lock("recovery-store", timeout=30.0))
        try:
            _reconcile_manifest_temps(prepared)
        except RecoveryManifestError as exc:
            raise file_ops.PreparedRecoveryBlocked(
                "publication recovery journal staging is blocked",
                {"transaction_id": transaction_id, "recovery_state": BLOCKED,
                 "cause": str(exc),
                 "blocked": {"code": "journal_staging_blocked", "member": 0}},
            ) from exc
        existing = load_manifest(prepared)
        manifest = None
        try:
            members = authenticate_prepared(prepared)
            manifest = load_manifest(prepared)
            if manifest is None:
                live_states = [classify_member(member) for member in members]
                if any(state not in {"before", "after"} for state in live_states):
                    raise RecoveryEvidenceError("prepared target state is ambiguous")
            else:
                live_states = _validate_progress_observations(members, manifest)
        except Exception as exc:
            if manifest is not None:
                if manifest["state"] != BLOCKED:
                    manifest = _block(manifest, "revalidation_failed", 0)
                _raise_blocked(manifest, str(exc))
            raise RecoveryEvidenceError(str(exc)) from exc
        if manifest is not None and manifest["state"] == BLOCKED:
            # BLOCKED is retryable. Full authentication and observation above
            # proved the recorded cause is currently clear.
            manifest = _activate(manifest)
        if manifest is not None and manifest["state"] == ROLLED_BACK:
            terminal = terminal_writer(manifest["state"]) if terminal_writer else None
            return {"state": manifest["state"], "manifest": manifest,
                    "members": members, "terminal": terminal}
        if manifest is None:
            if all(state == "before" for state in live_states):
                terminal = terminal_writer(ROLLED_BACK) if terminal_writer else None
                return {"state": ROLLED_BACK, "manifest": None,
                        "members": members, "terminal": terminal}
            try:
                store._admit_publication_rollback_locked(sum(
                    member["candidate_identity"][2]
                    for member, state in zip(members, live_states) if state == "after"
                ))
                manifest = _persist(_initial_manifest(prepared, live_states))
            except (FileExistsError, RecoveryManifestError) as exc:
                raise file_ops.PreparedRecoveryBlocked(
                    "publication recovery journal staging is blocked",
                    {"transaction_id": prepared["transaction_id"],
                     "recovery_state": BLOCKED, "cause": str(exc),
                     "blocked": {"code": "journal_staging_blocked", "member": 0}},
                ) from exc
            except Exception as exc:
                raise RecoveryEvidenceError(str(exc)) from exc
        else:
            incoming = _remaining_capture_bytes(members, manifest, live_states)
            if incoming:
                try:
                    store._admit_publication_rollback_locked(incoming)
                except Exception as exc:
                    if manifest["state"] != BLOCKED:
                        manifest = _block(manifest, "admission_failed", 0)
                    _raise_blocked(manifest, str(exc))

        current_number = 0
        try:
            # A resumed manifest has already rechecked capacity above for each
            # still-uncaptured after-state member.
            for member, journal_member in zip(members, manifest["members"]):
                current_number = member["number"]
                progress = journal_member["state"]
                live = classify_member(member)
                if progress == ALREADY_BEFORE:
                    if live != "before":
                        raise RecoveryEvidenceError("already-before member drifted")
                    continue
                if progress == RESTORED:
                    if live != "before":
                        raise RecoveryEvidenceError("restored member drifted")
                    continue

                # CAPTURE_INTENT may resume with the target absent (capture
                # completed) or before-state (restore completed before persist).
                capture_authenticated = False
                if progress == CAPTURE_INTENT:
                    if live not in {"after", "before"} and os.path.lexists(member["path"]):
                        raise RecoveryEvidenceError("capture-intent member drifted")
                    if live == "before":
                        if _derived_archive_record(member) is not None:
                            store._capture_publication_displaced_locked(
                                member["path"], transaction_id, member["number"],
                                member["after_sha256"], member["candidate_identity"],
                            )
                        manifest = _set_member(manifest, member["number"], RESTORED)
                        continue
                    store._capture_publication_displaced_locked(
                        member["path"], transaction_id, member["number"],
                        member["after_sha256"], member["candidate_identity"],
                    )
                    capture_authenticated = True
                    live = classify_member(member)
                    if os.path.lexists(member["path"]):
                        raise RecoveryEvidenceError("displaced capture left a target")
                    manifest = _set_member(manifest, member["number"], RESTORE_INTENT)
                    progress = RESTORE_INTENT

                if progress == RESTORE_INTENT:
                    # Reconcile and authenticate the deterministic displaced
                    # archive before trusting either an absent or restored target.
                    if not capture_authenticated:
                        store._capture_publication_displaced_locked(
                            member["path"], transaction_id, member["number"],
                            member["after_sha256"], member["candidate_identity"],
                        )
                    live = classify_member(member)
                    if live == "before":
                        manifest = _set_member(manifest, member["number"], RESTORED)
                        continue
                    if os.path.lexists(member["path"]):
                        raise RecoveryEvidenceError("restore-intent member drifted")
                    if member["before_sha256"] == "absent":
                        manifest = _set_member(manifest, member["number"], RESTORED)
                        continue
                    basename = _allocate_stage_basename(member)
                    manifest = _set_member(
                        manifest, member["number"], STAGE_ALLOCATE_INTENT,
                        stage_basename=basename,
                    )
                    progress = STAGE_ALLOCATE_INTENT

                journal_member = manifest["members"][member["number"] - 1]
                if progress == STAGE_ALLOCATE_INTENT:
                    identity = _owned_or_allocated_stage(member, journal_member)
                    manifest = _set_member(
                        manifest, member["number"], STAGE_OWNED,
                        stage_identity=identity,
                    )
                    progress = STAGE_OWNED

                journal_member = manifest["members"][member["number"] - 1]
                if progress == STAGE_OWNED:
                    identity = _require_journal_stage(member, journal_member)
                    store._write_publication_restore_stage_locked(
                        member["snapshot"], member["path"],
                        journal_member["stage_basename"], identity,
                    )
                    manifest = _set_member(
                        manifest, member["number"], STAGE_READY,
                    )
                    progress = STAGE_READY

                journal_member = manifest["members"][member["number"] - 1]
                if progress == STAGE_READY:
                    live = classify_member(member)
                    if live == "before":
                        observed = store._inspect_publication_restore_stage_locked(
                            member["path"], journal_member["stage_basename"],
                        )
                        if observed.get("state") == "PRESENT":
                            identity = _require_journal_stage(member, journal_member)
                            store._remove_publication_restore_stage_locked(
                                member["path"], journal_member["stage_basename"],
                                identity,
                            )
                    else:
                        if os.path.lexists(member["path"]):
                            raise RecoveryEvidenceError("stage-ready member drifted")
                        identity = _require_journal_stage(member, journal_member)
                        store._publish_publication_restore_stage_locked(
                            member["snapshot"], member["path"],
                            journal_member["stage_basename"], identity,
                        )
                    if classify_member(member) != "before":
                        raise RecoveryEvidenceError("restored member failed verification")
                    manifest = _set_member(manifest, member["number"], RESTORED)

            if any(classify_member(member) != "before" for member in members):
                raise RecoveryEvidenceError("publication rollback did not restore every member")
            terminal = dict(manifest)
            terminal["state"] = ROLLED_BACK
            terminal["blocked"] = None
            manifest = _persist(terminal)
            written = terminal_writer(ROLLED_BACK) if terminal_writer else None
            return {"state": ROLLED_BACK, "manifest": manifest,
                    "members": members, "terminal": written}
        except file_ops.PreparedRecoveryBlocked:
            raise
        except Exception as exc:
            try:
                manifest = _block(manifest, "recovery_failed", current_number)
            except Exception:
                # Preserve the original error; an unauthenticated write must not
                # be attempted to disguise a failed durable block transition.
                pass
            _raise_blocked(manifest, str(exc))


def finalize_observed(
    prepared: Mapping, *, transaction_lock_held: bool = False,
    terminal_writer: Callable[[str], dict] | None = None,
    authority_reader: Callable[[], tuple[Mapping, object]] | None = None,
) -> dict:
    """Commit only an authenticated all-after PREPARED publication."""
    members = authenticate_prepared(prepared)
    manifest = load_manifest(prepared)
    if manifest is not None:
        raise file_ops.PreparedFinalizeAfterRollbackStarted(
            "rollback intent already exists for this prepared transaction",
            {"transaction_id": prepared["transaction_id"],
             "recovery_state": manifest["state"]},
        )
    states = [classify_member(member) for member in members]
    if any(state not in {"before", "after"} for state in states):
        raise RecoveryEvidenceError("prepared target state is ambiguous")
    if not all(state == "after" for state in states):
        raise file_ops.PreparedFinalizeNotAllAfter(
            "finalize-observed requires every target in exact after-state",
            {"transaction_id": prepared["transaction_id"],
             "recovery_state": "PREPARED", "classification": (
                 "before" if all(state == "before" for state in states) else "mixed"
             )},
        )
    with ExitStack() as locks:
        locks.enter_context(
            nullcontext() if transaction_lock_held else store.Lock(
                "publication-recovery-" + prepared["transaction_id"], timeout=10.0,
            )
        )
        for _identity, name in _lock_paths(members):
            locks.enter_context(store.Lock(name, timeout=10.0))
        prepared, winner = _locked_authoritative_prepared(
            prepared, authority_reader,
        )
        if winner is not None:
            return {"state": winner.get("state"), "members": members,
                    "terminal": winner}
        locks.enter_context(store.Lock("recovery-store", timeout=30.0))
        try:
            _reconcile_manifest_temps(prepared)
        except RecoveryManifestError as exc:
            raise file_ops.PreparedRecoveryBlocked(
                "publication recovery journal staging is blocked",
                {"transaction_id": prepared["transaction_id"],
                 "recovery_state": BLOCKED, "cause": str(exc),
                 "blocked": {"code": "journal_staging_blocked", "member": 0}},
            ) from exc
        members, states = _revalidate(prepared)
        if not all(state == "after" for state in states):
            raise file_ops.PreparedFinalizeNotAllAfter(
                "prepared target state changed before finalize-observed",
                {"transaction_id": prepared["transaction_id"],
                 "recovery_state": "PREPARED"},
            )
        manifest = load_manifest(prepared)
        if manifest is not None:
            raise file_ops.PreparedFinalizeAfterRollbackStarted(
                "rollback intent already exists for this prepared transaction",
                {"transaction_id": prepared["transaction_id"],
                 "recovery_state": manifest["state"]},
            )
        terminal = terminal_writer("COMMITTED") if terminal_writer else None
        return {"state": "COMMITTED", "members": members, "terminal": terminal}
