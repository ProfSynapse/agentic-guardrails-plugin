"""The archive store: the machine-level, append-only home of every displaced
file version. Lives OUTSIDE synced trees (~/.agw by default; AGW_HOME env
overrides — used heavily by tests).

Layout:
  $AGW_HOME/
    archive/<folderhash>__<foldername>/<filename>/vNNN_<ts>_<filename>
    archive/.../manifest.jsonl       (one JSON line per archived version)
    oplog.jsonl                      (every agw/store operation, for undo)
    state.json                       (checkout registry)
    locks/
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
import tempfile
import time
import uuid
from datetime import datetime

from . import archive_transactions as archive_tx
from . import recovery_contracts

SCHEMA_VERSION = 1
_WINDOWS_SHARING_WINERRORS = {32, 33}
_WINDOWS_MISSING_LOCK_RETRIES = 3


class TransactionUndoError(RuntimeError):
    """An undo stopped safely; recovery records identify every displaced state."""

    def __init__(self, message: str, details: dict):
        super().__init__(message)
        self.details = details


def _ensure_directory(path: str, retry_seconds: float = 0.5) -> str:
    """Compatibility wrapper around the transaction layer's shared helper."""
    return archive_tx.ensure_directory(path, retry_seconds=retry_seconds)


def _lock_contention(exc: OSError, path: str) -> bool:
    if exc.errno == errno.EEXIST:
        return True
    if os.name != "nt":
        return False
    if getattr(exc, "winerror", None) in _WINDOWS_SHARING_WINERRORS:
        return True
    sharing_error = exc.errno in {errno.EACCES, errno.EAGAIN}
    # Treat an observable lock as contention. The caller separately gives a
    # vanished-lock TOCTOU race a few bounded retries before surfacing an ACL
    # failure.
    if not sharing_error:
        return False
    try:
        return os.path.lexists(path)
    except OSError:
        return False


def agw_home_path() -> str:
    """Return the configured recovery-store path without touching the filesystem."""
    return os.environ.get("AGW_HOME") or os.path.join(os.path.expanduser("~"), ".agw")


def agw_home() -> str:
    home = agw_home_path()
    return _ensure_directory(home)


def archive_store_writable() -> bool:
    """Verify real write access to the recovery store used by archive operations.

    ``os.access`` is not sufficient on sandboxed Windows hosts: the underlying
    ACL may look writable even though the active sandbox token cannot create an
    archive entry. Probe each internal write area with an empty temporary
    directory and immediately remove only that probe. No user data is involved.
    """
    probes = []
    try:
        home = agw_home()
        for name in ("archive", "transactions", "locks"):
            directory = os.path.join(home, name)
            _ensure_directory(directory)
            probes.append(tempfile.mkdtemp(prefix=".agw-write-probe-", dir=directory))
        return True
    except OSError:
        return False
    finally:
        for probe in reversed(probes):
            try:
                os.rmdir(probe)
            except OSError:
                pass


def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%dT%H-%M-%S")


def file_sha256(path: str, limit: int = 0) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class Lock:
    """Cross-platform best-effort lock via O_CREAT|O_EXCL lockfile."""

    def __init__(self, name: str, timeout: float = 10.0):
        self.path = os.path.join(agw_home(), "locks", name + ".lock")
        _ensure_directory(os.path.dirname(self.path))
        self.timeout = timeout
        self.fd = None

    def __enter__(self):
        deadline = time.monotonic() + self.timeout
        missing_lock_retries = _WINDOWS_MISSING_LOCK_RETRIES
        while True:
            try:
                self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(self.fd, str(os.getpid()).encode())
                return self
            except OSError as exc:
                if not _lock_contention(exc, self.path):
                    # Windows may report EACCES for O_EXCL contention, then the
                    # winner can remove the lock before lexists() observes it.
                    # Retry that narrow TOCTOU window a few times, but keep a
                    # genuine directory/ACL denial fast and bounded.
                    transient_access = (
                        os.name == "nt"
                        and exc.errno in {errno.EACCES, errno.EAGAIN}
                        and missing_lock_retries > 0
                    )
                    if transient_access:
                        missing_lock_retries -= 1
                        time.sleep(0.01)
                        continue
                    raise
                if time.monotonic() > deadline:
                    # stale-lock recovery: locks older than 60s are abandoned
                    try:
                        if time.time() - os.path.getmtime(self.path) > 60:
                            os.unlink(self.path)
                            continue
                    except OSError:
                        pass
                    raise TimeoutError(f"could not acquire lock {self.path}") from exc
                time.sleep(0.05)

    def __exit__(self, *exc):
        if self.fd is not None:
            os.close(self.fd)
        try:
            os.unlink(self.path)
        except OSError:
            pass


def _append_jsonl(path: str, record: dict):
    record.setdefault("schema_version", SCHEMA_VERSION)
    record.setdefault("ts", _ts())
    line = json.dumps(record, ensure_ascii=False)
    needs_boundary = False
    if os.path.exists(path) and os.path.getsize(path):
        with open(path, "rb") as existing:
            existing.seek(-1, os.SEEK_END)
            needs_boundary = existing.read(1) not in (b"\n", b"\r")
    with open(path, "a", encoding="utf-8") as f:
        if needs_boundary:
            f.write("\n")
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())


def _preserve_malformed_jsonl(path: str, line_number: int, raw: str,
                              error: Exception) -> dict:
    evidence = {
        "evidence_id": hashlib.sha256(
            f"{os.path.abspath(path)}:{line_number}:{raw}".encode("utf-8", "replace")
        ).hexdigest(),
        "source": os.path.abspath(path),
        "line_number": line_number,
        "raw": raw,
        "error": str(error),
    }
    evidence_path = path + ".malformed.jsonl"
    known = set()
    if os.path.exists(evidence_path):
        with open(evidence_path, encoding="utf-8") as handle:
            for line in handle:
                try:
                    known.add(json.loads(line).get("evidence_id"))
                except json.JSONDecodeError:
                    continue
    if evidence["evidence_id"] not in known:
        _append_jsonl(evidence_path, evidence)
    return {"status": "malformed_compatibility", "path": path,
            "line_number": line_number, "evidence": evidence_path,
            "error": str(error)}


def _read_jsonl_resilient(path: str) -> tuple[list, list]:
    records, malformed = [], []
    if not os.path.exists(path):
        return records, malformed
    with open(path, encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
                if not isinstance(value, dict):
                    raise ValueError("JSONL record is not an object")
                records.append(value)
            except (json.JSONDecodeError, ValueError) as exc:
                malformed.append(_preserve_malformed_jsonl(
                    path, line_number, raw.rstrip("\r\n"), exc
                ))
    return records, malformed


def _append_jsonl_unique(path: str, record: dict) -> tuple[bool, list]:
    records, malformed = _read_jsonl_resilient(path)
    transaction_id = record.get("transaction_id")
    if transaction_id and any(
            item.get("transaction_id") == transaction_id for item in records):
        return False, malformed
    _append_jsonl(path, record)
    return True, malformed


def oplog_append(op: dict):
    with Lock("oplog"):
        return _append_jsonl_unique(os.path.join(agw_home(), "oplog.jsonl"), op)


def oplog_read() -> list:
    path = os.path.join(agw_home(), "oplog.jsonl")
    if not os.path.exists(path):
        return []
    return _read_jsonl_resilient(path)[0]


def _folder_key(folder: str) -> str:
    folder = archive_tx.canonical_path(folder)
    digest = hashlib.sha256(folder.encode("utf-8", "replace")).hexdigest()[:10]
    base = os.path.basename(folder.rstrip("/\\")) or "root"
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in base)[:40]
    return f"{digest}__{safe}"


def _file_dir(src: str) -> str:
    canonical = archive_tx.canonical_path(src)
    folder = os.path.dirname(canonical)
    name = os.path.basename(canonical)
    safe = "".join(c if c.isalnum() or c in "-_. " else "_" for c in name)[:80]
    d = os.path.join(agw_home(), "archive", _folder_key(folder), safe)
    _ensure_directory(d)
    return d


def _next_version(file_dir: str) -> int:
    versions = [e for e in os.listdir(file_dir) if e.startswith("v") and "_" in e]
    nums = []
    for e in versions:
        try:
            nums.append(int(e[1:].split("_", 1)[0]))
        except ValueError:
            continue
    return max(nums, default=0) + 1


def archive_file(src: str, mode: str = "move", reason: str = "", actor: str = "agent",
                 dedupe: bool = False, _crash_after: str = None) -> dict:
    """Archive one file or directory. mode='move' (delete-replacement) or
    'copy' (pre-image snapshot, leaves the original)."""
    src = os.path.abspath(src)
    if not os.path.lexists(src):
        raise FileNotFoundError(src)
    link = archive_tx.link_metadata(src)
    digest = file_sha256(src) if link is None and os.path.isfile(src) else ""

    with Lock(_folder_key(os.path.dirname(src))):
        # Directory publication shares parents with every archive from this
        # source folder, so it belongs inside the same lock as versioning.
        file_dir = _file_dir(src)
        if dedupe and digest:
            last = latest_version(src)
            if last and last.get("sha256") == digest \
                    and archive_tx.entry_is_verified(agw_home(), last, src):
                return {**last, "deduped": True}
        version = _next_version(file_dir)
        name = os.path.basename(src)
        dest = os.path.join(file_dir, f"v{version:03d}_{_ts()}_{name}")
        entry = archive_tx.create_archive(
            agw_home(), src, dest, mode, version, reason, actor,
            crash_after=_crash_after,
        )
    _materialize_committed_transaction(entry["transaction_id"], _crash_after)
    return entry


def latest_version(src: str):
    entries = list_versions(src)
    return entries[-1] if entries else None


def list_versions(src: str) -> list:
    file_dir = _file_dir(src)
    manifest = os.path.join(file_dir, "manifest.jsonl")
    out = []
    if os.path.exists(manifest):
        out.extend(_read_jsonl_resilient(manifest)[0])
    # A committed transaction remains authoritative and discoverable even if a
    # crash happened before the compatibility JSONL index was appended.
    for item in archive_tx.discover(agw_home()):
        record = item.get("record")
        if not record or record.get("kind") != "archive" \
                or record.get("state") != archive_tx.COMMITTED:
            continue
        if archive_tx.canonical_path(record.get("src", "")) \
                == archive_tx.canonical_path(src):
            out.append(archive_tx.entry_from_record(record))
    unique = {}
    for entry in out:
        key = entry.get("transaction_id") or entry.get("dest")
        unique[key] = entry
    return sorted(unique.values(), key=lambda entry: int(entry.get("version") or 0))


def discover_archive_transactions() -> list:
    return archive_tx.discover(agw_home())


def _materialize_committed_transaction(transaction_id: str,
                                       crash_after: str = None) -> list:
    record = archive_tx.load(agw_home(), transaction_id)
    if record.get("kind") != "archive" or record.get("state") != archive_tx.COMMITTED:
        return []
    entry = archive_tx.entry_from_record(record)
    file_dir = _file_dir(record["src"])
    manifest = os.path.join(file_dir, "manifest.jsonl")
    malformed = []
    with Lock(_folder_key(os.path.dirname(record["src"]))):
        _appended, issues = _append_jsonl_unique(manifest, entry)
        malformed.extend(issues)
    if crash_after == "DERIVED_INDEX_APPENDED":
        raise archive_tx.SimulatedCrash("simulated crash after DERIVED_INDEX_APPENDED")
    archive_tx.update(agw_home(), transaction_id, derived_index=True)

    _appended, issues = oplog_append(entry)
    malformed.extend(issues)
    if crash_after == "DERIVED_OPLOG_APPENDED":
        raise archive_tx.SimulatedCrash("simulated crash after DERIVED_OPLOG_APPENDED")
    archive_tx.update(agw_home(), transaction_id, derived_oplog=True)
    return malformed


def recover_archive_transactions() -> list:
    results = archive_tx.recover_all(agw_home())
    malformed = []
    for result in results:
        record = result.get("record")
        if not record or record.get("kind") != "archive" \
                or record.get("state") != archive_tx.COMMITTED:
            continue
        malformed.extend(_materialize_committed_transaction(record["transaction_id"]))
    return results + malformed


def record_absent_tombstone(target: str, identity: tuple, reason: str = "") -> dict:
    return archive_tx.create_absent_tombstone(agw_home(), target, identity, reason)


def absent_tombstone_is_verified(record: dict, target: str,
                                 expected_identity: tuple = ()) -> bool:
    """Verify immutable source and parent identity for an ABSENT record."""
    if record.get("kind") != "absent_tombstone" \
            or record.get("state") != archive_tx.COMMITTED:
        return False
    target = os.path.abspath(target)
    if os.path.abspath(str(record.get("src") or "")) != target \
            or record.get("source_identity") != archive_tx.canonical_path(target):
        return False
    recorded_identity = tuple(record.get("identity") or ())
    if expected_identity and recorded_identity != tuple(expected_identity):
        return False
    if len(recorded_identity) < 3:
        return bool(recorded_identity)
    try:
        parent = str(recorded_identity[0])
        info = os.stat(parent, follow_symlinks=False)
    except (OSError, TypeError, ValueError):
        return False
    expected_dev, expected_ino = recorded_identity[1:3]
    return (
        (expected_dev is None or getattr(info, "st_dev", None) == expected_dev)
        and (expected_ino is None or getattr(info, "st_ino", None) == expected_ino)
    )


def rollback_absent_tombstone(transaction_id: str) -> dict:
    record = archive_tx.load(agw_home(), transaction_id)
    target = str(record.get("src") or "")
    if not absent_tombstone_is_verified(record, target):
        raise ValueError(
            "rollback requires a committed ABSENT tombstone whose source "
            "and parent identity are unchanged"
        )
    archived = None
    if os.path.lexists(target):
        archived = archive_file(
            target, mode="move", reason="rollback of ABSENT prestate",
            actor="guardrails-recovery",
        )
    archive_tx.update(
        agw_home(), transaction_id, rollback_committed=True,
        rollback_archive_transaction=(archived or {}).get("transaction_id", ""),
    )
    return {"target": target, "restored": "ABSENT", "archived": archived}


def _mutation_record(transaction_id: str) -> dict:
    """Find one addressable file mutation without broadening undo to other ops."""
    for operation in reversed(oplog_read()):
        kind = operation.get("op")
        if kind == "file-transaction-state" \
                and operation.get("prepared_transaction_id") == transaction_id:
            if operation.get("state") != "COMMITTED":
                raise TransactionUndoError(
                    "transaction recovery is prepared but its after-state is not verified",
                    {
                        "transaction_id": transaction_id,
                        "state": operation.get("state", "NEEDS_ATTENTION"),
                        "cause": operation.get("error", ""),
                    },
                )
            return {
                **operation, "op": "file-transaction",
                "transaction_id": transaction_id,
            }
        if kind == "file-transaction" \
                and operation.get("transaction_id") == transaction_id:
            return operation
        if kind == "file-mutation" and transaction_id in {
                operation.get("transaction_id"),
                operation.get("snapshot_transaction_id")}:
            return operation
        if kind == "file-transaction-prepared" \
                and operation.get("transaction_id") == transaction_id:
            raise TransactionUndoError(
                "transaction recovery is prepared but its after-state is not verified",
                {"transaction_id": transaction_id, "state": "PREPARED",
                 "operations": operation.get("operations", [])},
            )
    raise LookupError(f"no file mutation transaction found: {transaction_id}")


def _undo_members(operation: dict) -> list[dict]:
    if operation.get("op") == "file-mutation":
        raw_members = [operation]
    elif operation.get("op") == "file-transaction":
        raw_members = operation.get("operations") or []
    else:
        raise ValueError("transaction undo supports file mutations only")
    members = []
    seen_targets = set()
    for item in raw_members:
        raw_target = str(item.get("path") or item.get("src") or "")
        before = str(item.get("before_hash") or item.get("before_sha256") or "")
        after = str(item.get("after_hash") or item.get("after_sha256") or "")
        snapshot_id = str(item.get("snapshot_transaction_id") or "")
        if not raw_target or not before or not after or not snapshot_id:
            raise ValueError("file mutation record is missing recovery metadata")
        target = os.path.abspath(raw_target)
        identity = archive_tx.canonical_path(target)
        if identity in seen_targets:
            raise ValueError(f"file mutation record repeats target: {target}")
        seen_targets.add(identity)
        members.append({
            "path": target,
            "before_sha256": before,
            "after_sha256": after,
            "snapshot_transaction_id": snapshot_id,
            "before_identity": item.get("before_identity"),
            "after_identity": item.get("after_identity"),
        })
    if not members:
        raise ValueError("file mutation transaction has no operations")
    return members


def _current_file_hash(path: str) -> str:
    if not os.path.lexists(path):
        return "absent"
    if not os.path.isfile(path) or os.path.islink(path):
        raise ValueError(f"undo target is not an ordinary local file: {path}")
    return file_sha256(path)


def path_identity(path: str) -> dict:
    """Return an exact, JSON-safe identity for one literal filesystem target."""
    path = os.path.abspath(path)
    if not os.path.lexists(path):
        return {
            "state": "ABSENT",
            "path": path,
            "canonical_path": archive_tx.canonical_path(path),
        }
    info = os.lstat(path)
    link = archive_tx.link_metadata(path)
    if link is not None:
        kind = "link"
    elif os.path.isfile(path):
        kind = "file"
    elif os.path.isdir(path):
        kind = "directory"
    else:
        kind = "other"
    identity = {
        "state": "PRESENT",
        "path": path,
        "canonical_path": archive_tx.canonical_path(path),
        "kind": kind,
        "st_dev": getattr(info, "st_dev", None),
        "st_ino": getattr(info, "st_ino", None),
        "st_mode": getattr(info, "st_mode", None),
        "st_size": getattr(info, "st_size", None),
        "st_mtime_ns": getattr(info, "st_mtime_ns", None),
        "st_ctime_ns": getattr(info, "st_ctime_ns", None),
    }
    if kind != "file":
        fingerprint_kind, digest, size = archive_tx.artifact_fingerprint(path)
        identity["fingerprint"] = {
            "kind": fingerprint_kind, "sha256": digest, "size": size,
        }
    if link is not None:
        identity["link"] = link
    return identity


def _verify_current_after(member: dict):
    target = member["path"]
    expected_hash = member["after_sha256"]
    if expected_hash == "absent":
        if os.path.lexists(target):
            raise ValueError(f"undo conflict for {target}: expected absence")
        expected_identity = member.get("after_identity")
        if expected_identity and path_identity(target) != expected_identity:
            raise ValueError(f"undo conflict for {target}: absence identity changed")
        return
    if os.path.isfile(target) and not os.path.islink(target):
        actual = file_sha256(target)
        if actual != expected_hash:
            raise ValueError(
                f"undo conflict for {target}: expected current hash "
                f"{expected_hash}, found {actual}"
            )
        expected_identity = member.get("after_identity")
        if expected_identity and path_identity(target) != expected_identity:
            raise ValueError(f"undo conflict for {target}: target identity changed")
        return
    expected_identity = member.get("after_identity")
    if not expected_identity:
        raise ValueError(
            f"undo conflict for {target}: non-file target lacks exact after_identity"
        )
    actual_identity = path_identity(target)
    if actual_identity != expected_identity:
        raise ValueError(f"undo conflict for {target}: target identity changed")


def _verify_restored_before(member: dict, snapshot: dict):
    target = member["path"]
    if member["before_sha256"] == "absent":
        if os.path.lexists(target):
            raise OSError(f"undo verification failed for {target}: expected absence")
        return
    expected = (
        snapshot.get("source_kind", snapshot.get("artifact_kind")),
        snapshot.get("sha256"), snapshot.get("size"),
    )
    try:
        actual = archive_tx.artifact_fingerprint(target)
    except OSError as exc:
        raise OSError(f"undo verification failed for {target}: {exc}") from exc
    if actual != expected:
        raise OSError(
            f"undo verification failed for {target}: restored fingerprint changed"
        )


def _verified_snapshot(member: dict) -> dict:
    transaction_id = member["snapshot_transaction_id"]
    record = archive_tx.load(agw_home(), transaction_id)
    target = member["path"]
    if record.get("state") != archive_tx.COMMITTED \
            or archive_tx.canonical_path(record.get("src", "")) \
            != archive_tx.canonical_path(target):
        raise ValueError(f"recovery record is not committed for target: {target}")
    before = member["before_sha256"]
    if before == "absent":
        if not absent_tombstone_is_verified(record, target):
            raise ValueError(f"recovery record does not verify prior absence: {target}")
        return record
    if record.get("kind") != "archive" or record.get("sha256") != before:
        raise ValueError(f"recovery record does not match the prior hash: {target}")
    entry = archive_tx.entry_from_record(record)
    if not archive_tx.entry_is_verified(agw_home(), entry, target):
        raise ValueError(f"recovery artifact failed verification: {target}")
    return record


def _absent_identity(path: str) -> tuple:
    parent = os.path.dirname(path)
    while parent and not os.path.isdir(parent):
        previous = parent
        parent = os.path.dirname(parent)
        if parent == previous:
            break
    if not parent or not os.path.isdir(parent):
        raise OSError(f"undo target has no verifiable parent folder: {path}")
    info = os.stat(parent, follow_symlinks=False)
    return (
        os.path.realpath(parent), getattr(info, "st_dev", None),
        getattr(info, "st_ino", None), getattr(info, "st_mtime_ns", None),
    )


def _capture_undo_prestate(path: str, undo_id: str) -> dict:
    """Capture the state being displaced by undo and return its transaction."""
    if os.path.lexists(path):
        entry = archive_file(
            path, mode="move", reason=f"pre-image before transaction undo {undo_id}",
            actor="guardrails-recovery",
        )
        return {
            "kind": "archive", "transaction_id": entry["transaction_id"],
            "entry": entry,
        }
    tombstone = record_absent_tombstone(
        path, _absent_identity(path), reason=f"verified absence before undo {undo_id}"
    )
    return {
        "kind": "absent_tombstone",
        "transaction_id": tombstone["transaction_id"],
    }


def _restore_snapshot(member: dict, snapshot: dict):
    target = member["path"]
    if member["before_sha256"] == "absent":
        if os.path.lexists(target):
            raise FileExistsError(f"undo expected an absent target after capture: {target}")
        return
    archive_tx.publish_restore(
        agw_home(), archive_tx.entry_from_record(snapshot), target
    )


def _rollback_undo_member(member: dict, undo_id: str):
    """Restore the after-state captured immediately before an undo member."""
    target = member["path"]
    recovery_id = member["undo_recovery_transaction_id"]
    recovery = archive_tx.load(agw_home(), recovery_id)
    if os.path.lexists(target):
        archive_file(
            target, mode="move", reason=f"failed transaction undo {undo_id}",
            actor="guardrails-recovery",
        )
    if recovery.get("kind") == "archive":
        entry = archive_tx.entry_from_record(recovery)
        if not archive_tx.entry_is_verified(agw_home(), entry, target):
            raise ValueError(f"undo rollback artifact failed verification: {target}")
        archive_tx.publish_restore(agw_home(), entry, target)
        expected = (
            recovery.get("source_kind", recovery.get("artifact_kind")),
            recovery.get("sha256"), recovery.get("size"),
        )
        if archive_tx.artifact_fingerprint(target) != expected:
            raise OSError(f"undo rollback fingerprint changed: {target}")
    elif not absent_tombstone_is_verified(recovery, target):
        raise ValueError(f"undo rollback record is not verified: {target}")
    elif os.path.lexists(target):
        raise OSError(f"undo rollback expected absence: {target}")


def undo_transaction(transaction_id: str) -> dict:
    """Reverse one logged file mutation after strict hash and artifact checks.

    The current state displaced by the reversal is itself archived in a
    committed recovery transaction. No recovery record is consumed or deleted.
    """
    if not transaction_id:
        raise ValueError("transaction id is required")
    operation = _mutation_record(transaction_id)
    members = _undo_members(operation)
    prior_undos = {
        item.get("undid_transaction_id") for item in oplog_read()
        if item.get("op") == "transaction-undo" and item.get("state") == "COMMITTED"
    }
    if transaction_id in prior_undos:
        raise ValueError(f"transaction was already undone: {transaction_id}")

    snapshots = []
    for member in members:
        _verify_current_after(member)
        snapshots.append(_verified_snapshot(member))

    undo_id = uuid.uuid4().hex
    completed = []
    with Lock("transaction-undo"):
        try:
            for member, snapshot in zip(members, snapshots):
                _verify_current_after(member)
                displaced = _capture_undo_prestate(member["path"], undo_id)
                result = {**member, "undo_recovery_transaction_id":
                          displaced["transaction_id"]}
                completed.append(result)
                _restore_snapshot(member, snapshot)
                _verify_restored_before(member, snapshot)
        except Exception as exc:
            rollback_errors = []
            for member in reversed(completed):
                try:
                    _rollback_undo_member(member, undo_id)
                except Exception as rollback_exc:
                    rollback_errors.append({
                        "path": member["path"], "error": str(rollback_exc),
                        "undo_recovery_transaction_id":
                            member["undo_recovery_transaction_id"],
                    })
            failure = {
                "op": "transaction-undo-failed", "transaction_id": undo_id,
                "undid_transaction_id": transaction_id,
                "state": "NEEDS_ATTENTION", "operations": completed,
                "error": str(exc), "rolled_back": not rollback_errors,
                "rollback_errors": rollback_errors,
            }
            oplog_append(failure)
            raise TransactionUndoError(
                "transaction undo stopped; displaced states remain recoverable",
                failure,
            ) from exc

    result = {
        "op": "transaction-undo", "transaction_id": undo_id,
        "undid_transaction_id": transaction_id,
        "undid_op": operation.get("op"), "state": "COMMITTED",
        "operations": completed,
    }
    oplog_append(result)
    return result


def restore(src: str, version: int = 0, overwrite: bool = False) -> dict:
    """Restore an archived version of `src` to its original location."""
    entries = list_versions(src)
    if not entries:
        raise FileNotFoundError(f"no archived versions of {src}")
    entry = entries[-1] if not version else next(
        (e for e in entries if e.get("version") == version), None)
    if entry is None:
        raise FileNotFoundError(f"no version {version} of {src}")
    if not archive_tx.entry_is_verified(agw_home(), entry, src):
        raise ValueError("restore refused: the selected archive artifact is not verified")
    if os.path.lexists(src):
        # Moving the live target into its own verified transaction eliminates
        # the former copy-then-unlink crash window.
        archive_file(src, mode="move", reason="pre-restore safety archive", actor="agw")
    archive_tx.publish_restore(agw_home(), entry, src)
    op = {"op": "restore", "src": src, "from": entry["dest"], "version": entry["version"]}
    oplog_append(op)
    return op


def undo_last() -> dict:
    """Invert the most recent invertible operation in the oplog."""
    ops = oplog_read()
    for op in reversed(ops):
        if op.get("undone"):
            continue
        kind = op.get("op")
        if kind == "archive" and op.get("mode") == "move":
            if op.get("artifact_kind") == "link-metadata" \
                    and os.path.exists(op["dest"]) and not os.path.lexists(op["src"]):
                archive_tx.publish_restore(agw_home(), op, op["src"])
                oplog_append({"op": "undo", "undid": op})
                return {"undone": "archive", "restored": op["src"]}
            if os.path.exists(op["dest"]) and not os.path.exists(op["src"]):
                shutil.move(op["dest"], op["src"])
                oplog_append({"op": "undo", "undid": op})
                return {"undone": "archive", "restored": op["src"]}
        if kind == "move":
            if os.path.exists(op["dest"]) and not os.path.exists(op["src"]):
                shutil.move(op["dest"], op["src"])
                oplog_append({"op": "undo", "undid": op})
                return {"undone": "move", "restored": op["src"]}
    raise LookupError("nothing to undo")


def logged_move(src: str, dest: str) -> dict:
    src, dest = os.path.abspath(src), os.path.abspath(dest)
    if os.path.exists(dest):
        raise FileExistsError(f"destination exists: {dest} (archive it first)")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.move(src, dest)
    op = {"op": "move", "src": src, "dest": dest}
    oplog_append(op)
    return op


# --- checkout registry -------------------------------------------------------

def state_load() -> dict:
    path = os.path.join(agw_home(), "state.json")
    if not os.path.exists(path):
        return {"schema_version": SCHEMA_VERSION, "checkouts": {}}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"schema_version": SCHEMA_VERSION, "checkouts": {}}


def state_save(state: dict):
    path = os.path.join(agw_home(), "state.json")
    with Lock("state"):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, path)


def archive_size_bytes() -> int:
    root = os.path.join(agw_home(), "archive")
    total = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, name))
            except OSError:
                pass
    return total


# --- session approval memory --------------------------------------------------
# Remembers per-session that the user already approved access to a resource, so
# the same ask doesn't fire repeatedly. Keyed by session id; bounded; cleaned
# opportunistically. This is convenience state, not safety state — losing it
# just means an extra prompt.

def _sessions_dir() -> str:
    d = os.path.join(agw_home(), "sessions")
    os.makedirs(d, exist_ok=True)
    return d


def _session_path(session_id: str) -> str:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in (session_id or "_"))[:80]
    return os.path.join(_sessions_dir(), f"{safe or '_'}.json")


def session_approved(session_id: str, memo_key: str) -> bool:
    if not (session_id and memo_key):
        return False
    try:
        with open(_session_path(session_id), encoding="utf-8") as f:
            return memo_key in set(json.load(f).get("approved", []))
    except (OSError, json.JSONDecodeError):
        return False


def session_approve(session_id: str, memo_key: str):
    if not (session_id and memo_key):
        return
    path = _session_path(session_id)
    with Lock("session-" + os.path.basename(path)):
        approved = []
        try:
            with open(path, encoding="utf-8") as f:
                approved = json.load(f).get("approved", [])
        except (OSError, json.JSONDecodeError):
            pass
        if memo_key in approved:
            return
        approved.append(memo_key)
        approved = approved[-200:]  # bound per-session memory
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"schema_version": SCHEMA_VERSION, "approved": approved}, f)
        os.replace(tmp, path)


# --- retention / disk budget --------------------------------------------------

def retention_inventory() -> list[dict]:
    """Return verified copy artifacts eligible for human-reviewed retention."""
    records = []
    for discovered in archive_tx.discover(agw_home()):
        record = discovered.get("record")
        if not record or record.get("kind") != "archive" \
                or record.get("state") != archive_tx.COMMITTED \
                or record.get("mode") != "copy":
            continue
        entry = archive_tx.entry_from_record(record)
        if not archive_tx.entry_is_verified(agw_home(), entry, record.get("src")):
            continue
        records.append({
            "transaction_id": record["transaction_id"],
            "source": record["src"],
            "artifact": record["dest"],
            "sha256": record.get("sha256", ""),
            "bytes": int(record.get("size") or 0),
            "created_at_ns": int(record.get("created_at_ns") or 0),
            "version": int(record.get("version") or 0),
        })
    return records


def select_retention_candidates(inventory: list[dict], bytes_to_free: int) -> list[dict]:
    """Pure selection: oldest verified copies first, newest source copy kept."""
    newest = {}
    for item in inventory:
        key = archive_tx.canonical_path(item["source"])
        marker = (item["created_at_ns"], item["version"], item["transaction_id"])
        if key not in newest or marker > newest[key][0]:
            newest[key] = (marker, item["transaction_id"])
    eligible = [
        item for item in inventory
        if item["transaction_id"]
        != newest[archive_tx.canonical_path(item["source"])][1]
    ]
    eligible.sort(key=lambda item: (
        item["created_at_ns"], item["version"], item["transaction_id"]
    ))
    selected = []
    accumulated = 0
    for item in eligible:
        if accumulated >= max(0, bytes_to_free):
            break
        selected.append(dict(item))
        accumulated += item["bytes"]
    return selected


def plan_retention(max_bytes: int) -> dict:
    """Build a hash-bound retention dry run. This function never mutates data."""
    max_bytes = int(max_bytes or 0)
    total = archive_size_bytes()
    configured = max_bytes > 0
    required = max(0, total - max_bytes) if configured else 0
    inventory = retention_inventory() if required else []
    candidates = select_retention_candidates(inventory, required)
    reclaimable = sum(item["bytes"] for item in candidates)
    plan = {
        "schema_version": 1,
        "operation": "retention-plan",
        "dry_run": True,
        "automatic_apply_available": False,
        "budget_configured": configured,
        "budget_bytes": max_bytes if configured else 0,
        "current_bytes": total,
        "over_budget": bool(required),
        "bytes_to_free": required,
        "planned_reclaim_bytes": reclaimable,
        "projected_bytes": max(0, total - reclaimable),
        "capacity_satisfied_by_plan": reclaimable >= required,
        "candidates": candidates,
    }
    return recovery_contracts.bind_plan_hash(plan)


def retention_plan_valid(plan: dict) -> bool:
    return recovery_contracts.plan_hash_valid(plan)

def enforce_budget(max_bytes: int) -> dict:
    """Assess a configured budget without evicting recovery artifacts.

    ``enforced`` retains its compatibility meaning that a positive budget is
    configured; ``over_budget`` reports whether a human-reviewed plan is needed.
    A budget of 0/None means unlimited (the safe default — keep everything)."""
    if not max_bytes or max_bytes <= 0:
        return {"enforced": False}
    plan = plan_retention(max_bytes)
    return {
        "enforced": True,
        "evicted": 0,
        "bytes": plan["current_bytes"],
        "freed": 0,
        "budget": plan["budget_bytes"],
        "over_budget": plan["over_budget"],
        "required_free_bytes": plan["bytes_to_free"],
        "destructive": False,
        "retention_plan": plan,
        "plan_hash": plan["plan_sha256"],
    }
