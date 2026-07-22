"""Crash-discoverable archive transactions.

Each transaction has one authoritative JSON manifest. Version manifests and
the oplog are compatibility indexes derived only after COMMITTED.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import uuid


PREPARING = "PREPARING"
ARTIFACT_VERIFIED = "ARTIFACT_VERIFIED"
SOURCE_MUTATED = "SOURCE_MUTATED"
COMMITTED = "COMMITTED"
VERIFIED_STATES = {ARTIFACT_VERIFIED, SOURCE_MUTATED, COMMITTED}


class SimulatedCrash(RuntimeError):
    """Test-only fault used to exercise durable transition recovery."""


def canonical_path(path: str) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(str(path))))


def _root(home: str) -> str:
    path = os.path.join(home, "transactions")
    os.makedirs(path, exist_ok=True)
    return path


def _manifest_path(home: str, transaction_id: str) -> str:
    return os.path.join(_root(home), f"{transaction_id}.json")


def _flush_directory(path: str):
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        fd = os.open(path, flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        # Windows generally cannot fsync directory handles opened this way.
        pass


def _persist(home: str, record: dict):
    path = _manifest_path(home, record["transaction_id"])
    temp = path + f".{uuid.uuid4().hex}.tmp"
    with open(temp, "x", encoding="utf-8") as handle:
        json.dump(record, handle, ensure_ascii=False, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)
    _flush_directory(os.path.dirname(path))


def load(home: str, transaction_id: str) -> dict:
    with open(_manifest_path(home, transaction_id), encoding="utf-8") as handle:
        record = json.load(handle)
    if record.get("transaction_id") != transaction_id:
        raise ValueError("transaction manifest identity does not match its filename")
    return record


def update(home: str, transaction_id: str, **fields) -> dict:
    record = load(home, transaction_id)
    record.update(fields)
    _persist(home, record)
    return record


def discover(home: str) -> list[dict]:
    """Return every manifest, including corrupt manifests as explicit errors."""
    root = _root(home)
    found = []
    for name in sorted(os.listdir(root)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(root, name)
        try:
            with open(path, encoding="utf-8") as handle:
                record = json.load(handle)
            found.append({"path": path, "record": record, "error": ""})
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            found.append({"path": path, "record": None, "error": str(exc)})
    return found


def _fingerprint(path: str, exclude=()) -> tuple[str, str, int]:
    if os.path.islink(path):
        raise OSError(f"archive source is not an ordinary local file or folder: {path}")
    if os.path.isfile(path):
        digest = hashlib.sha256()
        size = 0
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(1 << 20)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
        return "file", digest.hexdigest(), size
    if os.path.isdir(path):
        digest = hashlib.sha256()
        size = 0
        excluded = {os.path.realpath(item) for item in exclude}
        for directory, dirnames, filenames in os.walk(path):
            dirnames[:] = [
                name for name in dirnames
                if os.path.realpath(os.path.join(directory, name)) not in excluded
            ]
            dirnames.sort()
            filenames.sort()
            rel_dir = os.path.relpath(directory, path)
            digest.update(("D:" + rel_dir).encode("utf-8", "surrogatepass"))
            for name in filenames:
                full = os.path.join(directory, name)
                rel = os.path.relpath(full, path)
                digest.update(("F:" + rel).encode("utf-8", "surrogatepass"))
                kind, child_digest, child_size = _fingerprint(full)
                digest.update(kind.encode("ascii"))
                digest.update(child_digest.encode("ascii"))
                size += child_size
        return "directory", digest.hexdigest(), size
    raise OSError(f"archive source is not a readable file, folder, or link: {path}")


def artifact_fingerprint(path: str) -> tuple[str, str, int]:
    return _fingerprint(path)


def _copy(source: str, destination: str, kind: str, exclude=()):
    if kind == "directory":
        excluded = {os.path.realpath(item) for item in exclude}

        def _ignore(directory, entries):
            return [
                name for name in entries
                if os.path.realpath(os.path.join(directory, name)) in excluded
            ]

        shutil.copytree(source, destination, symlinks=True, ignore=_ignore)
    elif kind == "symlink":
        os.symlink(os.readlink(source), destination, target_is_directory=False)
    else:
        shutil.copy2(source, destination)


def _remove(path: str, kind: str):
    if kind == "directory" and not os.path.islink(path):
        shutil.rmtree(path)
    else:
        os.unlink(path)


def _transition(home: str, record: dict, state: str):
    record["state"] = state
    _persist(home, record)


def _crash(crash_after: str | None, point: str):
    if crash_after == point:
        raise SimulatedCrash(f"simulated crash after {point}")


def create_archive(home: str, src: str, dest: str, mode: str, version: int,
                   reason: str = "", actor: str = "agent",
                   crash_after: str | None = None,
                   policy_revision: str = "") -> dict:
    """Create and commit one archive transaction.

    The source is never removed until a published artifact has been verified
    and ARTIFACT_VERIFIED is durably persisted.
    """
    if mode not in {"copy", "move"}:
        raise ValueError("archive mode must be 'copy' or 'move'")
    src = os.path.abspath(src)
    dest = os.path.abspath(dest)
    excluded_paths = [os.path.realpath(home), os.path.realpath(dest)]
    kind, digest, size = _fingerprint(src, excluded_paths)
    transaction_id = uuid.uuid4().hex
    temp = os.path.join(
        os.path.dirname(dest), f".{os.path.basename(dest)}.{transaction_id}.preparing"
    )
    record = {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "created_at_ns": time.time_ns(),
        "kind": "archive",
        "state": PREPARING,
        "src": src,
        "source_identity": canonical_path(src),
        "dest": dest,
        "temp": temp,
        "mode": mode,
        "version": version,
        "artifact_kind": kind,
        "sha256": digest,
        "size": size,
        "reason": reason,
        "actor": actor,
        "policy_revision": policy_revision,
        "excluded_paths": excluded_paths,
    }
    _persist(home, record)
    _crash(crash_after, PREPARING)

    _copy(src, temp, kind, excluded_paths)
    if _fingerprint(temp) != (kind, digest, size):
        raise OSError("temporary archive artifact did not match its source")
    # Persist verification metadata while still PREPARING so a crash immediately
    # after publish can be discovered and verified without trusting filenames.
    _persist(home, record)
    os.replace(temp, dest)
    _flush_directory(os.path.dirname(dest))
    _crash(crash_after, "ARTIFACT_PUBLISHED")
    if _fingerprint(dest) != (kind, digest, size):
        raise OSError("published archive artifact failed verification")
    _transition(home, record, ARTIFACT_VERIFIED)
    _crash(crash_after, ARTIFACT_VERIFIED)

    if mode == "move":
        if _fingerprint(src, excluded_paths) != (kind, digest, size):
            raise OSError("source changed before archive removal; source was preserved")
        _remove(src, kind)
        _crash(crash_after, "SOURCE_REMOVED")
        record["source_action"] = "removed"
    else:
        record["source_action"] = "preserved"
    _transition(home, record, SOURCE_MUTATED)
    _crash(crash_after, SOURCE_MUTATED)
    _transition(home, record, COMMITTED)
    _crash(crash_after, COMMITTED)
    return entry_from_record(record)


def create_absent_tombstone(home: str, target: str, identity: tuple,
                            reason: str = "", policy_revision: str = "") -> dict:
    transaction_id = uuid.uuid4().hex
    record = {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "created_at_ns": time.time_ns(),
        "kind": "absent_tombstone",
        "state": PREPARING,
        "src": os.path.abspath(target),
        "source_identity": canonical_path(target),
        "dest": "",
        "temp": "",
        "artifact_kind": "absence",
        "identity": list(identity),
        "reason": reason,
        "policy_revision": policy_revision,
    }
    _persist(home, record)
    if os.path.lexists(record["src"]):
        raise FileExistsError("target appeared before its absence could be recorded")
    _transition(home, record, ARTIFACT_VERIFIED)
    record["source_action"] = "preserved_absence"
    _transition(home, record, SOURCE_MUTATED)
    _transition(home, record, COMMITTED)
    return record


def bind_policy_revision(home: str, transaction_id: str, policy_revision: str) -> dict:
    """Bind a committed archive transaction to the policy that authorized it."""
    if not policy_revision:
        raise ValueError("policy revision is required")
    record = load(home, transaction_id)
    if record.get("kind") != "archive" or record.get("state") != COMMITTED:
        raise ValueError("policy revision can only be bound to a committed archive")
    existing = str(record.get("policy_revision") or "")
    if existing and existing != policy_revision:
        raise ValueError("archive is already bound to a different policy revision")
    record["policy_revision"] = policy_revision
    _persist(home, record)
    return record


def entry_from_record(record: dict) -> dict:
    return {
        "op": "archive",
        "mode": record.get("mode"),
        "src": record.get("src"),
        "dest": record.get("dest"),
        "version": record.get("version"),
        "sha256": record.get("sha256", ""),
        "size": record.get("size", 0),
        "reason": record.get("reason", ""),
        "actor": record.get("actor", "agent"),
        "policy_revision": record.get("policy_revision", ""),
        "transaction_id": record.get("transaction_id"),
        "created_at_ns": record.get("created_at_ns"),
        "source_identity": record.get("source_identity"),
        "artifact_kind": record.get("artifact_kind"),
        "transaction_state": record.get("state"),
        "verified": record.get("state") in VERIFIED_STATES,
    }


def entry_is_verified(home: str, entry: dict, requested_src: str = None) -> bool:
    transaction_id = entry.get("transaction_id")
    if not transaction_id:
        return False
    try:
        record = load(home, transaction_id)
        if record.get("kind") != "archive" or record.get("state") != COMMITTED:
            return False
        record_source = canonical_path(record["src"])
        if record.get("source_identity") != record_source:
            return False
        if canonical_path(entry.get("src", "")) != record_source \
                or entry.get("source_identity") != record_source:
            return False
        if requested_src is not None and canonical_path(requested_src) != record_source:
            return False
        if canonical_path(entry.get("dest", "")) != canonical_path(record["dest"]):
            return False
        bound_fields = (
            "transaction_id", "created_at_ns", "version", "mode", "artifact_kind",
            "policy_revision", "sha256", "size",
        )
        if any(entry.get(field) != record.get(field) for field in bound_fields):
            return False
        if entry.get("transaction_state") != record.get("state") \
                or entry.get("verified") is not True:
            return False
        expected = (record["artifact_kind"], record["sha256"], record["size"])
        return _fingerprint(record["dest"]) == expected
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False


def _quarantine(home: str, record: dict) -> str:
    temp = record.get("temp", "")
    if not temp or not os.path.lexists(temp):
        return record.get("quarantine", "")
    directory = os.path.join(home, "quarantine")
    os.makedirs(directory, exist_ok=True)
    destination = os.path.join(
        directory, f"{record['transaction_id']}__{os.path.basename(temp)}"
    )
    if os.path.lexists(destination):
        destination += "." + uuid.uuid4().hex
    os.replace(temp, destination)
    record["quarantine"] = destination
    record["recovery_status"] = "incomplete temporary artifact quarantined"
    _persist(home, record)
    return destination


def _record_error(home: str, record: dict, message: str) -> dict:
    record["recovery_error"] = message
    _persist(home, record)
    return {"transaction_id": record["transaction_id"], "status": "needs_attention",
            "error": message, "record": record}


def recover_record(home: str, record: dict) -> dict:
    """Recover one valid manifest idempotently without discarding artifacts."""
    state = record.get("state")
    expected = (record.get("artifact_kind"), record.get("sha256"), record.get("size"))
    src = record.get("src", "")
    dest = record.get("dest", "")

    if record.get("kind") == "absent_tombstone":
        return {"transaction_id": record["transaction_id"], "status": state,
                "record": record}

    if state == PREPARING:
        if dest and os.path.lexists(dest):
            try:
                if _fingerprint(dest) != expected:
                    return _record_error(home, record, "published artifact is corrupt")
            except OSError as exc:
                return _record_error(home, record, f"published artifact is unreadable: {exc}")
            _transition(home, record, ARTIFACT_VERIFIED)
            state = ARTIFACT_VERIFIED
        elif record.get("temp") and os.path.lexists(record["temp"]):
            if os.path.lexists(src):
                quarantine = _quarantine(home, record)
                return {"transaction_id": record["transaction_id"],
                        "status": PREPARING, "quarantine": quarantine, "record": record}
            try:
                if _fingerprint(record["temp"]) != expected:
                    return _record_error(home, record, "temporary artifact is corrupt")
                os.replace(record["temp"], dest)
                _transition(home, record, ARTIFACT_VERIFIED)
                state = ARTIFACT_VERIFIED
            except OSError as exc:
                return _record_error(home, record, f"temporary artifact could not be recovered: {exc}")
        else:
            message = ("source and recovery artifact are both unavailable" if not os.path.lexists(src)
                       else "transaction stopped before an artifact was created")
            return _record_error(home, record, message)

    if state in VERIFIED_STATES:
        try:
            if _fingerprint(dest) != expected:
                return _record_error(home, record, "verified artifact is corrupt")
        except OSError as exc:
            return _record_error(home, record, f"verified artifact is unreadable: {exc}")

    if state == ARTIFACT_VERIFIED:
        if record.get("mode") == "move" and os.path.lexists(src):
            try:
                if _fingerprint(src, record.get("excluded_paths", ())) != expected:
                    return _record_error(home, record, "source changed; recovery preserved both copies")
                _remove(src, record["artifact_kind"])
            except OSError as exc:
                return _record_error(home, record, f"source could not be safely finalized: {exc}")
            record["source_action"] = "removed"
        else:
            record["source_action"] = record.get("source_action", "preserved")
        _transition(home, record, SOURCE_MUTATED)
        state = SOURCE_MUTATED

    if state == SOURCE_MUTATED:
        _transition(home, record, COMMITTED)
        state = COMMITTED

    return {"transaction_id": record["transaction_id"], "status": state,
            "record": record}


def recover_all(home: str) -> list[dict]:
    results = []
    for item in discover(home):
        if item["error"]:
            results.append({"transaction_id": "", "status": "corrupt_manifest",
                            "path": item["path"], "error": item["error"]})
            continue
        try:
            results.append(recover_record(home, item["record"]))
        except Exception as exc:  # preserve and report; never erase evidence
            results.append({"transaction_id": item["record"].get("transaction_id", ""),
                            "status": "needs_attention", "path": item["path"],
                            "error": str(exc), "record": item["record"]})
    return results


def publish_restore(home: str, entry: dict, target: str):
    if not entry_is_verified(home, entry):
        raise ValueError("restore refused: the archive artifact is not verified")
    source = entry["dest"]
    kind, digest, size = _fingerprint(source)
    parent = os.path.dirname(os.path.abspath(target))
    os.makedirs(parent, exist_ok=True)
    temp = os.path.join(parent, f".{os.path.basename(target)}.{uuid.uuid4().hex}.restore")
    _copy(source, temp, kind)
    if _fingerprint(temp) != (kind, digest, size):
        raise OSError("restored temporary copy failed verification")
    if os.path.lexists(target):
        raise FileExistsError("restore target still exists after safety archive")
    os.replace(temp, target)
    _flush_directory(parent)
