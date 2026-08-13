"""Crash-discoverable archive transactions.

Each transaction has one authoritative JSON manifest. Version manifests and
the oplog are compatibility indexes derived only after COMMITTED.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import time
import uuid

from . import recovery_contracts


PREPARING = "PREPARING"
ARTIFACT_VERIFIED = "ARTIFACT_VERIFIED"
SOURCE_MUTATED = "SOURCE_MUTATED"
COMMITTED = "COMMITTED"
VERIFIED_STATES = {ARTIFACT_VERIFIED, SOURCE_MUTATED, COMMITTED}


class SimulatedCrash(RuntimeError):
    """Test-only fault used to exercise durable transition recovery."""


def ensure_directory(path: str, retry_seconds: float = 0.5) -> str:
    """Create one directory with a bounded retry for Windows publication races."""
    deadline = time.monotonic() + max(0.0, retry_seconds)
    while True:
        try:
            os.makedirs(path, exist_ok=True)
            return path
        except PermissionError:
            if os.name != "nt":
                raise
            if os.path.isdir(path):
                return path
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def canonical_path(path: str) -> str:
    absolute = os.path.abspath(str(path))
    # realpath follows Windows junctions and can block on an unavailable
    # network/cloud target. A link object's identity is its literal path.
    try:
        info = os.lstat(absolute)
        tag = int(getattr(info, "st_reparse_tag", 0) or 0)
        if stat.S_ISLNK(info.st_mode) or tag in {
                int(getattr(stat, "IO_REPARSE_TAG_SYMLINK", 0xA000000C)),
                int(getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003))}:
            return os.path.normcase(absolute)
    except OSError:
        pass
    return os.path.normcase(os.path.realpath(absolute))


def link_metadata(path: str) -> dict | None:
    """Describe a symlink/junction using lstat-only metadata.

    The target is read from the reparse point itself. This function never
    calls isdir/stat on the target and therefore never traverses it.
    """
    info = os.lstat(path)
    attributes = int(getattr(info, "st_file_attributes", 0) or 0)
    reparse_tag = int(getattr(info, "st_reparse_tag", 0) or 0)
    symlink_tag = int(getattr(stat, "IO_REPARSE_TAG_SYMLINK", 0xA000000C))
    mount_tag = int(getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003))
    is_symlink = (stat.S_ISLNK(info.st_mode) or reparse_tag == symlink_tag
                  or os.path.islink(path))
    is_junction = reparse_tag == mount_tag
    if hasattr(os.path, "isjunction"):
        try:
            is_junction = bool(os.path.isjunction(path)) or is_junction
        except OSError:
            pass
    if not (is_symlink or is_junction):
        return None
    try:
        target = os.readlink(path)
    except OSError as exc:
        raise OSError(
            f"archive source is not an ordinary local file or folder or a "
            f"supported link: {path}"
        ) from exc
    directory_flag = int(getattr(stat, "FILE_ATTRIBUTE_DIRECTORY", 0x10))
    return {
        "link_type": "junction" if is_junction else "symlink",
        "target": target,
        "target_is_directory": bool(attributes & directory_flag) or is_junction,
        "reparse_tag": reparse_tag,
    }


def _link_payload(metadata: dict) -> bytes:
    return (json.dumps(metadata, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")


def _unlink_link(path: str, metadata: dict):
    if metadata.get("target_is_directory"):
        os.rmdir(path)
    else:
        os.unlink(path)


def _create_link(path: str, metadata: dict):
    target = metadata["target"]
    if metadata.get("link_type") == "junction":
        if os.name != "nt":
            raise OSError("Windows junction recovery is unavailable on this platform")
        _validate_junction_command_paths(path, target)
        completed = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", path, target],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
            check=False,
        )
        if completed.returncode:
            raise OSError(
                "junction recovery failed: "
                + (completed.stderr.strip() or completed.stdout.strip())
            )
        return
    os.symlink(target, path,
               target_is_directory=bool(metadata.get("target_is_directory")))


def _validate_junction_command_paths(path: str, target: str):
    # cmd.exe owns the built-in mklink command. Refuse metacharacters rather
    # than risk interpreting an untrusted link path as command syntax.
    unsafe = set('&|<>^%!"\r\n')
    if any(char in unsafe for char in str(path) + str(target)):
        raise OSError(
            "junction path contains command metacharacters and cannot be "
            "restored safely by this Windows runtime"
        )


def _root(home: str) -> str:
    path = os.path.join(home, "transactions")
    return ensure_directory(path)


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


def _persist_new(home: str, record: dict):
    """Publish a supplied-id manifest using one bounded protocol temp.

    Before the authoritative manifest exists, this reserved path is treated as
    same-user protocol state: a safe regular single-link partial may be
    truncated and reused after process crash. Links/nonfiles/hardlinks block.
    """
    path = _manifest_path(home, record["transaction_id"])
    temp = path + ".fixed-new.tmp"
    if os.path.lexists(path):
        raise FileExistsError(
            f"archive transaction id already exists: {record['transaction_id']}"
        )
    fd = _open_fixed_protocol_temp(temp)
    try:
        payload = (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        os.ftruncate(fd, 0)
        _write_all(fd, payload)
        os.fsync(fd)
        identity = _fd_identity(fd)
    finally:
        os.close(fd)
    _require_fixed_identity(temp, identity)
    try:
        try:
            os.link(temp, path)
        except FileExistsError as exc:
            raise FileExistsError(
                f"archive transaction id already exists: {record['transaction_id']}"
            ) from exc
        _flush_directory(os.path.dirname(path))
    finally:
        try:
            temp_info = os.lstat(temp)
            path_info = os.lstat(path)
            if not stat.S_ISREG(temp_info.st_mode) or not stat.S_ISREG(path_info.st_mode) \
                    or int(getattr(temp_info, "st_nlink", 0)) != 2 \
                    or int(getattr(path_info, "st_nlink", 0)) != 2 \
                    or (int(getattr(temp_info, "st_dev", -1)),
                int(getattr(temp_info, "st_ino", 0))) != identity \
                    or (int(getattr(path_info, "st_dev", -1)),
                        int(getattr(path_info, "st_ino", 0))) != identity:
                raise ValueError("fixed-id manifest publication identity changed")
            os.unlink(temp)
            _require_fixed_identity(path, identity)
        except FileNotFoundError:
            pass


def _fixed_update_path(home: str, transaction_id: str) -> str:
    return _manifest_path(home, transaction_id) + ".fixed-update.tmp"


def _write_all(fd: int, payload: bytes):
    view = memoryview(payload)
    written = 0
    while written < len(view):
        count = os.write(fd, view[written:])
        if not isinstance(count, int) or count <= 0:
            raise OSError("fixed-id protocol write made no progress")
        written += count
    if written != len(view):
        raise OSError("fixed-id protocol write was incomplete")


def _fd_identity(fd: int) -> tuple[int, int]:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or int(getattr(info, "st_nlink", 1)) != 1:
        raise ValueError("fixed-id protocol artifact is not a safe ordinary file")
    identity = int(getattr(info, "st_dev", -1)), int(getattr(info, "st_ino", 0))
    if identity[0] < 0 or identity[1] <= 0:
        raise ValueError("fixed-id protocol artifact identity is not meaningful")
    return identity


def _require_fixed_identity(path: str, expected: tuple[int, int]) -> tuple[int, int]:
    info = os.lstat(path)
    if os.path.islink(path) or not stat.S_ISREG(info.st_mode) \
            or int(getattr(info, "st_nlink", 1)) != 1:
        raise ValueError("fixed-id protocol artifact is foreign or unsafe")
    actual = int(getattr(info, "st_dev", -1)), int(getattr(info, "st_ino", 0))
    if actual != expected:
        raise ValueError("fixed-id protocol artifact identity changed")
    return actual


def _open_fixed_protocol_temp(path: str) -> int:
    flags = os.O_RDWR | os.O_CREAT | int(getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(path, flags, 0o600)
    try:
        identity = _fd_identity(fd)
        _require_fixed_identity(path, identity)
        return fd
    except Exception:
        os.close(fd)
        raise


def _persist_fixed_update(home: str, record: dict):
    """Checkpoint a fixed-id manifest through one bounded update temp."""
    path = _manifest_path(home, record["transaction_id"])
    temp = _fixed_update_path(home, record["transaction_id"])
    fd = _open_fixed_protocol_temp(temp)
    try:
        payload = (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        os.ftruncate(fd, 0)
        _write_all(fd, payload)
        os.fsync(fd)
        identity = _fd_identity(fd)
    finally:
        os.close(fd)
    _require_fixed_identity(temp, identity)
    os.replace(temp, path)
    _flush_directory(os.path.dirname(path))


def _fixed_preparation_identity(path: str) -> tuple[int, int]:
    info = os.lstat(path)
    if os.path.islink(path) or not stat.S_ISREG(info.st_mode) \
            or int(getattr(info, "st_nlink", 1)) != 1:
        raise ValueError("fixed-id archive preparation is foreign or unsafe")
    identity = int(getattr(info, "st_dev", -1)), int(getattr(info, "st_ino", 0))
    if identity[0] < 0 or identity[1] <= 0:
        raise ValueError("fixed-id archive preparation identity is not meaningful")
    return identity


def _allocate_fixed_preparation(home: str, record: dict) -> tuple[int, int]:
    temp = record["temp"]
    checkpoint = record.get("preparation_identity")
    if os.path.lexists(temp):
        identity = _fixed_preparation_identity(temp)
        if checkpoint is not None and tuple(checkpoint) != identity:
            raise ValueError("fixed-id archive preparation identity changed")
        if checkpoint is None and os.path.getsize(temp) != 0:
            raise ValueError("uncheckpointed fixed-id preparation is not empty")
    else:
        if checkpoint is not None:
            raise ValueError("checkpointed fixed-id archive preparation is missing")
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        fd = os.open(temp, flags, 0o600)
        try:
            identity = _fd_identity(fd)
            os.fsync(fd)
        finally:
            os.close(fd)
        _require_fixed_identity(temp, identity)
    if checkpoint is None:
        record["preparation_identity"] = list(identity)
        _persist_fixed_update(home, record)
    return identity


def _write_fixed_preparation(record: dict, identity: tuple[int, int]):
    temp = record["temp"]
    _require_fixed_identity(temp, identity)
    flags = os.O_WRONLY | int(getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(temp, flags)
    try:
        if _fd_identity(fd) != identity:
            raise ValueError("fixed-id archive preparation changed before write")
        os.ftruncate(fd, 0)
        with open(record["src"], "rb") as source:
            for chunk in iter(lambda: source.read(1 << 20), b""):
                os.write(fd, chunk)
        os.fsync(fd)
    finally:
        os.close(fd)
    _require_fixed_identity(temp, identity)


def load(home: str, transaction_id: str) -> dict:
    with open(_manifest_path(home, transaction_id), encoding="utf-8") as handle:
        record = json.load(handle)
    if record.get("transaction_id") != transaction_id:
        raise ValueError("transaction manifest identity does not match its filename")
    return record


def update(home: str, transaction_id: str, **fields) -> dict:
    record = load(home, transaction_id)
    record.update(fields)
    if record.get("fixed_id_transaction") is True:
        _persist_fixed_update(home, record)
    else:
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
    metadata = link_metadata(path)
    if metadata is not None:
        payload = _link_payload(metadata)
        return "link", hashlib.sha256(payload).hexdigest(), len(payload)
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


def _artifact_fingerprint(path: str, artifact_kind: str) -> tuple[str, str, int]:
    if artifact_kind != "link-metadata":
        return _fingerprint(path)
    metadata = link_metadata(path)
    if metadata is not None or not os.path.isfile(path):
        raise OSError("link recovery artifact is not an ordinary metadata file")
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
    return "link-metadata", digest.hexdigest(), size


def _copy(source: str, destination: str, kind: str, exclude=(), link=None):
    if kind == "directory":
        excluded = {os.path.realpath(item) for item in exclude}

        def _ignore(directory, entries):
            return [
                name for name in entries
                if os.path.realpath(os.path.join(directory, name)) in excluded
            ]

        shutil.copytree(source, destination, symlinks=True, ignore=_ignore)
    elif kind == "link":
        metadata = link or link_metadata(source)
        if metadata is None:
            raise OSError("link metadata changed before recovery capture")
        with open(destination, "xb") as handle:
            handle.write(_link_payload(metadata))
            handle.flush()
            os.fsync(handle.fileno())
    else:
        shutil.copy2(source, destination)


def _remove(path: str, kind: str):
    if kind == "link":
        metadata = link_metadata(path)
        if metadata is None:
            raise OSError("link changed type before unlink")
        _unlink_link(path, metadata)
    elif kind == "directory" and not os.path.islink(path):
        shutil.rmtree(path)
    else:
        os.unlink(path)


def _transition(home: str, record: dict, state: str):
    record["state"] = state
    if record.get("fixed_id_transaction") is True:
        _persist_fixed_update(home, record)
    else:
        _persist(home, record)


def _crash(crash_after: str | None, point: str):
    if crash_after == point:
        raise SimulatedCrash(f"simulated crash after {point}")


def create_archive(home: str, src: str, dest: str, mode: str, version: int,
                   reason: str = "", actor: str = "agent",
                   crash_after: str | None = None,
                   policy_revision: str = "",
                   retention_class: str = "",
                   protected_until_ns: int = 0,
                   capture_group_id: str = "",
                   transaction_id: str = "",
                   recovery_source_identity=None) -> dict:
    """Create and commit one archive transaction.

    The source is never removed until a published artifact has been verified
    and ARTIFACT_VERIFIED is durably persisted.
    """
    if mode not in {"copy", "move"}:
        raise ValueError("archive mode must be 'copy' or 'move'")
    supplied_transaction_id = bool(transaction_id)
    transaction_id = (
        recovery_contracts.exact_transaction_id(transaction_id)
        if supplied_transaction_id else uuid.uuid4().hex
    )
    if supplied_transaction_id and os.path.lexists(
            _manifest_path(home, transaction_id)):
        raise FileExistsError(
            f"archive transaction id already exists: {transaction_id}"
        )
    src = os.path.abspath(src)
    dest = os.path.abspath(dest)
    excluded_paths = [os.path.realpath(home), os.path.realpath(dest)]
    kind, digest, size = _fingerprint(src, excluded_paths)
    link = link_metadata(src) if kind == "link" else None
    if link and link.get("link_type") == "junction":
        _validate_junction_command_paths(src, link.get("target", ""))
    artifact_kind = "link-metadata" if kind == "link" else kind
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
        "artifact_kind": artifact_kind,
        "source_kind": kind,
        **({"link": link} if link else {}),
        "sha256": digest,
        "size": size,
        "reason": reason,
        "actor": actor,
        "policy_revision": policy_revision,
        "retention_class": str(retention_class or ""),
        "protected_until_ns": max(0, int(protected_until_ns or 0)),
        "capture_group_id": str(capture_group_id or ""),
        **({"recovery_source_identity": list(recovery_source_identity)}
           if recovery_source_identity is not None else {}),
        "artifact_state": "PRESENT",
        "excluded_paths": excluded_paths,
        **({"fixed_id_transaction": True} if supplied_transaction_id else {}),
    }
    if supplied_transaction_id:
        _persist_new(home, record)
    else:
        _persist(home, record)
    _crash(crash_after, PREPARING)

    if supplied_transaction_id:
        if kind != "file":
            raise ValueError("fixed-id publication rollback capture requires a file")
        preparation_identity = _allocate_fixed_preparation(home, record)
        _write_fixed_preparation(record, preparation_identity)
    else:
        _copy(src, temp, kind, excluded_paths, link=link)
    if _artifact_fingerprint(temp, artifact_kind) != (artifact_kind, digest, size):
        raise OSError("temporary archive artifact did not match its source")
    # Persist verification metadata while still PREPARING so a crash immediately
    # after publish can be discovered and verified without trusting filenames.
    if supplied_transaction_id:
        _persist_fixed_update(home, record)
    else:
        _persist(home, record)
    os.replace(temp, dest)
    _flush_directory(os.path.dirname(dest))
    _crash(crash_after, "ARTIFACT_PUBLISHED")
    if _artifact_fingerprint(dest, artifact_kind) != (artifact_kind, digest, size):
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
    entry = {
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
        "retention_class": record.get("retention_class", ""),
        "protected_until_ns": int(record.get("protected_until_ns") or 0),
        "capture_group_id": record.get("capture_group_id", ""),
        "recovery_source_identity": record.get("recovery_source_identity"),
        "artifact_state": record.get("artifact_state", "PRESENT"),
        "transaction_id": record.get("transaction_id"),
        "created_at_ns": record.get("created_at_ns"),
        "source_identity": record.get("source_identity"),
        "artifact_kind": record.get("artifact_kind"),
        "source_kind": record.get("source_kind", record.get("artifact_kind")),
        "transaction_state": record.get("state"),
        "verified": record.get("state") in VERIFIED_STATES,
    }
    if record.get("link"):
        entry["link"] = record["link"]
    return entry


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
            "policy_revision", "retention_class", "protected_until_ns",
            "capture_group_id", "artifact_state", "sha256", "size",
            "recovery_source_identity",
        )
        if any(entry.get(field) != record.get(field) for field in bound_fields):
            return False
        if entry.get("transaction_state") != record.get("state") \
                or entry.get("verified") is not True:
            return False
        expected = (record["artifact_kind"], record["sha256"], record["size"])
        return _artifact_fingerprint(record["dest"], record["artifact_kind"]) == expected
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False


def _quarantine(home: str, record: dict) -> str:
    temp = record.get("temp", "")
    if not temp or not os.path.lexists(temp):
        return record.get("quarantine", "")
    directory = os.path.join(home, "quarantine")
    ensure_directory(directory)
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
    if record.get("fixed_id_transaction") is True:
        _persist_fixed_update(home, record)
    else:
        _persist(home, record)
    return {"transaction_id": record["transaction_id"], "status": "needs_attention",
            "error": message, "record": record}


def recover_record(home: str, record: dict) -> dict:
    """Recover one valid manifest idempotently without discarding artifacts."""
    state = record.get("state")
    expected = (record.get("artifact_kind"), record.get("sha256"), record.get("size"))
    src = record.get("src", "")
    dest = record.get("dest", "")

    if state == PREPARING and record.get("fixed_id_transaction") is True:
        return _resume_preparing_archive(home, record)

    if record.get("kind") == "absent_tombstone":
        return {"transaction_id": record["transaction_id"], "status": state,
                "record": record}

    if state == PREPARING:
        if dest and os.path.lexists(dest):
            try:
                if _artifact_fingerprint(dest, record.get("artifact_kind")) != expected:
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
                if _artifact_fingerprint(
                        record["temp"], record.get("artifact_kind")) != expected:
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
            if _artifact_fingerprint(dest, record.get("artifact_kind")) != expected:
                return _record_error(home, record, "verified artifact is corrupt")
        except OSError as exc:
            return _record_error(home, record, f"verified artifact is unreadable: {exc}")

    if state == ARTIFACT_VERIFIED:
        if record.get("mode") == "move" and os.path.lexists(src):
            try:
                source_expected = (
                    record.get("source_kind", record.get("artifact_kind")),
                    record.get("sha256"), record.get("size"),
                )
                if _fingerprint(src, record.get("excluded_paths", ())) != source_expected:
                    return _record_error(home, record, "source changed; recovery preserved both copies")
                _remove(src, record.get("source_kind", record["artifact_kind"]))
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


def _resume_preparing_archive(home: str, record: dict) -> dict:
    """Resume an authenticated fixed-id capture before normal reconciliation.

    The higher store layer authenticates the recovery binding before calling
    this helper. Under the reserved-path, same-user crash boundary, an
    incomplete checkpointed copy is truncated and rebuilt in the same inode;
    this path never creates quarantine or UUID-suffixed evidence.
    """
    if record.get("kind") != "archive":
        raise ValueError("only archive transactions can resume capture")
    if record.get("state") != PREPARING:
        return recover_record(home, record)
    expected = (
        record.get("artifact_kind"), record.get("sha256"), record.get("size")
    )
    source_expected = (
        record.get("source_kind", record.get("artifact_kind")),
        record.get("sha256"), record.get("size"),
    )
    src = str(record.get("src") or "")
    dest = str(record.get("dest") or "")
    temp = str(record.get("temp") or "")
    if dest and os.path.lexists(dest):
        if _artifact_fingerprint(dest, record.get("artifact_kind")) != expected:
            return _record_error(home, record, "published artifact is corrupt")
        _transition(home, record, ARTIFACT_VERIFIED)
        return recover_record(home, record)
    if not src or not os.path.lexists(src):
        return _record_error(
            home, record, "fixed-id archive source is unavailable before publication"
        )
    if _fingerprint(src, record.get("excluded_paths", ())) != source_expected:
        return _record_error(home, record, "source changed before capture resumed")
    if record.get("artifact_kind") != "file" \
            or record.get("source_kind", "file") != "file" \
            or not record.get("recovery_source_identity"):
        raise ValueError("bounded fixed-id resume requires publication file metadata")
    identity = _allocate_fixed_preparation(home, record)
    _write_fixed_preparation(record, identity)
    if _artifact_fingerprint(temp, record.get("artifact_kind")) != expected:
        return _record_error(home, record, "resumed temporary artifact is corrupt")
    os.replace(temp, dest)
    _flush_directory(os.path.dirname(dest))
    _transition(home, record, ARTIFACT_VERIFIED)
    return recover_record(home, record)


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
    record = load(home, entry["transaction_id"])
    artifact_kind = record["artifact_kind"]
    _kind, digest, size = _artifact_fingerprint(source, artifact_kind)
    source_kind = record.get("source_kind", artifact_kind)
    parent = os.path.dirname(os.path.abspath(target))
    ensure_directory(parent)
    temp = os.path.join(parent, f".{os.path.basename(target)}.{uuid.uuid4().hex}.restore")
    if artifact_kind == "link-metadata":
        with open(source, encoding="utf-8") as handle:
            metadata = json.load(handle)
        if metadata != record.get("link"):
            raise OSError("link recovery metadata does not match its transaction")
        _create_link(temp, metadata)
        if _fingerprint(temp) != (source_kind, digest, size):
            raise OSError("restored temporary link failed verification")
    else:
        _copy(source, temp, source_kind)
        if _fingerprint(temp) != (source_kind, digest, size):
            raise OSError("restored temporary copy failed verification")
    if os.path.lexists(target):
        raise FileExistsError("restore target still exists after safety archive")
    os.replace(temp, target)
    _flush_directory(parent)
