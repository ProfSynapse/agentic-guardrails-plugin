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
from contextlib import nullcontext
from datetime import datetime

from . import archive_transactions as archive_tx
from . import outcomes
from . import recovery_contracts
from . import retention
from . import retention_policy

SCHEMA_VERSION = 1
_WINDOWS_SHARING_WINERRORS = {32, 33}
_WINDOWS_MISSING_LOCK_RETRIES = 3
_MALFORMED_LOCK_STALE_SECONDS = 60.0
_MALFORMED_LOCK_SETTLE_SECONDS = 0.01


class TransactionUndoError(RuntimeError):
    """An undo stopped safely; recovery records identify every displaced state."""

    def __init__(self, message: str, details: dict):
        super().__init__(message)
        self.details = details


class ArchiveCapacityError(RuntimeError):
    """A store-growing operation cannot preserve recovery guarantees."""

    error_code = "archive_capacity_exceeded"

    def __init__(self, message: str, details: dict):
        super().__init__(message)
        self.details = dict(details)


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


def _process_is_alive(pid: int) -> bool:
    """Best-effort liveness check used only to recover abandoned locks."""
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if os.name == "nt":
        try:
            import ctypes
            query = 0x1000  # PROCESS_QUERY_LIMITED_INFORMATION
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            open_process = kernel32.OpenProcess
            open_process.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
            open_process.restype = ctypes.c_void_p
            handle = open_process(query, False, pid)
            if not handle:
                # Access denied means a process exists but is not inspectable.
                return ctypes.get_last_error() == 5  # ERROR_ACCESS_DENIED
            try:
                code = ctypes.c_ulong()
                get_exit_code = kernel32.GetExitCodeProcess
                get_exit_code.argtypes = [ctypes.c_void_p,
                                          ctypes.POINTER(ctypes.c_ulong)]
                get_exit_code.restype = ctypes.c_int
                if not get_exit_code(handle, ctypes.byref(code)):
                    return True
                return code.value == 259  # STILL_ACTIVE
            finally:
                close_handle = kernel32.CloseHandle
                close_handle.argtypes = [ctypes.c_void_p]
                close_handle.restype = ctypes.c_int
                close_handle(handle)
        except Exception:
            return True
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except (PermissionError, OSError):
        return True


def _lock_owner(path: str) -> tuple[int, str]:
    try:
        with open(path, "rb") as handle:
            raw = handle.read(256).decode("ascii").strip()
    except (OSError, UnicodeError):
        return 0, ""
    if ":" in raw:
        pid_raw, token = raw.split(":", 1)
    else:
        # Preserve a PID from a write truncated before the separator/token. A
        # live owner is stronger evidence than malformed content.
        pid_raw, token = raw, ""
    try:
        return int(pid_raw), token
    except ValueError:
        return 0, ""


def _lock_identity(path: str):
    try:
        info = os.stat(path, follow_symlinks=False)
        return (
            getattr(info, "st_dev", None), getattr(info, "st_ino", None),
            getattr(info, "st_size", None), getattr(info, "st_mtime_ns", None),
        )
    except OSError:
        return None


def _stale_malformed_lock_identity(path: str):
    """Return a stable stale malformed lock identity, otherwise ``None``.

    Fresh empty/truncated files may be between exclusive creation and the owner
    write, so they are never recovered. A stale truncated PID is also preserved
    while that process is alive. Two bounded observations reduce the chance of
    racing an owner that is still publishing its token.
    """
    first = _lock_identity(path)
    if first is None:
        return None
    age = time.time() - int(first[3] or 0) / 1_000_000_000
    if age <= _MALFORMED_LOCK_STALE_SECONDS:
        return None
    owner = _lock_owner(path)
    if owner[1] or (owner[0] > 0 and _process_is_alive(owner[0])):
        return None
    time.sleep(_MALFORMED_LOCK_SETTLE_SECONDS)
    if _lock_identity(path) != first or _lock_owner(path) != owner:
        return None
    return first


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


def _try_gate_lock(fd: int) -> bool:
    """Try one non-blocking kernel lock on the first byte of a gate file."""
    if os.name == "nt":
        import msvcrt
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK} \
                    or getattr(exc, "winerror", None) in _WINDOWS_SHARING_WINERRORS:
                return False
            raise
    import fcntl
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False


def _release_gate_lock(fd: int):
    if os.name == "nt":
        import msvcrt
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        return
    import fcntl
    fcntl.flock(fd, fcntl.LOCK_UN)


def _publish_lock_owner(path: str, pid: int, token: str):
    """Atomically publish complete owner metadata while the gate is held."""
    temp = path + "." + token + ".tmp"
    try:
        with open(temp, "xb") as handle:
            handle.write(f"{pid}:{token}".encode("ascii"))
            handle.flush()
            os.fsync(handle.fileno())
        # Hard-link publication is both complete and exclusive: unlike replace,
        # it cannot overwrite an owner created by a legacy process that does not
        # yet participate in the kernel gate.
        os.link(temp, path)
    finally:
        try:
            if os.path.lexists(temp):
                os.unlink(temp)
        except OSError:
            pass


class Lock:
    """Cross-platform kernel lock with a recoverable owner metadata file.

    The persistent ``.gate`` file is never unlinked. Its OS advisory lock is
    held for the complete critical section, so stale metadata cleanup cannot
    race another entrant. ``.lock`` remains an auditable owner record and a
    compatibility signal for older Guardrails processes.
    """

    def __init__(self, name: str, timeout: float = 10.0):
        self.path = os.path.join(agw_home(), "locks", name + ".lock")
        self.gate_path = os.path.join(agw_home(), "locks", name + ".gate")
        _ensure_directory(os.path.dirname(self.path))
        self.timeout = timeout
        self.fd = None
        self.token = uuid.uuid4().hex
        self.gate_locked = False

    def _close_gate(self):
        if self.gate_locked and self.fd is not None:
            try:
                _release_gate_lock(self.fd)
            except OSError:
                # Closing the descriptor below is the kernel-backed fallback
                # release on both supported platforms.
                pass
            finally:
                self.gate_locked = False
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None

    def __enter__(self):
        deadline = time.monotonic() + self.timeout
        missing_lock_retries = _WINDOWS_MISSING_LOCK_RETRIES
        while True:
            if self.fd is None:
                try:
                    self.fd = os.open(self.gate_path, os.O_CREAT | os.O_RDWR)
                    if os.fstat(self.fd).st_size == 0:
                        os.write(self.fd, b"\0")
                        os.fsync(self.fd)
                    os.lseek(self.fd, 0, os.SEEK_SET)
                except OSError as exc:
                    if self.fd is not None:
                        os.close(self.fd)
                        self.fd = None
                    if not _lock_contention(exc, self.gate_path):
                        # Windows may report EACCES for a just-removed legacy
                        # object. Retry only that narrow vanished-object race.
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
                        raise TimeoutError(
                            f"could not open lock gate {self.gate_path}"
                        ) from exc
                    time.sleep(0.05)
                    continue

            try:
                acquired = _try_gate_lock(self.fd)
            except Exception:
                self._close_gate()
                raise
            if not acquired:
                if time.monotonic() > deadline:
                    self._close_gate()
                    raise TimeoutError(f"could not acquire lock {self.path}")
                time.sleep(0.05)
                continue
            self.gate_locked = True

            try:
                if not os.path.lexists(self.path):
                    _publish_lock_owner(self.path, os.getpid(), self.token)
                    return self
                owner = _lock_owner(self.path)
                if owner[1] and not _process_is_alive(owner[0]):
                    os.unlink(self.path)
                    _publish_lock_owner(self.path, os.getpid(), self.token)
                    return self
                malformed_identity = _stale_malformed_lock_identity(self.path)
                if malformed_identity is not None \
                        and _lock_identity(self.path) == malformed_identity \
                        and not _lock_owner(self.path)[1]:
                    os.unlink(self.path)
                    _publish_lock_owner(self.path, os.getpid(), self.token)
                    return self
            except Exception:
                self._close_gate()
                raise

            # A live legacy owner or a fresh initializer is visible. Release the
            # gate while waiting so that its owner can finish normally.
            _release_gate_lock(self.fd)
            self.gate_locked = False
            if time.monotonic() > deadline:
                self._close_gate()
                raise TimeoutError(f"could not acquire lock {self.path}")
            time.sleep(0.05)

    def __exit__(self, *exc):
        try:
            if _lock_owner(self.path) == (os.getpid(), self.token):
                os.unlink(self.path)
        except OSError:
            pass
        finally:
            self._close_gate()


def _append_jsonl(path: str, record: dict):
    record.setdefault("schema_version", SCHEMA_VERSION)
    record.setdefault("ts", _ts())
    # Archive projections already carry the authoritative transaction creation
    # timestamp. Avoid introducing a second, newer activity time for them;
    # successful restore/undo/mutation records without created_at_ns receive a
    # durable nanosecond timestamp here.
    if not record.get("created_at_ns"):
        record.setdefault("timestamp_ns", time.time_ns())
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
        return _append_jsonl_unique(
            os.path.join(agw_home(), "oplog.jsonl"), outcomes.project_record(op)
        )


def oplog_read() -> list:
    path = os.path.join(agw_home(), "oplog.jsonl")
    if not os.path.exists(path):
        return []
    return [outcomes.project_record(record)
            for record in _read_jsonl_resilient(path)[0]]


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
                 dedupe: bool = False, _crash_after: str = None,
                 retention_class: str = "", protected_until_ns: int = 0,
                 capture_group_id: str = "",
                 retention_config: retention_policy.RetentionPolicy | None = None,
                 lock_context=None,
                 ) -> dict:
    """Archive one file or directory. mode='move' (delete-replacement) or
    'copy' (pre-image snapshot, leaves the original)."""
    src = os.path.abspath(src)
    if not os.path.lexists(src):
        raise FileNotFoundError(src)
    link = archive_tx.link_metadata(src)
    digest = file_sha256(src) if link is None and os.path.isfile(src) else ""
    try:
        incoming_bytes = int(os.path.getsize(src)) if os.path.isfile(src) \
            else int(archive_tx.artifact_fingerprint(src)[2])
    except OSError:
        incoming_bytes = 0

    context = lock_context or Lock("recovery-store", timeout=30.0)
    with context:
        maintain_retention(
            policy=retention_config, incoming_bytes=incoming_bytes,
            lock_context=nullcontext(),
        )
        with Lock(_folder_key(os.path.dirname(src))):
            # Directory publication shares parents with every archive from this
            # source folder, so it belongs inside the same lock as versioning.
            file_dir = _file_dir(src)
            if dedupe and digest:
                last = latest_version(src)
                if last and last.get("sha256") == digest \
                        and archive_tx.entry_is_verified(agw_home(), last, src) \
                        and (not retention_class
                             or last.get("retention_class") == retention_class):
                    if retention_class == "mutation_preimage":
                        refreshed = archive_tx.update(
                            agw_home(), last["transaction_id"],
                            last_referenced_at_ns=time.time_ns(),
                            protected_until_ns=max(
                                int(last.get("protected_until_ns") or 0),
                                int(protected_until_ns or 0),
                            ),
                        )
                        return {**archive_tx.entry_from_record(refreshed),
                                "deduped": True}
                    return {**last, "deduped": True}
            version = _next_version(file_dir)
            name = os.path.basename(src)
            dest = os.path.join(file_dir, f"v{version:03d}_{_ts()}_{name}")
            entry = archive_tx.create_archive(
                agw_home(), src, dest, mode, version, reason, actor,
                crash_after=_crash_after,
                retention_class=retention_class,
                protected_until_ns=protected_until_ns,
                capture_group_id=capture_group_id,
            )
        _materialize_committed_transaction(entry["transaction_id"], _crash_after)
        return entry


def latest_version(src: str):
    entries = list_versions(src)
    return entries[-1] if entries else None


def list_versions(src: str) -> list:
    file_dir = _file_dir(src)
    manifest = os.path.join(file_dir, "manifest.jsonl")
    compatibility = []
    if os.path.exists(manifest):
        compatibility.extend(_read_jsonl_resilient(manifest)[0])
    # A committed transaction remains authoritative and discoverable even if a
    # crash happened before the compatibility JSONL index was appended.
    authoritative_available = {}
    for item in archive_tx.discover(agw_home()):
        record = item.get("record")
        if not record or record.get("kind") != "archive":
            continue
        transaction_id = str(record.get("transaction_id") or "")
        if archive_tx.canonical_path(record.get("src", "")) \
                != archive_tx.canonical_path(src):
            continue
        if record.get("state") != archive_tx.COMMITTED \
                or record.get("artifact_state", "PRESENT") != "PRESENT":
            continue
        entry = archive_tx.entry_from_record(record)
        if archive_tx.entry_is_verified(agw_home(), entry, src):
            authoritative_available[transaction_id] = entry

    # Compatibility entries with authoritative transaction ids are only
    # projections. Never let a stale JSONL row resurrect a PURGED, missing, or
    # otherwise unavailable authoritative artifact. Transactionless legacy
    # rows remain visible for explicit verification/refusal by restore().
    out = []
    for entry in compatibility:
        transaction_id = str(entry.get("transaction_id") or "")
        if transaction_id:
            if transaction_id in authoritative_available:
                out.append(authoritative_available[transaction_id])
            continue
        destination = str(entry.get("dest") or "")
        if destination and os.path.lexists(destination):
            out.append(entry)
    out.extend(authoritative_available.values())
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


def _refresh_selected_snapshot(record: dict, target: str) -> dict:
    """Hold a selected artifact across nested capacity maintenance."""
    if record.get("kind") != "archive":
        return record
    now_ns = time.time_ns()
    refreshed = archive_tx.update(
        agw_home(), record["transaction_id"],
        last_referenced_at_ns=max(
            int(record.get("last_referenced_at_ns") or 0), now_ns,
        ),
        protected_until_ns=max(
            int(record.get("protected_until_ns") or 0),
            now_ns + retention.PLAN_TTL_NS,
        ),
    )
    if not archive_tx.entry_is_verified(
            agw_home(), archive_tx.entry_from_record(refreshed), target):
        raise ValueError(f"selected recovery artifact failed verification: {target}")
    return refreshed


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


def _capture_undo_prestate(
        path: str, undo_id: str, *,
        retention_config: retention_policy.RetentionPolicy | None = None,
        lock_context=None) -> dict:
    """Capture the state being displaced by undo and return its transaction."""
    if os.path.lexists(path):
        entry = archive_file(
            path, mode="move", reason=f"pre-image before transaction undo {undo_id}",
            actor="guardrails-recovery", retention_class="safety_archive",
            retention_config=retention_config, lock_context=lock_context,
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


def _rollback_undo_member(
        member: dict, undo_id: str, *,
        retention_config: retention_policy.RetentionPolicy | None = None,
        lock_context=None):
    """Restore the after-state captured immediately before an undo member."""
    target = member["path"]
    recovery_id = member["undo_recovery_transaction_id"]
    recovery = archive_tx.load(agw_home(), recovery_id)
    if os.path.lexists(target):
        archive_file(
            target, mode="move", reason=f"failed transaction undo {undo_id}",
            actor="guardrails-recovery", retention_class="safety_archive",
            retention_config=retention_config, lock_context=lock_context,
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


def undo_transaction(
        transaction_id: str,
        retention_config: retention_policy.RetentionPolicy | None = None) -> dict:
    """Reverse one logged file mutation after strict hash and artifact checks.

    The current state displaced by the reversal is itself archived in a
    committed recovery transaction. No recovery record is consumed or deleted.
    """
    if not transaction_id:
        raise ValueError("transaction id is required")
    with Lock("recovery-store", timeout=30.0):
        operation = _mutation_record(transaction_id)
        members = _undo_members(operation)
        prior_undos = {
            item.get("undid_transaction_id") for item in oplog_read()
            if item.get("op") == "transaction-undo"
            and item.get("state") == "COMMITTED"
        }
        if transaction_id in prior_undos:
            raise ValueError(f"transaction was already undone: {transaction_id}")

        snapshots = []
        for member in members:
            _verify_current_after(member)
            snapshot = _verified_snapshot(member)
            snapshots.append(_refresh_selected_snapshot(snapshot, member["path"]))

        undo_id = uuid.uuid4().hex
        completed = []
        with Lock("transaction-undo"):
            try:
                for member, snapshot in zip(members, snapshots):
                    _verify_current_after(member)
                    displaced = _capture_undo_prestate(
                        member["path"], undo_id,
                        retention_config=retention_config,
                        lock_context=nullcontext(),
                    )
                    result = {**member, "undo_recovery_transaction_id":
                              displaced["transaction_id"]}
                    completed.append(result)
                    _restore_snapshot(member, snapshot)
                    _verify_restored_before(member, snapshot)
            except Exception as exc:
                rollback_errors = []
                for member in reversed(completed):
                    try:
                        _rollback_undo_member(
                            member, undo_id,
                            retention_config=retention_config,
                            lock_context=nullcontext(),
                        )
                    except Exception as rollback_exc:
                        rollback_errors.append({
                            "path": member["path"], "error": str(rollback_exc),
                            "undo_recovery_transaction_id":
                                member["undo_recovery_transaction_id"],
                        })
                failure = outcomes.completed_record({
                    "op": "transaction-undo-failed", "transaction_id": undo_id,
                    "undid_transaction_id": transaction_id,
                    "state": "NEEDS_ATTENTION", "operations": completed,
                    "error": str(exc), "rolled_back": not rollback_errors,
                    "rollback_errors": rollback_errors,
                    "process_outcome": outcomes.ProcessOutcome.NOT_APPLICABLE.value,
                    "publication_outcome":
                        outcomes.PublicationOutcome.NOT_APPLICABLE.value,
                }, operation_outcome=outcomes.CompositeOutcome.PROCESS_FAILED)
                oplog_append(failure)
                raise TransactionUndoError(
                    "transaction undo stopped; displaced states remain recoverable",
                    failure,
                ) from exc

        result = outcomes.completed_record({
            "op": "transaction-undo", "transaction_id": undo_id,
            "undid_transaction_id": transaction_id,
            "undid_op": operation.get("op"), "state": "COMMITTED",
            "operations": completed,
            # These axes describe the verified undo operation itself. They do
            # not infer anything about the mutation being reversed from its
            # recovery state.
            "process_outcome": outcomes.ProcessOutcome.NOT_APPLICABLE.value,
            "contract_outcome": outcomes.ContractOutcome.SATISFIED.value,
            "publication_outcome": outcomes.PublicationOutcome.NOT_APPLICABLE.value,
        }, operation_outcome=outcomes.CompositeOutcome.SUCCESS)
        oplog_append(result)
        return result


def restore(src: str, version: int = 0, overwrite: bool = False,
            retention_config: retention_policy.RetentionPolicy | None = None) -> dict:
    """Restore an archived version of `src` to its original location."""
    with Lock("recovery-store", timeout=30.0):
        entries = list_versions(src)
        if not entries:
            raise FileNotFoundError(f"no archived versions of {src}")
        entry = entries[-1] if not version else next(
            (e for e in entries if e.get("version") == version), None)
        if entry is None:
            raise FileNotFoundError(f"no version {version} of {src}")
        if entry.get("transaction_id"):
            record = archive_tx.load(agw_home(), entry["transaction_id"])
            record = _refresh_selected_snapshot(record, src)
            entry = archive_tx.entry_from_record(record)
        if not archive_tx.entry_is_verified(agw_home(), entry, src):
            raise ValueError(
                "restore refused: the selected archive artifact is not verified"
            )
        if os.path.lexists(src):
            # Moving the live target into its own verified transaction eliminates
            # the former copy-then-unlink crash window.
            archive_file(
                src, mode="move", reason="pre-restore safety archive", actor="agw",
                retention_class="safety_archive",
                retention_config=retention_config, lock_context=nullcontext(),
            )
        archive_tx.publish_restore(agw_home(), entry, src)
        op = {
            "op": "restore", "src": src, "from": entry["dest"],
            "version": entry["version"],
        }
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


def resolved_retention_policy(settings=None) -> retention_policy.RetentionPolicy:
    """Resolve one retention contract for CLI, hooks, and store operations."""
    return retention_policy.resolve_retention_policy(settings or {})


def retention_state(settings=None) -> dict:
    """Return the typed, non-mutating state of the recovery cache."""
    policy = resolved_retention_policy(settings)
    return retention_policy.classify_retention_state(
        policy, archive_size_bytes()
    ).as_dict()


_MAX_RETENTION_JOURNALS = 10_000


def _retention_identifier_valid(value: str) -> bool:
    return len(value) == 32 and all(char in "0123456789abcdef" for char in value)


def _recover_retention_journals_locked() -> dict:
    """Recover every discoverable interrupted retention apply before planning.

    The caller holds the global recovery-store lock. Unknown, corrupt, or
    unbounded journal/staging state aborts maintenance rather than allowing a
    new plan to reason from incomplete evidence.
    """
    home = agw_home()
    journal_root = os.path.join(home, "retention", "transactions")
    staging_root = os.path.join(home, "retention", "staging")
    result = {"discovered": 0, "recovered": 0, "already_complete": 0,
              "plan_ids": []}
    journals = {}
    if os.path.lexists(journal_root):
        if os.path.islink(journal_root) or not os.path.isdir(journal_root):
            raise retention.InventoryIncompleteError(
                "retention journal root is not a local directory"
            )
        try:
            with os.scandir(journal_root) as entries:
                items = sorted(entries, key=lambda entry: entry.name)
        except OSError as exc:
            raise retention.InventoryIncompleteError(
                f"retention journals could not be discovered: {exc}"
            ) from exc
        if len(items) > _MAX_RETENTION_JOURNALS:
            raise retention.InventoryIncompleteError(
                "retention journal discovery limit exceeded"
            )
        for entry in items:
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False) \
                    or not entry.name.endswith(".json"):
                raise retention.InventoryIncompleteError(
                    "retention journal directory contains an unknown entry"
                )
            plan_id = entry.name[:-5]
            if not _retention_identifier_valid(plan_id):
                raise retention.InventoryIncompleteError(
                    "retention journal has an invalid identity"
                )
            try:
                journal = retention.load_journal(home, plan_id)
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
                raise retention.InventoryIncompleteError(
                    f"retention journal {plan_id} is unreadable"
                ) from exc
            if journal.get("plan_id") != plan_id:
                raise retention.InventoryIncompleteError(
                    f"retention journal {plan_id} has mismatched identity"
                )
            state = journal.get("state")
            if state not in {retention.PREPARED, retention.STAGED,
                             retention.PURGED}:
                raise retention.InventoryIncompleteError(
                    f"retention journal {plan_id} has unknown state"
                )
            journals[plan_id] = journal
            result["discovered"] += 1

    for plan_id, journal in journals.items():
        state = journal["state"]
        if state == retention.PURGED or (
                state == retention.PREPARED
                and journal.get("recovery_action") == "rolled_back_staging"):
            result["already_complete"] += 1
            continue
        try:
            recovered = retention.recover_journal(
                home, plan_id, lock_context=nullcontext()
            )
        except Exception as exc:
            raise retention.InventoryIncompleteError(
                f"retention journal {plan_id} could not be recovered"
            ) from exc
        if recovered.get("state") == retention.STAGED \
                or (recovered.get("state") == retention.PREPARED
                    and recovered.get("recovery_action")
                    != "rolled_back_staging"):
            raise retention.InventoryIncompleteError(
                f"retention journal {plan_id} remains incomplete"
            )
        result["recovered"] += 1
        result["plan_ids"].append(plan_id)

    if os.path.lexists(staging_root):
        if os.path.islink(staging_root) or not os.path.isdir(staging_root):
            raise retention.InventoryIncompleteError(
                "retention staging root is not a local directory"
            )
        try:
            with os.scandir(staging_root) as entries:
                staged = sorted(entries, key=lambda entry: entry.name)
        except OSError as exc:
            raise retention.InventoryIncompleteError(
                f"retention staging could not be verified: {exc}"
            ) from exc
        if len(staged) > _MAX_RETENTION_JOURNALS:
            raise retention.InventoryIncompleteError(
                "retention staging discovery limit exceeded"
            )
        for entry in staged:
            if entry.is_symlink() or not entry.is_dir(follow_symlinks=False) \
                    or not _retention_identifier_valid(entry.name) \
                    or entry.name not in journals:
                raise retention.InventoryIncompleteError(
                    "retention staging contains unjournaled state"
                )
            try:
                with os.scandir(entry.path) as children:
                    if next(children, None) is not None:
                        raise retention.InventoryIncompleteError(
                            f"retention staging {entry.name} remains nonempty"
                        )
            except OSError as exc:
                raise retention.InventoryIncompleteError(
                    f"retention staging {entry.name} is unreadable"
                ) from exc
    return result


def maintain_retention(*, policy: retention_policy.RetentionPolicy | None = None,
                       incoming_bytes: int = 0, lock_context=None) -> dict:
    """Automatically reclaim only expired, classified cache preimages.

    The caller may provide an already-held global-store lock via
    ``lock_context``.  Unknown, manual, move, evidence, corrupt, and recent
    records are never candidates.  If those protections leave insufficient
    room, the new store-growing operation is refused before publication.
    """
    context = lock_context or Lock("recovery-store", timeout=30.0)
    with context:
        return _maintain_retention_locked(
            policy=policy, incoming_bytes=incoming_bytes
        )


def _maintain_retention_locked(*,
        policy: retention_policy.RetentionPolicy | None = None,
        incoming_bytes: int = 0) -> dict:
    """Implementation requiring the recovery-store mutation lock."""
    policy = policy or resolved_retention_policy()
    incoming = max(0, int(incoming_bytes or 0))
    journal_recovery = _recover_retention_journals_locked()
    before = archive_size_bytes()
    projected = before + incoming
    state = retention_policy.classify_retention_state(policy, projected)
    migration = {"migrated": 0, "transaction_ids": [],
                 "protected_days": policy.min_protected_age_days}
    if state.prune_recommended:
        migration = retention.migrate_legacy_cache_records(
            agw_home(), protected_days=policy.min_protected_age_days
        )
    result = {
        "automatic": True,
        "before_bytes": before,
        "incoming_bytes": incoming,
        "projected_bytes": projected,
        "policy": policy.as_dict(),
        "state": state.as_dict(),
        "journal_recovery": journal_recovery,
        "legacy_migration": migration,
        "applied": False,
        "reclaimed_bytes": 0,
    }
    if state.prune_recommended and before:
        plan = retention.build_plan(
            agw_home(), policy=policy, current_bytes=projected,
        )
        result["plan"] = plan
        if plan.get("applicable") and plan.get("candidates"):
            applied = retention.apply_plan(
                agw_home(), plan, expected_plan_hash=plan["plan_sha256"],
                policy=policy, lock_context=nullcontext(),
            )
            result["applied"] = True
            result["apply"] = applied
            result["reclaimed_bytes"] = int(applied.get("reclaimed_bytes") or 0)

    after = archive_size_bytes()
    final_projected = after + incoming
    result["after_bytes"] = after
    result["final_projected_bytes"] = final_projected
    if not policy.unlimited and final_projected > policy.max_bytes:
        raise ArchiveCapacityError(
            "The recovery cache cannot safely make room for this operation.",
            {
                **result,
                "maximum_bytes": policy.max_bytes,
                "required_free_bytes": final_projected - policy.max_bytes,
                "protected_or_unavailable_bytes": max(
                    0, final_projected - policy.low_water_bytes
                    - int(result.get("reclaimed_bytes") or 0),
                ),
            },
        )
    return result


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
