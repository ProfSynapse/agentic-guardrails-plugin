"""Atomic, recoverable operations for ordinary text files."""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile
from typing import Callable, Optional

from core import engine, preimages, store


MAX_TEXT_BYTES = 32 * 1024 * 1024
MAX_CAPTURE_BYTES = 64 * 1024
PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_HUNK_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$"
)


class FileOperationError(RuntimeError):
    error_code = "file_operation_error"

    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.details = details or {}


class FileConflict(FileOperationError):
    error_code = "file_hash_conflict"


def resolve_target(path: str) -> str:
    raw = str(path or "").strip()
    if not raw or "\x00" in raw:
        raise FileOperationError("target path is missing or invalid")
    if any(char in raw for char in "*?["):
        raise FileOperationError("target path must be literal, not a wildcard")
    target = os.path.abspath(os.path.expanduser(raw))
    if os.path.isdir(target):
        raise FileOperationError("target must be a file, not a directory")
    parent = os.path.dirname(target)
    if not os.path.isdir(parent):
        raise FileOperationError("target parent directory does not exist")
    return target


def _current_hash(path: str) -> Optional[str]:
    if not os.path.lexists(path):
        return None
    if not os.path.isfile(path) or os.path.islink(path):
        raise FileOperationError("target must be an ordinary local file")
    return store.file_sha256(path)


def _check_expected(path: str, expected: str) -> Optional[str]:
    current = _current_hash(path)
    wanted = str(expected or "").strip().lower()
    if not wanted:
        return current
    if wanted in {"absent", "missing", "new"}:
        if current is not None:
            raise FileConflict("CONFLICT: target exists but absence was expected", {
                "path": path, "expected": "absent", "actual": current,
            })
        return current
    if not _HASH_RE.fullmatch(wanted):
        raise FileOperationError("expected hash must be a SHA-256 or 'absent'")
    if current is None or current.lower() != wanted:
        raise FileConflict("CONFLICT: file hash does not match expected version", {
            "path": path, "expected": wanted, "actual": current or "absent",
        })
    return current


def read_utf8(path: str, label: str = "input") -> str:
    source = os.path.abspath(os.path.expanduser(path))
    try:
        size = os.path.getsize(source)
    except OSError as exc:
        raise FileOperationError(f"{label} could not be read: {exc}") from exc
    if size > MAX_TEXT_BYTES:
        raise FileOperationError(
            f"{label} exceeds the {MAX_TEXT_BYTES // (1024 * 1024)} MB text limit"
        )
    try:
        with open(source, "r", encoding="utf-8-sig", newline="") as handle:
            return handle.read()
    except (OSError, UnicodeError) as exc:
        raise FileOperationError(f"{label} must be readable UTF-8 text: {exc}") from exc


def _snapshots(targets: list[str], operation: str, max_file_bytes: int = 0):
    policy = engine.load_policy(PLUGIN_ROOT)
    limit = max_file_bytes or int(os.environ.get(
        "AGW_PRESNAP_MAX_BYTES", 100 * 1024 * 1024
    ))
    result = preimages.prepare(
        targets, f"agw file {operation}", limit,
        policy_revision=policy.revision,
    )
    if not result.ok:
        raise FileOperationError(result.reason, {"path": result.failed_target})
    return result.receipts


def _snapshot(target: str, operation: str, max_file_bytes: int = 0):
    return _snapshots([target], operation, max_file_bytes)[0]


def write_text(
    target: str,
    text: str,
    *,
    expected_hash: str = "",
    dry_run: bool = False,
    operation: str = "write",
) -> dict:
    target = resolve_target(target)
    payload = text.encode("utf-8")
    if len(payload) > MAX_TEXT_BYTES:
        raise FileOperationError(
            f"content exceeds the {MAX_TEXT_BYTES // (1024 * 1024)} MB text limit"
        )
    after = hashlib.sha256(payload).hexdigest()
    lock_name = "file-" + hashlib.sha256(
        os.path.normcase(os.path.realpath(target)).encode("utf-8", "replace")
    ).hexdigest()[:32]
    stage = ""
    with store.Lock(lock_name, timeout=10.0):
        before = _check_expected(target, expected_hash)
        if before == after:
            return {
                "path": target, "operation": operation, "changed": 0,
                "before_hash": before, "after_hash": after,
            }
        if dry_run:
            return {
                "path": target, "operation": operation, "changed": 1,
                "dry_run": True, "before_hash": before or "absent",
                "after_hash": after,
            }
        fd, stage = tempfile.mkstemp(
            prefix=".agw-file-", suffix=".tmp", dir=os.path.dirname(target)
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            if store.file_sha256(stage) != after:
                raise FileOperationError("staged file failed hash verification")
            if _current_hash(target) != before:
                raise FileConflict("CONFLICT: file changed while content was staged", {
                    "path": target, "expected": before or "absent",
                    "actual": _current_hash(target) or "absent",
                })
            receipt = _snapshot(target, operation, MAX_TEXT_BYTES)
            if _current_hash(target) != before:
                raise FileConflict("CONFLICT: file changed before publication")
            os.replace(stage, target)
            stage = ""
            if store.file_sha256(target) != after:
                raise FileOperationError("published file failed final hash verification")
            store.oplog_append({
                "op": "file-mutation", "operation": operation, "src": target,
                "before_sha256": before or "absent", "after_sha256": after,
                "snapshot_transaction_id": receipt.transaction_id,
            })
            return {
                "path": target, "operation": operation, "changed": 1,
                "before_hash": before or "absent", "after_hash": after,
                "snapshot_transaction_id": receipt.transaction_id,
                "snapshot_state": receipt.state,
            }
        finally:
            if stage and os.path.exists(stage):
                try:
                    os.unlink(stage)
                except OSError:
                    pass


def transform_text(
    target: str,
    transform: Callable[[str], str],
    *,
    expected_hash: str = "",
    dry_run: bool = False,
    operation: str,
) -> dict:
    target = resolve_target(target)
    if not os.path.isfile(target):
        raise FileOperationError(f"agw file {operation} requires an existing file")
    original = read_utf8(target, "target")
    updated = transform(original)
    if not isinstance(updated, str):
        raise FileOperationError("text transform returned invalid content")
    return write_text(
        target, updated, expected_hash=expected_hash,
        dry_run=dry_run, operation=operation,
    )


def replace_text(original: str, old: str, new: str, *, replace_all: bool = False) -> str:
    count = original.count(old)
    if not old:
        raise FileOperationError("old text must not be empty")
    if count == 0:
        raise FileConflict("CONFLICT: old text was not found", {"matches": 0})
    if count != 1 and not replace_all:
        raise FileConflict(
            "CONFLICT: old text is not unique; use --all after review",
            {"matches": count},
        )
    return original.replace(old, new) if replace_all else original.replace(old, new, 1)


def apply_unified_patch(original: str, patch: str) -> str:
    """Apply a single-file unified diff with exact context and no fuzz."""
    source = original.splitlines()
    lines = patch.splitlines()
    if not lines or not any(line.startswith("@@ ") for line in lines):
        raise FileOperationError("patch must contain a unified-diff hunk")
    if sum(line.startswith("--- ") for line in lines) > 1:
        raise FileOperationError("patch must describe exactly one file")
    result = []
    source_index = 0
    index = 0
    while index < len(lines):
        match = _HUNK_RE.match(lines[index])
        if not match:
            index += 1
            continue
        old_start = int(match.group(1))
        old_count = int(match.group(2) or 1)
        new_count = int(match.group(4) or 1)
        hunk_start = max(0, old_start - 1)
        if hunk_start < source_index or hunk_start > len(source):
            raise FileConflict("CONFLICT: patch hunk is out of range")
        result.extend(source[source_index:hunk_start])
        source_index = hunk_start
        seen_old = 0
        seen_new = 0
        index += 1
        while index < len(lines) and not lines[index].startswith("@@ "):
            line = lines[index]
            if line.startswith(("--- ", "+++ ")):
                raise FileOperationError("unexpected file header inside patch hunk")
            if line == r"\ No newline at end of file":
                index += 1
                continue
            if not line or line[0] not in {" ", "+", "-"}:
                raise FileOperationError("invalid unified-diff hunk line")
            marker, content = line[0], line[1:]
            if marker in {" ", "-"}:
                if source_index >= len(source) or source[source_index] != content:
                    raise FileConflict("CONFLICT: patch context does not match target", {
                        "line": source_index + 1,
                    })
                source_index += 1
                seen_old += 1
            if marker in {" ", "+"}:
                result.append(content)
                seen_new += 1
            index += 1
        if seen_old != old_count or seen_new != new_count:
            raise FileOperationError("patch hunk counts do not match its header")
    result.extend(source[source_index:])
    newline = "\r\n" if "\r\n" in original else "\n"
    final_newline = newline if original.endswith(("\n", "\r")) else ""
    return newline.join(result) + final_newline


def run_declared(
    command: list[str],
    outputs: list[str],
    *,
    expected_hashes: Optional[list[str]] = None,
    cwd: str = "",
    dry_run: bool = False,
) -> dict:
    """Run a command after verified pre-images for every declared output."""
    if not command:
        raise FileOperationError("run requires a command after --")
    targets = [resolve_target(path) for path in outputs]
    if not targets:
        raise FileOperationError("run requires at least one --output")
    folded = [os.path.normcase(os.path.realpath(path)) for path in targets]
    if len(folded) != len(set(folded)):
        raise FileOperationError("declared outputs must be unique")
    expected_hashes = list(expected_hashes or [])
    if expected_hashes and len(expected_hashes) != len(targets):
        raise FileOperationError(
            "repeat --expected-hash once per --output, in the same order"
        )
    if not expected_hashes:
        expected_hashes = [""] * len(targets)
    working = os.path.abspath(os.path.expanduser(cwd or os.getcwd()))
    if not os.path.isdir(working):
        raise FileOperationError("run working directory does not exist")

    lock_material = "\0".join(sorted(folded)).encode("utf-8", "replace")
    lock_name = "run-" + hashlib.sha256(lock_material).hexdigest()[:32]
    with store.Lock(lock_name, timeout=10.0):
        before = [
            _check_expected(path, expected)
            for path, expected in zip(targets, expected_hashes)
        ]
        preview = [
            {"path": path, "before_hash": digest or "absent"}
            for path, digest in zip(targets, before)
        ]
        if dry_run:
            return {
                "dry_run": True, "command": command, "cwd": working,
                "outputs": preview, "executed": False,
            }
        receipts = _snapshots(targets, "run")
        for path, digest in zip(targets, before):
            if _current_hash(path) != digest:
                raise FileConflict(
                    "CONFLICT: declared output changed before command execution",
                    {"path": path},
                )
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            try:
                completed = subprocess.run(
                    command, cwd=working, stdin=subprocess.DEVNULL,
                    stdout=stdout_file, stderr=stderr_file, check=False,
                )
            except OSError as exc:
                raise FileOperationError(f"command could not be started: {exc}") from exc

            def captured(handle):
                handle.flush()
                size = handle.tell()
                handle.seek(max(0, size - MAX_CAPTURE_BYTES))
                return handle.read().decode("utf-8", "replace")

            stdout = captured(stdout_file)
            stderr = captured(stderr_file)
        after = [_current_hash(path) for path in targets]
        output_results = []
        missing_outputs = []
        for path, old, new, receipt in zip(targets, before, after, receipts):
            if old is None and new is None:
                missing_outputs.append(path)
            output_results.append({
                "path": path,
                "before_hash": old or "absent",
                "after_hash": new or "absent",
                "changed": old != new,
                "snapshot_transaction_id": receipt.transaction_id,
                "snapshot_state": receipt.state,
            })
        store.oplog_append({
            "op": "declared-run", "command": command[0], "cwd": working,
            "exit_code": completed.returncode,
            "outputs": [
                {"src": item["path"], "before_sha256": item["before_hash"],
                 "after_sha256": item["after_hash"],
                 "snapshot_transaction_id": item["snapshot_transaction_id"]}
                for item in output_results
            ],
        })
        return {
            "ok": completed.returncode == 0 and not missing_outputs,
            "executed": True,
            "exit_code": completed.returncode,
            "command": command,
            "cwd": working,
            "outputs": output_results,
            "stdout_tail": stdout,
            "stderr_tail": stderr,
            "declared_outputs_missing": missing_outputs,
            "capture_truncated": (
                len(stdout.encode("utf-8")) >= MAX_CAPTURE_BYTES
                or len(stderr.encode("utf-8")) >= MAX_CAPTURE_BYTES
            ),
        }


def publish_staged_file(
    target: str,
    stage: str,
    *,
    expected_hash: str = "",
    dry_run: bool = False,
    operation: str,
) -> dict:
    """Publish a verified same-directory stage with recovery coverage."""
    target = resolve_target(target)
    stage = os.path.abspath(stage)
    if os.path.dirname(stage) != os.path.dirname(target):
        raise FileOperationError("staged file must be in the target directory")
    if not os.path.isfile(stage) or os.path.islink(stage):
        raise FileOperationError("staged output is not an ordinary file")
    after = store.file_sha256(stage)
    lock_name = "file-" + hashlib.sha256(
        os.path.normcase(os.path.realpath(target)).encode("utf-8", "replace")
    ).hexdigest()[:32]
    with store.Lock(lock_name, timeout=10.0):
        before = _check_expected(target, expected_hash)
        if before == after:
            return {
                "path": target, "operation": operation, "changed": 0,
                "before_hash": before, "after_hash": after,
            }
        if dry_run:
            return {
                "path": target, "operation": operation, "changed": 1,
                "dry_run": True, "before_hash": before or "absent",
                "after_hash": after,
            }
        receipt = _snapshot(target, operation)
        if _current_hash(target) != before:
            raise FileConflict("CONFLICT: target changed before publication")
        os.replace(stage, target)
        if store.file_sha256(target) != after:
            raise FileOperationError("published file failed final hash verification")
        store.oplog_append({
            "op": "file-mutation", "operation": operation, "src": target,
            "before_sha256": before or "absent", "after_sha256": after,
            "snapshot_transaction_id": receipt.transaction_id,
        })
        return {
            "path": target, "operation": operation, "changed": 1,
            "before_hash": before or "absent", "after_hash": after,
            "snapshot_transaction_id": receipt.transaction_id,
            "snapshot_state": receipt.state,
        }
