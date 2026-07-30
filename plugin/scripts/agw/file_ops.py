"""Atomic, recoverable operations for ordinary text files."""
from __future__ import annotations

import hashlib
import errno
import fnmatch
import multiprocessing
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from typing import Callable, Optional

from core import engine, preimages, store


MAX_TEXT_BYTES = 32 * 1024 * 1024
MAX_CAPTURE_BYTES = 64 * 1024
OUTPUT_OBSERVATION_SECONDS = 5.0
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


class PublishBusy(FileOperationError):
    error_code = "publish_target_busy"


class UndeclaredOutput(FileOperationError):
    error_code = "undeclared_output"


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
    # A transform is a read-modify-write operation. Bind publication to the
    # exact version read even when the caller did not provide --expected-hash;
    # otherwise an external editor could update the file between the read and
    # atomic publication and have its newer content overwritten.
    baseline = _check_expected(target, expected_hash)
    original = read_utf8(target, "target")
    updated = transform(original)
    if not isinstance(updated, str):
        raise FileOperationError("text transform returned invalid content")
    current = _current_hash(target)
    if current != baseline:
        raise FileConflict(
            "CONFLICT: file changed while the transformation was prepared",
            {
                "path": target,
                "expected": baseline or "absent",
                "actual": current or "absent",
            },
        )
    return write_text(
        target, updated, expected_hash=baseline or "absent",
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
    output_roots: Optional[list[str]] = None,
    output_patterns: Optional[list[str]] = None,
    max_observed_files: int = 20_000,
    max_observed_depth: int = 8,
) -> dict:
    """Run a command after verified pre-images for every declared output."""
    if not command:
        raise FileOperationError("run requires a command after --")
    targets = [resolve_target(path) for path in outputs]
    output_patterns = list(output_patterns or [])
    if not targets and not output_patterns:
        raise FileOperationError("run requires at least one --output or --output-pattern")
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
    patterns = _validate_output_patterns(output_patterns)
    roots = _output_roots(targets, output_roots or [])
    if patterns and not roots:
        raise FileOperationError(
            "--output-pattern requires an explicit --output-root"
        )

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
            observation = _observe_requested_roots(
                roots, max_files=max_observed_files, max_depth=max_observed_depth,
            )
            return {
                "dry_run": True, "command": command, "cwd": working,
                "outputs": preview, "output_roots": roots,
                "output_patterns": patterns, "executed": False,
                "output_observation": {
                    "mode": "root_manifest" if roots else "exact_outputs",
                    "complete": True,
                    "files_observed": observation["count"],
                },
            }
        receipts = _snapshots(targets, "run")
        for path, digest in zip(targets, before):
            if _current_hash(path) != digest:
                raise FileConflict(
                    "CONFLICT: declared output changed before command execution",
                    {"path": path},
                )
        # Recovery preparation may create AGW_HOME beneath a test/work root.
        # Establish the execution baseline only after those declared pre-images
        # are durable so Guardrails' own metadata is not blamed on the command.
        before_observation = _observe_requested_roots(
            roots, max_files=max_observed_files, max_depth=max_observed_depth,
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
        after_observation = _observe_requested_roots(
            roots, max_files=max_observed_files, max_depth=max_observed_depth,
        )
        observed_changes = _observation_changes(
            before_observation, after_observation,
        )
        declared = {os.path.normcase(os.path.abspath(path)) for path in targets}
        undeclared = []
        for change in observed_changes:
            absolute = os.path.normcase(os.path.abspath(change["path"]))
            if absolute in declared or _matches_output_pattern(
                    change["path"], roots, patterns):
                continue
            undeclared.append(change)
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
            "ok": (completed.returncode == 0 and not missing_outputs
                   and not undeclared),
            "executed": True,
            "exit_code": completed.returncode,
            "command": command,
            "cwd": working,
            "outputs": output_results,
            "stdout_tail": stdout,
            "stderr_tail": stderr,
            "declared_outputs_missing": missing_outputs,
            "unclaimed_observed_changes": undeclared,
            # Compatibility alias retained for existing JSON consumers. A
            # before/after manifest cannot prove which process caused a change.
            "undeclared_outputs": undeclared,
            "output_roots": roots,
            "output_patterns": patterns,
            "output_observation": {
                "mode": "root_manifest" if roots else "exact_outputs",
                "complete": True,
                "files_before": before_observation["count"],
                "files_after": after_observation["count"],
                "changed_paths": len(observed_changes),
                "unclaimed_changes": len(undeclared),
            },
            "capture_truncated": (
                len(stdout.encode("utf-8")) >= MAX_CAPTURE_BYTES
                or len(stderr.encode("utf-8")) >= MAX_CAPTURE_BYTES
            ),
        }


def _output_roots(targets: list[str], supplied: list[str]) -> list[str]:
    # Exact declarations are deliberately exact. Recursively observing their
    # parent directories is expensive in large/synced folders and conflates
    # unrelated application activity with command side effects. Root manifests
    # are therefore an explicit opt-in.
    raw = supplied
    roots = []
    for value in raw:
        if any(char in str(value) for char in "*?["):
            raise FileOperationError("output roots must be literal directories")
        root = os.path.abspath(os.path.expanduser(value))
        if not os.path.isdir(root):
            raise FileOperationError(f"output root does not exist: {root}")
        folded = os.path.normcase(root)
        if folded not in {os.path.normcase(item) for item in roots}:
            roots.append(root)
    if roots:
        for target in targets:
            if not any(_path_is_within(target, root) for root in roots):
                raise FileOperationError(
                    f"declared output is outside every output root: {target}"
                )
    return roots


def _observe_requested_roots(roots: list[str], *, max_files: int,
                             max_depth: int) -> dict:
    if not roots:
        return {"entries": {}, "count": 0}
    return _observe_output_roots_bounded(
        roots, max_files=max_files, max_depth=max_depth,
    )


def _validate_output_patterns(patterns: list[str]) -> list[str]:
    result = []
    for raw in patterns:
        value = str(raw or "").replace("\\", "/").strip()
        if (not value or "\x00" in value or os.path.isabs(value)
                or any(part == ".." for part in value.split("/"))):
            raise FileOperationError(
                "output patterns must be non-empty relative patterns without '..'"
            )
        result.append(value)
    return result


def _path_is_within(path: str, root: str) -> bool:
    try:
        absolute = os.path.normcase(os.path.abspath(path))
        root_absolute = os.path.normcase(os.path.abspath(root))
        return os.path.normcase(os.path.commonpath([absolute, root_absolute])) \
            == root_absolute
    except ValueError:
        return False


def _observe_output_roots(roots: list[str], *, max_files: int,
                          max_depth: int) -> dict:
    if max_files < 1 or max_depth < 0:
        raise FileOperationError("output observation bounds are invalid")
    entries = {}
    count = 0
    for root in roots:
        stack = [(root, 0)]
        while stack:
            directory, depth = stack.pop()
            try:
                children = list(os.scandir(directory))
            except OSError as exc:
                raise FileOperationError(
                    f"output root could not be observed safely: {directory}: {exc}"
                ) from exc
            for child in children:
                count += 1
                if count > max_files:
                    raise FileOperationError(
                        f"output observation exceeded {max_files} paths; narrow "
                        "--output-root or raise --max-observed-files"
                    )
                try:
                    item = child.stat(follow_symlinks=False)
                except OSError as exc:
                    raise FileOperationError(
                        f"output path metadata could not be inspected: {child.path}: {exc}"
                    ) from exc
                attributes = int(getattr(item, "st_file_attributes", 0) or 0)
                reparse = bool(attributes & int(getattr(
                    stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
                )))
                is_directory = stat.S_ISDIR(item.st_mode) and not reparse
                entries[os.path.normcase(os.path.abspath(child.path))] = {
                    "path": os.path.abspath(child.path),
                    "kind": "directory" if is_directory else (
                        "link" if reparse or stat.S_ISLNK(item.st_mode) else "file"
                    ),
                    "size": int(item.st_size),
                    "mtime_ns": int(item.st_mtime_ns),
                    "mode": int(item.st_mode),
                    "identity": [int(getattr(item, "st_dev", 0)),
                                 int(getattr(item, "st_ino", 0))],
                }
                if is_directory and depth < max_depth:
                    stack.append((child.path, depth + 1))
    return {"entries": entries, "count": count}


def _observe_output_worker(connection, roots: list[str], max_files: int,
                           max_depth: int):
    try:
        connection.send({
            "ok": True,
            "result": _observe_output_roots(
                roots, max_files=max_files, max_depth=max_depth
            ),
        })
    except Exception as exc:  # sent as plain data; no child traceback leakage
        connection.send({"ok": False, "error": str(exc)})
    finally:
        connection.close()


def _observe_output_roots_bounded(roots: list[str], *, max_files: int,
                                  max_depth: int) -> dict:
    """Run filesystem enumeration in a killable worker with a hard deadline."""
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    worker = context.Process(
        target=_observe_output_worker,
        args=(sender, roots, max_files, max_depth),
        name="agw-output-observer",
    )
    worker.start()
    sender.close()
    deadline = time.monotonic() + OUTPUT_OBSERVATION_SECONDS
    payload = None
    try:
        while time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            if receiver.poll(min(0.05, remaining)):
                payload = receiver.recv()
                break
            if not worker.is_alive():
                break
        if payload is None and receiver.poll(0):
            payload = receiver.recv()
        if payload is None:
            raise FileOperationError(
                "output observation exceeded its hard 5-second deadline; "
                "narrow --output-root"
            )
        if not payload.get("ok"):
            raise FileOperationError(
                payload.get("error") or "output observation worker failed"
            )
        return payload["result"]
    finally:
        receiver.close()
        if worker.is_alive():
            worker.terminate()
        worker.join(timeout=1.0)
        if worker.is_alive() and hasattr(worker, "kill"):
            worker.kill()
            worker.join(timeout=1.0)


def _observation_changes(before: dict, after: dict) -> list[dict]:
    old = before["entries"]
    new = after["entries"]
    changes = []
    for key in sorted(set(old) | set(new)):
        if key not in old:
            changes.append({"path": new[key]["path"], "change": "created",
                            "kind": new[key]["kind"]})
        elif key not in new:
            changes.append({"path": old[key]["path"], "change": "removed",
                            "kind": old[key]["kind"]})
        elif old[key] != new[key] and new[key]["kind"] != "directory":
            changes.append({"path": new[key]["path"], "change": "modified",
                            "kind": new[key]["kind"]})
    return changes


def _matches_output_pattern(path: str, roots: list[str], patterns: list[str]) -> bool:
    for root in roots:
        if not _path_is_within(path, root):
            continue
        relative = os.path.relpath(path, root).replace("\\", "/")
        if any(fnmatch.fnmatchcase(relative, pattern) for pattern in patterns):
            return True
    return False


def replace_with_retry(source: str, target: str, retry_seconds: float = 5.0) -> int:
    deadline = time.monotonic() + max(0.0, float(retry_seconds))
    attempts = 0
    while True:
        attempts += 1
        try:
            os.replace(source, target)
            return attempts
        except OSError as exc:
            retryable = (
                exc.errno in {errno.EACCES, errno.EBUSY, errno.EPERM}
                or getattr(exc, "winerror", None) in {32, 33}
            )
            if not retryable or time.monotonic() >= deadline:
                raise PublishBusy(
                    f"target remained busy; staged output was preserved: {source}",
                    {"target": target, "staged": source, "attempts": attempts,
                     "retryable": retryable, "errno": exc.errno,
                     "winerror": getattr(exc, "winerror", None)},
                ) from exc
            time.sleep(min(0.5, max(0.05, deadline - time.monotonic())))


def publish_staged_file(
    target: str,
    stage: str,
    *,
    expected_hash: str = "",
    expected_stage_hash: str = "",
    dry_run: bool = False,
    operation: str = "publish-file",
    retry_seconds: float = 5.0,
) -> dict:
    """Validate a stage and atomically publish it with recovery coverage."""
    target = resolve_target(target)
    stage = os.path.abspath(os.path.expanduser(stage))
    if not os.path.isfile(stage) or os.path.islink(stage):
        raise FileOperationError("staged output is not an ordinary file")
    after = store.file_sha256(stage)
    wanted_stage = str(expected_stage_hash or "").strip().lower()
    if wanted_stage:
        if not _HASH_RE.fullmatch(wanted_stage):
            raise FileOperationError("expected staged hash must be a SHA-256")
        if wanted_stage != after:
            raise FileConflict(
                "CONFLICT: staged file hash does not match expected version",
                {"path": stage, "expected": wanted_stage, "actual": after},
            )
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
        candidate = stage
        copied_candidate = False
        if os.path.dirname(stage) != os.path.dirname(target):
            fd, candidate = tempfile.mkstemp(
                prefix=".agw-publish-", suffix=os.path.splitext(target)[1],
                dir=os.path.dirname(target),
            )
            os.close(fd)
            try:
                shutil.copy2(stage, candidate)
            except Exception:
                try:
                    os.unlink(candidate)
                except OSError:
                    pass
                raise
            copied_candidate = True
            if store.file_sha256(candidate) != after:
                try:
                    os.unlink(candidate)
                except OSError:
                    pass
                raise FileOperationError("same-directory staged copy failed verification")
        try:
            receipt = _snapshot(target, operation)
            if _current_hash(target) != before:
                raise FileConflict("CONFLICT: target changed before publication")
        except Exception:
            if copied_candidate and os.path.exists(candidate):
                try:
                    os.unlink(candidate)
                except OSError:
                    pass
            raise
        try:
            attempts = replace_with_retry(candidate, target, retry_seconds)
        except Exception:
            # The caller's original stage is never consumed on a failed publish.
            # Keep a same-directory stage as retry evidence; remove only our copy.
            if copied_candidate and os.path.exists(candidate):
                try:
                    os.unlink(candidate)
                except OSError:
                    pass
            raise
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
            "publish_attempts": attempts,
        }
