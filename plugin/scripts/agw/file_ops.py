"""Atomic, recoverable operations for ordinary text files."""
from __future__ import annotations

import bisect
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

from core import engine, preimages, profiles, store


MAX_TEXT_BYTES = 32 * 1024 * 1024
DEFAULT_READ_LINES = 200
DEFAULT_READ_BYTES = 32 * 1024
MAX_READ_OUTPUT_BYTES = 256 * 1024
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


class PlaceholderReadRefused(FileOperationError):
    error_code = "placeholder_read_refused"


def resolve_target(path: str, *, allow_missing_parent: bool = False) -> str:
    raw = str(path or "").strip()
    if not raw or "\x00" in raw:
        raise FileOperationError("target path is missing or invalid")
    if any(char in raw for char in "*?["):
        raise FileOperationError("target path must be literal, not a wildcard")
    target = os.path.abspath(os.path.expanduser(raw))
    if os.path.isdir(target):
        raise FileOperationError("target must be a file, not a directory")
    parent = os.path.dirname(target)
    if not allow_missing_parent and not os.path.isdir(parent):
        raise FileOperationError("target parent directory does not exist")
    if allow_missing_parent:
        probe = parent
        while probe and not os.path.lexists(probe):
            previous = probe
            probe = os.path.dirname(probe)
            if probe == previous:
                break
        if not probe or not os.path.isdir(probe) or os.path.islink(probe):
            raise FileOperationError(
                "target has no verified ordinary parent directory"
            )
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


def read_text_page(
    path: str,
    *,
    start_line: int = 1,
    start_byte: Optional[int] = None,
    limit: int = DEFAULT_READ_LINES,
    max_bytes: int = DEFAULT_READ_BYTES,
) -> dict:
    """Read one bounded, stable page from an exact UTF-8 text file."""
    if start_line < 1:
        raise FileOperationError("start line must be at least 1")
    if start_byte is not None and start_byte < 0:
        raise FileOperationError("start byte must be at least 0")
    if limit < 1:
        raise FileOperationError("line limit must be at least 1")
    if max_bytes < 1 or max_bytes > MAX_READ_OUTPUT_BYTES:
        raise FileOperationError(
            f"--max-bytes must be between 1 and {MAX_READ_OUTPUT_BYTES}; "
            f"usually omit it to use the {DEFAULT_READ_BYTES}-byte default",
            {
                "max_bytes": max_bytes,
                "default_bytes": DEFAULT_READ_BYTES,
                "maximum_bytes": MAX_READ_OUTPUT_BYTES,
            },
        )

    target = resolve_target(path)
    try:
        before = os.stat(target, follow_symlinks=False)
    except OSError as exc:
        raise FileOperationError(
            f"target could not be read: {exc}", {"path": target},
        ) from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise FileOperationError("target must be an ordinary local file")
    if profiles.is_placeholder(target, st=before):
        raise PlaceholderReadRefused(
            "file is a cloud-only placeholder; hydrate it before reading",
            {"path": target},
        )
    if int(before.st_size) > MAX_TEXT_BYTES:
        raise FileOperationError(
            f"file exceeds the {MAX_TEXT_BYTES // (1024 * 1024)} MB text limit"
        )

    try:
        with open(target, "rb") as handle:
            raw = handle.read(MAX_TEXT_BYTES + 1)
    except OSError as exc:
        raise FileOperationError(
            f"target could not be read: {exc}", {"path": target},
        ) from exc
    if len(raw) > MAX_TEXT_BYTES:
        raise FileOperationError(
            f"file exceeds the {MAX_TEXT_BYTES // (1024 * 1024)} MB text limit"
        )
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError as exc:
        raise FileOperationError("target must be valid UTF-8 text") from exc

    try:
        after = os.stat(target, follow_symlinks=False)
    except OSError as exc:
        raise FileConflict(
            "CONFLICT: file changed while it was being read",
            {"path": target, "error": str(exc)},
        ) from exc
    identity_before = (
        int(getattr(before, "st_dev", 0)), int(getattr(before, "st_ino", 0)),
        int(before.st_size), int(before.st_mtime_ns),
    )
    identity_after = (
        int(getattr(after, "st_dev", 0)), int(getattr(after, "st_ino", 0)),
        int(after.st_size), int(after.st_mtime_ns),
    )
    if identity_before != identity_after:
        raise FileConflict(
            "CONFLICT: file changed while it was being read", {"path": target},
        )

    decoded = text.encode("utf-8")
    lines = text.splitlines(keepends=True)
    encoded_lines = [line.encode("utf-8") for line in lines]
    line_offsets = [0]
    for encoded_line in encoded_lines:
        line_offsets.append(line_offsets[-1] + len(encoded_line))
    line_count = len(lines)
    if start_line > line_count + 1:
        raise FileOperationError(
            "start line is beyond the end of the file",
            {"path": target, "start_line": start_line,
             "line_count": line_count},
        )

    if start_byte is not None:
        if start_byte > len(decoded):
            raise FileOperationError(
                "start byte is beyond the end of the decoded UTF-8 file",
                {"path": target, "start_byte": start_byte,
                 "decoded_utf8_bytes": len(decoded)},
            )
        try:
            decoded[:start_byte].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FileOperationError(
                "start byte must be a UTF-8 character boundary; use the exact "
                "next_start_byte returned by the previous read",
                {"path": target, "start_byte": start_byte},
            ) from exc

        if start_byte == len(decoded):
            index = line_count
        else:
            index = bisect.bisect_right(line_offsets, start_byte) - 1
        line_number = index + 1
        line_end = line_offsets[index + 1] if index < line_count else start_byte
        remaining = decoded[start_byte:line_end]
        candidate = remaining[:max_bytes]
        content = candidate.decode("utf-8", errors="ignore")
        chunk = content.encode("utf-8")
        if remaining and not chunk:
            first_character_bytes = len(remaining.decode("utf-8")[0].encode("utf-8"))
            raise FileOperationError(
                "the output budget is smaller than the next UTF-8 character; use "
                f"--max-bytes {first_character_bytes} or omit the option",
                {"path": target, "start_byte": start_byte,
                 "minimum_next_bytes": first_character_bytes,
                 "default_bytes": DEFAULT_READ_BYTES,
                 "maximum_bytes": MAX_READ_OUTPUT_BYTES},
            )
        reached_line_end = len(chunk) == len(remaining)
        next_line = line_number + 1 if reached_line_end and index + 1 < line_count else None
        next_byte = None if reached_line_end else start_byte + len(chunk)
        complete = reached_line_end and index + 1 >= line_count
        return {
            "path": target,
            "content": content,
            "encoding": "utf-8",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "total_bytes": len(raw),
            "decoded_utf8_bytes": len(decoded),
            "returned_bytes": len(chunk),
            "max_bytes": max_bytes,
            "maximum_bytes": MAX_READ_OUTPUT_BYTES,
            "line_count": line_count,
            "start_line": line_number,
            "end_line": line_number if chunk else None,
            "start_byte": start_byte,
            "partial_line": not reached_line_end,
            "complete": complete,
            "stop_reason": None if complete else ("max_bytes" if next_byte is not None else "limit"),
            "next_start_line": next_line,
            "next_start_byte": next_byte,
            "byte_offset_basis": "decoded_utf8",
            "placeholder_detection": "checked",
        }

    index = start_line - 1
    selected = []
    returned_bytes = 0
    stop_reason = ""
    requested_end = min(line_count, index + limit)
    while index < requested_end:
        line = lines[index]
        encoded_size = len(line.encode("utf-8"))
        if returned_bytes + encoded_size > max_bytes:
            stop_reason = "max_bytes"
            break
        selected.append(line)
        returned_bytes += encoded_size
        index += 1
    if not selected and index < requested_end:
        line_bytes = encoded_lines[index]
        candidate = line_bytes[:max_bytes]
        content = candidate.decode("utf-8", errors="ignore")
        chunk = content.encode("utf-8")
        if not chunk:
            first_character_bytes = len(lines[index][0].encode("utf-8"))
            raise FileOperationError(
                "the output budget is smaller than the next UTF-8 character; use "
                f"--max-bytes {first_character_bytes} or omit the option",
                {"path": target, "line": index + 1,
                 "minimum_next_bytes": first_character_bytes,
                 "default_bytes": DEFAULT_READ_BYTES,
                 "maximum_bytes": MAX_READ_OUTPUT_BYTES},
            )
        return {
            "path": target,
            "content": content,
            "encoding": "utf-8",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "total_bytes": len(raw),
            "decoded_utf8_bytes": len(decoded),
            "returned_bytes": len(chunk),
            "max_bytes": max_bytes,
            "maximum_bytes": MAX_READ_OUTPUT_BYTES,
            "line_count": line_count,
            "start_line": index + 1,
            "end_line": index + 1,
            "start_byte": line_offsets[index],
            "partial_line": True,
            "complete": False,
            "stop_reason": "max_bytes",
            "next_start_line": None,
            "next_start_byte": line_offsets[index] + len(chunk),
            "byte_offset_basis": "decoded_utf8",
            "placeholder_detection": "checked",
        }
    if not stop_reason and index < line_count:
        stop_reason = "limit"
    complete = index >= line_count
    content = "".join(selected)
    end_line = start_line + len(selected) - 1 if selected else None
    return {
        "path": target,
        "content": content,
        "encoding": "utf-8",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "total_bytes": len(raw),
        "decoded_utf8_bytes": len(decoded),
        "returned_bytes": returned_bytes,
        "max_bytes": max_bytes,
        "maximum_bytes": MAX_READ_OUTPUT_BYTES,
        "line_count": line_count,
        "start_line": start_line,
        "end_line": end_line,
        "start_byte": None,
        "partial_line": False,
        "complete": complete,
        "stop_reason": stop_reason or None,
        "next_start_line": None if complete else index + 1,
        "next_start_byte": None,
        "byte_offset_basis": "decoded_utf8",
        "placeholder_detection": "checked",
    }


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
    allow_missing_output_parents: bool = False,
) -> dict:
    """Run a command after verified pre-images for every declared output."""
    if not command:
        raise FileOperationError("run requires a command after --")
    targets = [
        resolve_target(path, allow_missing_parent=allow_missing_output_parents)
        for path in outputs
    ]
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
    roots = _output_roots(output_roots or [])
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


def _output_roots(supplied: list[str]) -> list[str]:
    # Exact declarations are deliberately exact. Recursively observing their
    # parent directories is expensive in large/synced folders and conflates
    # unrelated application activity with command side effects. Root manifests
    # are therefore an explicit opt-in for dynamic sidecars, independent of
    # exact output locations.
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
