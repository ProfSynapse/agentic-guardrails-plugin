"""Atomic, recoverable operations for ordinary text files."""
from __future__ import annotations

import bisect
from contextlib import ExitStack
import difflib
import hashlib
import errno
import fnmatch
import json
import multiprocessing
import os
import re
import shutil
import stat
import tempfile
import time
import uuid
from typing import Callable, Optional

from core import engine, preimages, profiles, store
import execution
import path_safety
import retention_config


MAX_TEXT_BYTES = 32 * 1024 * 1024
DEFAULT_READ_LINES = 200
DEFAULT_READ_BYTES = 32 * 1024
MAX_READ_OUTPUT_BYTES = 256 * 1024
MAX_CAPTURE_BYTES = execution.MAX_CAPTURE_BYTES
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
    error_code = "file_conflict"


class PreimageHashConflict(FileConflict):
    error_code = "preimage_hash_conflict"


class PatchContextConflict(FileConflict):
    error_code = "patch_context_conflict"


class PatchHunkCountMismatch(FileConflict):
    error_code = "patch_hunk_count_mismatch"


class MalformedPatchHunk(FileOperationError):
    error_code = "malformed_patch_hunk"


class ReplaceMatchConflict(FileConflict):
    error_code = "replace_match_conflict"


class FileTransactionError(FileOperationError):
    error_code = "file_transaction_error"


class PublishBusy(FileOperationError):
    error_code = "publish_target_busy"


class PublishParentBindingInvalid(FileOperationError):
    error_code = "publish_parent_binding_invalid"


class PreparedRollForwardUnavailable(FileOperationError):
    error_code = "prepared_roll_forward_unavailable"


class PreparedRollbackUnavailable(FileOperationError):
    error_code = "prepared_rollback_unavailable"


class PreparedRecoveryBlocked(FileOperationError):
    error_code = "prepared_recovery_blocked"


class PreparedFinalizeNotAllAfter(FileOperationError):
    error_code = "prepared_finalize_not_all_after"


class PreparedFinalizeAfterRollbackStarted(FileOperationError):
    error_code = "prepared_finalize_after_rollback_started"


class UndeclaredOutput(FileOperationError):
    error_code = "undeclared_output"


class PlaceholderReadRefused(FileOperationError):
    error_code = "placeholder_read_refused"


class UnsafeTarget(FileOperationError):
    error_code = "unsafe_target"


def resolve_target(path: str, *, allow_missing_parent: bool = False) -> str:
    raw = str(path or "").strip()
    if not raw or "\x00" in raw:
        raise FileOperationError("target path is missing or invalid")
    if any(char in raw for char in "*?["):
        raise FileOperationError("target path must be literal, not a wildcard")
    target = path_safety.identify(raw).absolute
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
    state = os.stat(path, follow_symlinks=False)
    if profiles.is_placeholder(path, st=state):
        raise UnsafeTarget(
            "target is a cloud-only placeholder; hydrate it before mutation",
            {"path": path, "classification": "cloud_placeholder"},
        )
    if profiles.is_sync_artifact(path):
        raise UnsafeTarget(
            "sync lock/conflict artifacts are not valid mutation targets",
            {"path": path, "classification": "sync_artifact"},
        )
    return store.file_sha256(path)


def _check_expected(path: str, expected: str) -> Optional[str]:
    current = _current_hash(path)
    wanted = str(expected or "").strip().lower()
    if not wanted:
        return current
    if wanted in {"absent", "missing", "new"}:
        if current is not None:
            raise PreimageHashConflict("CONFLICT: target exists but absence was expected", {
                "path": path, "expected": "absent", "actual": current,
            })
        return current
    if not _HASH_RE.fullmatch(wanted):
        raise FileOperationError("expected hash must be a SHA-256 or 'absent'")
    if current is None or current.lower() != wanted:
        raise PreimageHashConflict("CONFLICT: file hash does not match expected version", {
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
        raise PreimageHashConflict(
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
        raise PreimageHashConflict(
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
    resolved_retention = retention_config.load(PLUGIN_ROOT)
    limit = max_file_bytes or int(os.environ.get(
        "AGW_PRESNAP_MAX_BYTES", 100 * 1024 * 1024
    ))
    result = preimages.prepare(
        targets, f"agw file {operation}", limit,
        policy_revision=policy.revision,
        retention_config=resolved_retention,
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
                raise PreimageHashConflict("CONFLICT: file changed while content was staged", {
                    "path": target, "expected": before or "absent",
                    "actual": _current_hash(target) or "absent",
                })
            receipt = _snapshot(target, operation, MAX_TEXT_BYTES)
            if _current_hash(target) != before:
                raise PreimageHashConflict("CONFLICT: file changed before publication")
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
                "recovery": receipt.to_dict(),
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
        raise PreimageHashConflict(
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
        raise ReplaceMatchConflict(
            "CONFLICT: old text was not found", {"matches": 0, "expected_matches": 1},
        )
    if count != 1 and not replace_all:
        raise ReplaceMatchConflict(
            "CONFLICT: old text is not unique; use --all after review",
            {"matches": count, "expected_matches": 1},
        )
    return original.replace(old, new) if replace_all else original.replace(old, new, 1)


def apply_unified_patch(original: str, patch: str) -> str:
    """Apply a single-file unified diff with exact context and no fuzz."""
    source = original.splitlines()
    lines = patch.splitlines()
    if not lines:
        raise FileOperationError("patch must contain a unified-diff hunk")
    expected_header = "@@ -OLD_START[,OLD_COUNT] +NEW_START[,NEW_COUNT] @@"
    hunk_headers = []
    for patch_line, line in enumerate(lines, start=1):
        if not line.startswith("@@"):
            continue
        if not _HUNK_RE.match(line):
            hint = (
                "bare '@@' apply_patch shorthand is not supported; include "
                "standard unified-diff line ranges"
                if line == "@@"
                else "include standard unified-diff line ranges"
            )
            raise MalformedPatchHunk(
                f"malformed unified-diff hunk header at patch line {patch_line}; "
                f"expected '{expected_header}'; {hint}",
                {
                    "patch_line": patch_line,
                    "header": line,
                    "expected_header": expected_header,
                    "hint": hint,
                },
            )
        hunk_headers.append((patch_line, line))
    if not hunk_headers:
        raise FileOperationError(
            "patch must contain a unified-diff hunk with a header like "
            f"'{expected_header}'"
        )
    if sum(line.startswith("--- ") for line in lines) > 1:
        raise FileOperationError("patch must describe exactly one file")
    result = []
    source_index = 0
    index = 0
    hunk_number = 0
    while index < len(lines):
        match = _HUNK_RE.match(lines[index])
        if not match:
            index += 1
            continue
        hunk_number += 1
        header = lines[index]
        header_patch_line = index + 1
        old_start = int(match.group(1))
        old_count = int(match.group(2) or 1)
        new_start = int(match.group(3))
        new_count = int(match.group(4) or 1)
        hunk_start = max(0, old_start - 1)
        if hunk_start < source_index or hunk_start > len(source):
            raise PatchContextConflict(
                "CONFLICT: patch hunk is out of range",
                {
                    "hunk": hunk_number,
                    "header": header,
                    "patch_line": header_patch_line,
                    "target_line": old_start,
                },
            )
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
                    raise PatchContextConflict(
                        "CONFLICT: patch context does not match target",
                        {
                            "hunk": hunk_number,
                            "header": header,
                            "patch_line": index + 1,
                            "target_line": source_index + 1,
                        },
                    )
                source_index += 1
                seen_old += 1
            if marker in {" ", "+"}:
                result.append(content)
                seen_new += 1
            index += 1
        if seen_old != old_count or seen_new != new_count:
            def hunk_range(start, count):
                return str(start) if count == 1 else f"{start},{count}"

            suffix_at = header.find("@@", 2)
            suffix = header[suffix_at + 2:] if suffix_at >= 0 else ""
            suggested = (
                f"@@ -{hunk_range(old_start, seen_old)} "
                f"+{hunk_range(new_start, seen_new)} @@{suffix}"
            )
            raise PatchHunkCountMismatch(
                "CONFLICT: patch hunk counts do not match its header",
                {
                    "hunk": hunk_number,
                    "header": header,
                    "patch_line": header_patch_line,
                    "expected": {
                        "old_lines": old_count,
                        "new_lines": new_count,
                    },
                    "observed": {
                        "old_lines": seen_old,
                        "new_lines": seen_new,
                    },
                    "suggested_header": suggested,
                },
            )
    result.extend(source[source_index:])
    newline = "\r\n" if "\r\n" in original else "\n"
    final_newline = newline if original.endswith(("\n", "\r")) else ""
    return newline.join(result) + final_newline


def _plan_path(value: str, working: str, label: str) -> str:
    raw = str(value or "").strip()
    if not raw or "\x00" in raw or any(char in raw for char in "*?["):
        raise FileOperationError(f"{label} must be a literal path")
    return os.path.abspath(os.path.join(working, os.path.expanduser(raw))) \
        if not os.path.isabs(os.path.expanduser(raw)) \
        else os.path.abspath(os.path.expanduser(raw))


def _plan_payload(item: dict, inline_key: str, file_key: str, working: str,
                  label: str) -> str:
    inline = item.get(inline_key)
    source = item.get(file_key)
    if (inline is None) == (source is None):
        raise FileOperationError(
            f"{label} requires exactly one of {inline_key} or {file_key}"
        )
    if inline is not None:
        if not isinstance(inline, str):
            raise FileOperationError(f"{inline_key} must be a string")
        text = inline
    else:
        text = read_utf8(_plan_path(source, working, file_key), label)
    if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
        raise FileOperationError(
            f"{label} exceeds the {MAX_TEXT_BYTES // (1024 * 1024)} MB text limit"
        )
    return text


def _text_shape(text: str, *, encoding: str = "utf-8") -> dict:
    crlf = text.count("\r\n")
    remaining = text.replace("\r\n", "")
    lf = remaining.count("\n")
    cr = remaining.count("\r")
    kinds = [name for name, count in (("crlf", crlf), ("lf", lf), ("cr", cr)) if count]
    newline = kinds[0] if len(kinds) == 1 else ("mixed" if kinds else "none")
    return {
        "encoding": encoding,
        "bytes": len(text.encode("utf-8")),
        "lines": len(text.splitlines()),
        "newline": newline,
        "final_newline": text.endswith(("\n", "\r")),
    }


def _target_text_encoding(path: str, existed: bool) -> str:
    if not existed:
        return "absent"
    try:
        with open(path, "rb") as handle:
            return "utf-8-sig" if handle.read(3) == b"\xef\xbb\xbf" else "utf-8"
    except OSError:
        return "utf-8"


def _line_changes(before: str, after: str) -> dict:
    old_lines = before.splitlines()
    new_lines = after.splitlines()
    inserted = deleted = replaced = 0
    for tag, old_start, old_end, new_start, new_end in difflib.SequenceMatcher(
            None, old_lines, new_lines, autojunk=False).get_opcodes():
        if tag == "insert":
            inserted += new_end - new_start
        elif tag == "delete":
            deleted += old_end - old_start
        elif tag == "replace":
            deleted += old_end - old_start
            inserted += new_end - new_start
            replaced += max(old_end - old_start, new_end - new_start)
    return {"inserted": inserted, "deleted": deleted, "replaced_span": replaced}


def _plan_review(path: str, before: str, after: str, *, existed: bool) -> dict:
    before_encoding = _target_text_encoding(path, existed)
    old_shape = _text_shape(before, encoding=before_encoding)
    if not existed:
        old_shape = {
            "encoding": "absent", "bytes": 0, "lines": 0,
            "newline": "none", "final_newline": False,
        }
    new_shape = _text_shape(after, encoding="utf-8")
    return {
        "before": old_shape,
        "after": new_shape,
        "line_changes": _line_changes(before, after),
        "encoding_changed": old_shape["encoding"] not in {"absent", new_shape["encoding"]},
        "newline_changed": (
            old_shape["newline"] != new_shape["newline"]
            or old_shape["final_newline"] != new_shape["final_newline"]
        ),
    }


def build_file_plan(spec: dict, *, cwd: str = "") -> dict:
    """Materialize exact text proposals without changing any target files."""
    if not isinstance(spec, dict) or spec.get("version", 1) != 1:
        raise FileOperationError("operations file must use version 1")
    supplied = spec.get("operations")
    if not isinstance(supplied, list) or not supplied:
        raise FileOperationError("operations file requires a non-empty operations list")
    working = os.path.abspath(os.path.expanduser(cwd or os.getcwd()))
    if not os.path.isdir(working):
        raise FileOperationError("plan working directory does not exist")
    planned = []
    identities = set()
    unicode_identities = {}
    for number, item in enumerate(supplied, 1):
        if not isinstance(item, dict):
            raise FileOperationError(
                "each planned operation must be a JSON object", {"operation": number},
            )
        kind = str(item.get("op") or "").strip().lower()
        if kind not in {"write", "patch", "replace"}:
            raise FileOperationError(
                "planned op must be write, patch, or replace", {"operation": number},
            )
        target = resolve_target(_plan_path(item.get("path"), working, "path"))
        path_identity = path_safety.identify(target)
        identity = path_identity.native_key
        if identity in identities:
            raise FileOperationError(
                "a transaction may target each file only once",
                {"operation": number, "path": target},
            )
        identities.add(identity)
        previous_unicode = unicode_identities.get(path_identity.unicode_key)
        if previous_unicode:
            raise FileOperationError(
                "transaction targets collide after Unicode normalization",
                {"operation": number, "paths": [previous_unicode, target],
                 "normalization": "NFC"},
            )
        unicode_identities[path_identity.unicode_key] = target
        before = _check_expected(target, str(item.get("expected_hash") or ""))
        original = read_utf8(target, "target") if before is not None else ""
        if kind == "write":
            updated = _plan_payload(
                item, "content", "content_file", working, "write content",
            )
        else:
            if before is None:
                raise FileOperationError(
                    f"planned {kind} requires an existing file",
                    {"operation": number, "path": target},
                )
            if kind == "patch":
                patch = _plan_payload(
                    item, "patch", "patch_file", working, "patch",
                )
                updated = apply_unified_patch(original, patch)
            else:
                old = _plan_payload(
                    item, "old", "old_file", working, "old text",
                )
                new = _plan_payload(
                    item, "new", "new_file", working, "new text",
                )
                updated = replace_text(
                    original, old, new, replace_all=bool(item.get("all", False)),
                )
        payload = updated.encode("utf-8")
        planned.append({
            "number": number,
            "op": kind,
            "path": target,
            "before_hash": before or "absent",
            "after_hash": hashlib.sha256(payload).hexdigest(),
            "changed": before != hashlib.sha256(payload).hexdigest(),
            "review": _plan_review(
                target, original, updated, existed=before is not None,
            ),
            "path_warnings": list(path_identity.warnings),
            "content": updated,
        })
    return {
        "schema": "agw-file-plan/v1",
        "cwd": working,
        "operations": planned,
    }


def create_file_plan(
    spec: dict,
    plan_path: str,
    *,
    cwd: str = "",
    expected_plan_hash: str = "absent",
) -> dict:
    """Write a self-contained, hashable proposal while leaving targets untouched."""
    plan = build_file_plan(spec, cwd=cwd)
    target = resolve_target(plan_path)
    target_identity = os.path.normcase(os.path.realpath(target))
    if target_identity in {
            os.path.normcase(os.path.realpath(item["path"]))
            for item in plan["operations"]}:
        raise FileOperationError("plan file must not also be a transaction target")
    serialized = json.dumps(
        plan, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ) + "\n"
    written = write_text(
        target, serialized, expected_hash=expected_plan_hash, operation="plan",
    )
    return {
        "operation": "plan",
        "plan_file": target,
        "plan_hash": written["after_hash"],
        "changed": written["changed"],
        "operations": [
            {key: item[key] for key in (
                "number", "op", "path", "before_hash", "after_hash", "changed",
                "review",
                "path_warnings",
            )}
            for item in plan["operations"]
        ],
        "targets_changed": sum(bool(item["changed"]) for item in plan["operations"]),
        "validation_scope": "content_and_target_versions",
    }


def _json_without_duplicates(text: str, label: str) -> dict:
    def collect(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=collect)
    except (json.JSONDecodeError, ValueError) as exc:
        raise FileOperationError(f"{label} is not valid unambiguous JSON: {exc}") from exc


def _publication_retry_seconds(path: str) -> float:
    profile = profiles.detect(os.path.dirname(path) or path)
    return 5.0 if profile.sync_provider else 0.0


def _restore_published(receipt, before: Optional[str], target: str):
    if before is None:
        if os.path.lexists(target):
            if not os.path.isfile(target) or os.path.islink(target):
                raise OSError("new target is no longer an ordinary file")
            os.unlink(target)
        return
    fd, stage = tempfile.mkstemp(
        prefix=".agw-rollback-", suffix=".tmp", dir=os.path.dirname(target),
    )
    os.close(fd)
    try:
        shutil.copy2(receipt.artifact, stage)
        if store.file_sha256(stage) != before:
            raise OSError("recovery artifact failed hash verification")
        replace_with_retry(stage, target, _publication_retry_seconds(target))
        stage = ""
    finally:
        if stage and os.path.exists(stage):
            os.unlink(stage)


def apply_file_plan(plan_path: str, *, expected_plan_hash: str) -> dict:
    """Apply every proposal under one lock; roll back the set on handled failure."""
    plan_target = resolve_target(plan_path)
    plan_digest = _check_expected(plan_target, expected_plan_hash)
    if not expected_plan_hash:
        raise FileOperationError("apply-plan requires --expected-plan-hash")
    plan_text = read_utf8(plan_target, "plan file")
    if hashlib.sha256(plan_text.encode("utf-8")).hexdigest() != plan_digest:
        raise PreimageHashConflict(
            "CONFLICT: plan file changed while it was being read",
            {"path": plan_target, "expected": plan_digest},
        )
    plan = _json_without_duplicates(plan_text, "plan file")
    if not isinstance(plan, dict) or plan.get("schema") != "agw-file-plan/v1":
        raise FileOperationError("unsupported or missing file-plan schema")
    supplied = plan.get("operations")
    if not isinstance(supplied, list) or not supplied:
        raise FileOperationError("plan contains no operations")
    operations = []
    identities = set()
    unicode_identities = set()
    total_bytes = 0
    for number, item in enumerate(supplied, 1):
        if not isinstance(item, dict) or item.get("number") != number:
            raise FileOperationError("plan operation numbering is invalid")
        target = str(item.get("path") or "")
        if not os.path.isabs(target) or resolve_target(target) != os.path.abspath(target):
            raise FileOperationError(
                "plan targets must be normalized absolute paths", {"operation": number},
            )
        path_identity = path_safety.identify(target)
        identity = path_identity.native_key
        if identity in identities or path_identity.unicode_key in unicode_identities:
            raise FileOperationError("plan contains duplicate or Unicode-ambiguous targets")
        identities.add(identity)
        unicode_identities.add(path_identity.unicode_key)
        before_label = str(item.get("before_hash") or "")
        if before_label != "absent" and not _HASH_RE.fullmatch(before_label):
            raise FileOperationError("plan contains an invalid before hash")
        content = item.get("content")
        if not isinstance(content, str):
            raise FileOperationError("plan content must be UTF-8 text")
        payload = content.encode("utf-8")
        total_bytes += len(payload)
        if len(payload) > MAX_TEXT_BYTES or total_bytes > MAX_TEXT_BYTES * 4:
            raise FileOperationError("plan exceeds the bounded transaction size")
        after = hashlib.sha256(payload).hexdigest()
        if after != item.get("after_hash"):
            raise FileOperationError(
                "plan content does not match its after hash", {"operation": number},
            )
        operations.append({
            "number": number, "op": str(item.get("op") or ""), "path": target,
            "before_label": before_label, "before": None if before_label == "absent" else before_label,
            "after": after, "payload": payload, "changed": before_label != after,
        })
        if operations[-1]["op"] not in {"write", "patch", "replace"}:
            raise FileOperationError(
                "plan contains an invalid operation", {"operation": number},
            )
    if os.path.normcase(os.path.realpath(plan_target)) in identities:
        raise FileOperationError("plan file must not also be a transaction target")
    stages = {}
    changed = [item for item in operations if item["changed"]]
    lock_identities = identities | {os.path.normcase(os.path.realpath(plan_target))}
    with ExitStack() as held_locks:
        for identity in sorted(lock_identities):
            lock_name = "file-" + hashlib.sha256(
                identity.encode("utf-8", "replace")
            ).hexdigest()[:32]
            held_locks.enter_context(store.Lock(lock_name, timeout=10.0))
        _check_expected(plan_target, expected_plan_hash)
        for item in operations:
            _check_expected(item["path"], item["before_label"])
        if not changed:
            return {
                "operation": "apply-plan", "plan_file": plan_target,
                "plan_hash": plan_digest, "changed": 0, "operations": [],
            }
        try:
            for item in changed:
                fd, stage = tempfile.mkstemp(
                    prefix=".agw-plan-", suffix=".tmp",
                    dir=os.path.dirname(item["path"]),
                )
                stages[item["number"]] = stage
                with os.fdopen(fd, "wb") as handle:
                    handle.write(item["payload"])
                    handle.flush()
                    os.fsync(handle.fileno())
                if store.file_sha256(stage) != item["after"]:
                    raise FileOperationError("staged transaction file failed verification")
            receipts = _snapshots(
                [item["path"] for item in changed], "apply-plan", MAX_TEXT_BYTES,
            )
            for item in operations:
                _check_expected(item["path"], item["before_label"])
            published = []
            try:
                for item, receipt in zip(changed, receipts):
                    stage = stages[item["number"]]
                    item["publish_attempts"] = replace_with_retry(
                        stage, item["path"],
                        _publication_retry_seconds(item["path"]),
                    )
                    stages[item["number"]] = ""
                    published.append((item, receipt))
                    if store.file_sha256(item["path"]) != item["after"]:
                        raise FileOperationError("published transaction file failed verification")
            except Exception as exc:
                rollback_errors = []
                for item, receipt in reversed(published):
                    try:
                        _restore_published(receipt, item["before"], item["path"])
                        if _current_hash(item["path"]) != item["before"]:
                            raise OSError("restored target failed verification")
                    except Exception as rollback_exc:
                        rollback_errors.append({
                            "path": item["path"], "error": str(rollback_exc),
                            "snapshot_transaction_id": receipt.transaction_id,
                        })
                raise FileTransactionError(
                    "file transaction failed; " + (
                        "recovery is required for one or more targets"
                        if rollback_errors else "all published changes were rolled back"
                    ),
                    {
                        "cause": str(exc),
                        "rolled_back": not rollback_errors,
                        "rollback_errors": rollback_errors,
                    },
                ) from exc
            transaction_id = uuid.uuid4().hex
            result_operations = []
            for item, receipt in zip(changed, receipts):
                result_operations.append({
                    "number": item["number"], "op": item["op"],
                    "path": item["path"], "before_hash": item["before_label"],
                    "after_hash": item["after"], "changed": 1,
                    "snapshot_transaction_id": receipt.transaction_id,
                    "snapshot_state": receipt.state,
                    "recovery": receipt.to_dict(transaction_id),
                    "publish_attempts": item.get("publish_attempts", 1),
                })
            store.oplog_append({
                "op": "file-transaction", "transaction_id": transaction_id,
                "plan_sha256": plan_digest, "operations": result_operations,
            })
            return {
                "operation": "apply-plan", "transaction_id": transaction_id,
                "plan_file": plan_target, "plan_hash": plan_digest,
                "changed": len(result_operations), "operations": result_operations,
            }
        finally:
            for stage in stages.values():
                if stage and os.path.exists(stage):
                    try:
                        os.unlink(stage)
                    except OSError:
                        pass


def run_declared(
    command: list[str],
    outputs: list[str],
    *,
    expected_hashes: Optional[list[str]] = None,
    cwd: str = "",
    dry_run: bool = False,
    output_roots: Optional[list[str]] = None,
    output_patterns: Optional[list[str]] = None,
    optional_outputs: Optional[list[bool]] = None,
    max_observed_files: int = 20_000,
    max_observed_depth: int = 8,
    allow_missing_output_parents: bool = False,
    timeout_seconds: float = execution.DEFAULT_TIMEOUT_SECONDS,
    isolation_mode: str = "observed",
    network_policy: str = "inherit",
    execution_provider=None,
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
    try:
        target_identities = path_safety.require_unique(
            targets, label="declared outputs"
        )
    except path_safety.PathSafetyError as exc:
        raise FileOperationError(str(exc), exc.details) from exc
    folded = [item.native_key for item in target_identities]
    expected_hashes = list(expected_hashes or [])
    if expected_hashes and len(expected_hashes) != len(targets):
        raise FileOperationError(
            "repeat --expected-hash once per --output, in the same order"
        )
    if not expected_hashes:
        expected_hashes = [""] * len(targets)
    optional_outputs = list(optional_outputs or [])
    if optional_outputs and len(optional_outputs) != len(targets):
        raise FileOperationError(
            "optional-output declarations must align with exact outputs"
        )
    if not optional_outputs:
        optional_outputs = [False] * len(targets)
    if any(not isinstance(value, bool) for value in optional_outputs):
        raise FileOperationError("optional-output declarations must be booleans")
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
            {"path": path, "before_hash": digest or "absent", "optional": optional}
            for path, digest, optional in zip(targets, before, optional_outputs)
        ]
        if dry_run:
            observation = _observe_requested_roots(
                roots, max_files=max_observed_files, max_depth=max_observed_depth,
            )
            return {
                "dry_run": True, "command": command, "cwd": working,
                "outputs": preview, "output_roots": roots,
                "output_patterns": patterns, "executed": False,
                "validation_scope": "contract_only",
                "execution_policy": {
                    "isolation_mode": isolation_mode,
                    "network_policy": network_policy,
                    "timeout_seconds": float(timeout_seconds),
                },
                "output_observation": {
                    "mode": "root_manifest" if roots else "exact_outputs",
                    "complete": True,
                    "files_observed": observation["count"],
                },
            }
        receipts = _snapshots(targets, "run")
        for path, digest in zip(targets, before):
            if _current_hash(path) != digest:
                raise PreimageHashConflict(
                    "CONFLICT: declared output changed before command execution",
                    {"path": path},
                )
        # Recovery preparation may create AGW_HOME beneath a test/work root.
        # Establish the execution baseline only after those declared pre-images
        # are durable so Guardrails' own metadata is not blamed on the command.
        before_observation = _observe_requested_roots(
            roots, max_files=max_observed_files, max_depth=max_observed_depth,
        )
        transaction_id = uuid.uuid4().hex
        prepared_operations = [
            {
                "path": path, "before_hash": old or "absent",
                "snapshot_transaction_id": receipt.transaction_id,
            }
            for path, old, receipt in zip(targets, before, receipts)
        ]
        store.oplog_append({
            "op": "file-transaction-prepared", "transaction_id": transaction_id,
            "operation": "declared-run", "command": command[0], "cwd": working,
            "state": "PREPARED", "operations": prepared_operations,
        })
        try:
            completed = execution.run(
                execution.ExecutionRequest(
                    command=list(command), cwd=working,
                    timeout_seconds=timeout_seconds,
                    isolation=execution.IsolationRequest(
                        mode=isolation_mode, network=network_policy,
                    ),
                ),
                provider=execution_provider,
            )
        except execution.ExecutionError as exc:
            store.oplog_append({
                "op": "file-transaction-state",
                "prepared_transaction_id": transaction_id,
                "state": "NOT_STARTED", "error": str(exc),
            })
            raise FileOperationError(str(exc), getattr(exc, "details", {})) from exc
        stdout = completed.stdout_tail
        stderr = completed.stderr_tail
        try:
            post_states = [_post_execution_state(path) for path in targets]
        except Exception as exc:
            store.oplog_append({
                "op": "file-transaction-state",
                "prepared_transaction_id": transaction_id,
                "state": "NEEDS_ATTENTION", "error": str(exc),
            })
            raise FileTransactionError(
                "post-execution target state could not be verified; prepared recovery is available",
                {"transaction_id": transaction_id, "cause": str(exc),
                 "undo_argv": ["agw", "undo", "--transaction", transaction_id]},
            ) from exc
        output_results = []
        missing_outputs = []
        unsupported_outputs = []
        transaction_operations = []
        for path, old, post_state, receipt, optional in zip(
                targets, before, post_states, receipts, optional_outputs):
            after_label = post_state.get("after_hash") or post_state["display_state"]
            # Optional means an output that was absent may remain absent. It
            # never makes deletion of a pre-existing output successful.
            if after_label == "absent" and (old is not None or not optional):
                missing_outputs.append(path)
            if post_state.get("after_identity"):
                unsupported_outputs.append(path)
            output_results.append({
                "path": path,
                "before_hash": old or "absent",
                "after_hash": after_label,
                "changed": (old or "absent") != after_label,
                "snapshot_transaction_id": receipt.transaction_id,
                "snapshot_state": receipt.state,
                "recovery": receipt.to_dict(transaction_id),
                "optional": optional,
            })
            operation = {
                "path": path, "before_hash": old or "absent",
                "after_hash": post_state["after_hash"],
                "snapshot_transaction_id": receipt.transaction_id,
            }
            if post_state.get("after_identity"):
                operation["after_identity"] = post_state["after_identity"]
            transaction_operations.append(operation)
        # Bind the receipts to an addressable transaction immediately after
        # process exit, before any broader observation that can time out or
        # fail. This record is the durable recovery handoff for every later
        # error path.
        store.oplog_append({
            "op": "file-transaction-state",
            "prepared_transaction_id": transaction_id,
            "operation": "declared-run", "command": command[0], "cwd": working,
            "exit_code": completed.exit_code, "state": "COMMITTED",
            "operations": transaction_operations,
        })
        if unsupported_outputs:
            raise FileTransactionError(
                "declared output became a non-file target; recovery is available",
                {"transaction_id": transaction_id, "outputs": unsupported_outputs,
                 "undo_argv": ["agw", "undo", "--transaction", transaction_id]},
            )
        try:
            after_observation = _observe_requested_roots(
                roots, max_files=max_observed_files, max_depth=max_observed_depth,
            )
            observed_changes = _observation_changes(
                before_observation, after_observation,
            )
        except Exception as exc:
            raise FileTransactionError(
                "post-execution observation failed; declared-output recovery is available",
                {"transaction_id": transaction_id, "cause": str(exc),
                 "undo_argv": ["agw", "undo", "--transaction", transaction_id]},
            ) from exc
        declared = {os.path.normcase(os.path.abspath(path)) for path in targets}
        undeclared, ignored_sidecar_changes = _partition_observed_changes(
            observed_changes, declared, roots, patterns,
        )
        unchanged_outputs = [
            output["path"] for output in output_results
            if not output["changed"]
        ]
        return {
            "ok": (completed.exit_code == 0 and not missing_outputs
                   and not undeclared and not completed.timed_out),
            "executed": True,
            "exit_code": completed.exit_code,
            "command": command,
            "cwd": working,
            "transaction_id": transaction_id,
            "outputs": output_results,
            "stdout_tail": stdout,
            "stderr_tail": stderr,
            "timed_out": completed.timed_out,
            "duration_seconds": completed.duration_seconds,
            "execution_policy": {
                "isolation_mode": completed.isolation_mode,
                "network_policy": completed.network_policy,
                "timeout_seconds": float(timeout_seconds),
            },
            "declared_outputs_missing": missing_outputs,
            # This is an exact declared-output state inventory. A required
            # output that was absent before and remains absent is both
            # unchanged and missing; callers should use the missing inventory
            # for contract evaluation.
            "unchanged_outputs": unchanged_outputs,
            "unclaimed_observed_changes": undeclared,
            # Compatibility alias retained for existing JSON consumers. A
            # before/after manifest cannot prove which process caused a change.
            "undeclared_outputs": undeclared,
            # Output patterns are intentional after-the-fact exclusions, not
            # isolation. Return every suppressed changed path and the exact
            # root/pattern that matched so consumers do not infer silence.
            "ignored_sidecar_changes": ignored_sidecar_changes,
            "output_roots": roots,
            "output_patterns": patterns,
            "output_observation": {
                "mode": "root_manifest" if roots else "exact_outputs",
                "complete": True,
                "files_before": before_observation["count"],
                "files_after": after_observation["count"],
                "changed_paths": len(observed_changes),
                "unclaimed_changes": len(undeclared),
                "ignored_changes": len(ignored_sidecar_changes),
            },
            "capture_truncated": completed.capture_truncated,
        }


def _post_execution_state(path: str) -> dict:
    """Capture a hash or exact lstat identity without following non-file targets."""
    if not os.path.lexists(path):
        return {"after_hash": "absent", "display_state": "absent"}
    st = os.lstat(path)
    if stat.S_ISREG(st.st_mode) and not os.path.islink(path):
        digest = store.file_sha256(path)
        return {"after_hash": digest, "display_state": digest}
    kind = (
        "symlink" if stat.S_ISLNK(st.st_mode) else
        "directory" if stat.S_ISDIR(st.st_mode) else "special"
    )
    return {
        "after_hash": "non-file",
        "display_state": f"unsupported:{kind}",
        "after_identity": store.path_identity(path),
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
    recovery_root = os.path.normcase(os.path.abspath(store.agw_home()))
    for root in roots:
        if _path_is_within(root, recovery_root):
            continue
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
                if _path_is_within(child.path, recovery_root):
                    continue
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


def _output_pattern_match(path: str, roots: list[str],
                          patterns: list[str]) -> Optional[dict]:
    """Return deterministic match evidence for an observed output change."""
    for root in roots:
        if not _path_is_within(path, root):
            continue
        relative = os.path.relpath(path, root).replace("\\", "/")
        for pattern in patterns:
            if fnmatch.fnmatchcase(relative, pattern):
                return {
                    "output_root": root,
                    "relative_path": relative,
                    "matched_pattern": pattern,
                }
    return None


def _partition_observed_changes(changes: list[dict], declared: set[str],
                                roots: list[str], patterns: list[str]
                                ) -> tuple[list[dict], list[dict]]:
    """Separate unclaimed changes from exact pattern-matched exclusions."""
    unclaimed = []
    ignored = []
    for change in changes:
        absolute = os.path.normcase(os.path.abspath(change["path"]))
        if absolute in declared:
            continue
        match = _output_pattern_match(change["path"], roots, patterns)
        if match is None:
            unclaimed.append(change)
        else:
            ignored.append({**change, **match})
    return unclaimed, ignored


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
    """Publish one stage through the recoverable-set implementation."""
    # Lazy import keeps the publication module free to reuse the established
    # file operation errors and recovery helpers without a module-load cycle.
    import publication

    plan = publication.build_publish_plan([{
        "stage": stage,
        "target": target,
        "expected_hash": expected_hash,
        "expected_stage_hash": expected_stage_hash,
        "validation": "raw",
    }])
    try:
        batch = publication.publish_staged_batch(
            plan,
            expected_plan_hash=plan["plan_sha256"],
            dry_run=dry_run,
            retry_seconds=retry_seconds,
        )
    except FileTransactionError as exc:
        # Preserve the established single-target busy error contract. The batch
        # journal still records the handled rollback before this is re-raised.
        if isinstance(exc.__cause__, PublishBusy):
            raise exc.__cause__
        raise
    item = batch["operations"][0] if batch["operations"] else {
        "path": resolve_target(target),
        "before_hash": _current_hash(resolve_target(target)),
        "after_hash": store.file_sha256(os.path.abspath(os.path.expanduser(stage))),
        "changed": 0,
    }
    # Historical publish-file callers create a same-directory disposable stage
    # and expect a successful publish to consume it. The batch primitive always
    # preserves supplied stages; retain this lifecycle detail only at the
    # compatibility boundary.
    original_stage = os.path.abspath(os.path.expanduser(stage))
    resolved_target = resolve_target(target)
    if not dry_run and item.get("changed") \
            and os.path.dirname(original_stage) == os.path.dirname(resolved_target) \
            and os.path.exists(original_stage):
        try:
            os.unlink(original_stage)
        except OSError:
            pass
    result = {
        "path": item["path"], "operation": operation,
        "changed": int(item.get("changed", 0)),
        "before_hash": item.get("before_hash") or "absent",
        "after_hash": item["after_hash"],
    }
    if dry_run:
        result["dry_run"] = True
    for key in (
        "snapshot_transaction_id", "snapshot_state", "recovery", "publish_attempts",
    ):
        if key in item:
            result[key] = item[key]
    if batch.get("transaction_id"):
        result["transaction_id"] = batch["transaction_id"]
    result["atomicity"] = batch["atomicity"]
    result["visibility"] = batch["visibility"]
    for key in (
        "process_outcome", "publication_outcome", "operation_outcome", "outcome",
        "outcome_known", "outcome_source",
    ):
        if key in batch:
            result[key] = batch[key]
    return result
