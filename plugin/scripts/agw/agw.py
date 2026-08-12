#!/usr/bin/env python3
"""agw - the agent workspace CLI. The safe-verb vocabulary that replaces raw
destructive primitives. Every verb is reversible by construction, dual-output
(human line + JSON via --json), and self-logging.

Verbs: init scan list search checkout convert diff publish publish-file publish-plan
       run-plan archive unlink-link move rename snapshot restore undo status log
       doctor prune office
"""
from __future__ import annotations

import argparse
import difflib
import json
import math
import os
import re
import sys
import time
import uuid

# Windows consoles default to a legacy code page (cp1252) that cannot encode
# non-ASCII output; force UTF-8 so the CLI never dies with a UnicodeEncodeError
# mid-operation (by print time it has often already mutated state - e.g. a
# checkout that succeeded then crashed on its result line).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))  # scripts/ -> core importable
PLUGIN_ROOT = os.environ.get("CLAUDE_PLUGIN_ROOT") or os.path.dirname(os.path.dirname(_HERE))

from core import agw_contract              # noqa: E402
from core import profiles as prof          # noqa: E402
from core import store                      # noqa: E402
from core import archive_transactions as archive_tx  # noqa: E402
from core import launcher                   # noqa: E402
from core import retention_policy           # noqa: E402
from core import workflows                  # noqa: E402
import converters                           # noqa: E402
import cli_schema                           # noqa: E402
import file_ops                             # noqa: E402
import office                               # noqa: E402
import office_tx                            # noqa: E402
import publication                          # noqa: E402
import retention_config                    # noqa: E402
import run_plans                            # noqa: E402
import scan_worker                          # noqa: E402

SNAPSHOT_MAX_BYTES = int(os.environ.get("AGW_SNAPSHOT_MAX_BYTES", 2 * 1024 ** 3))
_ROOT_CLI_PARSER = None
_JSON_ERRORS_ACTIVE = False


class _CompactArgumentParser(argparse.ArgumentParser):
    """Keep invalid nested-operation errors actionable and token efficient."""

    json_errors_enabled = False

    def error(self, message):
        if self.json_errors_enabled:
            payload = {
                "ok": False,
                "error": {
                    "code": "argument_error",
                    "message": str(message),
                    "details": {"command": self.prog},
                },
            }
            self.exit(
                2,
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n",
            )
        if (self.prog == "agw office"
                and "argument operation: invalid choice" in str(message)):
            self.exit(
                2,
                "agw: unknown Office operation; use `agw office --help`.\n",
            )
        super().error(message)


def _out(args, human: str, data: dict):
    if getattr(args, "json", False):
        print(json.dumps(data, ensure_ascii=False, default=str,
                         separators=(",", ":")))
    else:
        print(human)


def _err(message: str, code: int = 1, *, error_code: str = "cli_error",
         details: dict | None = None):
    if _JSON_ERRORS_ACTIVE:
        print(json.dumps({
            "ok": False,
            "error": {
                "code": error_code,
                "message": str(message),
                "details": details or {},
            },
        }, ensure_ascii=False, separators=(",", ":")), file=sys.stderr)
    else:
        print(f"agw: {message}", file=sys.stderr)
    sys.exit(code)


def _office_err(args, exc, default_code: int = 1):
    current = exc
    error_code = "office_error"
    details = {}
    while current is not None:
        error_code = getattr(current, "error_code", error_code)
        details = getattr(current, "details", details)
        current = getattr(current, "__cause__", None)
    message = str(exc)
    code = 3 if message.startswith("CONFLICT:") or "conflict" in error_code \
        else default_code
    if getattr(args, "json", False):
        print(json.dumps({
            "ok": False,
            "error": {"code": error_code, "message": message, "details": details},
        }, ensure_ascii=False, separators=(",", ":")), file=sys.stderr)
        raise SystemExit(code)
    _err(message, code=code)


def _file_err(args, exc, default_code: int = 1):
    error_code = getattr(exc, "error_code", "file_operation_error")
    details = getattr(exc, "details", {})
    message = str(exc)
    code = 3 if message.startswith("CONFLICT:") or "conflict" in error_code \
        else default_code
    if getattr(args, "json", False):
        print(json.dumps({
            "ok": False,
            "error": {"code": error_code, "message": message, "details": details},
        }, ensure_ascii=False, separators=(",", ":")), file=sys.stderr)
        raise SystemExit(code)
    _err(message, code=code)


def _json_object_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json_stdin(label: str) -> str:
    limit = 1024 * 1024
    binary = getattr(sys.stdin, "buffer", None)
    if binary is None:  # primarily useful for embedded/test StringIO streams
        raw = sys.stdin.read(limit + 1)
        if len(raw.encode("utf-8")) > limit:
            _err(f"{label}: stdin payload exceeds 1 MiB")
        return raw.lstrip("\ufeff")

    payload = binary.read(limit + 5)
    if len(payload) > limit:
        _err(f"{label}: stdin payload exceeds 1 MiB")
    try:
        if payload.startswith((b"\xff\xfe", b"\xfe\xff")):
            return payload.decode("utf-16")
        return payload.decode("utf-8-sig")
    except UnicodeDecodeError:
        _err(f"{label}: stdin payload must be UTF-8 or BOM-marked UTF-16 JSON")


def _load_json_payload(inline: str, file_path: str, label: str, expected):
    if inline and file_path:
        _err(f"{label}: inline and file payloads are mutually exclusive")
    if file_path:
        resolved = _resolve(file_path)
        if os.path.getsize(resolved) > 1024 * 1024:
            _err(f"{label}: payload file exceeds 1 MiB")
        with open(resolved, encoding="utf-8") as handle:
            raw = handle.read()
    elif inline == "-":
        raw = _read_json_stdin(label)
    else:
        raw = inline
        if len(raw.encode("utf-8")) > 6 * 1024:
            _err(f"{label}: inline payload exceeds 6 KiB; use a payload file")
    if raw.startswith("\ufeff"):
        raw = raw[1:]
    if not raw:
        _err(f"{label}: payload is required")
    try:
        value = json.loads(
            raw, object_pairs_hook=_json_object_no_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {token}")
            ),
        )
    except (json.JSONDecodeError, ValueError) as exc:
        _err(f"{label}: invalid JSON ({exc})")
    if expected is not None and not isinstance(value, expected):
        kind = "object" if expected is dict else "array"
        _err(f"{label}: payload must be a JSON {kind}")
    def count_nodes(item, depth=0):
        if depth > 16:
            raise ValueError("JSON nesting exceeds 16 levels")
        if isinstance(item, dict):
            return 1 + sum(count_nodes(v, depth + 1) for v in item.values())
        if isinstance(item, list):
            return 1 + sum(count_nodes(v, depth + 1) for v in item)
        return 1
    try:
        if count_nodes(value) > 100000:
            _err(f"{label}: payload exceeds 100000 JSON nodes")
    except ValueError as exc:
        _err(f"{label}: {exc}")
    return value


def _write_plan_file(plan: dict, path: str, expected_file_hash: str,
                     operation: str) -> dict:
    """Publish an inert plan through the ordinary recoverable file boundary."""
    serialized = json.dumps(
        plan, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ) + "\n"
    written = file_ops.write_text(
        path, serialized, expected_hash=expected_file_hash,
        operation=operation,
    )
    return {
        **plan,
        "plan_file": written["path"],
        "plan_file_sha256": written["after_hash"],
        "plan_file_changed": written["changed"],
        "plan_file_recovery": written.get("recovery", {}),
    }


def _plan_error(args, exc):
    error_code = getattr(exc, "error_code", "plan_error")
    details = dict(getattr(exc, "details", {}) or {})
    if "conflict" in error_code or error_code in {
            "run_plan_consumed", "run_plan_expired"}:
        details.setdefault("precondition_outcome", "stale")
    code = 3 if "precondition_outcome" in details else 1
    if getattr(args, "json", False):
        print(json.dumps({
            "ok": False,
            "error": {
                "code": error_code, "message": str(exc), "details": details,
            },
        }, ensure_ascii=False, separators=(",", ":")), file=sys.stderr)
        raise SystemExit(code)
    _err(str(exc), code=code, error_code=error_code, details=details)


def _resolve(path: str) -> str:
    p = os.path.abspath(os.path.expanduser(path))
    if not os.path.exists(p):
        _err(f"path not found: {p}")
    return p


def _read_text_payload(path: str, label: str) -> str:
    if path != "-":
        return file_ops.read_utf8(path, label)
    binary = getattr(sys.stdin, "buffer", None)
    if binary is None:
        value = sys.stdin.read(file_ops.MAX_TEXT_BYTES + 1)
        if len(value.encode("utf-8")) > file_ops.MAX_TEXT_BYTES:
            _err(f"{label}: stdin exceeds the text payload limit")
        return value.lstrip("\ufeff")
    payload = binary.read(file_ops.MAX_TEXT_BYTES + 1)
    if len(payload) > file_ops.MAX_TEXT_BYTES:
        _err(f"{label}: stdin exceeds the text payload limit")
    try:
        return payload.decode("utf-8-sig")
    except UnicodeDecodeError:
        _err(f"{label}: stdin must be UTF-8 text")


def _require_archive_store():
    if not store.archive_store_writable():
        _err(
            "Guardrails cannot write a recovery copy from this sandbox. "
            "The original file was not moved or changed. Ask the agent to retry "
            "the same Guardrails operation using the host's normal approval. "
            "Do not change folder permissions or security settings."
        )


# --- verbs -------------------------------------------------------------------

def cmd_init(args):
    folder = _resolve(args.path)
    ws = os.path.join(folder, "_workspace")
    os.makedirs(ws, exist_ok=True)
    profile = prof.detect(folder)
    _out(args, f"initialized workspace in {folder} (profile: {profile.name})",
         {"folder": folder, "workspace": ws, "profile": profile.name})


def cmd_scan(args):
    started_at = time.monotonic()
    deep, max_seconds, max_files, max_entries, max_depth = \
        _resolve_discovery_bounds(args, "scan")
    no_size = bool(args.no_size or not deep)
    request = {
        "path": args.path,
        "started_at": started_at,
        "max_seconds": float(max_seconds),
        "max_files": int(max_files),
        "max_entries": int(max_entries),
        "max_depth": int(max_depth),
        "no_size": no_size,
        "profile_override": getattr(args, "profile", "auto"),
    }
    stats, fatal = scan_worker.run_bounded_scan(request)
    stats.pop("_worker_pid", None)
    if fatal:
        if args.json:
            print(json.dumps({"ok": False, "error": fatal}, ensure_ascii=False,
                             separators=(",", ":")), file=sys.stderr)
            raise SystemExit(2)
        _err(fatal["message"], code=2)

    folder = stats["path"]
    size_label = "size skipped" if no_size else f"{stats['bytes'] / 1e6:.1f} MB"
    human = (f"{folder} [{stats['profile']}]: {stats['files']} files, "
             f"{size_label}; "
             f"placeholders: {len(stats['placeholders'])}, "
             f"gdoc stubs: {len(stats['gdoc_stubs'])}, "
             f"sync artifacts: {len(stats['sync_artifacts'])}")
    if not stats["complete"]:
        human += f"; partial: {stats['stop_reason']}"
    if stats["placeholders"]:
        human += "\n  cloud-only (do NOT edit before hydrating): " + \
                 ", ".join(stats["placeholders"][:10])
    if stats["gdoc_stubs"]:
        human += "\n  google-docs stubs (no local content): " + \
                 ", ".join(stats["gdoc_stubs"][:10])
    _out(args, human, stats)


def _validate_discovery_bounds(operation: str, *, max_seconds: float,
                               max_files: int, max_entries: int,
                               max_depth: int, max_matches: int = 1,
                               max_file_bytes: int = 1) -> None:
    if not math.isfinite(max_seconds):
        _err(f"{operation} requires --max-seconds to be finite")
    values = {
        "max-seconds": (max_seconds, 0, scan_worker.HARD_MAX_SECONDS),
        "max-files": (max_files, 0, scan_worker.HARD_MAX_FILES),
        "max-entries": (max_entries, 0, scan_worker.HARD_MAX_ENTRIES),
        "max-depth": (max_depth, -1, scan_worker.HARD_MAX_DEPTH),
        "max-matches": (max_matches, 0, scan_worker.HARD_MAX_MATCHES),
        "max-file-bytes": (max_file_bytes, 0, scan_worker.HARD_MAX_FILE_BYTES),
    }
    for label, (value, minimum, maximum) in values.items():
        if value <= minimum:
            comparator = ">= 0" if label == "max-depth" else "> 0"
            _err(f"{operation} requires --{label} {comparator}")
        if value > maximum:
            _err(f"{operation} --{label} exceeds the hard ceiling of {maximum}")


def _resolve_discovery_bounds(args, operation: str):
    if args.fast and args.deep:
        _err(f"{operation} accepts either --fast or --deep, not both")
    deep = bool(args.deep)
    max_seconds = args.max_seconds if args.max_seconds is not None \
        else (scan_worker.DEEP_MAX_SECONDS if deep
              else scan_worker.BOUNDED_MAX_SECONDS)
    max_files = args.max_files if args.max_files is not None \
        else (scan_worker.DEEP_MAX_FILES if deep
              else scan_worker.BOUNDED_MAX_FILES)
    max_entries = args.max_entries if args.max_entries is not None \
        else (scan_worker.DEEP_MAX_ENTRIES if deep
              else scan_worker.BOUNDED_MAX_ENTRIES)
    max_depth = args.max_depth if args.max_depth is not None \
        else (scan_worker.DEEP_MAX_DEPTH if deep
              else scan_worker.BOUNDED_MAX_DEPTH)
    _validate_discovery_bounds(
        operation, max_seconds=max_seconds, max_files=max_files,
        max_entries=max_entries, max_depth=max_depth,
    )
    return deep, max_seconds, max_files, max_entries, max_depth


def cmd_search(args):
    if not args.query:
        _err("search query must not be empty")
    if args.regex:
        try:
            re.compile(args.query, re.IGNORECASE if args.ignore_case else 0)
        except re.error as exc:
            _err(f"invalid search pattern: {exc}", code=2)

    _deep, max_seconds, max_files, max_entries, max_depth = \
        _resolve_discovery_bounds(args, "search")
    max_matches = args.max_matches if args.max_matches is not None \
        else scan_worker.DEFAULT_MAX_MATCHES
    max_file_bytes = args.max_file_bytes if args.max_file_bytes is not None \
        else scan_worker.DEFAULT_MAX_FILE_BYTES
    _validate_discovery_bounds(
        "search", max_seconds=max_seconds, max_files=max_files,
        max_entries=max_entries, max_depth=max_depth,
        max_matches=max_matches, max_file_bytes=max_file_bytes,
    )

    started_at = time.monotonic()
    request = {
        "operation": "search",
        "path": args.path,
        "query": args.query,
        "regex": bool(args.regex),
        "ignore_case": bool(args.ignore_case),
        "filename_only": bool(args.files),
        "include_globs": list(args.include or []),
        "exclude_globs": list(args.exclude or []),
        "kind": "file",
        "started_at": started_at,
        "max_seconds": float(max_seconds),
        "max_files": int(max_files),
        "max_entries": int(max_entries),
        "max_depth": int(max_depth),
        "max_matches": int(max_matches),
        "max_file_bytes": int(max_file_bytes),
        "profile_override": getattr(args, "profile", "auto"),
    }
    result, fatal = scan_worker.run_bounded_search(request)
    result.pop("_worker_pid", None)
    if fatal:
        if args.json:
            print(json.dumps({"ok": False, "error": fatal}, ensure_ascii=False,
                             separators=(",", ":")), file=sys.stderr)
            raise SystemExit(2)
        _err(fatal["message"], code=2)

    if result["filename_only"]:
        human = (f"{result['path']}: {result['matches_found']} matching "
                 f"filename(s)")
    else:
        human = (
            f"{result['path']}: {result['matches_found']} match(es) in "
            f"{result['files_searched']} searched file(s)"
        )
    if not result["complete"]:
        human += f"; partial: {result['stop_reason']}"
    for item in result["matches"][:20]:
        if result["filename_only"]:
            human += f"\n  {item['path']}"
        else:
            human += (f"\n  {item['path']}:{item['line']}:{item['column']} "
                      f"{item['preview']}")
    if len(result["matches"]) > 20:
        human += (f"\n  … {len(result['matches']) - 20} more; rerun with --json "
                  "to return all bounded matches")
    _out(args, human, result)


def cmd_list(args):
    _deep, max_seconds, max_files, max_entries, max_depth = \
        _resolve_discovery_bounds(args, "list")
    max_results = args.max_results if args.max_results is not None \
        else scan_worker.DEFAULT_MAX_RESULTS
    _validate_discovery_bounds(
        "list", max_seconds=max_seconds, max_files=max_files,
        max_entries=max_entries, max_depth=max_depth,
        max_matches=max_results,
    )
    started_at = time.monotonic()
    request = {
        "operation": "list",
        "path": args.path,
        "query": args.name,
        "regex": False,
        "glob_query": True,
        "ignore_case": os.name == "nt",
        "filename_only": True,
        "include_globs": [],
        "exclude_globs": list(args.exclude or []),
        "kind": args.kind,
        "started_at": started_at,
        "max_seconds": float(max_seconds),
        "max_files": int(max_files),
        "max_entries": int(max_entries),
        "max_depth": int(max_depth),
        "max_matches": int(max_results),
        "max_file_bytes": 1,
        "profile_override": getattr(args, "profile", "auto"),
    }
    result, fatal = scan_worker.run_bounded_list(request)
    result.pop("_worker_pid", None)
    if fatal:
        if args.json:
            print(json.dumps({"ok": False, "error": fatal}, ensure_ascii=False,
                             separators=(",", ":")), file=sys.stderr)
            raise SystemExit(2)
        _err(fatal["message"], code=2)

    entries = result.pop("matches")
    result["entries"] = entries
    result["returned"] = result.pop("matches_found")
    result["bounds"]["max_results"] = result["bounds"].pop("max_matches")
    if result["stop_reason"] == "max_matches":
        result["stop_reason"] = "max_results"
    human = f"{result['path']}: {result['returned']} bounded path result(s)"
    if not result["complete"]:
        human += f"; partial: {result['stop_reason']}"
    for item in entries[:50]:
        suffix = "/" if item["kind"] == "directory" else ""
        human += f"\n  {item['path']}{suffix}"
    if len(entries) > 50:
        human += (f"\n  … {len(entries) - 50} more; rerun with --json to "
                  "return all bounded results")
    _out(args, human, result)


def cmd_checkout(args):
    control_target = str(getattr(args, "control_target", "") or "")
    if args.path == "close":
        if not control_target:
            _err("checkout close requires the original source path")
        args.path = control_target
        return cmd_checkout_close(args)
    if args.path == "reopen":
        if not control_target:
            _err("checkout reopen requires a checkout-close transaction id")
        args.transaction_id = control_target
        return cmd_checkout_reopen(args)
    if control_target:
        _err("checkout takes one file; use `agw checkout close PATH` to close tracking")
    src = _resolve(args.path)
    if not os.path.isfile(src):
        _err("checkout takes a single file")
    if prof.is_gdoc_stub(src):
        _err("this is a Google Docs pointer stub with no local content - export it "
             "through a Google Drive/Docs connector instead")
    if prof.is_placeholder(src):
        _err("file is a cloud-only placeholder - hydrate it first ('Always keep on "
             "this device' / 'Available offline')")
    folder = os.path.dirname(src)
    ext = os.path.splitext(src)[1].lower()
    preserve_office = args.mode == "preserve" or (
        args.mode == "auto" and ext in {".xlsx", ".xlsm"}
    )
    if args.workspace_dir:
        ws = os.path.abspath(os.path.expanduser(args.workspace_dir))
    elif preserve_office:
        workspace_root = os.path.abspath(os.path.expanduser(
            os.environ.get("AGW_WORKSPACE_HOME")
            or os.path.join(store.agw_home(), "workspaces")
        ))
        stem = "".join(
            char if char.isalnum() or char in "-_" else "_"
            for char in os.path.splitext(os.path.basename(src))[0]
        )[:48] or "office"
        ws = os.path.join(
            workspace_root,
            f"{stem}-{office_tx._target_id(src)[:12]}",
        )
    else:
        ws = os.path.join(folder, "_workspace")
    result = converters.to_open_format(src, ws, mode=args.mode)
    state = store.state_load()
    created_at_ns = time.time_ns()
    state["checkouts"][src] = {
        "working": result["dest"], "workings": result.get("dests", [result["dest"]]),
        "base_sha256": store.file_sha256(src), "mode": result["mode"],
        "checkout_mode": result.get("checkout_mode", "data"),
        "workspace": ws,
        "created_at_ns": created_at_ns,
        "last_activity_at_ns": created_at_ns,
    }
    store.state_save(state)
    store.oplog_append({"op": "checkout", "src": src, "working": result["dest"]})
    note = " (style-preserving working copy)" \
        if result.get("checkout_mode") == "preserve" else \
        (" (lossy data checkout)" if result.get("lossy") else "")
    _out(args, f"checked out -> {result['dest']}{note}",
         {"src": src, "workspace": ws, **result})


def cmd_checkout_close(args):
    src = os.path.abspath(os.path.expanduser(args.path))
    state = store.state_load()
    entry = state.get("checkouts", {}).get(src)
    if not entry:
        _err(f"no checkout registered for {src}")
    working = str(entry.get("working") or "")
    working_hash = store.file_sha256(working) if os.path.isfile(working) else "absent"
    expected = str(args.expected_working_hash or "").strip().lower()
    if expected and expected != working_hash.lower():
        _file_err(args, file_ops.PreimageHashConflict(
            "CONFLICT: working-copy hash does not match expected version",
            {"path": working, "expected": expected, "actual": working_hash},
        ))
    transaction_id = uuid.uuid4().hex
    del state["checkouts"][src]
    store.state_save(state)
    store.oplog_append({
        "op": "checkout-close", "transaction_id": transaction_id,
        "src": src, "working": working, "working_sha256": working_hash,
        "checkout_entry": entry, "closed_at_ns": time.time_ns(),
    })
    data = {
        "transaction_id": transaction_id,
        "src": src,
        "working": working,
        "working_preserved": os.path.lexists(working),
        "working_hash": working_hash,
        "undo_argv": ["agw", "checkout", "reopen", transaction_id],
    }
    _out(args, f"closed checkout registry entry for {src}; working copy preserved", data)


def cmd_checkout_reopen(args):
    transaction_id = str(args.transaction_id or "").strip()
    closed = None
    operations = store.oplog_read()
    if any(
            operation.get("op") == "checkout-reopen"
            and operation.get("reopened_transaction_id") == transaction_id
            for operation in operations):
        _err("checkout close transaction was already reopened")
    for operation in reversed(operations):
        if operation.get("op") == "checkout-close" \
                and operation.get("transaction_id") == transaction_id:
            closed = operation
            break
    if not closed:
        _err("checkout close transaction was not found")
    src = str(closed.get("src") or "")
    entry = closed.get("checkout_entry")
    if not src or not isinstance(entry, dict):
        _err("checkout close transaction is incomplete")
    state = store.state_load()
    if src in state.get("checkouts", {}):
        _err("CONFLICT: a checkout is already registered for this source", code=3)
    state.setdefault("checkouts", {})[src] = entry
    entry["last_activity_at_ns"] = time.time_ns()
    store.state_save(state)
    store.oplog_append({
        "op": "checkout-reopen", "transaction_id": uuid.uuid4().hex,
        "reopened_transaction_id": transaction_id, "src": src,
    })
    data = {
        "reopened_transaction_id": transaction_id,
        "src": src,
        "working": entry.get("working", ""),
        "source_exists": os.path.isfile(src),
        "working_exists": os.path.isfile(str(entry.get("working") or "")),
    }
    _out(args, f"reopened checkout registry entry for {src}", data)


def cmd_convert(args):
    src = _resolve(args.path)
    dest_dir = args.dest or os.path.join(os.path.dirname(src), "_workspace")
    result = converters.to_open_format(src, dest_dir)
    _out(args, f"converted -> {result['dest']} ({result['mode']})", result)


def cmd_diff(args):
    src = _resolve(args.path)
    state = store.state_load()
    entry = state["checkouts"].get(src)
    if not entry:
        _err(f"no checkout registered for {src}")
    working = entry["working"]
    live_hash = store.file_sha256(src)
    drifted = live_hash != entry["base_sha256"]
    if entry.get("checkout_mode") == "preserve":
        working_hash = store.file_sha256(working)
        changed = working_hash != entry["base_sha256"]
        diff = "(working workbook changed)" if changed else ""
        data = {
            "src": src, "working": working, "drifted": drifted,
            "changed": changed, "base_hash": entry["base_sha256"],
            "working_hash": working_hash, "diff": diff,
            "checkout_mode": "preserve",
        }
        human = diff or "(no changes in style-preserving working copy)"
        if drifted:
            human = "WARNING: live file changed since checkout!\n" + human
        _out(args, human, data)
        return
    try:
        with open(working, encoding="utf-8", errors="replace") as f:
            work_lines = f.readlines()
        base_lines = []
        if working.endswith(".md") or entry["mode"] == "copy":
            tmp = converters.to_open_format(src, os.path.join(store.agw_home(), "tmp"))
            with open(tmp["dest"], encoding="utf-8", errors="replace") as f:
                base_lines = f.readlines()
        diff = "".join(difflib.unified_diff(base_lines, work_lines,
                                            "live(converted)", "working", n=2))
    except Exception as exc:
        diff = f"(diff unavailable: {exc})"
    human = diff or "(no changes in working copy)"
    if drifted:
        human = "WARNING: live file changed since checkout!\n" + human
    _out(args, human, {"src": src, "drifted": drifted, "diff": diff})


def cmd_publish(args):
    src = os.path.abspath(os.path.expanduser(args.path))
    state = store.state_load()
    entry = state["checkouts"].get(src)
    if not entry:
        _err(f"no checkout registered for {src} - use `agw checkout` first")
    working = entry["working"]
    if not os.path.exists(working):
        _err(f"working copy missing: {working}")
    live_hash = None
    if os.path.exists(src):
        live_hash = store.file_sha256(src)
        if live_hash != entry["base_sha256"] and not args.force:
            _err("CONFLICT: the live file changed since checkout (someone else edited "
                 "it?). Review with `agw diff`, then publish --force to overwrite, or "
                 "re-checkout.", code=3)
    profile = prof.detect(os.path.dirname(src))
    import tempfile as _tempfile
    fd, tmp_out = _tempfile.mkstemp(
        prefix=".agw-publishing-", suffix=os.path.splitext(src)[1],
        dir=os.path.dirname(src),
    )
    os.close(fd)
    result = converters.to_original_format(working, src, tmp_out)
    try:
        office_validation = None
        extension = os.path.splitext(src)[1].lower()
        if extension in {".docx", ".pptx", ".xlsx", ".xlsm"}:
            package_validation = _validate_office_stage(tmp_out, extension)
            office_validation = package_validation
        if extension == ".xlsm":
            preservation = office_tx.validate_package_preservation(
                src, tmp_out, expected_original_sha256=live_hash or ""
            )
            office_validation = {
                **preservation, "package_validation": package_validation,
            }
        published = file_ops.publish_staged_file(
            src, tmp_out, expected_hash=live_hash or "absent",
            operation="checkout-publish", retry_seconds=args.retry_seconds,
        )
        if not published.get("changed") and os.path.exists(tmp_out):
            os.unlink(tmp_out)
    except office_tx.TransactionError as exc:
        _office_err(args, exc)
    except (OSError, file_ops.FileOperationError) as exc:
        _file_err(args, exc)
    entry["base_sha256"] = store.file_sha256(src)
    entry["last_activity_at_ns"] = time.time_ns()
    store.state_save(state)
    store.oplog_append({"op": "publish", "src": src, "working": working,
                        "conversion": result["mode"]})
    note = "" if result["mode"] == "converted" else " (copy mode - no format conversion)"
    versioning = f"; upstream: {profile.upstream_versioning}" if \
        profile.upstream_versioning else ""
    _out(args, f"published {src}{note} - previous version archived"
               f" (restore with `agw restore {os.path.basename(src)}`){versioning}",
         {"src": src, "conversion": result["mode"],
          "checkout_mode": entry.get("checkout_mode", "data"),
          "office_validation": office_validation,
          "publication": published})


def cmd_archive(args):
    paths = [_resolve(path) for path in args.paths]
    _require_archive_store()
    results = []
    try:
        resolved_retention = retention_config.load(PLUGIN_ROOT)
        for p in paths:
            entry = store.archive_file(
                p, mode="move", reason=args.reason or "agw archive", actor="agw",
                retention_class="safety_archive",
                retention_config=resolved_retention,
            )
            results.append(entry)
            if not getattr(args, "json", False):
                print(f"archived {p} -> {entry['dest']}")
    except Exception as exc:
        _file_err(args, exc, default_code=4)
    if getattr(args, "json", False):
        print(json.dumps(results, ensure_ascii=False, default=str,
                         separators=(",", ":")))


def cmd_unlink_link(args):
    path = os.path.abspath(os.path.expanduser(args.path))
    try:
        metadata = archive_tx.link_metadata(path)
    except (FileNotFoundError, OSError) as exc:
        _file_err(args, file_ops.FileOperationError(
            f"link could not be inspected without following its target: {exc}"
        ))
    if metadata is None:
        _file_err(args, file_ops.FileOperationError(
            "unlink-link requires a symbolic link or Windows junction; ordinary "
            "files and directories are refused"
        ))
    expected = str(args.expected_target or "")
    if expected:
        def normalize(value):
            value = str(value)
            if value.startswith("\\\\?\\UNC\\"):
                value = "\\\\" + value[8:]
            elif value.startswith("\\\\?\\"):
                value = value[4:]
            elif value.startswith("\\??\\"):
                value = value[4:]
            return os.path.normcase(os.path.normpath(value))
        if normalize(metadata["target"]) != normalize(expected):
            _file_err(args, file_ops.FileConflict(
                "CONFLICT: link target does not match --expected-target",
                {"path": path, "expected": expected,
                 "actual": metadata["target"]},
            ))
    if args.dry_run:
        data = {"path": path, "dry_run": True, "changed": 1, **metadata}
    else:
        _require_archive_store()
        try:
            resolved_retention = retention_config.load(PLUGIN_ROOT)
            entry = store.archive_file(
                path, mode="move", reason=args.reason or "agw unlink-link",
                actor="agw unlink-link", retention_class="safety_archive",
                retention_config=resolved_retention,
            )
        except Exception as exc:
            _file_err(args, exc, default_code=4)
        data = {"path": path, "changed": 1, **metadata, "archive": entry}
    _out(
        args,
        (("would unlink" if args.dry_run else "unlinked")
         + f" {metadata['link_type']} {path} -> {metadata['target']}"
         + ("" if args.dry_run else "; link metadata archived")),
        data,
    )


def cmd_file(args):
    try:
        if args.file_op == "read":
            data = file_ops.read_text_page(
                args.path, start_line=args.start_line,
                start_byte=args.start_byte, limit=args.limit,
                max_bytes=args.max_bytes,
            )
        elif args.file_op == "write":
            content = _read_text_payload(args.content_file, "content")
            data = file_ops.write_text(
                args.path, content, expected_hash=args.expected_hash,
                dry_run=args.dry_run, operation="write",
            )
        elif args.file_op == "patch":
            patch = _read_text_payload(args.patch, "patch")
            data = file_ops.transform_text(
                args.path,
                lambda original: file_ops.apply_unified_patch(original, patch),
                expected_hash=args.expected_hash, dry_run=args.dry_run,
                operation="patch",
            )
        elif args.file_op == "replace":
            if args.old_file and args.old is not None:
                raise file_ops.FileOperationError(
                    "--old and --old-file are mutually exclusive"
                )
            if args.new_file and args.new is not None:
                raise file_ops.FileOperationError(
                    "--new and --new-file are mutually exclusive"
                )
            old = _read_text_payload(args.old_file, "old text") \
                if args.old_file else args.old
            new = _read_text_payload(args.new_file, "new text") \
                if args.new_file else args.new
            if old is None or new is None:
                raise file_ops.FileOperationError(
                    "replace requires old and new text (inline or file)"
                )
            data = file_ops.transform_text(
                args.path,
                lambda original: file_ops.replace_text(
                    original, old, new, replace_all=args.all
                ),
                expected_hash=args.expected_hash, dry_run=args.dry_run,
                operation="replace",
            )
        elif args.file_op == "plan":
            raw = _read_text_payload(args.operations_file, "operations")
            try:
                spec = json.loads(raw, object_pairs_hook=_json_object_no_duplicates)
            except (json.JSONDecodeError, ValueError) as exc:
                raise file_ops.FileOperationError(
                    f"operations file is not valid unambiguous JSON: {exc}"
                ) from exc
            data = file_ops.create_file_plan(
                spec, args.plan_file, cwd=args.cwd,
                expected_plan_hash=args.expected_plan_hash,
            )
        elif args.file_op == "apply-plan":
            positional = str(getattr(args, "plan_file", "") or "")
            option = str(getattr(args, "plan_file_option", "") or "")
            if positional and option and os.path.abspath(positional) != os.path.abspath(option):
                raise file_ops.FileOperationError(
                    "positional plan path and --plan-file refer to different files",
                    {"positional": positional, "plan_file": option},
                )
            plan_file = option or positional
            if not plan_file:
                raise file_ops.FileOperationError(
                    "apply-plan requires a plan path, positionally or with --plan-file",
                    {"suggested_correction": "agw file apply-plan --plan-file PLAN --expected-plan-hash SHA256"},
                )
            data = file_ops.apply_file_plan(
                plan_file, expected_plan_hash=args.expected_plan_hash,
            )
        else:
            raise file_ops.FileOperationError("unknown file operation")
    except (OSError, file_ops.FileOperationError) as exc:
        _file_err(args, exc)
    if args.file_op == "read":
        if args.json:
            _out(args, data["content"], data)
        else:
            sys.stdout.write(data["content"])
    elif args.file_op == "plan":
        reviews = []
        for item in data["operations"]:
            review = item.get("review", {})
            changes = review.get("line_changes", {})
            reviews.append(
                f"{item['path']}: +{changes.get('inserted', 0)} "
                f"-{changes.get('deleted', 0)}; {item['before_hash']} -> {item['after_hash']}"
            )
        _out(
            args,
            (f"planned {len(data['operations'])} operation(s) in "
             f"{data['plan_file']} ({data['plan_hash']})"
             + (("\n" + "\n".join(reviews)) if reviews else "")),
            data,
        )
    elif args.file_op == "apply-plan":
        _out(
            args,
            (f"applied {data['changed']} planned change(s)"
             + (f" ({data['transaction_id']})" if data.get("transaction_id") else "")),
            data,
        )
    else:
        _out(
            args,
            (f"{data['operation']} {data['path']}: "
             f"{'changed' if data['changed'] else 'no change'} "
             f"({data['after_hash']})"),
            data,
        )


def cmd_run(args):
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    try:
        parameter_values = {}
        for item in args.param:
            if "=" not in item:
                raise workflows.WorkflowError(
                    "--param must use NAME=VALUE; repeat it for each parameter"
                )
            name, value = item.split("=", 1)
            if not name or name in parameter_values:
                raise workflows.WorkflowError(
                    f"workflow parameter {name!r} is empty or duplicated"
                )
            parameter_values[name] = value
        workflow = None
        if args.workflow:
            if args.output or args.expected_hash or args.output_root or args.output_pattern:
                raise workflows.WorkflowError(
                    "--workflow resolves its own output contract; do not combine it "
                    "with --output, --expected-hash, --output-root, or --output-pattern"
                )
            workflow = workflows.resolve_run(
                args.workflow, command, args.cwd, parameters=parameter_values,
            )
            command = workflow["command"]
            outputs = workflow["outputs"]
            expected_hashes = workflow["expected_hashes"]
            output_roots = workflow["output_roots"]
            output_patterns = workflow["output_patterns"]
        else:
            if parameter_values:
                raise workflows.WorkflowError("--param requires --workflow")
            outputs = args.output
            expected_hashes = args.expected_hash
            output_roots = args.output_root
            output_patterns = args.output_pattern
        data = file_ops.run_declared(
            command, outputs, expected_hashes=expected_hashes,
            cwd=args.cwd, dry_run=args.dry_run,
            output_roots=output_roots,
            output_patterns=output_patterns,
            optional_outputs=(workflow or {}).get("optional_outputs", []),
            allow_missing_output_parents=bool(workflow),
            timeout_seconds=getattr(args, "timeout_seconds", 300.0),
            isolation_mode=getattr(args, "isolation", "observed"),
            network_policy=getattr(args, "network", "inherit"),
        )
        if workflow:
            data["workflow"] = workflow["workflow"]
            data["workflow_manifest_sha256"] = workflow["manifest_sha256"]
            data["script_sha256"] = workflow["script_sha256"]
            data["workflow_parameters"] = workflow.get("parameters", {})
    except (OSError, file_ops.FileOperationError, workflows.WorkflowError) as exc:
        _file_err(args, exc)
    human_parts = []
    if data.get("stdout_tail"):
        human_parts.append(data["stdout_tail"].rstrip())
    if data.get("stderr_tail"):
        human_parts.append(data["stderr_tail"].rstrip())
    human_parts.append(
        "validated declared outputs" if data.get("dry_run") else
        f"command exited {data['exit_code']}; {len(data['outputs'])} declared output(s) tracked"
    )
    if data.get("timed_out"):
        human_parts.append("command exceeded its bounded timeout and its process tree was terminated")
    _out(args, "\n".join(part for part in human_parts if part), data)
    if data.get("executed") and data.get("exit_code"):
        raise SystemExit(data["exit_code"])
    if data.get("executed") and not data.get("ok", True):
        raise SystemExit(2)


def _plan_payload(path: str, label: str) -> dict:
    return _load_json_payload("", path, label, dict)


def _publication_candidate_validator(candidate: str, item: dict):
    validation = item.get("validation", "raw")
    if not isinstance(validation, dict) or validation.get("kind") != "office":
        return {"valid": True, "mode": "raw"}
    extension = os.path.splitext(item.get("target", ""))[1].lower()
    tier = validation.get("tier") or "office-schema"
    validation_tier = (
        "excel-strict" if tier == "auto" and extension in {".xlsx", ".xlsm"}
        else "office-schema" if tier == "auto" else tier
    )
    office_tx.validate_office_package(candidate, tier=validation_tier)
    preserve = str(validation.get("preserve_against") or "")
    preserve_hash = str(validation.get("preserve_against_sha256") or "")
    if extension == ".xlsm" and not (preserve and preserve_hash):
        raise file_ops.FileOperationError(
            ".xlsm publication requires an authenticated preserve-against baseline"
        )
    preservation_verified = False
    if preserve:
        if not preserve_hash:
            raise file_ops.FileOperationError(
                "preserve-against requires its authenticated SHA-256"
            )
        office_tx.validate_package_preservation(
            preserve, candidate, expected_original_sha256=preserve_hash,
        )
        preservation_verified = True
    return {
        "valid": True, "candidate_sha256": store.file_sha256(candidate),
        "tier": tier, "package_validation": True,
        "baseline_path": preserve,
        "baseline_expected_sha256": preserve_hash,
        "baseline_actual_sha256": store.file_sha256(preserve) if preserve else "",
        "preservation_validation": preservation_verified,
    }


def _plan_human(data: dict) -> str:
    outcome = data.get("outcome")
    if outcome == "environment_failure":
        if data.get("error_code") == "immutable_execution_unavailable":
            return "execution not started: no provider can prove immutable script execution"
        return "execution not started: " + str(data.get("error") or "environment unavailable")
    if outcome == "policy_blocked":
        return "execution blocked by policy"
    if outcome == "stale_precondition":
        return "plan refused because a precondition is stale"
    if outcome == "process_failed":
        return "process did not succeed; declared outputs were not published"
    if outcome == "success_extra_outputs":
        return "process succeeded but produced undeclared observed outputs"
    if outcome == "success_output_mismatch":
        return "process succeeded but its declared output contract was not satisfied"
    if outcome == "success":
        return "plan completed successfully"
    if data.get("dry_run"):
        return "plan validated; no execution or publication occurred"
    return "plan operation completed"


def cmd_run_plan(args):
    try:
        if args.plan_op == "create":
            spec = _plan_payload(args.spec_file, "run-plan specification")
            allowed = {
                "command", "mode", "cwd", "artifacts", "observed_roots",
                "timeout_seconds", "isolation", "network", "provider",
                "issued_at_utc", "expires_at_utc", "plan_id",
            }
            unknown = sorted(set(spec) - allowed)
            if unknown:
                raise run_plans.RunPlanError(
                    "run-plan specification contains unknown fields",
                    {"fields": unknown},
                )
            if not isinstance(spec.get("command"), list):
                raise run_plans.RunPlanError(
                    "run-plan specification command must be a JSON array"
                )
            plan = run_plans.create_run_plan(
                spec.get("command"), mode=spec.get("mode"),
                cwd=spec.get("cwd", ""), artifacts=spec.get("artifacts"),
                observed_roots=spec.get("observed_roots"),
                timeout_seconds=spec.get("timeout_seconds", 300.0),
                isolation=spec.get("isolation", "observed"),
                network=spec.get("network", "inherit"),
                provider=spec.get("provider", "installed"),
                issued_at_utc=spec.get("issued_at_utc"),
                expires_at_utc=spec.get("expires_at_utc"),
                plan_id=spec.get("plan_id", ""),
            )
            data = _write_plan_file(
                plan, args.plan_file, args.expected_plan_file_hash,
                "run-plan-create",
            )
            human = (
                f"created single-use run plan {data['freshness']['plan_id']} at "
                f"{data['plan_file']} ({data['plan_sha256']})"
            )
        else:
            plan = _plan_payload(args.plan_file, "run plan")
            data = run_plans.apply_run_plan(
                plan, expected_plan_hash=args.expected_plan_hash,
                dry_run=args.dry_run,
                candidate_validator=_publication_candidate_validator,
            )
            human = _plan_human(data)
    except (OSError, file_ops.FileOperationError, run_plans.RunPlanError) as exc:
        _plan_error(args, exc)
    _out(args, human, data)
    if args.plan_op == "apply" and not data.get("ok", True):
        raise SystemExit(4 if data.get("outcome") == "environment_failure" else 2)


def cmd_publish_plan(args):
    try:
        if args.plan_op == "create":
            operations = _load_json_payload(
                "", args.operations_file, "publish operations", list,
            )
            plan = publication.build_publish_plan(operations, cwd=args.cwd)
            data = _write_plan_file(
                plan, args.plan_file, args.expected_plan_file_hash,
                "publish-plan-create",
            )
            human = (
                f"created publish plan for {len(plan['operations'])} file(s) at "
                f"{data['plan_file']} ({data['plan_sha256']})"
            )
        elif args.plan_op == "apply":
            plan = _plan_payload(args.plan_file, "publish plan")
            data = publication.publish_staged_batch(
                plan, expected_plan_hash=args.expected_plan_hash,
                candidate_validator=_publication_candidate_validator,
                dry_run=args.dry_run,
            )
            human = (
                ("publication validated; no process ran" if data.get("dry_run")
                 else "publication committed; no process outcome applies")
                + f"; {len(data.get('operations', []))} staged file(s); "
                + f"atomicity={data['atomicity']}, visibility={data['visibility']}"
            )
        elif args.recovery_action == "inspect":
            data = publication.inspect_prepared_transaction(args.transaction_id)
            human = (
                f"publication {args.transaction_id}: "
                f"{data.get('state', 'unknown')}; "
                f"classification={data.get('classification', 'terminal')}"
            )
        else:
            data = publication.recover_prepared_transaction(
                args.transaction_id, action=args.recovery_action,
            )
            human = (
                f"publication {args.transaction_id}: {data.get('state', 'unknown')} "
                f"after explicit {args.recovery_action} recovery"
            )
    except (OSError, LookupError, file_ops.FileOperationError) as exc:
        _plan_error(args, exc)
    _out(args, human, data)


def cmd_workflow(args):
    try:
        if args.workflow_op == "trust":
            if not args.approve_trust:
                raise workflows.WorkflowTrustError(
                    "review the manifest and pass --approve-trust; the host will "
                    "also request confirmation"
                )
            def show_phase(item):
                if args.progress:
                    print(
                        f"agw: workflow phase {item['phase']} "
                        f"({item['elapsed_seconds']:.3f}s)", file=sys.stderr,
                    )

            data = workflows.trust_manifest(
                args.manifest, args.expected_manifest_hash, replace=args.replace,
                phase_callback=show_phase,
            )
            human = (
                ("trusted" if data["changed"] else "already trusted")
                + f" workflow {data['workflow']}"
            )
        elif args.workflow_op == "list":
            items = workflows.list_trusted()
            data = {"workflows": items, "count": len(items)}
            human = "\n".join(
                ((item.get("id", "") + (
                    f" - {item.get('description', '')}" if item.get("description") else ""
                )) or f"unverified record: {item.get('record', 'unknown')}")
                for item in items
            ) or "no trusted workflows"
        elif args.workflow_op == "match":
            command = list(args.command)
            if command and command[0] == "--":
                command = command[1:]
            if not command:
                raise workflows.WorkflowError(
                    "workflow match requires a literal script command after --"
                )
            diagnostics = workflows.diagnose_matching_workflows(
                command, args.cwd or os.getcwd(),
            )
            workflow_ids = diagnostics["matches"]
            available = {
                item.get("id"): item for item in workflows.list_trusted()
                if item.get("verified") and item.get("id")
            }
            matches = [{
                "id": item,
                "description": str(available.get(item, {}).get("description") or ""),
            } for item in workflow_ids]
            recommended = diagnostics.get("recommended_argv", [])
            data = {
                "matches": matches, "count": len(matches),
                "cwd": os.path.realpath(os.path.abspath(args.cwd or os.getcwd())),
                "recommended_argv": recommended,
                "suggested_argv": diagnostics.get("suggested_argv", {
                    "deprecated": True,
                    "replacement": "recommended_argv",
                    "value_included": False,
                }),
                "candidates": diagnostics.get("candidates", []),
                "candidate_count": diagnostics.get("candidate_count", 0),
            }
            headline = (
                f"exact trusted workflow match: {workflow_ids[0]}"
                if len(workflow_ids) == 1 else
                ("multiple exact workflow matches: " + ", ".join(workflow_ids)
                 if workflow_ids else "no exact trusted workflow match")
            )
            candidate_lines = [
                f"{item.get('candidate_class', 'incompatible')}: "
                f"{item.get('id') or item.get('record', 'unverified')}"
                for item in diagnostics.get("candidates", [])
            ]
            recommendation = diagnostics.get("recommended_argv", [])
            if recommendation:
                candidate_lines.append("one revalidated recommendation is available in JSON")
            human = "\n".join([headline, *candidate_lines])
        elif args.workflow_op == "propose":
            command = list(args.command)
            if command and command[0] == "--":
                command = command[1:]
            if not command:
                raise workflows.WorkflowError(
                    "workflow propose requires a literal script command after --"
                )
            data = workflows.build_workflow_proposal(
                command, args.cwd or os.getcwd(), workflow_id=args.workflow_id,
                outputs=args.output, allowed_roots=args.allowed_root,
                expected_states=args.expected, description=args.description,
            )
            human = json.dumps(data, ensure_ascii=True, indent=2)
        elif args.workflow_op == "info":
            record = workflows.load_trusted(args.workflow_id)
            manifest = record["manifest"]
            data = {
                "id": manifest["id"], "description": manifest.get("description", ""),
                "command": manifest["command"],
                "allowed_roots": manifest["allowed_roots"],
                "outputs": manifest["outputs"],
                "observed_roots": manifest.get("observed_roots", []),
                "parameters": manifest.get("parameters", {}),
                "manifest_sha256": record["manifest_sha256"],
                "trusted_at": record["trusted_at"], "verified": True,
            }
            human = f"trusted workflow {manifest['id']} ({manifest['command']['runtime']})"
        elif args.workflow_op == "validate":
            validated = workflows.validate_manifest_file(
                args.manifest, args.expected_manifest_hash,
            )
            validated.pop("manifest", None)
            data = validated
            human = (
                f"valid workflow {data['workflow']} ({data['schema']}); "
                f"{data['outputs']} exact output(s), "
                f"{data.get('parameter_count', 0)} parameter(s)"
            )
        elif args.workflow_op == "status":
            data = workflows.manifest_status(args.manifest)
            human = f"workflow {data['workflow']}: {data['status']}"
        elif args.workflow_op == "init":
            built = workflows.initialize_manifest(
                args.script, args.manifest, workflow_id=args.workflow_id,
                runtime=args.runtime, args=args.arg, outputs=args.output,
                expected=args.expected, allowed_roots=args.allowed_root,
                description=args.description,
            )
            serialized = json.dumps(
                built["manifest"], ensure_ascii=True, indent=2,
            ) + "\n"
            written = file_ops.write_text(
                args.manifest, serialized,
                expected_hash=args.expected_manifest_hash,
                operation="workflow-init",
            )
            data = {
                "ok": True, "workflow": built["manifest"]["id"],
                "schema": built["manifest"]["schema"],
                "manifest": written["path"],
                "manifest_sha256": written["after_hash"],
                "script_sha256": built["manifest"]["command"]["script_sha256"],
                "arguments_bound": True,
                "argument_count": len(built["manifest"]["command"]["args"]),
                "outputs": len(built["manifest"]["outputs"]),
                "changed": written["changed"],
                "snapshot_transaction_id": written.get("snapshot_transaction_id", ""),
            }
            human = f"initialized workflow manifest {data['workflow']} at {data['manifest']}"
        else:
            raise workflows.WorkflowError("unknown workflow operation")
    except (OSError, file_ops.FileOperationError, workflows.WorkflowError) as exc:
        _file_err(args, exc)
    _out(args, human, data)


def _validate_office_stage(path: str, extension: str, requested_tier: str = "auto") -> dict:
    """Apply one shared Office publication boundary with compatibility fields."""
    office_tx._package_preflight(path, mutating=False)
    tier = requested_tier
    if tier == "auto":
        tier = "excel-strict" if extension in {".xlsx", ".xlsm"} else "office-schema"
    report = office_tx.validate_office_package(path, tier=tier)
    return {**report, "verified": True, "package": "valid-ooxml"}


def cmd_publish_file(args):
    try:
        staged = os.path.abspath(os.path.expanduser(args.staged))
        target = os.path.abspath(os.path.expanduser(args.target))
        staged_extension = os.path.splitext(staged)[1].lower()
        target_extension = os.path.splitext(target)[1].lower()
        office_validation = None
        effective_expected_hash = args.expected_hash
        if not effective_expected_hash and os.path.isfile(target):
            effective_expected_hash = store.file_sha256(target)
        office_extensions = {".docx", ".pptx", ".xlsx", ".xlsm"}
        if staged_extension in office_extensions or target_extension in office_extensions:
            if staged_extension != target_extension:
                raise file_ops.FileOperationError(
                    "Office publish requires matching staged and target extensions"
                )
            validation_tier = getattr(args, "office_validation_tier", "auto")
            office_validation = _validate_office_stage(
                staged, staged_extension, validation_tier,
            )
            if target_extension == ".xlsm":
                baseline = os.path.abspath(os.path.expanduser(
                    args.preserve_against or target
                ))
                if not os.path.isfile(baseline):
                    raise file_ops.FileOperationError(
                        "new .xlsm publication requires --preserve-against ORIGINAL"
                    )
                expected_baseline = args.expected_preservation_hash
                if not expected_baseline and os.path.normcase(baseline) == os.path.normcase(target):
                    expected_baseline = args.expected_hash
                preservation = office_tx.validate_package_preservation(
                    baseline, staged,
                    expected_original_sha256=expected_baseline,
                )
                office_validation = {
                    **preservation, "package_validation": office_validation,
                }
        data = file_ops.publish_staged_file(
            target, staged,
            expected_hash=effective_expected_hash,
            expected_stage_hash=args.expected_staged_hash,
            dry_run=args.dry_run,
            retry_seconds=args.retry_seconds,
        )
    except office_tx.TransactionError as exc:
        _office_err(args, exc)
    except (OSError, file_ops.FileOperationError) as exc:
        _file_err(args, exc)
    if office_validation is not None:
        data["office_validation"] = office_validation
    _out(
        args,
        (("would publish" if data.get("dry_run") else "published")
         + f" {args.staged} -> {data['path']}"
         + ("" if data.get("dry_run") else "; prior target recoverable")),
        data,
    )


def cmd_move(args):
    src = _resolve(args.src)
    op = store.logged_move(src, os.path.abspath(os.path.expanduser(args.dest)))
    _out(args, f"moved {op['src']} -> {op['dest']} (undo with `agw undo`)", op)


def cmd_snapshot(args):
    folder = _resolve(args.path)
    total = 0
    for dirpath, dirnames, filenames in os.walk(folder):
        dirnames[:] = [d for d in dirnames if d != "_workspace"]
        for name in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, name))
            except OSError:
                pass
    if total > SNAPSHOT_MAX_BYTES and not args.force:
        _err(f"folder is {total / 1e9:.1f} GB (> {SNAPSHOT_MAX_BYTES / 1e9:.0f} GB "
             "preflight limit). Re-run with --force if you really want this.", code=3)
    _require_archive_store()
    try:
        resolved_retention = retention_config.load(PLUGIN_ROOT)
        entry = store.archive_file(
            folder, mode="copy", reason=args.reason or "agw snapshot", actor="agw",
            retention_class="manual_snapshot",
            retention_config=resolved_retention,
        )
    except Exception as exc:
        _file_err(args, exc, default_code=4)
    _out(args, f"snapshot of {folder} -> {entry['dest']} ({total / 1e6:.1f} MB)", entry)


def cmd_restore(args):
    target = os.path.abspath(os.path.expanduser(args.path))
    try:
        resolved_retention = retention_config.load(PLUGIN_ROOT)
        op = store.restore(
            target, version=args.version or 0,
            retention_config=resolved_retention,
        )
    except Exception as exc:
        _file_err(args, exc, default_code=4)
    _out(args, f"restored {target} from v{op['version']}", op)


def cmd_undo(args):
    try:
        if getattr(args, "transaction", ""):
            resolved_retention = retention_config.load(PLUGIN_ROOT)
            op = store.undo_transaction(
                args.transaction, retention_config=resolved_retention
            )
            human = (
                f"undid transaction {op['undid_transaction_id']}; "
                f"restored {len(op['operations'])} target(s)"
            )
        else:
            op = store.undo_last()
            human = f"undid {op['undone']}: {op['restored']} is back"
    except Exception as exc:
        _file_err(args, exc, default_code=4)
    _out(args, human, op)


def cmd_status(args):
    from core import engine
    state = store.state_load()
    try:
        resolved_retention = retention_policy.resolve_retention_policy(
            engine.load_policy(PLUGIN_ROOT).settings
        )
        size = store.archive_size_bytes()
        retention_state = retention_policy.classify_retention_state(
            resolved_retention, size
        ).as_dict()
    except (retention_policy.RetentionPolicyError, OSError) as exc:
        _file_err(args, exc, default_code=4)
    all_checkouts = state.get("checkouts", {})
    cwd_filter = os.path.realpath(os.path.abspath(os.path.expanduser(args.cwd))) \
        if getattr(args, "cwd", "") else ""
    now_ns = time.time_ns()
    stale_days = max(0.0, float(getattr(args, "stale_days", 30.0)))
    checkouts = {}
    for src, raw_entry in all_checkouts.items():
        if cwd_filter:
            try:
                if os.path.commonpath([
                        os.path.normcase(os.path.realpath(src)),
                        os.path.normcase(cwd_filter),
                ]) != os.path.normcase(cwd_filter):
                    continue
            except ValueError:
                continue
        entry = dict(raw_entry)
        created = int(entry.get("created_at_ns") or 0)
        age_days = ((now_ns - created) / 86_400_000_000_000) if created else None
        reasons = []
        if not os.path.isfile(src):
            reasons.append("source_missing")
        working = str(entry.get("working") or "")
        if not os.path.isfile(working):
            reasons.append("working_copy_missing")
        if age_days is not None and age_days >= stale_days:
            reasons.append("age_threshold")
        if os.path.isfile(src) and store.file_sha256(src) != entry.get("base_sha256"):
            reasons.append("live_file_changed")
        entry["age_days"] = age_days
        entry["stale"] = bool(reasons)
        entry["stale_reasons"] = reasons
        checkouts[src] = entry
    lines = [f"archive store: {store.agw_home()} ({size / 1e6:.1f} MB)",
             ("retention: " + retention_state["classification"]
              + f" (high {retention_state['high_water_bytes'] / 1e9:.2f} GB, "
              + f"max {retention_state['max_bytes'] / 1e9:.2f} GB)"),
             f"open checkouts: {len(checkouts)}"
             + (f" (filtered from {len(all_checkouts)})" if cwd_filter else "")]
    for src, entry in list(checkouts.items())[:20]:
        suffix = ("  [" + ", ".join(entry["stale_reasons"]) + "]") \
            if entry["stale_reasons"] else ""
        lines.append(f"  {src} -> {entry['working']}{suffix}")
    pending_office = office_tx.transaction_status()
    lines.append(f"incomplete office transactions: {len(pending_office)}")
    for item in pending_office[:20]:
        lines.append(
            f"  {item['mutation_id']} [{item['state']}] "
            f"{item.get('operation', '')}"
        )
    _out(args, "\n".join(lines),
         {"archive_bytes": size, "retention": retention_state,
          "checkouts": checkouts,
          "checkout_count_total": len(all_checkouts),
          "checkout_filter_cwd": cwd_filter,
          "stale_days": stale_days,
          "home": store.agw_home(),
          "incomplete_office_transactions": pending_office})


def cmd_log(args):
    ops = store.oplog_read()[-(args.n):]
    lines = [f"{op.get('ts', '?')}  {op.get('op', '?'):9} {op.get('src', '')}"
             for op in ops]
    _out(args, "\n".join(lines) or "(no operations logged)", {"ops": ops})


def cmd_doctor(args):
    from core import engine
    caps = converters.capabilities()
    home = store.agw_home_path()
    writable = store.archive_store_writable()
    profile = prof.detect(os.getcwd())
    loaded_policy = engine.load_policy(PLUGIN_ROOT)
    cfg = engine.resolve_settings(loaded_policy)
    try:
        resolved_retention = retention_policy.resolve_retention_policy(
            loaded_policy.settings
        )
        size = store.archive_size_bytes()
        retention = retention_policy.classify_retention_state(
            resolved_retention, size
        ).as_dict()
    except (retention_policy.RetentionPolicyError, OSError) as exc:
        _file_err(args, exc, default_code=4)
    office_caps = office.capabilities()
    validation_caps = office_tx.office_validation_capabilities()
    checks = {
        "agw_home": home, "agw_home_writable": writable,
        "python": sys.version.split()[0], "cwd_profile": profile.name,
        "enforcement_level": cfg.get("level"), "enforcement": cfg.get("enforcement"),
        "session_memory": cfg.get("session_memory"),
        "regenerable_rm": cfg.get("regenerable_rm"),
        "archive_bytes": size,
        "archive_budget": retention["max_bytes"] or "unlimited",
        "archive_retention_state": retention["classification"],
        "archive_over_budget": retention["capacity_exceeded"],
        "archive_required_free_bytes": retention["over_capacity_bytes"],
        "archive_automatic_prune": not resolved_retention.unlimited,
        **{f"converter_{k}": v for k, v in caps.items()},
        **{f"office_{k}": v for k, v in office_caps.items()},
        "office_validation_tiers": ",".join(validation_caps["tiers"]),
        "office_native_roundtrip_available": validation_caps["roundtrip"]["available"],
        "office_native_roundtrip_reason": validation_caps["roundtrip"].get(
            "reason_code", ""
        ),
    }
    lines = [f"{'OK ' if v is not False and v is not None else 'MISSING '} {k}: {v}"
             for k, v in checks.items()]
    if not caps["pandoc"]:
        lines.append("note: pandoc not found - Office checkouts degrade to copy-only "
                     "(archive safety unaffected). Install: https://pandoc.org")
    if not office_caps["xlsx_advanced"]:
        lines.append(
            "note: dependency-free Excel set-cell is available; install openpyxl "
            "only for advanced workbook reads and table/row mutations"
        )
    if retention["capacity_exceeded"]:
        lines.append(
            f"note: archive ({size} B) exceeds capacity "
            f"({retention['max_bytes']} B); only expired classified cache "
            "preimages can be reclaimed automatically."
        )
    checks["retention"] = retention
    _out(args, "\n".join(lines), checks)


def cmd_office(args):
    path = _resolve(args.path)
    try:
        if args.op == "validate":
            data = office_tx.validate_office_package(path, tier=args.tier)
            human = (
                f"valid {args.tier} Office package; "
                f"{len(data['validators'])} validator tier(s) passed"
            )
        elif args.op == "info":
            if args.scope == "preservation":
                data = office_tx.package_preservation_manifest(path)
            elif os.path.splitext(path)[1].lower() in (".xlsx", ".xlsm") and args.scope:
                import office_excel
                data = office_excel.workbook_info(path, scope=args.scope)
            else:
                data = office.info(path)
            human = json.dumps(data, ensure_ascii=False, indent=2, default=str)
        elif args.op == "validate-preservation":
            data = office_tx.validate_package_preservation(
                args.against, path,
                expected_original_sha256=args.expected_original_hash,
            )
            human = (
                f"verified {data['protected_part_count']} protected Office part(s); "
                "macros and package integrations unchanged"
            )
        elif args.op == "normalize":
            data = office_tx.normalize_safe_metadata(
                path, args.output,
                expected_sha256=args.expected_file_hash,
                expected_output_sha256=args.expected_output_hash,
                dry_run=args.dry_run,
            )
            human = (
                ("dry-run: " if args.dry_run else "")
                + f"normalized {data['input']} -> {data['output']}; "
                + f"removed {data['removed_count']} safe metadata attribute(s)"
            )
        elif args.op == "get-text":
            text = office.get_text(path)
            data = {"path": path, "text": text,
                    "preservation": office.preservation_info(path)}
            human = text
        elif args.op == "replace-text":
            if args.dry_run:
                matches = office.find_matches(path, args.find)
                data = {"matches": matches, "count": len(matches),
                        "preservation": office.preservation_info(path)}
                human = "\n".join(
                    [f"{len(matches)} match(es) for {args.find!r}:"] +
                    [f"  #{m['n']} ({m['where']}) ...{m['context']}..."
                     for m in matches]) if matches else f"no matches for {args.find!r}"
            else:
                data = office.replace_text(path, args.find, args.replace,
                                           all_matches=args.all, nth=args.nth)
                if data["replacements"]:
                    human = (f"replaced {data['replacements']} of {data['matches']} "
                             f"occurrence(s) in {path} (pre-image archived as "
                             f"v{data['snapshot_version']})")
                else:
                    human = f"no matches for {args.find!r}; file untouched"
        elif args.op == "set-cell":
            if not (args.sheet and args.cell):
                _err("set-cell needs --sheet and --cell")
            data = office.set_cell(path, args.sheet, args.cell, args.value,
                                   force_text=args.text,
                                   expected_sha256=args.expected_file_hash,
                                   dry_run=args.dry_run)
            human = (f"{args.sheet}!{args.cell}: {data['old']!r} -> {data['new']!r} "
                     + ("(no change; file untouched)" if not data.get("changed") else
                        "(dry-run; file untouched)" if args.dry_run else
                        f"(pre-image archived as v{data['snapshot_version']})"))
        elif args.op == "append-rows":
            if not args.sheet:
                _err("append-rows needs --sheet")
            if args.from_csv:
                import csv
                with open(_resolve(args.from_csv), newline="", encoding="utf-8") as f:
                    rows = list(csv.reader(f))
            else:
                rows = _load_json_payload(
                    args.rows, "", "--rows", list
                ) if args.rows else []
                if not (isinstance(rows, list) and
                        all(isinstance(r, list) for r in rows)):
                    _err("--rows must be a JSON array of arrays")
            if not rows:
                _err("no rows given: use --from-csv FILE or --rows '[[...],...]'")
            data = office.append_rows(path, args.sheet, rows, force_text=args.text)
            human = (f"appended {data['appended']} row(s) to {args.sheet} in {path} "
                     f"(pre-image archived as v{data['snapshot_version']})")
        elif args.op == "read-table":
            import office_excel
            if args.values_only and args.include_formulas:
                _err("read-table: --values-only and --include-formulas are mutually exclusive")
            columns = [value for value in args.columns.split(",") if value] \
                if args.columns else None
            where = _load_json_payload(args.where_json, "", "--where-json", dict) \
                if args.where_json else None
            data = office_excel.read_table(
                path, args.table, sheet=args.sheet, columns=columns, where=where,
                offset=args.offset, limit=args.limit, values_only=args.values_only,
                include_formulas=args.include_formulas,
            )
            human = (f"{data['table']} on {data['sheet']}: "
                     f"{data['returned']} row(s)"
                     f"{' (more)' if data['more'] else ''}")
        elif args.op == "read-range":
            import office_excel
            data = office_excel.read_range(
                path, args.sheet, args.range,
                include_formulas=args.formulas,
            )
            human = (f"{data['sheet']}!{data['range']}: "
                     f"{data['cell_count']} cell(s)")
        elif args.op == "validate-formulas":
            import office_excel
            data = office_excel.validate_formulas(
                path, offset=args.offset, limit=args.limit,
            )
            human = (
                f"{data['formula_count']} formula(s); "
                f"{data['missing_cached_values']} missing cached value(s); "
                f"{data['external_references']} external reference(s)"
            )
        elif args.op == "ensure-table":
            import office_excel
            headers = _load_json_payload(
                args.headers_json, args.headers_file, "ensure-table headers", list
            ) if args.headers_json or args.headers_file else None
            columns = _load_json_payload(
                args.columns_json, args.columns_file, "ensure-table columns", None
            ) if args.columns_json or args.columns_file else None
            data = office_excel.ensure_table(
                path, args.table, sheet=args.sheet, headers=headers,
                cell_range=args.range, style=args.style, columns=columns,
                create_sheet=args.create_sheet,
                expected_sha256=args.expected_file_hash,
                dry_run=args.dry_run,
            )
            human = ("dry-run: " if args.dry_run else "") + \
                f"{data.get('changed', 0)} change(s) for {args.table} on {args.sheet}"
        elif args.op == "append-table-row":
            import office_excel
            row = _load_json_payload(
                args.row_json, args.row_file, "append-table-row", dict
            )
            if args.unique_columns_json or args.unique_columns_file:
                if args.unique_column:
                    _err("unique-column and unique-columns JSON are mutually exclusive")
                unique_columns = _load_json_payload(
                    args.unique_columns_json, args.unique_columns_file,
                    "append-table-row unique columns", list,
                )
            else:
                unique_columns = args.unique_column
            data = office_excel.append_table_row(
                path, args.table, row, sheet=args.sheet,
                expected_sha256=args.expected_file_hash,
                dry_run=args.dry_run,
                coerce_iso_dates=args.coerce_iso_dates,
                unique_columns=unique_columns,
            )
            human = ("dry-run: " if args.dry_run else "") + \
                f"{data.get('changed', data.get('appended', 0))} row(s) for {args.table}"
        elif args.op == "update-table-row":
            import office_excel
            updates = _load_json_payload(
                args.set_json, args.set_file, "update-table-row", dict
            )
            key = _load_json_payload(
                args.key_json, "", "--key-json", None
            ) if args.key_json else args.key
            if isinstance(key, (dict, list)):
                _err("--key-json must be a JSON scalar")
            data = office_excel.update_table_row(
                path, args.table, args.key_column, key, updates,
                sheet=args.sheet, expected_sha256=args.expected_file_hash,
                dry_run=args.dry_run,
                coerce_iso_dates=args.coerce_iso_dates,
            )
            human = ("dry-run: " if args.dry_run else "") + \
                f"{data.get('changed', data.get('updated', 0))} row(s) for {args.table}"
        elif args.op == "outline":
            import office_word
            data = office_word.outline(path, offset=args.offset, limit=args.limit)
            human = (f"{data['returned']} Word block(s)"
                     f"{' (more)' if data['more'] else ''}")
        elif args.op == "read-blocks":
            import office_word
            ids = [value for value in args.ids.split(",") if value]
            data = office_word.read_blocks(path, ids)
            human = f"{len(data['blocks'])} Word block(s)"
        elif args.op == "patch":
            import office_word
            operations = _load_json_payload(
                args.ops_json, args.ops_file, "patch", list
            )
            data = office_word.patch(
                path, operations, expected_sha256=args.expected_file_hash,
                dry_run=args.dry_run,
            )
            human = ("dry-run: " if args.dry_run else "") + \
                f"{data.get('changed', data.get('patched', 0))} Word operation(s)"
        else:  # pragma: no cover - argparse restricts choices
            _err(f"unknown office op: {args.op}")
    except office.MissingLibrary as exc:
        _office_err(args, exc, default_code=2)
    except office.OfficeError as exc:
        _office_err(args, exc)
    except Exception as exc:
        # Adapter errors are intentionally plain exceptions so optional
        # dependencies remain lazy. Keep CLI errors concise and preserve the
        # established conflict exit code.
        _office_err(args, exc)
    _out(args, human, data)


def cmd_prune(args):
    # Manual maintenance is still acknowledged explicitly; normal store-growing
    # operations invoke this same bounded selector automatically under pressure.
    print("prune permanently reclaims only expired classified cache preimages.",
          file=sys.stderr)
    if not args.yes_i_am_a_human:
        _err("refusing: pass --yes-i-am-a-human after reviewing `agw status`", code=4)
    try:
        policy = retention_config.load(PLUGIN_ROOT)
        result = store.maintain_retention(
            policy=policy, lock_context=store.Lock("recovery-store", timeout=30.0)
        )
    except Exception as exc:
        _file_err(args, exc, default_code=4)
    _out(
        args,
        (f"retention maintenance reclaimed {result['reclaimed_bytes']} byte(s); "
         f"cache now uses {result['after_bytes']} byte(s)"),
        result,
    )


def cmd_schema(args):
    try:
        data = cli_schema.project(_ROOT_CLI_PARSER, list(args.command_path))
    except cli_schema.SchemaLookupError as exc:
        if args.json:
            print(json.dumps({
                "ok": False,
                "error": {"code": exc.error_code, "message": str(exc), "details": {}},
            }, ensure_ascii=False, separators=(",", ":")), file=sys.stderr)
            raise SystemExit(2)
        _err(str(exc), code=2)
    _out(args, json.dumps(data, ensure_ascii=False, indent=2), data)


def main(argv=None):
    global _ROOT_CLI_PARSER, _JSON_ERRORS_ACTIVE
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        argv = launcher.decode_internal_argv(argv)
    except ValueError as exc:
        _err(f"invalid trusted-launcher arguments: {exc}", code=2)
    _JSON_ERRORS_ACTIVE = "--json" in argv
    _CompactArgumentParser.json_errors_enabled = "--json" in argv
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                        help="machine-readable output")
    parser = _CompactArgumentParser(
        prog="agw", parents=[common],
        description="agent workspace - CRUA file safety",
        epilog=("Use `agw <command> --help`; for Office use "
                "`agw office <operation> --help`."),
    )
    _ROOT_CLI_PARSER = parser
    sub = parser.add_subparsers(dest="verb", required=True, metavar="command")

    def add(name, fn, *specs, **kw):
        if agw_contract.operation(name) is None:
            raise RuntimeError(f"AGW command is absent from the shared contract: {name}")
        p = sub.add_parser(name, parents=[common], **kw)
        for spec in specs:
            p.add_argument(*spec[0], **spec[1])
        p.set_defaults(fn=fn)
        return p

    add("init", cmd_init, (["path"], {"nargs": "?", "default": "."}),
        help="initialize workspace metadata")
    add("scan", cmd_scan, (["path"], {"nargs": "?", "default": "."}),
        (["--fast"], {"action": "store_true",
                       "help": "compatibility alias; bounded mode is already the default"}),
        (["--deep"], {"action": "store_true",
                       "help": "explicit larger profile: 30s/100000 files/200000 entries/depth 64"}),
        (["--max-seconds"], {"type": float, "default": None,
                             "help": "hard wall-clock deadline (default: 3)"}),
        (["--max-files"], {"type": int, "default": None,
                           "help": "stop after inspecting this many files"}),
        (["--max-entries"], {"type": int, "default": None,
                             "help": "stop after visiting this many files/directories"}),
        (["--max-depth"], {"type": int, "default": None,
                           "help": "maximum directory depth below the root"}),
        (["--no-size"], {"action": "store_true",
                         "help": "skip per-file stat; placeholder detection is limited"}),
        (["--profile"], {
            "choices": ["auto", "local", "git", "gdrive-sync",
                        "onedrive-sharepoint", "dropbox"],
            "default": "auto",
            "help": "validated folder profile override (default: auto)",
        }),
        help="bounded folder inventory")
    add("search", cmd_search,
        (["query"], {"help": "literal text to find (use --regex for a pattern)"}),
        (["path"], {"nargs": "?", "default": "."}),
        (["--regex"], {"action": "store_true",
                        "help": "interpret query as a Python regular expression"}),
        (["--ignore-case"], {"action": "store_true",
                              "help": "case-insensitive matching"}),
        (["--files"], {"action": "store_true",
                        "help": "match filenames instead of opening file contents"}),
        (["--include"], {"action": "append", "default": [], "metavar": "GLOB",
                          "help": "search only matching file paths; repeatable"}),
        (["--exclude"], {"action": "append", "default": [], "metavar": "GLOB",
                          "help": "skip matching files or directory subtrees; repeatable"}),
        (["--fast"], {"action": "store_true",
                       "help": "compatibility alias; bounded mode is already the default"}),
        (["--deep"], {"action": "store_true",
                       "help": "explicit larger traversal profile"}),
        (["--max-seconds"], {"type": float, "default": None,
                             "help": "hard wall-clock deadline (default: 3)"}),
        (["--max-files"], {"type": int, "default": None,
                           "help": "stop after inspecting this many files"}),
        (["--max-entries"], {"type": int, "default": None,
                             "help": "stop after visiting this many files/directories"}),
        (["--max-depth"], {"type": int, "default": None,
                           "help": "maximum directory depth below the root"}),
        (["--max-matches"], {"type": int, "default": None,
                             "help": "stop after returning this many matches (default: 100)"}),
        (["--max-file-bytes"], {"type": int, "default": None,
                                "help": "skip files larger than this size (default: 1048576)"}),
        (["--profile"], {
            "choices": ["auto", "local", "git", "gdrive-sync",
                        "onedrive-sharepoint", "dropbox"],
            "default": "auto",
            "help": "validated folder profile override (default: auto)",
        }),
        help="bounded content/name search")
    add("list", cmd_list,
        (["path"], {"nargs": "?", "default": "."}),
        (["--kind"], {"choices": ["all", "file", "directory"],
                       "default": "all", "help": "result kind (default: all)"}),
        (["--name"], {"default": "*", "metavar": "GLOB",
                       "help": "filename/path glob (default: *)"}),
        (["--exclude"], {"action": "append", "default": [], "metavar": "GLOB",
                          "help": "skip matching files or directory subtrees; repeatable"}),
        (["--fast"], {"action": "store_true",
                       "help": "compatibility alias; bounded mode is already the default"}),
        (["--deep"], {"action": "store_true",
                       "help": "explicit larger traversal profile"}),
        (["--max-seconds"], {"type": float, "default": None,
                             "help": "hard wall-clock deadline (default: 3)"}),
        (["--max-files"], {"type": int, "default": None,
                           "help": "stop after inspecting this many files"}),
        (["--max-entries"], {"type": int, "default": None,
                             "help": "stop after visiting this many files/directories"}),
        (["--max-depth"], {"type": int, "default": None,
                           "help": "maximum directory depth below the root"}),
        (["--max-results"], {"type": int, "default": None,
                             "help": "stop after returning this many paths (default: 500)"}),
        (["--profile"], {
            "choices": ["auto", "local", "git", "gdrive-sync",
                        "onedrive-sharepoint", "dropbox"],
            "default": "auto",
            "help": "validated folder profile override (default: auto)",
        }),
        help="bounded file listing")
    add("checkout", cmd_checkout, (["path"], {}),
        (["control_target"], {
            "nargs": "?", "default": "", "metavar": "PATH_OR_TRANSACTION",
            "help": argparse.SUPPRESS,
        }),
        (["--mode"], {"choices": ["auto", "preserve", "data"],
                       "default": "auto",
                       "help": "preserve .xlsx/.xlsm by default; data is lossy"}),
        (["--workspace-dir"], {
            "default": "",
            "help": ("working-copy directory; preserved Excel defaults to a "
                     "non-synced Guardrails workspace"),
        }),
        (["--expected-working-hash"], {
            "default": "", "help": argparse.SUPPRESS,
        }),
        help="create a tracked working copy")
    add("convert", cmd_convert, (["path"], {}), (["--dest"], {"default": ""}),
        help="convert to an editable working format")
    add("diff", cmd_diff, (["path"], {}), help="compare a checkout with its source")
    add("publish", cmd_publish, (["path"], {}), (["--force"], {"action": "store_true"}),
        (["--retry-seconds"], {"type": float, "default": 5.0,
                                "help": "bounded retry window for a busy target"}),
        help="archive current version and replace with the working copy")
    add(
        "publish-file", cmd_publish_file,
        (["--staged"], {"required": True, "help": "validated temporary output"}),
        (["--target"], {"required": True, "help": "literal live target path"}),
        (["--expected-hash"], {
            "default": "", "help": "expected live SHA-256, or absent",
        }),
        (["--expected-staged-hash"], {
            "default": "", "help": "expected staged SHA-256",
        }),
        (["--preserve-against"], {
            "default": "", "metavar": "ORIGINAL",
            "help": "Office preservation baseline; required for a new .xlsm target",
        }),
        (["--expected-preservation-hash"], {
            "default": "", "metavar": "SHA256",
            "help": "expected SHA-256 of --preserve-against",
        }),
        (["--retry-seconds"], {
            "type": float, "default": 5.0,
            "help": "bounded retry window for sharing violations/EBUSY",
        }),
        (["--office-validation-tier"], {
            "choices": ["auto", "package", "office-schema", "excel-strict"],
            "default": "auto",
            "help": argparse.SUPPRESS,
        }),
        (["--dry-run"], {"action": "store_true",
                           "help": "validate hashes without publishing"}),
        help="hash-guarded atomic publication of a staged file",
    )
    add("archive", cmd_archive, (["paths"], {"nargs": "+"}),
        (["--reason"], {"default": ""}),
        help="reversible delete: move into the archive store")
    add(
        "unlink-link", cmd_unlink_link,
        (["path"], {"help": "literal symbolic-link or Windows junction path"}),
        (["--expected-target"], {
            "default": "", "help": "refuse unless the recorded link target matches",
        }),
        (["--reason"], {"default": ""}),
        (["--dry-run"], {"action": "store_true",
                           "help": "inspect and report without unlinking"}),
        help="archive link metadata and remove only the link object",
    )
    file_parser = sub.add_parser(
        "file", parents=[common],
        help="bounded file operations",
        description=("Exact text-file operations. Choose an operation, then run "
                     "`agw file <operation> --help` for only its arguments."),
    )
    file_sub = file_parser.add_subparsers(
        dest="file_op", required=True, metavar="operation",
    )

    def add_file(name, summary, *specs, example=""):
        parser_for_op = file_sub.add_parser(
            name, parents=[common], help=summary, description=summary,
            epilog=(f"example:\n  {example}" if example else None),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser_for_op.add_argument("path", help="literal target file path")
        for spec in specs:
            parser_for_op.add_argument(*spec[0], **spec[1])
        parser_for_op.set_defaults(fn=cmd_file)
        return parser_for_op

    file_expected = (["--expected-hash", "--expected-file-hash"], {
        "default": "", "help": "expected SHA-256, or 'absent' for creation",
    })
    file_existing_expected = (["--expected-hash", "--expected-file-hash"], {
        "default": "", "help": "expected SHA-256 of the existing target file",
    })
    file_dry_run = (["--dry-run"], {
        "action": "store_true", "help": "validate and hash without writing or archiving",
    })
    add_file(
        "read", "Read bounded UTF-8 text without scanning sibling files",
        (["--start-line"], {"type": int, "default": 1, "help": "first line; 1-based"}),
        (["--start-byte"], {
            "type": int, "default": None,
            "help": "exact continuation offset returned by a prior read",
        }),
        (["--limit"], {"type": int, "default": file_ops.DEFAULT_READ_LINES,
                        "help": "maximum lines"}),
        (["--max-bytes"], {"type": int, "default": file_ops.DEFAULT_READ_BYTES,
                            "help": ("optional output budget; default 32768, maximum "
                                     "262144; usually omit")}),
        example="agw file read app.log --start-line 201 --limit 100 --json",
    )
    add_file(
        "write", "Write UTF-8 text atomically from a file or stdin",
        (["--content-file"], {"required": True, "help": "UTF-8 source file or -"}),
        file_expected, file_dry_run,
        example="agw file write app.js --content-file app.js.new --expected-hash SHA256",
    )
    add_file(
        "patch", "Apply a numbered unified diff atomically",
        (["--patch"], {
            "required": True,
            "help": "standard unified diff file or -; bare '@@' is invalid",
        }),
        file_existing_expected, file_dry_run,
        example="agw file patch app.js --patch change.diff --expected-hash SHA256",
    )
    add_file(
        "replace", "Replace exact UTF-8 text atomically",
        (["--old"], {"default": None, "help": "old text; prefer --old-file for large text"}),
        (["--new"], {"default": None, "help": "new text; prefer --new-file for large text"}),
        (["--old-file"], {"default": "", "help": "UTF-8 old-text file"}),
        (["--new-file"], {"default": "", "help": "UTF-8 new-text file"}),
        (["--all"], {"action": "store_true", "help": "replace every exact match"}),
        file_existing_expected, file_dry_run,
        example="agw file replace app.js --old-file old.txt --new-file new.txt --expected-hash SHA256",
    )
    plan_parser = file_sub.add_parser(
        "plan", parents=[common],
        help="materialize a validated multi-file text transaction",
        description=("Validate every write, patch, and replacement and write one "
                     "self-contained plan without changing target files."),
        epilog=("operations JSON:\n"
                "  {\"version\":1,\"operations\":[{\"op\":\"patch\","
                "\"path\":\"app.js\",\"patch_file\":\"change.diff\","
                "\"expected_hash\":\"SHA256\"}]}\n"
                "payloads: write content|content_file; patch patch|patch_file; "
                "replace old|old_file plus new|new_file\n"
                "example:\n  agw file plan --operations-file ops.json "
                "--plan-file change.agw-plan --expected-plan-hash absent --json"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    plan_parser.add_argument(
        "--operations-file", required=True,
        help="version-1 operations JSON file or - for stdin",
    )
    plan_parser.add_argument("--plan-file", required=True, help="plan output path")
    plan_parser.add_argument(
        "--expected-plan-hash", default="absent",
        help="expected existing plan SHA-256, or absent",
    )
    plan_parser.add_argument(
        "--cwd", default="", help="base folder for relative paths in operations JSON",
    )
    plan_parser.set_defaults(fn=cmd_file)
    apply_plan_parser = file_sub.add_parser(
        "apply-plan", parents=[common],
        help="apply a hash-bound multi-file plan as one transaction",
        description=("Verify the plan hash and every target precondition, capture all "
                     "pre-images, then publish the complete set with rollback on failure."),
        epilog=("example:\n  agw file apply-plan change.agw-plan "
                "--expected-plan-hash SHA256 --json"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    apply_plan_parser.add_argument(
        "plan_file", nargs="?", default="", help="self-contained plan file",
    )
    apply_plan_parser.add_argument(
        "--plan-file", dest="plan_file_option", default="",
        help="self-contained plan file (alternative to the positional form)",
    )
    apply_plan_parser.add_argument(
        "--expected-plan-hash", required=True, help="exact SHA-256 of the plan file",
    )
    apply_plan_parser.set_defaults(fn=cmd_file)
    add(
        "run", cmd_run,
        (["--workflow"], {"default": "", "metavar": "ID",
                           "help": "workflow"}),
        (["--param"], {"action": "append", "default": [], "metavar": "NAME=VALUE",
                       "help": "typed value; repeat"}),
        (["--output"], {"action": "append", "default": [], "metavar": "FILE",
                        "help": "root-independent output with recovery"}),
        (["--output-root"], {"action": "append", "default": [], "metavar": "DIR",
                              "help": "not an output boundary"}),
        (["--output-pattern"], {"action": "append", "default": [], "metavar": "GLOB",
                                 "help": "sidecar glob; needs root"}),
        (["--expected-hash"], {"action": "append", "default": [], "metavar": "HASH",
                               "help": "hash/absent per output"}),
        (["--cwd"], {"default": "", "metavar": "DIR", "help": "working dir"}),
        (["--timeout-seconds"], {
            "type": float, "default": 300.0, "metavar": "SECONDS",
            "help": argparse.SUPPRESS,
        }),
        (["--isolation"], {
            "choices": ["observed", "read-only", "strict"], "default": "observed",
            "help": argparse.SUPPRESS,
        }),
        (["--network"], {
            "choices": ["inherit", "deny"], "default": "inherit",
            "help": argparse.SUPPRESS,
        }),
        (["--dry-run"], {"action": "store_true",
                          "help": "validate only; no execution"}),
        (["command"], {"nargs": argparse.REMAINDER, "metavar": "...",
                        "help": "command after --"}),
        help="run with declared recoverable outputs",
    )
    run_plan_parser = sub.add_parser(
        "run-plan", parents=[common], help="create or apply a hash-bound run plan",
        description="Fresh, canonical, single-use plans for bounded local scripts.",
    )
    run_plan_sub = run_plan_parser.add_subparsers(
        dest="plan_op", required=True, metavar="operation",
    )
    run_plan_create = run_plan_sub.add_parser(
        "create", parents=[common], help="create an inert single-use run plan",
        description=("Create a canonical run plan from duplicate-key-safe JSON and "
                     "write it through the recoverable Guardrails file boundary."),
    )
    run_plan_create.add_argument(
        "--spec-file", required=True,
        help="JSON object describing command, mode, artifacts, and isolation",
    )
    run_plan_create.add_argument("--plan-file", required=True, help="plan output path")
    run_plan_create.add_argument(
        "--expected-plan-file-hash", default="absent",
        help="expected current SHA-256 of the plan file, or absent",
    )
    run_plan_create.set_defaults(fn=cmd_run_plan)
    run_plan_apply = run_plan_sub.add_parser(
        "apply", parents=[common], help="validate, claim once, and apply a run plan",
        description=("Require the canonical plan hash, then validate provider support "
                     "before the single-use claim and any execution."),
    )
    run_plan_apply.add_argument("--plan-file", required=True, help="run-plan JSON file")
    run_plan_apply.add_argument(
        "--expected-plan-hash", required=True,
        help="exact canonical plan_sha256 recorded inside the plan",
    )
    run_plan_apply.add_argument(
        "--dry-run", action="store_true",
        help="validate only; do not claim, execute, or publish",
    )
    run_plan_apply.set_defaults(fn=cmd_run_plan)

    publish_plan_parser = sub.add_parser(
        "publish-plan", parents=[common],
        help="staged batch publication plans",
        description=("Hash-bound recoverable-set publication with sequential "
                     "per-file visibility."),
    )
    publish_plan_sub = publish_plan_parser.add_subparsers(
        dest="plan_op", required=True, metavar="operation",
    )
    publish_plan_create = publish_plan_sub.add_parser(
        "create", parents=[common], help="create an inert staged publication plan",
    )
    publish_plan_create.add_argument(
        "--operations-file", required=True,
        help="duplicate-key-safe JSON array of staged/target operations",
    )
    publish_plan_create.add_argument("--plan-file", required=True, help="plan output path")
    publish_plan_create.add_argument("--cwd", default="", help="base for relative paths")
    publish_plan_create.add_argument(
        "--expected-plan-file-hash", default="absent",
        help="expected current SHA-256 of the plan file, or absent",
    )
    publish_plan_create.set_defaults(fn=cmd_publish_plan)
    publish_plan_apply = publish_plan_sub.add_parser(
        "apply", parents=[common], help="apply an exact staged publication plan",
    )
    publish_plan_apply.add_argument("--plan-file", required=True, help="publish-plan JSON file")
    publish_plan_apply.add_argument(
        "--expected-plan-hash", required=True,
        help="exact canonical plan_sha256 recorded inside the plan",
    )
    publish_plan_apply.add_argument(
        "--dry-run", action="store_true",
        help="validate candidates and preconditions without publication",
    )
    publish_plan_apply.set_defaults(fn=cmd_publish_plan)
    publish_plan_recover = publish_plan_sub.add_parser(
        "recover", parents=[common],
        help="inspect or finalize one PREPARED publication",
        description=("No automatic roll-forward. Inspect is read-only; rollback "
                     "fails until a crash-resumable journal exists; finalize-observed "
                     "records only an authenticated all-after state."),
    )
    publish_plan_recover.add_argument(
        "transaction_id", help="prepared publication transaction id",
    )
    publish_plan_recover.add_argument(
        "--action", dest="recovery_action", required=True,
        choices=["inspect", "rollback", "finalize-observed"],
        help="inspect, unavailable rollback, or all-after finalization",
    )
    publish_plan_recover.set_defaults(fn=cmd_publish_plan)
    workflow_parser = sub.add_parser(
        "workflow", parents=[common],
        help="trusted script contracts",
        description="Hash-bound script contracts; choose an operation for leaf help.",
    )
    workflow_sub = workflow_parser.add_subparsers(
        dest="workflow_op", required=True, metavar="operation",
    )
    workflow_trust = workflow_sub.add_parser(
        "trust", parents=[common],
        help="install one reviewed hash-checked manifest",
        description=("Validate and copy a workflow manifest into the protected "
                     "Guardrails trust store. Repository manifests are inert until "
                     "this explicit operation is approved."),
    )
    workflow_trust.add_argument("manifest", help="literal manifest JSON file")
    workflow_trust.add_argument(
        "--expected-manifest-hash", required=True,
        help="expected SHA-256 of the manifest file",
    )
    workflow_trust.add_argument(
        "--approve-trust", action="store_true",
        help="confirm that the manifest and resolved script identity were reviewed",
    )
    workflow_trust.add_argument(
        "--replace", action="store_true",
        help="replace a different trusted record with the same id after review",
    )
    workflow_trust.add_argument(
        "--progress", action="store_true",
        help="report trust phases to stderr",
    )
    workflow_trust.set_defaults(fn=cmd_workflow)
    workflow_list = workflow_sub.add_parser(
        "list", parents=[common], help="list trusted workflows and purposes",
    )
    workflow_list.set_defaults(fn=cmd_workflow)
    workflow_match = workflow_sub.add_parser(
        "match", parents=[common], help="match an exact script command",
    )
    workflow_match.add_argument("--cwd", default="", help="command working directory")
    workflow_match.add_argument(
        "command", nargs=argparse.REMAINDER, metavar="...", help="command after --",
    )
    workflow_match.set_defaults(fn=cmd_workflow)
    workflow_propose = workflow_sub.add_parser(
        "propose", parents=[common],
        help="draft",
        description=("Build and validate a workflow proposal without writing a "
                     "manifest or changing trusted workflow state."),
    )
    workflow_propose.add_argument("--id", dest="workflow_id", required=True,
                                  help="stable workflow id")
    workflow_propose.add_argument("--cwd", default="", help="command working directory")
    workflow_propose.add_argument("--output", action="append", default=[], required=True,
                                  help="exact declared output; repeat")
    workflow_propose.add_argument("--expected", action="append", default=[], required=True,
                                  help="any/absent/present/SHA-256 per output; repeat")
    workflow_propose.add_argument("--allowed-root", action="append", default=[], required=True,
                                  help="permitted output root; repeat")
    workflow_propose.add_argument("--description", default="", help="short reviewed purpose")
    workflow_propose.add_argument(
        "command", nargs=argparse.REMAINDER, metavar="...", help="command after --",
    )
    workflow_propose.set_defaults(fn=cmd_workflow)
    workflow_info = workflow_sub.add_parser(
        "info", parents=[common], help="verify and inspect one trusted workflow",
    )
    workflow_info.add_argument("workflow_id", help="trusted workflow id")
    workflow_info.set_defaults(fn=cmd_workflow)
    workflow_validate = workflow_sub.add_parser(
        "validate", parents=[common],
        help="validate an inert manifest and script hash",
    )
    workflow_validate.add_argument("manifest", help="literal manifest JSON file")
    workflow_validate.add_argument(
        "--expected-manifest-hash", default="",
        help="optional expected manifest SHA-256",
    )
    workflow_validate.set_defaults(fn=cmd_workflow)
    workflow_status = workflow_sub.add_parser(
        "status", parents=[common],
        help="compare a manifest with this machine's trusted record",
    )
    workflow_status.add_argument("manifest", help="literal manifest JSON file")
    workflow_status.set_defaults(fn=cmd_workflow)
    workflow_init = workflow_sub.add_parser(
        "init", parents=[common],
        help="generate an escaped validated v2 manifest",
    )
    workflow_init.add_argument("--script", required=True, help="versioned script path")
    workflow_init.add_argument("--manifest", required=True, help="manifest output path")
    workflow_init.add_argument("--id", dest="workflow_id", required=True,
                               help="stable workflow id")
    workflow_init.add_argument("--runtime", choices=["python", "node", "powershell"],
                               default="", help="inferred from script extension")
    workflow_init.add_argument("--arg", action="append", default=[],
                               help="exact bound script argument; repeat")
    workflow_init.add_argument("--output", action="append", default=[], required=True,
                               help="exact output template; repeat")
    workflow_init.add_argument("--expected", action="append", default=[],
                               help="any/absent/present/SHA-256 per output")
    workflow_init.add_argument("--allowed-root", action="append", default=[], required=True,
                               help="permitted output-root template; repeat")
    workflow_init.add_argument("--description", default="", help="short reviewed purpose")
    workflow_init.add_argument("--expected-manifest-hash", default="absent",
                               help="expected existing manifest SHA-256, or absent")
    workflow_init.set_defaults(fn=cmd_workflow)
    add("move", cmd_move, (["src"], {}), (["dest"], {}),
        help="logged, undoable move or rename")
    sub._name_parser_map["rename"] = sub._name_parser_map["move"]
    add("snapshot", cmd_snapshot, (["path"], {"nargs": "?", "default": "."}),
        (["--reason"], {"default": ""}), (["--force"], {"action": "store_true"}),
        help="capture a recoverable folder pre-image")
    add("restore", cmd_restore, (["path"], {}),
        (["--version"], {"type": int, "default": 0}),
        help="recover an archived version")
    add("undo", cmd_undo,
        (["--transaction"], {
            "default": "", "metavar": "ID",
            "help": "reverse one exact file-mutation transaction",
        }),
        help="reverse recovery")
    add("status", cmd_status,
        (["--cwd"], {"default": "", "help": "show only checkouts under this folder"}),
        (["--stale-days"], {"type": float, "default": 30.0,
                             "help": "age threshold used for stale warnings"}),
        help="show checkout/recovery status")
    add("log", cmd_log, (["-n"], {"type": int, "default": 20}),
        help="show recent recovery operations")
    add("doctor", cmd_doctor, help="check environment, policy, and recovery health")
    add("schema", cmd_schema,
        (["command_path"], {"nargs": "+", "metavar": "COMMAND",
                            "help": "narrow command path, for example: file apply-plan"}),
        help="argument schema")
    office_parser = sub.add_parser(
        "office", parents=[common],
        help="guarded Office operations",
        description="Guarded Office operations; choose one for leaf help.",
    )
    office_sub = office_parser.add_subparsers(
        dest="op", required=True, metavar="operation",
    )

    def add_office(name, summary, *specs, example="", aliases=()):
        parser_for_op = office_sub.add_parser(
            name, aliases=list(aliases), parents=[common], help=summary,
            description=summary,
            epilog=(f"example:\n  {example}" if example else None),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser_for_op.add_argument("path", help="Office file path")
        for spec in specs:
            parser_for_op.add_argument(*spec[0], **spec[1])
        parser_for_op.set_defaults(fn=cmd_office, op=name)
        return parser_for_op

    dry_run = (["--dry-run"], {"action": "store_true",
                                "help": "validate and report without writing or archiving"})
    sheet = (["--sheet"], {"default": "", "help": "worksheet name"})
    table = (["--table"], {"default": "", "help": "Excel table name (required)"})
    expected_hash = (["--expected-file-hash"], {
        "default": "", "help": "refuse if the live SHA-256 differs",
    })
    page = (
        (["--offset"], {"type": int, "default": 0}),
        (["--limit"], {"type": int, "default": 50}),
    )

    add_office(
        "validate", "Validate OOXML",
        (["--tier"], {
            "choices": ["package", "office-schema", "excel-strict"],
            "default": "office-schema",
            "help": "cumulative validation tier",
        }),
        example="agw office validate workbook.xlsx --tier excel-strict --json",
    )
    add_office(
        "info", "Inspect Office structure and risks",
        (["--scope"], {"choices": ["tables", "names", "preservation"], "default": "",
                        "help": "limit Excel details"}),
        example="agw office info workbook.xlsx --scope tables --json",
        aliases=("inspect",),
    )
    add_office(
        "validate-preservation", "Verify protected Excel content",
        (["--against"], {"required": True, "help": "original .xlsx/.xlsm baseline"}),
        (["--expected-original-hash"], {
            "default": "", "help": "expected SHA-256 of the original baseline",
        }),
        example="agw office validate-preservation staged.xlsm --against original.xlsm --json",
    )
    add_office(
        "normalize", "Remove allowlisted OOXML metadata",
        (["--output"], {"required": True, "help": "normalized .xlsx output path"}),
        expected_hash,
        (["--expected-output-hash"], {
            "default": "", "help": "expected output SHA-256, or absent",
        }),
        dry_run,
        example="agw office normalize input.xlsx --output normalized.xlsx --expected-output-hash absent --json",
    )
    add_office(
        "get-text", "Extract text from a Word or PowerPoint file",
        example="agw office get-text report.docx --json",
    )
    add_office(
        "replace-text", "Replace a unique Office text occurrence",
        (["--find"], {"default": "", "help": "text to find (required)"}),
        (["--replace"], {"default": "", "help": "replacement text"}),
        (["--all"], {"action": "store_true",
                     "help": "replace all occurrences"}),
        (["--nth"], {"type": int, "default": 0,
                     "help": "replace occurrence N (1-based)"}),
        dry_run,
        example='agw office replace-text report.docx --find "Old" --replace "New"',
    )
    add_office(
        "set-cell", "Set one Excel cell with a guarded atomic write",
        (["--sheet"], {"default": "", "help": "worksheet name (required)"}),
        (["--cell"], {"default": "", "help": "cell reference, for example B2 (required)"}),
        (["--value"], {"default": "", "help": "value; empty clears the cell"}),
        (["--text"], {"action": "store_true", "help": "store literal text"}),
        expected_hash, dry_run,
        example='agw office set-cell workbook.xlsx --sheet Data --cell B2 --value 55',
    )
    add_office(
        "append-rows", "Append rectangular rows to an Excel worksheet",
        (["--sheet"], {"default": "", "help": "worksheet name (required)"}),
        (["--rows"], {"default": "", "help": "JSON row array or - for stdin"}),
        (["--from-csv"], {"default": "", "help": "CSV file containing rows"}),
        (["--text"], {"action": "store_true", "help": "store literal text"}),
        example="agw office append-rows workbook.xlsx --sheet Data --from-csv rows.csv",
    )
    add_office(
        "read-table", "Read a compact, paginated Excel table",
        table, sheet,
        (["--columns"], {"default": "", "help": "comma-separated columns"}),
        (["--where-json"], {"default": "", "help": "JSON filter or - for stdin"}),
        *page,
        (["--values-only"], {"action": "store_true",
                             "help": "omit cell type metadata"}),
        (["--include-formulas"], {"action": "store_true",
                                  "help": "return both cached values and formulas"}),
        example="agw office read-table workbook.xlsx --table Orders --limit 50 --json",
    )
    add_office(
        "read-range", "Read a bounded Excel range",
        (["--sheet"], {"required": True, "help": "worksheet name"}),
        (["--range"], {"required": True, "help": "finite A1 rectangle"}),
        (["--formulas"], {"action": "store_true",
                           "help": "return both cached values and formulas"}),
        example="agw office read-range workbook.xlsx --sheet Data --range A1:D20 --formulas --json",
    )
    add_office(
        "validate-formulas", "Inspect formulas and cached-result coverage",
        *page,
        example="agw office validate-formulas workbook.xlsx --limit 50 --json",
    )
    add_office(
        "ensure-table", "Create or validate an Excel table",
        table,
        (["--sheet"], {"default": "", "help": "worksheet name (required)"}),
        (["--headers-json"], {"default": "", "help": "JSON header array or -"}),
        (["--headers-file"], {"default": "", "help": "JSON header file"}),
        (["--columns-json"], {"default": "", "help": "JSON column metadata or -"}),
        (["--columns-file"], {"default": "", "help": "JSON column metadata file"}),
        (["--range"], {"default": "", "help": "explicit rectangular range"}),
        (["--style"], {"default": "", "help": "Excel table style"}),
        (["--create-sheet"], {"action": "store_true", "help": "create missing sheet"}),
        expected_hash, dry_run,
        example="agw office ensure-table workbook.xlsx --sheet Data --table Orders --headers-file headers.json --dry-run",
    )
    add_office(
        "append-table-row", "Append one typed table row",
        table, sheet,
        (["--row-json"], {"default": "", "help": "JSON row object or - for stdin"}),
        (["--row-file"], {"default": "", "help": "JSON row file"}),
        (["--unique-column"], {"action": "append", "default": [],
                                "help": "uniqueness column; repeat for composites"}),
        (["--unique-columns-json"], {"default": "", "help": "JSON column array or -"}),
        (["--unique-columns-file"], {"default": "", "help": "JSON column-array file"}),
        expected_hash, dry_run,
        (["--coerce-iso-dates"], {"action": "store_true", "help": "coerce ISO dates"}),
        example="agw office append-table-row workbook.xlsx --table Orders --row-file row.json --unique-column ID",
    )
    add_office(
        "update-table-row", "Update one exact-key table row",
        table, sheet,
        (["--key-column"], {"default": "", "help": "exact key column (required)"}),
        (["--key"], {"default": "", "help": "string key"}),
        (["--key-json"], {"default": "", "help": "typed JSON scalar or -"}),
        (["--set-json"], {"default": "", "help": "JSON updates object or -"}),
        (["--set-file"], {"default": "", "help": "JSON updates file"}),
        expected_hash, dry_run,
        (["--coerce-iso-dates"], {"action": "store_true", "help": "coerce ISO dates"}),
        example="agw office update-table-row workbook.xlsx --table Orders --key-column ID --key 42 --set-file updates.json",
    )
    add_office(
        "outline", "List stable, paginated Word block IDs", *page,
        example="agw office outline report.docx --limit 50 --json",
    )
    add_office(
        "read-blocks", "Read selected Word blocks",
        (["--ids"], {"default": "", "help": "comma-separated block IDs"}),
        example="agw office read-blocks report.docx --ids p1-abc,p2-def --json",
    )
    add_office(
        "patch", "Apply guarded Word block operations",
        (["--ops-json"], {"default": "", "help": "JSON operation array or -"}),
        (["--ops-file"], {"default": "", "help": "JSON operations file"}),
        expected_hash, dry_run,
        example="agw office patch report.docx --ops-file patch.json --expected-file-hash SHA256",
    )
    add("prune", cmd_prune, (["--yes-i-am-a-human"], {"action": "store_true"}),
        help="human-only permanent archive cleanup")

    contract_problem = agw_contract.registration_problem(sub.choices)
    if contract_problem:
        raise RuntimeError("AGW command contract mismatch: " + contract_problem)

    args = parser.parse_args(argv)
    if not hasattr(args, "json"):
        args.json = False
    try:
        args.fn(args)
    except PermissionError:
        _err(
            "Guardrails was denied access by the host sandbox and stopped "
            "without changing permissions or bypassing the sandbox. The requested "
            "operation did not complete. Ask the agent to retry using the host's "
            "normal approval."
        )


if __name__ == "__main__":
    main()
