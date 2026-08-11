"""Killable, progress-reporting worker for bounded filesystem scans."""
from __future__ import annotations

import fnmatch
import json
import os
import queue
import re
import stat
import subprocess
import sys
import threading
import time
from typing import Callable, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

from core import profiles

MAX_REPORTED_ENTRIES = 50
MAX_EXTENSION_KEYS = 200
MAX_STDERR_TAIL_CHARS = 2048
MAX_MATCH_PREVIEW_CHARS = 240
BOUNDED_MAX_SECONDS = 3.0
BOUNDED_MAX_FILES = 5_000
BOUNDED_MAX_ENTRIES = 10_000
BOUNDED_MAX_DEPTH = 4
DEEP_MAX_SECONDS = 30.0
DEEP_MAX_FILES = 100_000
DEEP_MAX_ENTRIES = 200_000
DEEP_MAX_DEPTH = 64
DEFAULT_MAX_MATCHES = 100
DEFAULT_MAX_RESULTS = 500
DEFAULT_MAX_FILE_BYTES = 1024 * 1024
HARD_MAX_SECONDS = 300.0
HARD_MAX_FILES = 1_000_000
HARD_MAX_ENTRIES = 2_000_000
HARD_MAX_DEPTH = 256
HARD_MAX_MATCHES = 10_000
HARD_MAX_FILE_BYTES = 16 * 1024 * 1024
IGNORED_DIRECTORIES = {
    "_workspace", ".git", ".hg", ".svn", "node_modules",
    "bower_components", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".tox", ".nox", ".cache", ".next",
    ".nuxt", "dist", "build", "target", "vendor",
}
SENSITIVE_DIRECTORIES = {".ssh", ".aws", ".azure", ".kube", "gcloud"}
SENSITIVE_NAMES = {
    ".netrc", ".pgpass", ".git-credentials", "credentials", "credentials.json",
    "service_account.json", "service-account.json", "secrets.json", "secrets.yaml",
    "secrets.yml",
}
FATAL_EXIT_CODES = {
    "path_not_found": 10,
    "not_directory": 11,
    "path_validation_error": 12,
}
EXIT_FATAL_CODES = {value: key for key, value in FATAL_EXIT_CODES.items()}


def initial_result(request: dict) -> dict:
    if request.get("operation") in {"search", "list"}:
        return initial_search_result(request)
    no_size = bool(request["no_size"])
    return {
        "path": request["path"],
        "files": 0,
        "dirs": 0,
        "bytes": None if no_size else 0,
        "by_ext": {},
        "placeholders": [],
        "gdoc_stubs": [],
        "sync_artifacts": [],
        "profile": "unknown",
        "profile_detection": "pending",
        "placeholder_detection": "limited" if no_size else "available",
        "complete": True,
        "stop_reason": "",
        "files_inspected": 0,
        "directories_inspected": 0,
        "entries_seen": 0,
        "elapsed_seconds": 0.0,
        "bounds": {
            "max_seconds": request["max_seconds"],
            "max_files": request["max_files"],
            "max_entries": request.get(
                "max_entries", max(request["max_files"] * 2, 1)
            ),
            "max_depth": request["max_depth"],
            "no_size": no_size,
        },
        "ignored_directories": sorted(IGNORED_DIRECTORIES),
        "errors": [],
    }


def initial_search_result(request: dict) -> dict:
    return {
        "operation": request.get("operation", "search"),
        "path": request["path"],
        "query": request["query"],
        "regex": bool(request["regex"]),
        "ignore_case": bool(request["ignore_case"]),
        "filename_only": bool(request.get("filename_only")),
        "include_globs": list(request.get("include_globs", [])),
        "exclude_globs": list(request.get("exclude_globs", [])),
        "kind": request.get("kind", "file"),
        "matches": [],
        "matches_found": 0,
        "entries_tested": 0,
        "files_inspected": 0,
        "files_searched": 0,
        "files_skipped_binary": 0,
        "files_skipped_large": 0,
        "files_skipped_placeholder": 0,
        "files_skipped_sensitive": 0,
        "files_skipped_link": 0,
        "directories_inspected": 0,
        "entries_seen": 0,
        "profile": "unknown",
        "profile_detection": "pending",
        "complete": True,
        "stop_reason": "",
        "elapsed_seconds": 0.0,
        "bounds": {
            "max_seconds": request["max_seconds"],
            "max_files": request["max_files"],
            "max_entries": request["max_entries"],
            "max_depth": request["max_depth"],
            "max_matches": request["max_matches"],
            "max_file_bytes": request["max_file_bytes"],
        },
        "ignored_directories": sorted(IGNORED_DIRECTORIES),
        "errors": [],
    }


def _elapsed(request: dict) -> float:
    return round(max(0.0, time.monotonic() - request["started_at"]), 6)


def _message(kind: str, result: dict, request: dict, **extra) -> dict:
    result["elapsed_seconds"] = _elapsed(request)
    return {"kind": kind, "result": result, **extra}


def _record_error(result: dict, path: str, exc: BaseException) -> None:
    if len(result["errors"]) < MAX_REPORTED_ENTRIES:
        item = {
            "path": path,
            "error": type(exc).__name__,
        }
        detail = str(exc).strip()
        if detail:
            item["detail"] = detail[:160]
        result["errors"].append(item)


def _test_block(request: dict, stage: str) -> None:
    """Deterministic blocking-call injection, enabled only in test mode."""
    if os.environ.get("AGW_TEST_MODE") == "1" \
            and request.get("_test_block_stage") == stage:
        time.sleep(float(request.get("_test_block_seconds", 60.0)))


def _deadline_reached(request: dict) -> bool:
    return time.monotonic() >= request["worker_deadline"]


def scan_in_process(
    request: dict,
    emit: Optional[Callable[[str, dict], None]] = None,
) -> tuple[dict, Optional[dict]]:
    """Run one scan. The caller must isolate this function in a process."""
    result = initial_result(request)

    def publish(kind="progress", **extra):
        result["elapsed_seconds"] = _elapsed(request)
        if emit is not None:
            emit(kind, {"result": result, **extra})

    path = request["path"]
    publish()
    _test_block(request, "path_validation")
    try:
        path_state = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        fatal = {"code": "path_not_found", "message": f"path not found: {path}"}
        publish("fatal", fatal=fatal)
        return result, fatal
    except OSError as exc:
        fatal = {
            "code": "path_validation_error",
            "message": f"scan could not validate path: {type(exc).__name__}",
        }
        publish("fatal", fatal=fatal)
        return result, fatal
    if not stat.S_ISDIR(path_state.st_mode):
        fatal = {
            "code": "not_directory",
            "message": f"scan requires a directory, not a file: {path}",
        }
        publish("fatal", fatal=fatal)
        return result, fatal

    publish()
    _test_block(request, "profile_detection")
    override = request.get("profile_override", "auto")
    try:
        profile = profiles.detect(
            path,
            assume_directory=True,
            override="" if override == "auto" else override,
        )
        result["profile"] = profile.name
        result["profile_detection"] = "explicit" if override != "auto" else "complete"
    except (OSError, ValueError) as exc:
        profile = profiles.BUILTIN["unknown"]
        result["profile_detection"] = "error"
        _record_error(result, ".", exc)
    publish()

    stack = [(path, 0)]
    max_entries = request.get("max_entries", max(request["max_files"] * 2, 1))
    while stack:
        if _deadline_reached(request):
            result["complete"] = False
            result["stop_reason"] = "max_seconds"
            publish("final")
            return result, None

        dirpath, depth = stack.pop()
        result["directories_inspected"] += 1
        publish()
        _test_block(request, "scandir")
        try:
            iterator = os.scandir(dirpath)
        except OSError as exc:
            result["complete"] = False
            result["stop_reason"] = result["stop_reason"] or "scan_errors"
            _record_error(result, os.path.relpath(dirpath, path), exc)
            publish()
            continue

        try:
            while True:
                if _deadline_reached(request):
                    result["complete"] = False
                    result["stop_reason"] = "max_seconds"
                    publish("final")
                    return result, None
                if result["entries_seen"] >= max_entries:
                    result["complete"] = False
                    result["stop_reason"] = "max_entries"
                    publish("final")
                    return result, None
                publish()
                _test_block(request, "scandir_next")
                try:
                    entry = next(iterator)
                except StopIteration:
                    break
                except OSError as exc:
                    result["complete"] = False
                    result["stop_reason"] = result["stop_reason"] or "scan_errors"
                    _record_error(result, os.path.relpath(dirpath, path), exc)
                    break

                result["entries_seen"] += 1
                publish()
                _test_block(request, "is_dir")
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                except OSError as exc:
                    is_dir = False
                    _record_error(result, os.path.relpath(entry.path, path), exc)

                if is_dir:
                    if entry.name.casefold() in IGNORED_DIRECTORIES:
                        continue
                    result["dirs"] += 1
                    if depth >= request["max_depth"]:
                        result["complete"] = False
                        result["stop_reason"] = result["stop_reason"] or "max_depth"
                    else:
                        stack.append((entry.path, depth + 1))
                    publish()
                    continue

                result["files"] += 1
                result["files_inspected"] += 1
                ext = os.path.splitext(entry.name)[1].lower() or "(none)"
                if ext not in result["by_ext"] \
                        and len(result["by_ext"]) >= MAX_EXTENSION_KEYS:
                    ext = "(other)"
                result["by_ext"][ext] = result["by_ext"].get(ext, 0) + 1
                relative = os.path.relpath(entry.path, path)

                file_state = None
                if not request["no_size"]:
                    publish()
                    _test_block(request, "stat")
                    try:
                        file_state = entry.stat(follow_symlinks=False)
                    except OSError as exc:
                        _record_error(result, relative, exc)
                if file_state is not None:
                    result["bytes"] += int(file_state.st_size)

                if profiles.is_gdoc_stub(entry.path) \
                        and len(result["gdoc_stubs"]) < MAX_REPORTED_ENTRIES:
                    result["gdoc_stubs"].append(relative)
                elif file_state is not None and profiles.is_placeholder(
                        entry.path, st=file_state, profile=profile) \
                        and len(result["placeholders"]) < MAX_REPORTED_ENTRIES:
                    result["placeholders"].append(relative)
                elif profiles.is_sync_artifact(entry.path) \
                        and len(result["sync_artifacts"]) < MAX_REPORTED_ENTRIES:
                    result["sync_artifacts"].append(relative)

                publish()
                if result["files_inspected"] >= request["max_files"]:
                    result["complete"] = False
                    result["stop_reason"] = "max_files"
                    publish("final")
                    return result, None
        finally:
            try:
                iterator.close()
            except OSError:
                pass

    publish("final")
    return result, None


def _path_matches_globs(relative: str, name: str, patterns: list[str]) -> bool:
    relative = relative.replace("\\", "/")
    candidates = (relative, name)
    if os.name == "nt":
        candidates = tuple(value.casefold() for value in candidates)
        patterns = [value.replace("\\", "/").casefold() for value in patterns]
    else:
        patterns = [value.replace("\\", "/") for value in patterns]
    return any(
        fnmatch.fnmatchcase(candidate, pattern)
        for pattern in patterns for candidate in candidates
    )


def _path_selected(relative: str, name: str, request: dict) -> bool:
    excludes = request.get("exclude_globs", [])
    if excludes and _path_matches_globs(relative, name, excludes):
        return False
    includes = request.get("include_globs", [])
    return not includes or _path_matches_globs(relative, name, includes)


def _is_sensitive_search_path(relative: str, name: str) -> bool:
    lowered = name.casefold()
    if lowered.startswith(".env") and not lowered.endswith(
            (".example", ".sample", ".template", ".dist")):
        return True
    if lowered in SENSITIVE_NAMES or re.fullmatch(
            r"id_(?:rsa|dsa|ecdsa|ed25519)|.*\.(?:pem|key|p12|pfx|jks|keystore|ppk)",
            lowered):
        return True
    parts = {value.casefold() for value in relative.replace("\\", "/").split("/")}
    return bool(parts & SENSITIVE_DIRECTORIES)


def search_in_process(
    request: dict,
    emit: Optional[Callable[[str, dict], None]] = None,
) -> tuple[dict, Optional[dict]]:
    """Run one bounded content search. The caller must isolate it in a process."""
    result = initial_search_result(request)
    pending_matches = []

    def publish(kind="progress", **extra):
        result["elapsed_seconds"] = _elapsed(request)
        if emit is None:
            return
        if kind == "final" or kind == "fatal":
            emit(kind, {"result": result, **extra})
            pending_matches.clear()
            return
        snapshot = {key: value for key, value in result.items() if key != "matches"}
        payload = {"result": snapshot, "merge_result": True, **extra}
        if pending_matches:
            payload["append_matches"] = list(pending_matches)
            pending_matches.clear()
        emit(kind, payload)

    path = request["path"]
    publish()
    _test_block(request, "path_validation")
    try:
        path_state = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        fatal = {"code": "path_not_found", "message": f"path not found: {path}"}
        publish("fatal", fatal=fatal)
        return result, fatal
    except OSError as exc:
        fatal = {
            "code": "path_validation_error",
            "message": f"search could not validate path: {type(exc).__name__}",
        }
        publish("fatal", fatal=fatal)
        return result, fatal
    if not stat.S_ISDIR(path_state.st_mode):
        fatal = {
            "code": "not_directory",
            "message": f"search requires a directory, not a file: {path}",
        }
        publish("fatal", fatal=fatal)
        return result, fatal

    if request.get("glob_query"):
        expression = fnmatch.translate(request["query"])
    else:
        expression = request["query"] if request["regex"] \
            else re.escape(request["query"])
    flags = re.IGNORECASE if request["ignore_case"] else 0
    try:
        matcher = re.compile(expression, flags)
    except re.error as exc:
        fatal = {
            "code": "invalid_pattern",
            "message": f"invalid search pattern: {exc}",
        }
        publish("fatal", fatal=fatal)
        return result, fatal

    def add_match(item: dict) -> bool:
        result["matches"].append(item)
        result["matches_found"] += 1
        pending_matches.append(item)
        publish()
        if result["matches_found"] >= request["max_matches"]:
            result["complete"] = False
            result["stop_reason"] = "max_matches"
            publish("final")
            return True
        return False

    def filename_matches(relative: str) -> bool:
        candidate = relative.replace("\\", "/")
        return bool(matcher.search(candidate))

    publish()
    _test_block(request, "profile_detection")
    override = request.get("profile_override", "auto")
    try:
        profile = profiles.detect(
            path,
            assume_directory=True,
            override="" if override == "auto" else override,
        )
        result["profile"] = profile.name
        result["profile_detection"] = "explicit" if override != "auto" else "complete"
    except (OSError, ValueError) as exc:
        profile = profiles.BUILTIN["unknown"]
        result["profile_detection"] = "error"
        _record_error(result, ".", exc)
    publish()

    stack = [(path, 0)]
    while stack:
        if _deadline_reached(request):
            result["complete"] = False
            result["stop_reason"] = "max_seconds"
            publish("final")
            return result, None

        dirpath, depth = stack.pop()
        result["directories_inspected"] += 1
        publish()
        _test_block(request, "scandir")
        try:
            iterator = os.scandir(dirpath)
        except OSError as exc:
            result["complete"] = False
            result["stop_reason"] = result["stop_reason"] or "search_errors"
            _record_error(result, os.path.relpath(dirpath, path), exc)
            publish()
            continue

        try:
            while True:
                if _deadline_reached(request):
                    result["complete"] = False
                    result["stop_reason"] = "max_seconds"
                    publish("final")
                    return result, None
                if result["entries_seen"] >= request["max_entries"]:
                    result["complete"] = False
                    result["stop_reason"] = "max_entries"
                    publish("final")
                    return result, None
                publish()
                _test_block(request, "scandir_next")
                try:
                    entry = next(iterator)
                except StopIteration:
                    break
                except OSError as exc:
                    result["complete"] = False
                    result["stop_reason"] = result["stop_reason"] or "search_errors"
                    _record_error(result, os.path.relpath(dirpath, path), exc)
                    break

                result["entries_seen"] += 1
                publish()
                try:
                    if entry.is_symlink():
                        result["files_skipped_link"] += 1
                        publish()
                        continue
                except OSError as exc:
                    _record_error(result, os.path.relpath(entry.path, path), exc)
                    publish()
                    continue
                _test_block(request, "is_dir")
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                except OSError as exc:
                    is_dir = False
                    _record_error(result, os.path.relpath(entry.path, path), exc)

                if is_dir:
                    relative = os.path.relpath(entry.path, path)
                    if entry.name.casefold() in IGNORED_DIRECTORIES:
                        continue
                    if request.get("exclude_globs") and _path_matches_globs(
                            relative, entry.name, request["exclude_globs"]):
                        continue
                    if request.get("filename_only") \
                            and request.get("kind") in {"all", "directory"}:
                        result["entries_tested"] += 1
                        if _path_selected(relative, entry.name, request) \
                                and filename_matches(relative):
                            if add_match({"path": relative, "kind": "directory"}):
                                return result, None
                    if depth >= request["max_depth"]:
                        result["complete"] = False
                        result["stop_reason"] = result["stop_reason"] or "max_depth"
                    else:
                        stack.append((entry.path, depth + 1))
                    publish()
                    continue

                if result["files_inspected"] >= request["max_files"]:
                    result["complete"] = False
                    result["stop_reason"] = "max_files"
                    publish("final")
                    return result, None
                result["files_inspected"] += 1
                relative = os.path.relpath(entry.path, path)
                if not _path_selected(relative, entry.name, request):
                    publish()
                    continue

                if request.get("filename_only"):
                    if request.get("kind") in {"all", "file"}:
                        result["entries_tested"] += 1
                        if filename_matches(relative):
                            if add_match({"path": relative, "kind": "file"}):
                                return result, None
                    publish()
                    continue

                if _is_sensitive_search_path(relative, entry.name):
                    result["files_skipped_sensitive"] += 1
                    publish()
                    continue

                publish()
                _test_block(request, "stat")
                try:
                    file_state = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    _record_error(result, relative, exc)
                    publish()
                    continue
                if file_state.st_size > request["max_file_bytes"]:
                    result["files_skipped_large"] += 1
                    publish()
                    continue
                if profiles.is_gdoc_stub(entry.path):
                    result["files_skipped_placeholder"] += 1
                    publish()
                    continue
                try:
                    if profiles.is_placeholder(
                        entry.path, st=file_state, profile=profile
                    ):
                        result["files_skipped_placeholder"] += 1
                        publish()
                        continue
                except OSError as exc:
                    _record_error(result, relative, exc)
                    publish()
                    continue

                publish()
                _test_block(request, "open")
                try:
                    with open(entry.path, "rb") as handle:
                        _test_block(request, "read")
                        payload = handle.read(request["max_file_bytes"] + 1)
                except OSError as exc:
                    _record_error(result, relative, exc)
                    publish()
                    continue
                if len(payload) > request["max_file_bytes"]:
                    result["files_skipped_large"] += 1
                    publish()
                    continue
                if b"\x00" in payload[:8192]:
                    result["files_skipped_binary"] += 1
                    publish()
                    continue

                text = payload.decode("utf-8", errors="replace")
                result["files_searched"] += 1
                result["entries_tested"] += 1
                for line_number, line in enumerate(text.splitlines(), 1):
                    for match in matcher.finditer(line):
                        preview = " ".join(line.strip().split())
                        if len(preview) > MAX_MATCH_PREVIEW_CHARS:
                            preview = preview[:MAX_MATCH_PREVIEW_CHARS - 1] + "…"
                        item = {
                            "path": relative,
                            "line": line_number,
                            "column": match.start() + 1,
                            "preview": preview,
                        }
                        if add_match(item):
                            return result, None
                publish()
        finally:
            try:
                iterator.close()
            except OSError:
                pass

    publish("final")
    return result, None


def _worker_cli() -> int:
    request = None
    try:
        for stream in (sys.stdin, sys.stdout):
            try:
                stream.reconfigure(encoding="utf-8", errors="strict")
            except (AttributeError, ValueError):
                pass
        raw = sys.stdin.buffer.readline(1024 * 1024 + 1)
        if not raw or len(raw) > 1024 * 1024:
            return 2
        request = json.loads(raw.decode("utf-8"))

        if os.environ.get("AGW_TEST_MODE") == "1" \
                and request.get("_test_worker_exit"):
            sys.stderr.write(str(request.get("_test_worker_stderr", "worker test exit")))
            sys.stderr.flush()
            return int(request.get("_test_worker_exit"))

        def emit(kind, payload):
            message = _message(
                kind, payload["result"], request,
                **{key: value for key, value in payload.items() if key != "result"},
            )
            _write_json_line(message)

        if request.get("operation") in {"search", "list"}:
            _result, fatal = search_in_process(request, emit=emit)
        else:
            _result, fatal = scan_in_process(request, emit=emit)
        return FATAL_EXIT_CODES.get(fatal["code"], 13) if fatal else 0
    except BaseException as exc:  # child must convert failures to structured output
        if request is None:
            return 2
        result = initial_result(request)
        result["complete"] = False
        result["stop_reason"] = "worker_error"
        _record_error(result, ".", exc)
        _write_json_line(_message("final", result, request))
        return 1


def _write_json_line(payload: dict) -> None:
    """Emit UTF-8 IPC, escaping non-ASCII only if the stream rejects it."""
    try:
        line = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":"),
        ) + "\n"
        sys.stdout.write(line)
        sys.stdout.flush()
    except UnicodeEncodeError:
        line = json.dumps(
            payload, ensure_ascii=True, separators=(",", ":"),
        ) + "\n"
        sys.stdout.write(line)
        sys.stdout.flush()


def _drain(messages: queue.Queue, latest: dict):
    final = None
    fatal = None
    while True:
        try:
            message = messages.get_nowait()
        except queue.Empty:
            break
        incoming = message.get("result", latest)
        if message.get("merge_result"):
            existing_matches = list(latest.get("matches", []))
            latest = {**latest, **incoming}
            latest["matches"] = existing_matches + list(
                message.get("append_matches", [])
            )
        else:
            latest = incoming
        if message.get("kind") == "fatal":
            fatal = message.get("fatal")
            final = latest
        elif message.get("kind") == "final":
            final = latest
    return latest, final, fatal


def _fatal_from_exit(returncode: int, path: str, operation: str) -> Optional[dict]:
    code = EXIT_FATAL_CODES.get(returncode)
    if code == "path_not_found":
        message = f"path not found: {path}"
    elif code == "not_directory":
        message = f"{operation} requires a directory, not a file: {path}"
    elif code == "path_validation_error":
        message = f"{operation} could not validate path"
    else:
        return None
    return {"code": code, "message": message}


def _run_bounded_worker(request: dict) -> tuple[dict, Optional[dict]]:
    """Run a discovery worker under a parent-owned wall-clock deadline."""
    max_seconds = float(request["max_seconds"])
    deadline = request["started_at"] + max_seconds
    # Reserve bounded time for termination, pipe draining, and JSON creation.
    # Windows process/pipe teardown needs materially more than a few tens of
    # milliseconds for short deadlines; the reserve remains capped so useful
    # scan time dominates ordinary multi-second requests.
    reserve = min(0.5, max(0.05, max_seconds * 0.20), max_seconds * 0.50)
    worker_deadline = max(request["started_at"], deadline - reserve)
    request = {**request, "worker_deadline": worker_deadline}
    latest = initial_result(request)
    final = fatal = None
    timed_out = False
    termination_requested = False

    messages = queue.Queue()
    reader_done = threading.Event()
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) \
        if os.name == "nt" else 0
    process = None
    reader = None
    stderr_reader = None
    stderr_parts = []
    stderr_lock = threading.Lock()
    try:
        worker_env = os.environ.copy()
        worker_env["PYTHONUTF8"] = "1"
        worker_env["PYTHONIOENCODING"] = "utf-8"
        process = subprocess.Popen(
            [sys.executable, "-X", "utf8", os.path.abspath(__file__), "--worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=creationflags,
            env=worker_env,
        )

        def read_messages():
            try:
                for line in process.stdout:
                    try:
                        messages.put(json.loads(line))
                    except json.JSONDecodeError:
                        messages.put({
                            "kind": "protocol_error",
                            "result": latest,
                        })
            except (OSError, ValueError):
                pass
            finally:
                try:
                    process.stdout.close()
                except (OSError, ValueError):
                    pass
                reader_done.set()

        reader = threading.Thread(target=read_messages, daemon=True)
        reader.start()

        def read_stderr():
            try:
                while True:
                    chunk = process.stderr.read(1024)
                    if not chunk:
                        break
                    with stderr_lock:
                        stderr_parts.append(chunk)
                        combined = "".join(stderr_parts)
                        if len(combined) > MAX_STDERR_TAIL_CHARS:
                            stderr_parts[:] = [combined[-MAX_STDERR_TAIL_CHARS:]]
            except (OSError, ValueError):
                pass
            finally:
                try:
                    process.stderr.close()
                except (OSError, ValueError):
                    pass

        stderr_reader = threading.Thread(target=read_stderr, daemon=True)
        stderr_reader.start()
        process.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
        process.stdin.close()
        while time.monotonic() < worker_deadline and final is None and fatal is None:
            latest, final, fatal = _drain(messages, latest)
            if process.poll() is not None:
                reader_done.wait(timeout=max(
                    0.0, min(0.05, deadline - time.monotonic())
                ))
                latest, final, fatal = _drain(messages, latest)
                break
            time.sleep(min(0.01, max(0.0, worker_deadline - time.monotonic())))

        if final is None and fatal is None:
            latest, final, fatal = _drain(messages, latest)
        timed_out = (
            final is None and fatal is None
            and time.monotonic() >= worker_deadline
            and process.poll() is None
        )
    except (BrokenPipeError, OSError, RuntimeError, ValueError) as exc:
        latest["complete"] = False
        latest["stop_reason"] = "worker_start_error"
        _record_error(latest, ".", exc)
        final = latest
    finally:
        if process is not None and process.poll() is None:
            termination_requested = True
            process.terminate()
            try:
                process.wait(timeout=max(0.0, min(0.15, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                pass
        if process is not None and process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
        if reader is not None:
            reader.join(timeout=max(0.0, deadline - time.monotonic()))
        if stderr_reader is not None:
            stderr_reader.join(timeout=max(0.0, deadline - time.monotonic()))
        if process is not None and process.stdin is not None:
            process.stdin.close()

    latest, late_final, late_fatal = _drain(messages, latest)
    if final is None and late_final is not None:
        final = late_final
        timed_out = False
    if fatal is None and late_fatal is not None:
        fatal = late_fatal
        timed_out = False

    if final is None and fatal is None and process is not None:
        fatal = _fatal_from_exit(
            process.returncode, request["path"], request.get("operation", "scan")
        )
        if fatal is not None:
            latest["complete"] = False
            latest["stop_reason"] = fatal["code"]
            final = latest
            timed_out = False

    if timed_out:
        latest["complete"] = False
        latest["stop_reason"] = "max_seconds"
        latest["profile_detection"] = (
            "timed_out" if latest["profile_detection"] == "pending"
            else latest["profile_detection"]
        )
        final = latest
    elif final is None:
        # A short-lived worker can exit after flushing its terminal snapshot
        # while the reader thread is between the OS pipe and the queue. A clean
        # exit is authoritative; reconstruct the bounded terminal state from
        # the last progress message rather than inventing a worker failure.
        if process is not None and process.returncode == 0:
            if latest["files_inspected"] >= request["max_files"]:
                latest["complete"] = False
                latest["stop_reason"] = "max_files"
            elif not latest["stop_reason"]:
                latest["complete"] = True
            final = latest
        else:
            latest["complete"] = False
            latest["stop_reason"] = "worker_error"
            with stderr_lock:
                stderr_tail = "".join(stderr_parts)[-MAX_STDERR_TAIL_CHARS:].strip()
            error = {
                "path": ".", "error": "WorkerExited",
                "returncode": process.returncode if process is not None else None,
            }
            if stderr_tail:
                error["detail"] = stderr_tail
            if len(latest["errors"]) >= MAX_REPORTED_ENTRIES:
                latest["errors"][-1] = error
            else:
                latest["errors"].append(error)
            final = latest

    elapsed = max(0.0, time.monotonic() - request["started_at"])
    final["elapsed_seconds"] = round(min(elapsed, max_seconds), 6)
    final["deadline_enforced"] = True
    final["worker_terminated"] = bool(termination_requested)
    worker_alive = process is not None and process.poll() is None
    final["worker_cleanup"] = "complete" if not worker_alive else "incomplete"
    final["_worker_pid"] = process.pid if process is not None else None
    return final, fatal


def run_bounded_scan(request: dict) -> tuple[dict, Optional[dict]]:
    return _run_bounded_worker({**request, "operation": "scan"})


def run_bounded_search(request: dict) -> tuple[dict, Optional[dict]]:
    return _run_bounded_worker({**request, "operation": "search"})


def run_bounded_list(request: dict) -> tuple[dict, Optional[dict]]:
    return _run_bounded_worker({**request, "operation": "list"})


if __name__ == "__main__" and "--worker" in sys.argv:
    raise SystemExit(_worker_cli())
