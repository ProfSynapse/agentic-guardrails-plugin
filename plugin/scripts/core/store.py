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
import time
from datetime import datetime

SCHEMA_VERSION = 1


def agw_home() -> str:
    home = os.environ.get("AGW_HOME") or os.path.join(os.path.expanduser("~"), ".agw")
    os.makedirs(home, exist_ok=True)
    return home


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
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.timeout = timeout
        self.fd = None

    def __enter__(self):
        deadline = time.time() + self.timeout
        while True:
            try:
                self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(self.fd, str(os.getpid()).encode())
                return self
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise
                if time.time() > deadline:
                    # stale-lock recovery: locks older than 60s are abandoned
                    try:
                        if time.time() - os.path.getmtime(self.path) > 60:
                            os.unlink(self.path)
                            continue
                    except OSError:
                        pass
                    raise TimeoutError(f"could not acquire lock {self.path}")
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
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def oplog_append(op: dict):
    with Lock("oplog"):
        _append_jsonl(os.path.join(agw_home(), "oplog.jsonl"), op)


def oplog_read() -> list:
    path = os.path.join(agw_home(), "oplog.jsonl")
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return out


def _folder_key(folder: str) -> str:
    folder = os.path.abspath(folder)
    digest = hashlib.sha256(folder.encode("utf-8", "replace")).hexdigest()[:10]
    base = os.path.basename(folder.rstrip("/\\")) or "root"
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in base)[:40]
    return f"{digest}__{safe}"


def _file_dir(src: str) -> str:
    folder = os.path.dirname(os.path.abspath(src))
    name = os.path.basename(src)
    safe = "".join(c if c.isalnum() or c in "-_. " else "_" for c in name)[:80]
    d = os.path.join(agw_home(), "archive", _folder_key(folder), safe)
    os.makedirs(d, exist_ok=True)
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
                 dedupe: bool = False) -> dict:
    """Archive one file or directory. mode='move' (delete-replacement) or
    'copy' (pre-image snapshot, leaves the original)."""
    src = os.path.abspath(src)
    if not os.path.exists(src):
        raise FileNotFoundError(src)
    file_dir = _file_dir(src)
    digest = file_sha256(src) if os.path.isfile(src) else ""

    with Lock(_folder_key(os.path.dirname(src))):
        if dedupe and digest:
            last = latest_version(src)
            if last and last.get("sha256") == digest:
                return {**last, "deduped": True}
        version = _next_version(file_dir)
        name = os.path.basename(src)
        dest = os.path.join(file_dir, f"v{version:03d}_{_ts()}_{name}")
        if mode == "move":
            shutil.move(src, dest)
        else:
            if os.path.isdir(src):
                # The archive store may live inside the tree being copied
                # (e.g. `agw snapshot ~` with AGW_HOME at ~/.agw) — skip it,
                # or copytree recurses into its own output forever.
                skip = {os.path.realpath(agw_home()), os.path.realpath(dest)}

                def _ignore(d, entries):
                    rd = os.path.realpath(d)
                    return [e for e in entries
                            if os.path.realpath(os.path.join(rd, e)) in skip]

                shutil.copytree(src, dest, symlinks=True, ignore=_ignore)
            else:
                shutil.copy2(src, dest)
        entry = {"op": "archive", "mode": mode, "src": src, "dest": dest,
                 "version": version, "sha256": digest, "reason": reason, "actor": actor}
        _append_jsonl(os.path.join(file_dir, "manifest.jsonl"), entry)
    oplog_append(entry)
    return entry


def latest_version(src: str):
    entries = list_versions(src)
    return entries[-1] if entries else None


def list_versions(src: str) -> list:
    file_dir = _file_dir(src)
    manifest = os.path.join(file_dir, "manifest.jsonl")
    if not os.path.exists(manifest):
        return []
    out = []
    with open(manifest, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return out


def restore(src: str, version: int = 0, overwrite: bool = False) -> dict:
    """Restore an archived version of `src` to its original location."""
    entries = list_versions(src)
    if not entries:
        raise FileNotFoundError(f"no archived versions of {src}")
    entry = entries[-1] if not version else next(
        (e for e in entries if e.get("version") == version), None)
    if entry is None:
        raise FileNotFoundError(f"no version {version} of {src}")
    if os.path.exists(src) and not overwrite:
        # never clobber a live file: archive it first (copy), then restore
        archive_file(src, mode="copy", reason="pre-restore safety copy", actor="agw")
        if os.path.isdir(src):
            shutil.rmtree(src)
        else:
            os.unlink(src)
    if os.path.isdir(entry["dest"]):
        shutil.copytree(entry["dest"], src, symlinks=True)
    else:
        os.makedirs(os.path.dirname(src), exist_ok=True)
        shutil.copy2(entry["dest"], src)
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

def enforce_budget(max_bytes: int) -> dict:
    """Keep the archive under max_bytes by evicting oldest *pre-image copy*
    snapshots first. NEVER evicts move-mode archives (the only copy of a
    displaced file) or the newest version in any file_dir. Returns a summary.
    A budget of 0/None means unlimited (the safe default — keep everything)."""
    if not max_bytes or max_bytes <= 0:
        return {"enforced": False}
    total = archive_size_bytes()
    if total <= max_bytes:
        return {"enforced": True, "evicted": 0, "bytes": total, "freed": 0}

    root = os.path.join(agw_home(), "archive")
    candidates = []  # (ts, path, size, file_dir)
    for file_dir, _dirs, files in os.walk(root):
        versions = sorted(f for f in files if f.startswith("v") and "_" in f)
        if len(versions) <= 1:
            continue  # never evict the sole version of anything
        manifest = os.path.join(file_dir, "manifest.jsonl")
        modes = {}
        try:
            with open(manifest, encoding="utf-8") as fh:
                for line in fh:
                    try:
                        e = json.loads(line)
                        modes[os.path.basename(e.get("dest", ""))] = e.get("mode")
                    except json.JSONDecodeError:
                        continue
        except OSError:
            modes = {}
        for v in versions[:-1]:  # keep the newest version in every file_dir
            if modes.get(v) and modes.get(v) != "copy":
                continue  # only evict pre-image *copies*, never moves
            full = os.path.join(file_dir, v)
            try:
                candidates.append((v.split("_", 2)[1] if v.count("_") >= 2 else v,
                                   full, os.path.getsize(full), file_dir))
            except OSError:
                continue
    candidates.sort()  # oldest timestamp first
    freed, evicted = 0, 0
    with Lock("retention"):
        for _ts_key, full, size, _fd in candidates:
            if total - freed <= max_bytes:
                break
            try:
                os.unlink(full)
                _append_jsonl(os.path.join(agw_home(), "oplog.jsonl"),
                              {"op": "evict", "dest": full, "bytes": size,
                               "reason": "archive budget"})
                freed += size
                evicted += 1
            except OSError:
                continue
    return {"enforced": True, "evicted": evicted, "bytes": total - freed,
            "freed": freed, "budget": max_bytes}
