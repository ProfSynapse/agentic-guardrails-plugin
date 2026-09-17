"""Folder-profile detection: which kind of folder is a path inside, and how
should guardrails behave there?

Profiles are the plugin's "connectors". Detection is signal-based (path
prefixes, marker files, env vars); YAML profile packs can extend/override the
built-ins (profiles/*.yaml in the plugin, ~/.agw/profiles.d for local).
"""
from __future__ import annotations

import json
import os
import stat as stat_mod
import sys
import time
from dataclasses import dataclass, field

GDOC_STUB_EXTS = {".gdoc", ".gsheet", ".gslides", ".gdraw", ".gform", ".gtable", ".gjam"}
PROPRIETARY_EXTS = {".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".odt", ".ods", ".odp"}
LOCK_ARTIFACTS = ("~$", ".~lock.")
CONFLICT_MARKERS = ("[conflict]", "conflicted copy", "-conflictedcopy")
SYNC_STAGING = (".tmp.drivedownload", ".tmp.driveupload", ".dropbox.cache")


@dataclass
class Profile:
    name: str
    sync_provider: bool = False
    archive_location: str = "central"      # central | in-place
    write_strategy: str = "atomic"          # atomic | retry-in-place
    upstream_versioning: str = ""
    git_passthrough: bool = False
    notes: str = ""
    extra: dict = field(default_factory=dict)


BUILTIN = {
    "unknown": Profile("unknown"),
    "local": Profile("local"),
    "git": Profile("git", git_passthrough=True),
    "gdrive-sync": Profile("gdrive-sync", sync_provider=True,
                           write_strategy="retry-in-place",
                           upstream_versioning="drive (30d/100 revisions — not an undo log)"),
    "onedrive-sharepoint": Profile("onedrive-sharepoint", sync_provider=True,
                                   write_strategy="retry-in-place",
                                   upstream_versioning="sharepoint (auto-versions)"),
    "dropbox": Profile("dropbox", sync_provider=True,
                       write_strategy="retry-in-place",
                       upstream_versioning="dropbox (30-180d)"),
}

_cache: dict = {}

# The marker walk (up to twelve ancestors, five existence probes each) is the
# only part of detection that touches the disk, and a hook process never gets
# to reuse its answer: `_cache` above dies with the process. The walk's result
# for a directory is therefore also kept under $AGW_HOME/profile-cache.json,
# keyed on the st_mtime_ns of the directory and each ancestor probed (a marker
# created or removed inside a directory changes that directory's mtime), with a
# short TTL as a safety net. Only folder-profile verdicts are stored here;
# placeholder detection for a file is never cached.
_PROFILE_CACHE_SCHEMA = "agw.profile-cache/1"
_PROFILE_CACHE_NAME = "profile-cache.json"
_PROFILE_CACHE_TTL = 600
_PROFILE_CACHE_MAX = 256
_MARKER_DEPTH = 12
_persisted = None  # (agw_home, entries) loaded once per process


def detect(path: str, *, assume_directory: bool = False, override: str = "") -> Profile:
    """Detect the profile governing `path` by walking up to a recognizable
    root. Results are cached per ancestor directory."""
    if override:
        if override not in BUILTIN or override == "unknown":
            raise ValueError(f"unknown folder profile: {override}")
        return BUILTIN[override]
    p = os.path.abspath(os.path.expanduser(path or "."))
    probe = p if assume_directory or os.path.isdir(p) else os.path.dirname(p) or "/"
    if probe in _cache:
        return _cache[probe]
    profile = _detect_uncached(probe)
    _cache[probe] = profile
    return profile


def _detect_uncached(directory: str) -> Profile:
    lower = directory.lower().replace("\\", "/")

    # macOS File Provider: ~/Library/CloudStorage/<Provider>-<account>
    if "/library/cloudstorage/" in lower:
        seg = lower.split("/library/cloudstorage/", 1)[1].split("/", 1)[0]
        if seg.startswith("onedrive"):
            return BUILTIN["onedrive-sharepoint"]
        if seg.startswith("googledrive"):
            return BUILTIN["gdrive-sync"]
        if seg.startswith("dropbox"):
            return BUILTIN["dropbox"]

    # path-name heuristics (WSL /mnt/c/Users/x/OneDrive - Org, Google Drive mounts)
    parts = lower.split("/")
    for part in parts:
        if part.startswith("onedrive"):
            return BUILTIN["onedrive-sharepoint"]
        if part in ("google drive", "googledrive", "my drive",
                    "shared drive", "shared drives") \
                or part.startswith("googledrive-"):
            return BUILTIN["gdrive-sync"]
        if part == "dropbox":
            return BUILTIN["dropbox"]

    # Known/configurable provider roots. These are lexical path checks only;
    # detection performs no registry, directory enumeration, or network access.
    provider_roots = {
        "onedrive-sharepoint": (
            "OneDrive", "OneDriveCommercial", "OneDriveConsumer", "ONEDRIVE",
        ),
        "gdrive-sync": (
            "GOOGLE_DRIVE", "GOOGLE_DRIVE_ROOT", "GOOGLE_DRIVEFS_ROOT",
        ),
        "dropbox": ("DROPBOX", "DROPBOX_ROOT"),
    }
    for profile_name, variables in provider_roots.items():
        for variable in variables:
            root = os.environ.get(variable)
            if root and _is_under(directory, root):
                return BUILTIN[profile_name]

    # A mounted Drive volume may have a provider label even when its drive
    # letter/path contains no provider name. This uses local kernel metadata;
    # scan invokes detection only inside its killable worker.
    label = _windows_volume_label(directory).lower()
    if "google" in label and "drive" in label:
        return BUILTIN["gdrive-sync"]
    if "onedrive" in label or "sharepoint" in label:
        return BUILTIN["onedrive-sharepoint"]
    if "dropbox" in label:
        return BUILTIN["dropbox"]

    return BUILTIN[_marker_profile(directory)]


def _ancestors(directory: str) -> list:
    """The directory and its parents, innermost first, as the walk probes them."""
    chain = []
    cur = directory
    for _ in range(_MARKER_DEPTH):
        chain.append(cur)
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return chain


def _walk_markers(ancestors: list) -> str:
    """Marker paths walking up. Direct existence probes avoid enumerating every
    entry in every ancestor directory."""
    git_found = False
    for cur in ancestors:
        if any(os.path.exists(os.path.join(cur, marker))
               for marker in (".tmp.drivedownload", ".tmp.driveupload")):
            return "gdrive-sync"
        if any(os.path.exists(os.path.join(cur, marker))
               for marker in (".dropbox.cache", ".dropbox")):
            return "dropbox"
        if os.path.exists(os.path.join(cur, ".git")):
            git_found = True
    return "git" if git_found else "local"


def _marker_key(ancestors: list) -> list:
    key = []
    for cur in ancestors:
        try:
            key.append([cur, os.stat(cur).st_mtime_ns])
        except OSError:
            key.append([cur, None])
    return key


def _agw_home() -> str:
    return os.environ.get("AGW_HOME") or os.path.join(os.path.expanduser("~"), ".agw")


def _persisted_entries(home: str) -> dict:
    """The on-disk entries, read once per process (per AGW_HOME)."""
    global _persisted
    if _persisted is not None and _persisted[0] == home:
        return _persisted[1]
    entries = {}
    try:
        with open(os.path.join(home, _PROFILE_CACHE_NAME), "rb") as handle:
            data = json.loads(handle.read().decode("utf-8"))
        if isinstance(data, dict) and data.get("schema") == _PROFILE_CACHE_SCHEMA \
                and isinstance(data.get("entries"), dict):
            entries = data["entries"]
    except (OSError, ValueError, UnicodeDecodeError):
        entries = {}
    _persisted = (home, entries)
    return entries


def _remember(home: str, entries: dict, directory: str, key: list, name: str) -> None:
    """Add one verdict and rewrite the file atomically. Best effort only."""
    entries[directory] = {"key": key, "profile": name, "at": time.time()}
    if len(entries) > _PROFILE_CACHE_MAX:
        oldest = sorted(entries, key=lambda item: entries[item].get("at", 0))
        for item in oldest[:len(entries) - _PROFILE_CACHE_MAX]:
            del entries[item]
    if not os.path.isdir(home):
        # Detection must not create the store root as a side effect: a scan
        # of a tree that happens to contain AGW_HOME would then find it.
        return
    path = os.path.join(home, _PROFILE_CACHE_NAME)
    temp = "%s.%d.tmp" % (path, os.getpid())
    try:
        with open(temp, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"schema": _PROFILE_CACHE_SCHEMA, "entries": entries}))
        os.replace(temp, path)
    except (OSError, TypeError, ValueError):
        try:
            os.unlink(temp)
        except OSError:
            pass


def _marker_profile(directory: str) -> str:
    """The marker-walk verdict for a directory, from the persisted cache when
    the directory and its ancestors are unchanged and the entry is fresh."""
    ancestors = _ancestors(directory)
    key = _marker_key(ancestors)
    home = _agw_home()
    entries = _persisted_entries(home)
    entry = entries.get(directory)
    if isinstance(entry, dict) and entry.get("key") == key \
            and entry.get("profile") in BUILTIN and entry.get("profile") != "unknown" \
            and 0 <= time.time() - float(entry.get("at", 0)) <= _PROFILE_CACHE_TTL:
        return entry["profile"]
    name = _walk_markers(ancestors)
    _remember(home, entries, directory, key, name)
    return name


def _windows_volume_label(path: str) -> str:
    if sys.platform != "win32":
        return ""
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        volume_path = ctypes.create_unicode_buffer(32768)
        if not kernel32.GetVolumePathNameW(
                wintypes.LPCWSTR(path), volume_path, len(volume_path)):
            return ""
        label = ctypes.create_unicode_buffer(261)
        if not kernel32.GetVolumeInformationW(
                volume_path.value, label, len(label), None, None, None, None, 0):
            return ""
        return label.value
    except (AttributeError, OSError, ValueError):
        return ""


def _is_under(path: str, root: str) -> bool:
    try:
        path = os.path.normcase(os.path.abspath(path))
        root = os.path.normcase(os.path.abspath(os.path.expanduser(root)))
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def is_placeholder(path: str, *, st=None, profile: Profile = None) -> bool:
    """Cloud-only placeholder detection.

    Authoritative OS signals (trusted on their own): Windows
    RECALL_ON_DATA_ACCESS/OFFLINE attributes; macOS SF_DATALESS flag.

    POSIX/WSL fallback: st_blocks == 0 with st_size > 0 (the signature from
    the Cowork/OneDrive corruption issue #62140). This is an *inference*, not
    an OS flag — it also fires on filesystems that don't report block
    allocation normally (tmpfs, many FUSE/network mounts, some WSL DrvFs and
    bind mounts), where ordinary files would be misread as placeholders. So
    the bare st_blocks==0 signal is only trusted when the path is under a
    detected cloud-sync profile; on plain local/git folders it is ignored.
    False for missing files."""
    if st is None:
        try:
            st = os.stat(path, follow_symlinks=False)
        except OSError:
            return False
    if st.st_size == 0:
        return False
    if sys.platform == "win32":
        attrs = getattr(st, "st_file_attributes", 0)
        recall = getattr(stat_mod, "FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS", 0x00400000)
        offline = getattr(stat_mod, "FILE_ATTRIBUTE_OFFLINE", 0x00001000)
        return bool(attrs & (recall | offline))
    blocks = getattr(st, "st_blocks", None)
    if blocks is None:
        return False
    if sys.platform == "darwin":
        dataless = getattr(stat_mod, "SF_DATALESS", 0x40000000)
        if getattr(st, "st_flags", 0) & dataless:
            return True
    if blocks != 0:
        return False
    # Corroborate the st_blocks==0 inference with a cloud-sync profile so odd
    # filesystems (tmpfs/FUSE/DrvFs) don't trigger false positives.
    return (profile or detect(path)).sync_provider


def is_gdoc_stub(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in GDOC_STUB_EXTS


def is_sync_artifact(path: str) -> bool:
    base = os.path.basename(path).lower()
    if any(base.startswith(p) for p in LOCK_ARTIFACTS):
        return True
    return any(m in base for m in CONFLICT_MARKERS)
