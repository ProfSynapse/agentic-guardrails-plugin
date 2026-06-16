"""Folder-profile detection: which kind of folder is a path inside, and how
should guardrails behave there?

Profiles are the plugin's "connectors". Detection is signal-based (path
prefixes, marker files, env vars); YAML profile packs can extend/override the
built-ins (profiles/*.yaml in the plugin, ~/.agw/profiles.d for local).
"""
from __future__ import annotations

import os
import stat as stat_mod
import sys
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


def detect(path: str) -> Profile:
    """Detect the profile governing `path` by walking up to a recognizable
    root. Results are cached per ancestor directory."""
    p = os.path.abspath(os.path.expanduser(path or "."))
    probe = p if os.path.isdir(p) else os.path.dirname(p) or "/"
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

    # env-var roots (OneDrive on Windows; honored cross-platform for tests)
    for var in ("OneDrive", "OneDriveCommercial", "OneDriveConsumer", "ONEDRIVE"):
        root = os.environ.get(var)
        if root and _is_under(directory, root):
            return BUILTIN["onedrive-sharepoint"]

    # path-name heuristics (WSL /mnt/c/Users/x/OneDrive - Org, Google Drive mounts)
    parts = lower.split("/")
    for part in parts:
        if part.startswith("onedrive"):
            return BUILTIN["onedrive-sharepoint"]
        if part in ("google drive", "googledrive", "my drive") or part.startswith("googledrive-"):
            return BUILTIN["gdrive-sync"]
        if part == "dropbox":
            return BUILTIN["dropbox"]

    # marker files walking up
    cur = directory
    for _ in range(12):
        try:
            names = set(os.listdir(cur))
        except OSError:
            names = set()
        if names & {".tmp.drivedownload", ".tmp.driveupload"}:
            return BUILTIN["gdrive-sync"]
        if ".dropbox.cache" in names or ".dropbox" in names:
            return BUILTIN["dropbox"]
        if ".git" in names:
            return BUILTIN["git"]
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return BUILTIN["local"]


def _is_under(path: str, root: str) -> bool:
    try:
        path = os.path.realpath(path)
        root = os.path.realpath(os.path.expanduser(root))
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def is_placeholder(path: str) -> bool:
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
    try:
        st = os.stat(path)
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
    return detect(path).sync_provider


def is_gdoc_stub(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in GDOC_STUB_EXTS


def is_sync_artifact(path: str) -> bool:
    base = os.path.basename(path).lower()
    if any(base.startswith(p) for p in LOCK_ARTIFACTS):
        return True
    return any(m in base for m in CONFLICT_MARKERS)
