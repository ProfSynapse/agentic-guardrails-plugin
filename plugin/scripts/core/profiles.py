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

    # Marker paths walking up. Direct existence probes avoid enumerating every
    # entry in every ancestor directory.
    cur = directory
    git_found = False
    for _ in range(12):
        if any(os.path.exists(os.path.join(cur, marker))
               for marker in (".tmp.drivedownload", ".tmp.driveupload")):
            return BUILTIN["gdrive-sync"]
        if any(os.path.exists(os.path.join(cur, marker))
               for marker in (".dropbox.cache", ".dropbox")):
            return BUILTIN["dropbox"]
        if os.path.exists(os.path.join(cur, ".git")):
            git_found = True
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    if git_found:
        return BUILTIN["git"]
    return BUILTIN["local"]


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
