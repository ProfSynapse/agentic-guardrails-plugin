"""Recovery accounting classes. Classification never grants deletion authority."""
from __future__ import annotations

import fnmatch
import json
import os
import uuid


CLASSES = ("documents", "media", "derived", "unclassified")
MEDIA_EXTENSIONS = frozenset(
    ".mp4 .mov .mkv .webm .avi .m4v .mpeg .mpg .mts .mxf "
    ".mp3 .wav .flac .aac .m4a .ogg .opus .aiff .aif .wma "
    ".jpg .jpeg .png .gif .webp .tif .tiff .heic .heif .raw .cr2 .nef .psd .exr".split()
)
CACHE_NAME = "archive-storage-size.json"


def classify(path: str, *, is_directory: bool = False, rules=()) -> str:
    normalized = os.path.abspath(path).replace("\\", "/")
    for pattern, bucket in rules:
        if fnmatch.fnmatchcase(os.path.normcase(normalized),
                              os.path.normcase(pattern.replace("\\", "/"))):
            return bucket
    # Directory snapshots may contain mixed media. Do not let a container
    # consume document headroom merely because its own name has no extension.
    if is_directory or os.path.splitext(path)[1].lower() in MEDIA_EXTENSIONS:
        return "media"
    return "documents"


def record_class(record: dict) -> str:
    stored = record.get("storage_class")
    if "storage_class" in record:
        return stored if stored in CLASSES else "unclassified"
    # Legacy accounting is read-only and uses the built-in mapping, not new
    # derived rules. Retention eligibility remains independently protected.
    if not record.get("src"):
        return "unclassified"
    return classify(record["src"], is_directory=record.get("artifact_kind") == "directory")


def read_cache(home: str, total: int, count: int) -> dict | None:
    try:
        with open(os.path.join(home, CACHE_NAME), encoding="utf-8") as handle:
            data = json.load(handle)
        usage = data["usage"]
        if data.get("schema") != 1 or data["manifest_count"] != count \
                or data["total_bytes"] != total or set(usage) != set(CLASSES):
            return None
        if any(type(value) is not int or value < 0 for value in usage.values()) \
                or sum(usage.values()) != total:
            return None
        return usage
    except (OSError, ValueError, TypeError, KeyError):
        return None


def write_cache(home: str, usage: dict, count: int):
    path = os.path.join(home, CACHE_NAME)
    temporary = path + "." + uuid.uuid4().hex + ".tmp"
    try:
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump({"schema": 1, "total_bytes": sum(usage.values()),
                       "manifest_count": count, "usage": usage}, handle)
        os.replace(temporary, path)
    except OSError:
        try:
            os.unlink(temporary)
        except OSError:
            pass

