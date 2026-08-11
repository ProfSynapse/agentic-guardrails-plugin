"""Literal path identity and Unicode-risk checks for Guardrails operations.

This module deliberately separates the spelling passed to the operating system
from comparison keys used to detect ambiguous targets.  Guardrails never
silently normalizes a user-supplied path before opening it.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import unicodedata
from typing import Iterable


_BIDI_CONTROLS = {
    "\u061c", "\u200e", "\u200f", "\u202a", "\u202b", "\u202c",
    "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069",
}
_SCRIPT_PREFIXES = (
    "LATIN", "CYRILLIC", "GREEK", "HEBREW", "ARABIC", "HIRAGANA",
    "KATAKANA", "HANGUL", "CJK",
)


class PathSafetyError(ValueError):
    """A literal path set cannot be distinguished safely."""

    error_code = "ambiguous_path_identity"

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.details = details or {}


@dataclass(frozen=True)
class PathIdentity:
    original: str
    absolute: str
    real: str
    native_key: str
    unicode_key: str
    warnings: tuple[dict, ...]

    def as_dict(self) -> dict:
        return {
            "path": self.absolute,
            "unicode_normalization": "NFC",
            "warnings": list(self.warnings),
        }


def _scripts(value: str) -> set[str]:
    scripts = set()
    for char in value:
        name = unicodedata.name(char, "")
        for prefix in _SCRIPT_PREFIXES:
            if name.startswith(prefix):
                scripts.add(prefix)
                break
    return scripts


def unicode_warnings(path: str) -> tuple[dict, ...]:
    """Return privacy-safe warnings for visually ambiguous path spelling."""
    warnings = []
    basename = os.path.basename(path)
    if unicodedata.normalize("NFC", basename) != basename:
        warnings.append({
            "code": "non_nfc_path",
            "message": "filename is not in NFC Unicode normalization form",
        })
    if any(char in _BIDI_CONTROLS for char in basename):
        warnings.append({
            "code": "bidi_control_in_path",
            "message": "filename contains a bidirectional display control",
        })
    if any(unicodedata.category(char) == "Cf" and char not in _BIDI_CONTROLS
           for char in basename):
        warnings.append({
            "code": "format_control_in_path",
            "message": "filename contains an invisible Unicode format control",
        })
    scripts = _scripts(basename)
    confusable_scripts = scripts & {"LATIN", "CYRILLIC", "GREEK"}
    if len(confusable_scripts) > 1:
        warnings.append({
            "code": "mixed_confusable_scripts",
            "message": "filename mixes visually confusable writing systems",
            "scripts": sorted(confusable_scripts),
        })
    return tuple(warnings)


def identify(path: str) -> PathIdentity:
    original = str(path)
    absolute = os.path.abspath(os.path.expanduser(original))
    real = os.path.realpath(absolute)
    native_key = os.path.normcase(real)
    unicode_key = unicodedata.normalize("NFC", native_key).casefold()
    return PathIdentity(
        original=original,
        absolute=absolute,
        real=real,
        native_key=native_key,
        unicode_key=unicode_key,
        warnings=unicode_warnings(absolute),
    )


def require_unique(paths: Iterable[str], *, label: str = "targets") -> list[PathIdentity]:
    """Return identities or reject native/Unicode-equivalent duplicates."""
    identities = [identify(path) for path in paths]
    native = {}
    unicode_keys = {}
    for item in identities:
        if item.native_key in native:
            raise PathSafetyError(
                f"{label} resolve to the same filesystem identity",
                {"paths": [native[item.native_key], item.absolute]},
            )
        native[item.native_key] = item.absolute
        if item.unicode_key in unicode_keys:
            raise PathSafetyError(
                f"{label} collide after Unicode normalization",
                {"paths": [unicode_keys[item.unicode_key], item.absolute],
                 "normalization": "NFC"},
            )
        unicode_keys[item.unicode_key] = item.absolute
    return identities


def is_within(path: str, root: str) -> bool:
    try:
        path_key = os.path.normcase(os.path.realpath(os.path.abspath(path)))
        root_key = os.path.normcase(os.path.realpath(os.path.abspath(root)))
        return os.path.commonpath([path_key, root_key]) == root_key
    except ValueError:
        return False
