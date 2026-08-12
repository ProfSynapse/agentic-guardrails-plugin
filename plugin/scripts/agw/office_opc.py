"""Shared, side-effect-free OPC relationship target resolution."""
from __future__ import annotations

import posixpath
import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable, Optional
from urllib.parse import unquote_to_bytes, urlsplit


VALID = "valid"
NONCANONICAL_RESOLVABLE = "noncanonical_resolvable"
UNSAFE = "unsafe"
UNRESOLVED = "unresolved"

_PERCENT_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")
_BAD_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_ENCODED_SEPARATOR = re.compile(r"%(?:2f|5c)", re.IGNORECASE)
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)


@dataclass(frozen=True)
class RelationshipResolution:
    relationship_part: str
    relationship_id: str
    raw_target: str
    target_mode: str
    resolved_part: str
    actual_part: str
    classification: str
    reason: str

    @property
    def usable(self) -> bool:
        return self.classification in {VALID, NONCANONICAL_RESOLVABLE}


def relationship_owner(relationship_part: str) -> Optional[str]:
    """Return the owner part, None for package relationships, or ``""`` if invalid."""
    if relationship_part.casefold() == "_rels/.rels":
        return None
    directory, filename = posixpath.split(relationship_part)
    if (posixpath.basename(directory).casefold() != "_rels"
            or not filename.casefold().endswith(".rels")):
        return ""
    owner_directory = posixpath.dirname(directory)
    owner_name = filename[:-5]
    return posixpath.join(owner_directory, owner_name) \
        if owner_directory else owner_name


def relationship_part_for(owner_part: str) -> str:
    directory, filename = posixpath.split(owner_part)
    return posixpath.join(directory, "_rels", filename + ".rels")


def _result(relationship_part: str, relationship_id: str, raw_target: str,
            target_mode: str, classification: str, reason: str,
            resolved_part: str = "", actual_part: str = "") \
        -> RelationshipResolution:
    return RelationshipResolution(
        relationship_part=relationship_part,
        relationship_id=relationship_id,
        raw_target=raw_target,
        target_mode=target_mode,
        resolved_part=resolved_part,
        actual_part=actual_part,
        classification=classification,
        reason=reason,
    )


def _decoded_path(raw_path: str) -> tuple[str, bool, Optional[str]]:
    if _BAD_PERCENT_ESCAPE.search(raw_path):
        return "", False, "malformed_percent_escape"
    if _ENCODED_SEPARATOR.search(raw_path):
        return "", False, "encoded_path_separator"
    try:
        decoded = unquote_to_bytes(raw_path).decode("utf-8")
    except UnicodeDecodeError:
        return "", False, "invalid_percent_encoding"
    if "\x00" in decoded or any(ord(character) < 32 for character in decoded):
        return "", False, "control_character"
    percent_unreserved = any(
        chr(int(match.group(1), 16)) in _UNRESERVED
        for match in _PERCENT_ESCAPE.finditer(raw_path)
    )
    return decoded, percent_unreserved, None


def _identity(part: str) -> str:
    return unicodedata.normalize("NFC", part).casefold()


def resolve_relationship(
    part_names: Iterable[str], relationship_part: str, relationship_id: str,
    raw_target: str, target_mode: str = "", *,
    owner_part: Optional[str] | object = ...,
) -> RelationshipResolution:
    """Classify one relationship without opening its target.

    Safe noncanonical spellings resolve only when they identify exactly one package
    member. External relationships are recorded but deliberately never resolved.
    """
    target = str(raw_target or "")
    mode = str(target_mode or "")
    if mode.casefold() == "external":
        return _result(
            relationship_part, relationship_id, target, mode, VALID,
            "external_target_not_opened",
        )
    if mode:
        return _result(
            relationship_part, relationship_id, target, mode, UNSAFE,
            "invalid_target_mode",
        )
    if not target:
        return _result(
            relationship_part, relationship_id, target, mode, UNRESOLVED,
            "empty_target",
        )
    if "\\" in target:
        return _result(
            relationship_part, relationship_id, target, mode, UNSAFE,
            "backslash_path_separator",
        )
    if "?" in target or "#" in target:
        return _result(
            relationship_part, relationship_id, target, mode, UNSAFE,
            "query_or_fragment",
        )
    if "\x00" in target or any(ord(character) < 32 for character in target):
        return _result(
            relationship_part, relationship_id, target, mode, UNSAFE,
            "control_character",
        )
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or target.startswith("//"):
        return _result(
            relationship_part, relationship_id, target, mode, UNSAFE,
            "internal_authority_or_scheme",
        )
    decoded, percent_unreserved, decode_error = _decoded_path(parsed.path)
    if decode_error:
        return _result(
            relationship_part, relationship_id, target, mode, UNSAFE,
            decode_error,
        )
    decoded_uri = urlsplit(decoded)
    if decoded_uri.scheme or decoded_uri.netloc or decoded.startswith("//"):
        return _result(
            relationship_part, relationship_id, target, mode, UNSAFE,
            "internal_authority_or_scheme",
        )

    owner = relationship_owner(relationship_part) \
        if owner_part is ... else owner_part
    if owner == "":
        return _result(
            relationship_part, relationship_id, target, mode, UNRESOLVED,
            "invalid_relationship_part",
        )
    package_root_relative = decoded.startswith("/")
    base = "" if package_root_relative or owner is None else posixpath.dirname(owner)
    candidate = posixpath.join(base, decoded.lstrip("/"))
    normalized = posixpath.normpath(candidate)
    if normalized in {"", ".", ".."} or normalized.startswith("../"):
        return _result(
            relationship_part, relationship_id, target, mode, UNSAFE,
            "package_root_escape",
        )

    names = tuple(part_names)
    exact = normalized if normalized in names else ""
    identity_matches = tuple(name for name in names if _identity(name) == _identity(normalized))
    if len(identity_matches) > 1:
        return _result(
            relationship_part, relationship_id, target, mode, UNSAFE,
            "ambiguous_part_identity", normalized,
        )
    actual = exact or (identity_matches[0] if identity_matches else "")
    if not actual:
        return _result(
            relationship_part, relationship_id, target, mode, UNRESOLVED,
            "target_part_missing", normalized,
        )

    raw_segments = decoded.lstrip("/").split("/")
    redundant_dot = any(segment in {"", ".", ".."} for segment in raw_segments)
    identity_adjusted = actual != normalized
    noncanonical = (package_root_relative or redundant_dot or percent_unreserved
                    or identity_adjusted)
    return _result(
        relationship_part, relationship_id, target, mode,
        NONCANONICAL_RESOLVABLE if noncanonical else VALID,
        (
            "safe_noncanonical_target" if noncanonical
            else "canonical_target"
        ),
        normalized, actual,
    )
