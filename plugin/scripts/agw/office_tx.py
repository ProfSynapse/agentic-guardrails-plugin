"""Shared guarded transaction lifecycle for targeted Office mutations."""
from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import shutil
import stat
import tempfile
import unicodedata
import uuid
import warnings
import zipfile
from dataclasses import dataclass
from typing import Callable, Optional, Protocol
from urllib.parse import unquote, urlsplit
from xml.etree import ElementTree

from core import profiles, store
import retention_config

MAX_PACKAGE_BYTES = 32 * 1024 * 1024
MAX_ZIP_ENTRIES = 4096
MAX_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_ENTRY_BYTES = 128 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200


class TransactionError(Exception):
    pass


class TransactionConflict(TransactionError):
    error_code = "file_conflict"


class UnsupportedOfficeFile(TransactionError):
    error_code = "unsupported_office_file"


class _PackagePreflightError(UnsupportedOfficeFile):
    """Internal package refusal with a stable validation issue code."""

    def __init__(self, validation_code: str, message: str):
        self.validation_code = validation_code
        super().__init__(message)


class PreservationError(UnsupportedOfficeFile):
    error_code = "office_preservation_risk"

    def __init__(self, risks: list[dict]):
        self.details = {"risks": risks}
        summary = "; ".join(
            f"{risk.get('part', 'package')}: {risk.get('message', 'preservation risk')}"
            for risk in risks[:3]
        )
        super().__init__(f"Office preservation check refused the mutation: {summary}")


class OfficeValidationError(UnsupportedOfficeFile):
    """A structured refusal from tiered Office package validation."""

    error_code = "office_validation_failed"

    def __init__(self, report: dict):
        self.report = report
        self.details = {
            "tier": report.get("tier", ""),
            "issues": report.get("issues", []),
            "report": report,
        }
        issues = report.get("issues", [])
        summary = "; ".join(
            f"{issue.get('part', 'package')}: {issue.get('message', 'validation failed')}"
            for issue in issues[:3]
        )
        super().__init__(f"Office {report.get('tier', '')} validation failed: {summary}")


@dataclass(frozen=True)
class MutationPlan:
    operation: str
    preview: dict
    tracking: dict
    changed: bool = True


class OfficeRoundtripAdapter(Protocol):
    """Adapter seam for an optional native Office roundtrip implementation."""

    def capability(self) -> dict:
        ...

    def validate(self, path: str) -> dict:
        ...


def _target_id(path: str) -> str:
    canonical = os.path.normcase(os.path.realpath(path))
    return hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()


def _write_manifest(record: dict) -> str:
    root = os.path.join(store.agw_home(), "office-transactions")
    os.makedirs(root, exist_ok=True)
    path = os.path.join(root, record["mutation_id"] + ".json")
    fd, tmp = tempfile.mkstemp(prefix=".office-tx-", suffix=".json", dir=root)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(record, handle, ensure_ascii=False, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return path


def transaction_status() -> list[dict]:
    """Return incomplete Office mutations without exposing document content."""
    root = os.path.join(store.agw_home(), "office-transactions")
    if not os.path.isdir(root):
        return []
    pending = []
    for name in os.listdir(root):
        if not name.endswith(".json"):
            continue
        path = os.path.join(root, name)
        try:
            with open(path, encoding="utf-8") as handle:
                record = json.load(handle)
        except (OSError, json.JSONDecodeError):
            pending.append({"mutation_id": name[:-5], "state": "UNREADABLE"})
            continue
        if record.get("state") not in {"COMMITTED", "ABORTED"}:
            pending.append({
                "mutation_id": record.get("mutation_id", name[:-5]),
                "state": record.get("state", "UNKNOWN"),
                "operation": record.get("operation", ""),
                "target_id": record.get("target_id", ""),
                "snapshot_version": record.get("snapshot_version"),
            })
    return pending


_LOSSY_WARNING = re.compile(
    r"(?i)(?:not supported|unsupported|will be removed|cannot be preserved|lossy|extension)"
)
_EXTENSION_NAMESPACE_MARKERS = (
    "/office/spreadsheetml/2009/9/", "/office/spreadsheetml/2010/11/",
    "/office/spreadsheetml/2014/", "/office/spreadsheetml/2016/",
    "/office/drawing/2010/",
)
_SAFE_METADATA_ATTRIBUTES = {
    ("http://schemas.microsoft.com/office/spreadsheetml/2009/9/ac", "knownFonts"),
    ("http://schemas.microsoft.com/office/spreadsheetml/2009/9/ac", "dyDescent"),
}
_KNOWN_LOSSY_PART_PREFIXES = (
    "xl/slicers/", "xl/slicerCaches/", "xl/timelines/",
    "xl/timelineCaches/", "xl/persons/", "xl/threadedComments/",
)


def _warning_risks(captured, phase: str) -> list[dict]:
    risks = []
    for item in captured:
        message = str(item.message)
        if _LOSSY_WARNING.search(message):
            risks.append({
                "code": "library_preservation_warning",
                "feature": item.category.__name__,
                "part": "package",
                "phase": phase,
                "message": message,
            })
    return risks


def _run_capturing_warnings(callback, phase: str):
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        value = callback()
    risks = _warning_risks(captured, phase)
    if risks:
        raise PreservationError(risks)
    return value


def _qualified_name(value: str) -> tuple[str, str]:
    if value.startswith("{") and "}" in value:
        namespace, local = value[1:].split("}", 1)
        return namespace, local
    return "", value


def _extension_descriptors(payload: bytes) -> list[dict]:
    """Describe extension nodes/namespaces while ignoring proven-safe metadata."""
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError:
        return [{"extension_uri": "", "namespaces": [], "elements": [],
                 "parse_error": True}]
    descriptors = []
    seen = set()
    ext_lists = []
    for node in root.iter():
        namespace, local = _qualified_name(node.tag)
        if local == "extLst":
            ext_lists.append(node)
        if local == "ext":
            uri = str(node.attrib.get("uri", ""))
            child_namespaces = sorted({
                _qualified_name(child.tag)[0]
                for child in node.iter() if child is not node
                and _qualified_name(child.tag)[0]
            })
            elements = sorted({
                _qualified_name(child.tag)[1]
                for child in node.iter() if child is not node
            })
            key = (uri, tuple(child_namespaces), tuple(elements))
            if key not in seen:
                seen.add(key)
                descriptors.append({
                    "extension_uri": uri,
                    "namespaces": child_namespaces,
                    "elements": elements,
                })
        if namespace and any(marker in namespace
                             for marker in _EXTENSION_NAMESPACE_MARKERS):
            key = ("", (namespace,), (local,))
            if key not in seen:
                seen.add(key)
                descriptors.append({
                    "extension_uri": "", "namespaces": [namespace],
                    "elements": [local],
                })
        for attribute in node.attrib:
            attr_namespace, attr_local = _qualified_name(attribute)
            if not attr_namespace or not any(
                    marker in attr_namespace
                    for marker in _EXTENSION_NAMESPACE_MARKERS):
                continue
            if (attr_namespace, attr_local) in _SAFE_METADATA_ATTRIBUTES:
                continue
            key = ("", (attr_namespace,), (f"@{attr_local}",))
            if key not in seen:
                seen.add(key)
                descriptors.append({
                    "extension_uri": "", "namespaces": [attr_namespace],
                    "elements": [f"@{attr_local}"],
                })
    if ext_lists and not any(item.get("extension_uri") for item in descriptors):
        key = ("", (), ("extLst",))
        if key not in seen:
            descriptors.append({
                "extension_uri": "", "namespaces": [], "elements": ["extLst"],
            })
    return descriptors


def inspect_preservation_risks(path: str) -> list[dict]:
    """Return known OOXML features that common Python libraries lose on save."""
    risks = []
    seen = set()
    with zipfile.ZipFile(path) as package:
        for item in package.infolist():
            name = item.filename.replace("\\", "/")
            lower = name.lower()
            if any(lower.startswith(prefix.lower())
                   for prefix in _KNOWN_LOSSY_PART_PREFIXES):
                key = ("unsupported_ooxml_part", lower)
                if key not in seen:
                    seen.add(key)
                    risks.append({
                        "code": key[0], "feature": "unsupported OOXML extension",
                        "part": name,
                        "message": "this OOXML part is not safely round-tripped",
                    })
            if not lower.startswith("xl/") or not lower.endswith(".xml"):
                continue
            with package.open(item) as handle:
                sample = handle.read(min(item.file_size, 8 * 1024 * 1024))
            descriptors = _extension_descriptors(sample)
            for descriptor in descriptors:
                key = (
                    "unsupported_ooxml_extension", lower,
                    descriptor.get("extension_uri", ""),
                    tuple(descriptor.get("namespaces", [])),
                    tuple(descriptor.get("elements", [])),
                )
                if key in seen:
                    continue
                seen.add(key)
                risks.append({
                    "code": key[0], "feature": "OOXML extension",
                    "part": name,
                    "extension_uri": descriptor.get("extension_uri", ""),
                    "namespaces": descriptor.get("namespaces", []),
                    "elements": descriptor.get("elements", []),
                    **({"parse_error": True} if descriptor.get("parse_error") else {}),
                    "message": (
                        "the part contains an OOXML extension that may be removed "
                        "on save"
                    ),
                })
    return risks


def normalize_safe_metadata(
    path: str,
    output: str,
    *,
    expected_sha256: str = "",
    expected_output_sha256: str = "",
    dry_run: bool = False,
) -> dict:
    """Remove only allowlisted compatibility metadata into a guarded output."""
    from file_ops import publish_staged_file

    source = os.path.abspath(os.path.expanduser(path))
    output = os.path.abspath(os.path.expanduser(output))
    _package_preflight(source, mutating=False)
    if os.path.splitext(source)[1].lower() not in {".xlsx", ".xlsm"}:
        raise UnsupportedOfficeFile("normalize currently supports Excel OOXML files")
    risks = inspect_preservation_risks(source)
    if risks:
        raise PreservationError(risks)
    before = store.file_sha256(source)
    if expected_sha256 and before.lower() != expected_sha256.lower():
        raise TransactionConflict("CONFLICT: input file hash does not match expected version")
    if not os.path.isdir(os.path.dirname(output)):
        raise UnsupportedOfficeFile("normalize output directory does not exist")

    fd, stage = tempfile.mkstemp(
        prefix=".agw-office-normalize-",
        suffix=os.path.splitext(output)[1] or ".xlsx",
        dir=os.path.dirname(output),
    )
    os.close(fd)
    removed = []
    try:
        with zipfile.ZipFile(source) as package, zipfile.ZipFile(
                stage, "w", zipfile.ZIP_DEFLATED) as normalized:
            normalized.comment = package.comment
            for item in package.infolist():
                payload = package.read(item)
                if item.filename.lower().endswith(".xml"):
                    prefixes = re.findall(
                        rb'xmlns:([A-Za-z_][\w.-]*)="'
                        rb'http://schemas\.microsoft\.com/office/'
                        rb'spreadsheetml/2009/9/ac"',
                        payload,
                    )
                    for prefix in prefixes:
                        for attribute in (b"knownFonts", b"dyDescent"):
                            pattern = re.compile(
                                rb"\s+" + re.escape(prefix) + rb":" + attribute
                                + rb'="[^"]*"'
                            )
                            payload, count = pattern.subn(b"", payload)
                            if count:
                                removed.append({
                                    "part": item.filename,
                                    "namespace": (
                                        "http://schemas.microsoft.com/office/"
                                        "spreadsheetml/2009/9/ac"
                                    ),
                                    "attribute": attribute.decode("ascii"),
                                    "count": count,
                                })
                normalized.writestr(item, payload)
        _package_preflight(stage, mutating=False)
        staged_risks = inspect_preservation_risks(stage)
        if staged_risks:
            raise PreservationError(staged_risks)
        if store.file_sha256(source) != before:
            raise TransactionConflict("CONFLICT: input file changed during normalization")
        published = publish_staged_file(
            output, stage, expected_hash=expected_output_sha256,
            dry_run=dry_run, operation="office-normalize",
        )
        if published.get("changed") and not published.get("dry_run"):
            stage = ""
        return {
            "input": source, "output": output,
            "input_hash": before,
            "removed_safe_metadata": removed,
            "removed_count": sum(item["count"] for item in removed),
            "preservation": {"safe_to_mutate": True, "risks": []},
            **published,
        }
    finally:
        if stage and os.path.exists(stage):
            try:
                os.unlink(stage)
            except OSError:
                pass


def _relationship_set(payload: bytes) -> set[tuple[str, str, str]]:
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as exc:
        raise UnsupportedOfficeFile("Office package contains malformed relationships") from exc
    return {
        (node.attrib.get("Type", ""), node.attrib.get("Target", ""),
         node.attrib.get("TargetMode", ""))
        for node in root
    }


def _package_state(path: str) -> dict:
    state = {"parts": {}, "relationships": {}}
    with zipfile.ZipFile(path) as package:
        for item in package.infolist():
            name = item.filename.replace("\\", "/")
            payload = package.read(item)
            state["parts"][name] = hashlib.sha256(payload).hexdigest()
            if name.lower().endswith(".rels"):
                state["relationships"][name] = _relationship_set(payload)
    return state


_PRESERVED_PART_PREFIXES = (
    "_xmlsignatures/",
    "customxml/",
    "customui/",
    "xl/activex/",
    "xl/ctrlprops/",
    "xl/dialogsheets/",
    "xl/embeddings/",
    "xl/externallinks/",
    "xl/macrosheets/",
    "xl/model/",
)
_PRESERVED_PART_NAMES = {
    "xl/connections.xml",
    "xl/vbaproject.bin",
    "xl/vbaprojectsignature.bin",
}
_PRESERVED_MARKERS = (
    "activex", "customui", "customxml", "dialogsheets", "digitalsignature",
    "externallink", "macrosheet", "macroenabled", "oleobject", "vbaproject",
    "vmldrawing",
)


def _preserved_category(name: str) -> str:
    lower = name.replace("\\", "/").lower().lstrip("/")
    if "vbaprojectsignature" in lower or lower.startswith("_xmlsignatures/"):
        return "signature"
    if "vbaproject" in lower:
        return "vba"
    if lower.startswith("xl/activex/"):
        return "activex"
    if lower.startswith(("xl/embeddings/", "xl/ctrlprops/")):
        return "embedded"
    if lower.startswith(("xl/dialogsheets/", "xl/macrosheets/")):
        return "legacy_macro"
    if lower.startswith("xl/drawings/") and lower.endswith(".vml"):
        return "legacy_controls"
    if lower.startswith("customxml/"):
        return "custom_xml"
    if lower.startswith("customui/"):
        return "custom_ui"
    if lower.startswith("xl/externallinks/"):
        return "external_links"
    if lower == "xl/connections.xml":
        return "connections"
    if lower.startswith("xl/model/"):
        return "data_model"
    return ""


def _preserved_part(name: str) -> bool:
    lower = name.replace("\\", "/").lower().lstrip("/")
    return (
        lower in _PRESERVED_PART_NAMES
        or any(lower.startswith(prefix) for prefix in _PRESERVED_PART_PREFIXES)
        or (lower.startswith("xl/drawings/") and lower.endswith(".vml"))
        or "vbaproject" in lower
    )


def _preserved_relationships(payload: bytes) -> list[dict]:
    root = ElementTree.fromstring(payload)
    result = []
    for node in root:
        rel_type = node.attrib.get("Type", "")
        target = node.attrib.get("Target", "")
        signal = f"{rel_type} {target}".lower()
        if any(marker in signal for marker in _PRESERVED_MARKERS):
            result.append({
                "type": rel_type,
                "target": target.replace("\\", "/"),
                "target_mode": node.attrib.get("TargetMode", ""),
            })
    return sorted(result, key=lambda item: (
        item["type"], item["target"], item["target_mode"]
    ))


def _preserved_content_types(payload: bytes) -> list[dict]:
    root = ElementTree.fromstring(payload)
    result = []
    for node in root:
        part_name = node.attrib.get("PartName", "")
        content_type = node.attrib.get("ContentType", "")
        extension = node.attrib.get("Extension", "")
        signal = f"{part_name} {content_type} {extension}".lower()
        if _preserved_part(part_name) or any(
                marker in signal for marker in _PRESERVED_MARKERS):
            result.append({
                "part_name": part_name.replace("\\", "/"),
                "extension": extension,
                "content_type": content_type,
            })
    return sorted(result, key=lambda item: (
        item["part_name"], item["extension"], item["content_type"]
    ))


def package_preservation_manifest(path: str) -> dict:
    """Describe content that a staged Excel edit must preserve exactly."""
    path = os.path.abspath(os.path.expanduser(path))
    _package_preflight(path, mutating=False)
    extension = os.path.splitext(path)[1].lower()
    if extension not in {".xlsx", ".xlsm"}:
        raise UnsupportedOfficeFile(
            "package preservation manifests support .xlsx and .xlsm"
        )
    parts = {}
    relationships = {}
    content_types = []
    with zipfile.ZipFile(path) as package:
        for item in package.infolist():
            name = item.filename.replace("\\", "/")
            payload = package.read(item)
            if _preserved_part(name):
                parts[name] = {
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "bytes": len(payload),
                    "category": _preserved_category(name) or "protected",
                }
            if name.lower().endswith(".rels"):
                selected = _preserved_relationships(payload)
                if selected:
                    relationships[name] = selected
            elif name.lower() == "[content_types].xml":
                content_types = _preserved_content_types(payload)
    categories = {}
    for item in parts.values():
        category = item["category"]
        categories[category] = categories.get(category, 0) + 1
    return {
        "schema": "agw-office-preservation-v1",
        "path": path,
        "extension": extension,
        "file_sha256": store.file_sha256(path),
        "protected_parts": parts,
        "protected_relationships": relationships,
        "protected_content_types": content_types,
        "categories": categories,
        "protected_part_count": len(parts),
    }


def validate_package_preservation(
    original_path: str,
    candidate_path: str,
    *,
    expected_original_sha256: str = "",
) -> dict:
    """Verify that a candidate retains active and integration-bearing parts."""
    original = package_preservation_manifest(original_path)
    candidate = package_preservation_manifest(candidate_path)
    wanted = str(expected_original_sha256 or "").strip().lower()
    if wanted and original["file_sha256"].lower() != wanted:
        raise TransactionConflict(
            "CONFLICT: preservation baseline hash does not match expected version"
        )
    risks = []
    if original["extension"] != candidate["extension"]:
        risks.append({
            "code": "office_extension_changed", "part": "package",
            "message": (
                f"extension changed from {original['extension']} "
                f"to {candidate['extension']}"
            ),
        })
    before_parts = original["protected_parts"]
    after_parts = candidate["protected_parts"]
    for name in sorted(set(before_parts) | set(after_parts)):
        if name not in after_parts:
            message = "protected Office part was removed"
            code = "removed_protected_ooxml_part"
        elif name not in before_parts:
            message = "protected Office part was added"
            code = "added_protected_ooxml_part"
        elif before_parts[name]["sha256"] != after_parts[name]["sha256"]:
            message = "protected Office part was altered"
            code = "altered_protected_ooxml_part"
        else:
            continue
        risks.append({
            "code": code,
            "feature": (before_parts.get(name) or after_parts[name])["category"],
            "part": name,
            "message": message,
        })
    for key, label in (
        ("protected_relationships", "protected Office relationships changed"),
        ("protected_content_types", "protected Office content types changed"),
    ):
        if original[key] != candidate[key]:
            risks.append({
                "code": f"altered_{key}", "feature": "package integration",
                "part": "package", "message": label,
            })
    if risks:
        raise PreservationError(risks)
    return {
        "verified": True,
        "schema": original["schema"],
        "original": original["path"],
        "candidate": candidate["path"],
        "original_hash": original["file_sha256"],
        "candidate_hash": candidate["file_sha256"],
        "protected_part_count": original["protected_part_count"],
        "categories": original["categories"],
        "macros_unchanged": True,
    }


def _mutable_part(name: str, extension: str, operation: str) -> bool:
    lower = name.lower()
    if lower in {"[content_types].xml", "docprops/core.xml", "docprops/app.xml"}:
        return True
    if extension == ".xlsx":
        return lower in {
            "xl/workbook.xml", "xl/styles.xml", "xl/sharedstrings.xml",
            "xl/calcchain.xml", "xl/_rels/workbook.xml.rels",
        } or lower.startswith(("xl/worksheets/", "xl/tables/"))
    if extension == ".docx":
        return lower == "word/document.xml"
    if extension == ".pptx":
        return lower == "ppt/presentation.xml" or lower.startswith("ppt/slides/")
    return False


def verify_package_preservation(before_path: str, after_path: str,
                                operation: str) -> dict:
    """Refuse staged packages that lose or unexpectedly rewrite OOXML parts."""
    before = _package_state(before_path)
    after = _package_state(after_path)
    extension = os.path.splitext(before_path)[1].lower()
    before_names = set(before["parts"])
    after_names = set(after["parts"])
    removed = sorted(before_names - after_names)
    allowed_removed = {name for name in removed if name.lower() == "xl/calcchain.xml"}
    unexpected_removed = [name for name in removed if name not in allowed_removed]
    added = sorted(after_names - before_names)
    unexpected_added = [
        name for name in added
        if not (extension == ".xlsx" and operation == "ensure-table"
                and _mutable_part(name, extension, operation))
    ]
    altered = sorted(
        name for name in before_names & after_names
        if before["parts"][name] != after["parts"][name]
        and not _mutable_part(name, extension, operation)
    )
    relationship_changes = sorted(
        name for name in set(before["relationships"]) & set(after["relationships"])
        if before["relationships"][name] != after["relationships"][name]
        and not _mutable_part(name, extension, operation)
    )
    risks = []
    for code, names in (
        ("removed_ooxml_part", unexpected_removed),
        ("added_ooxml_part", unexpected_added),
        ("altered_ooxml_part", altered),
        ("altered_ooxml_relationships", relationship_changes),
    ):
        risks.extend({
            "code": code, "feature": "OOXML package preservation", "part": name,
            "message": code.replace("_", " "),
        } for name in names)
    if risks:
        raise PreservationError(risks)
    return {
        "verified": True,
        "removed_regenerable_parts": sorted(allowed_removed),
    }


def _package_preflight(path: str, *, mutating: bool = True) -> None:
    if os.path.getsize(path) > MAX_PACKAGE_BYTES:
        raise _PackagePreflightError(
            "package_too_large",
            f"Office mutation limit is {MAX_PACKAGE_BYTES // (1024 * 1024)} MiB"
        )
    try:
        with zipfile.ZipFile(path) as package:
            infos = package.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                raise _PackagePreflightError(
                    "package_too_many_entries",
                    "Office package has too many ZIP entries",
                )
            total = 0
            names = set()
            for item in infos:
                # ZipInfo.filename normalizes the platform path separator;
                # orig_filename preserves the package's literal central-dir name.
                literal_name = getattr(item, "orig_filename", item.filename)
                name = literal_name.replace("\\", "/")
                canonical = "/".join(part for part in name.split("/") if part not in ("", "."))
                if ("\\" in literal_name or name.startswith(("/", "\\"))
                        or ":" in name.split("/", 1)[0]
                        or ".." in name.split("/") or "\x00" in name):
                    raise _PackagePreflightError(
                        "package_unsafe_part_name",
                        "Office package contains an unsafe ZIP path",
                    )
                if canonical in names:
                    raise _PackagePreflightError(
                        "package_duplicate_part",
                        "Office package contains duplicate ZIP paths",
                    )
                names.add(canonical)
                if item.flag_bits & 0x1:
                    raise _PackagePreflightError(
                        "package_encrypted_entry",
                        "encrypted Office packages are unsupported",
                    )
                total += item.file_size
                if item.file_size > MAX_ENTRY_BYTES or total > MAX_UNCOMPRESSED_BYTES:
                    raise _PackagePreflightError(
                        "package_expansion_limit",
                        "Office package expands beyond safety limits",
                    )
                if item.file_size > 1024 * 1024:
                    ratio = item.file_size / max(1, item.compress_size)
                    if ratio > MAX_COMPRESSION_RATIO:
                        raise _PackagePreflightError(
                            "package_compression_ratio_unsafe",
                            "Office package compression ratio is unsafe",
                        )
                if name.lower().endswith(".xml"):
                    prefix = package.open(item).read(min(item.file_size, 1024 * 1024))
                    upper = prefix.upper()
                    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
                        raise _PackagePreflightError(
                            "package_unsafe_xml_declaration",
                            "Office package contains unsafe XML declarations",
                        )
            lower = {name.lower() for name in names}
            if mutating and any(
                    marker in name
                    for name in lower
                    for marker in (
                        "vbaproject.bin", "_xmlsignatures/", "activex/",
                        "embeddings/", "ctrlprops/",
                    )):
                raise _PackagePreflightError(
                    "package_active_content_unsupported",
                    "this Office package contains active, signed, or embedded content "
                    "that targeted mutation does not safely preserve",
                )
    except zipfile.BadZipFile as exc:
        raise _PackagePreflightError(
            "package_invalid_zip", "file is not a valid Office OOXML package",
        ) from exc


_VALIDATION_TIERS = ("package", "office-schema", "excel-strict")
_RELATIONSHIP_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
_CONTENT_TYPES_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
_OFFICE_DOCUMENT_REL = "/officeDocument"
_COMMENTS_REL = "/comments"
_VML_DRAWING_REL = "/vmlDrawing"
_VBA_PROJECT_REL = "/vbaProject"
_VBA_CONTENT_TYPE = "application/vnd.ms-office.vbaproject"
_MACRO_WORKBOOK_CONTENT_TYPES = {
    "application/vnd.ms-excel.sheet.macroenabled.main+xml",
    "application/vnd.ms-excel.template.macroenabled.main+xml",
    "application/vnd.ms-excel.addin.macroenabled.main+xml",
}


@dataclass(frozen=True)
class _Relationship:
    relationship_part: str
    owner_part: Optional[str]
    relationship_id: str
    relationship_type: str
    target: str
    target_mode: str
    resolved_target: str = ""


@dataclass
class _ValidationContext:
    path: str
    extension: str
    package: zipfile.ZipFile
    part_names: set[str]
    xml_roots: dict[str, ElementTree.Element]
    relationships: list[_Relationship]
    content_type_defaults: dict[str, str]
    content_type_overrides: dict[str, str]

    def read(self, part: str) -> bytes:
        return self.package.read(part)


def _validation_issue(code: str, message: str, *, part: str = "package",
                      **details) -> dict:
    return {
        "code": code,
        "severity": "error",
        "part": part,
        "message": message,
        **details,
    }


def _preflight_issue(error: UnsupportedOfficeFile) -> dict:
    message = str(error)
    validation_code = getattr(error, "validation_code", "")
    if validation_code:
        return _validation_issue(validation_code, message)
    mappings = (
        ("mutation limit", "package_too_large"),
        ("too many ZIP entries", "package_too_many_entries"),
        ("unsafe ZIP path", "package_unsafe_part_name"),
        ("duplicate ZIP paths", "package_duplicate_part"),
        ("encrypted Office packages", "package_encrypted_entry"),
        ("expands beyond safety limits", "package_expansion_limit"),
        ("compression ratio is unsafe", "package_compression_ratio_unsafe"),
        ("unsafe XML declarations", "package_unsafe_xml_declaration"),
        ("valid Office OOXML package", "package_invalid_zip"),
    )
    code = next(
        (candidate for marker, candidate in mappings if marker in message),
        "package_preflight_failed",
    )
    return _validation_issue(code, message)


def _local_name(value: str) -> str:
    return _qualified_name(value)[1]


def _part_identity(name: str) -> tuple[Optional[str], Optional[str]]:
    """Return a comparison identity and a refusal reason for an OPC part name."""
    if re.search(r"%(?![0-9A-Fa-f]{2})", name):
        return None, "part name contains an invalid percent escape"
    if re.search(r"%(?:2f|5c)", name, re.IGNORECASE):
        return None, "part name contains an encoded path separator"
    decoded = unquote(name)
    if decoded.startswith(("/", "\\")) or "\\" in decoded or "\x00" in decoded:
        return None, "part name has an unsafe absolute or escaped path"
    if "?" in decoded or "#" in decoded:
        return None, "part name contains a URI query or fragment delimiter"
    if any(ord(character) < 32 for character in decoded):
        return None, "part name contains a control character"
    segments = decoded.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        return None, "part name contains an empty or relative segment"
    normalized = unicodedata.normalize("NFC", decoded).casefold()
    return normalized, None


def _relationship_owner(relationship_part: str) -> Optional[str]:
    if relationship_part.casefold() == "_rels/.rels":
        return None
    directory, filename = posixpath.split(relationship_part)
    if posixpath.basename(directory).casefold() != "_rels" or not filename.endswith(".rels"):
        return ""
    owner_directory = posixpath.dirname(directory)
    owner_name = filename[:-5]
    return posixpath.join(owner_directory, owner_name) if owner_directory else owner_name


def _resolve_relationship_target(
    owner_part: Optional[str], target: str,
) -> tuple[str, Optional[str]]:
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc:
        return "", "internal relationship target must not contain a URI authority"
    raw_path = unquote(parsed.path)
    if not raw_path or "\\" in raw_path or "\x00" in raw_path:
        return "", "internal relationship target is empty or unsafe"
    if any(ord(character) < 32 for character in raw_path):
        return "", "internal relationship target contains a control character"
    if raw_path.startswith("/"):
        candidate = raw_path.lstrip("/")
    else:
        base = posixpath.dirname(owner_part) if owner_part else ""
        candidate = posixpath.join(base, raw_path)
    normalized = posixpath.normpath(candidate)
    if normalized in {"", ".", ".."} or normalized.startswith("../"):
        return "", "internal relationship target escapes the package root"
    return normalized, None


def _validate_part_identities(context: _ValidationContext) -> list[dict]:
    issues = []
    identities = {}
    for name in sorted(context.part_names):
        identity, reason = _part_identity(name)
        if reason:
            issues.append(_validation_issue(
                "opc_unsafe_part_identity", reason, part=name,
            ))
            continue
        if identity in identities:
            issues.append(_validation_issue(
                "opc_duplicate_part_identity",
                "multiple package parts resolve to the same normalized identity",
                part=name, conflicts_with=identities[identity],
            ))
        else:
            identities[identity] = name
    return issues


def _parse_xml_parts(context: _ValidationContext) -> list[dict]:
    issues = []
    for name in sorted(context.part_names):
        if not (name.casefold().endswith((".xml", ".rels"))
                or name.casefold() == "[content_types].xml"):
            continue
        payload = context.read(name)
        upper = payload.upper()
        if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
            issues.append(_validation_issue(
                "opc_xml_declaration_unsafe",
                "package XML part contains a DTD or entity declaration",
                part=name,
            ))
            continue
        try:
            context.xml_roots[name] = ElementTree.fromstring(payload)
        except ElementTree.ParseError as error:
            issues.append(_validation_issue(
                "opc_xml_malformed", "package XML part is not well-formed",
                part=name, parse_error=str(error),
            ))
    return issues


def _find_part(context: _ValidationContext, wanted: str) -> str:
    folded = wanted.casefold()
    return next((name for name in context.part_names if name.casefold() == folded), "")


def _validate_content_types(context: _ValidationContext) -> list[dict]:
    issues = []
    part = _find_part(context, "[Content_Types].xml")
    if not part:
        return [_validation_issue(
            "opc_content_types_missing",
            "package is missing [Content_Types].xml",
            part="[Content_Types].xml",
        )]
    root = context.xml_roots.get(part)
    if root is None:
        return issues
    namespace, local = _qualified_name(root.tag)
    if local != "Types" or namespace != _CONTENT_TYPES_NS:
        issues.append(_validation_issue(
            "opc_content_types_root_invalid",
            "content-types part has an invalid root element or namespace",
            part=part,
        ))
    for node in root:
        node_namespace, kind = _qualified_name(node.tag)
        if node_namespace != _CONTENT_TYPES_NS:
            issues.append(_validation_issue(
                "opc_content_type_element_invalid",
                "content-types part contains an element from an invalid namespace",
                part=part, element=kind,
            ))
            continue
        if kind == "Default":
            extension = node.attrib.get("Extension", "").strip().casefold()
            content_type = node.attrib.get("ContentType", "").strip()
            if not extension or not content_type:
                issues.append(_validation_issue(
                    "opc_content_type_declaration_invalid",
                    "default content-type declaration is incomplete", part=part,
                ))
            elif extension in context.content_type_defaults:
                issues.append(_validation_issue(
                    "opc_content_type_default_duplicate",
                    "content-type extension is declared more than once",
                    part=part, extension=extension,
                ))
            else:
                context.content_type_defaults[extension] = content_type
        elif kind == "Override":
            raw_name = node.attrib.get("PartName", "").strip()
            content_type = node.attrib.get("ContentType", "").strip()
            normalized_name = raw_name.lstrip("/")
            unused_identity, unsafe_reason = _part_identity(normalized_name) \
                if normalized_name else (None, "part name is empty")
            if (not raw_name.startswith("/") or not normalized_name
                    or not content_type or unsafe_reason):
                issues.append(_validation_issue(
                    "opc_content_type_declaration_invalid",
                    "override content-type declaration is incomplete or unsafe",
                    part=part, declared_part=raw_name,
                    **({"reason": unsafe_reason} if unsafe_reason else {}),
                ))
            elif normalized_name in context.content_type_overrides:
                issues.append(_validation_issue(
                    "opc_content_type_override_duplicate",
                    "package part has multiple content-type overrides",
                    part=part, declared_part=raw_name,
                ))
            else:
                context.content_type_overrides[normalized_name] = content_type
                if normalized_name not in context.part_names:
                    issues.append(_validation_issue(
                        "opc_content_type_override_target_missing",
                        "content-type override references a missing package part",
                        part=part, declared_part=raw_name,
                    ))
        else:
            issues.append(_validation_issue(
                "opc_content_type_element_invalid",
                "content-types part contains an unsupported declaration",
                part=part, element=kind,
            ))
    for name in sorted(context.part_names):
        if name == part:
            continue
        extension = name.rsplit(".", 1)[1].casefold() if "." in name else ""
        if (name not in context.content_type_overrides
                and extension not in context.content_type_defaults):
            issues.append(_validation_issue(
                "opc_content_type_missing",
                "package part has no matching content type",
                part=name,
            ))
    return issues


def _validate_relationships(context: _ValidationContext) -> list[dict]:
    issues = []
    relationship_parts = sorted(
        name for name in context.part_names if name.casefold().endswith(".rels")
    )
    root_relationships = _find_part(context, "_rels/.rels")
    if not root_relationships:
        issues.append(_validation_issue(
            "opc_root_relationships_missing",
            "package is missing its root relationships part", part="_rels/.rels",
        ))
    for part in relationship_parts:
        owner = _relationship_owner(part)
        if owner == "":
            issues.append(_validation_issue(
                "opc_relationship_part_name_invalid",
                "relationship part is not stored in an OPC _rels directory",
                part=part,
            ))
            continue
        if owner is not None and owner not in context.part_names:
            issues.append(_validation_issue(
                "opc_relationship_owner_missing",
                "relationship part belongs to a missing package part",
                part=part, owner_part=owner,
            ))
        root = context.xml_roots.get(part)
        if root is None:
            continue
        namespace, local = _qualified_name(root.tag)
        if local != "Relationships" or namespace != _RELATIONSHIP_NS:
            issues.append(_validation_issue(
                "opc_relationships_root_invalid",
                "relationships part has an invalid root element or namespace",
                part=part,
            ))
        identifiers = set()
        for node in root:
            node_namespace, node_local = _qualified_name(node.tag)
            if node_local != "Relationship" or node_namespace != _RELATIONSHIP_NS:
                issues.append(_validation_issue(
                    "opc_relationship_element_invalid",
                    "relationships part contains an unsupported element", part=part,
                ))
                continue
            relationship_id = node.attrib.get("Id", "").strip()
            relationship_type = node.attrib.get("Type", "").strip()
            target = node.attrib.get("Target", "").strip()
            target_mode = node.attrib.get("TargetMode", "").strip()
            if not relationship_id:
                issues.append(_validation_issue(
                    "opc_relationship_id_missing",
                    "relationship is missing its Id", part=part,
                ))
            elif relationship_id in identifiers:
                issues.append(_validation_issue(
                    "opc_relationship_id_duplicate",
                    "relationship Id is duplicated within its part",
                    part=part, relationship_id=relationship_id,
                ))
            identifiers.add(relationship_id)
            if not relationship_type or not urlsplit(relationship_type).scheme:
                issues.append(_validation_issue(
                    "opc_relationship_type_invalid",
                    "relationship Type must be an absolute URI",
                    part=part, relationship_id=relationship_id,
                ))
            if not target:
                issues.append(_validation_issue(
                    "opc_relationship_target_missing",
                    "relationship is missing its Target",
                    part=part, relationship_id=relationship_id,
                ))
            if target_mode and target_mode != "External":
                issues.append(_validation_issue(
                    "opc_relationship_target_mode_invalid",
                    "relationship TargetMode must be External when present",
                    part=part, relationship_id=relationship_id,
                ))
            resolved_target = ""
            if target and target_mode != "External":
                resolved_target, reason = _resolve_relationship_target(owner, target)
                if reason:
                    issues.append(_validation_issue(
                        "opc_relationship_target_unsafe", reason, part=part,
                        relationship_id=relationship_id, target=target,
                    ))
                elif resolved_target not in context.part_names:
                    issues.append(_validation_issue(
                        "opc_relationship_target_missing_part",
                        "relationship target does not exist in the package",
                        part=part, relationship_id=relationship_id,
                        target=target, resolved_target=resolved_target,
                    ))
            context.relationships.append(_Relationship(
                relationship_part=part,
                owner_part=owner,
                relationship_id=relationship_id,
                relationship_type=relationship_type,
                target=target,
                target_mode=target_mode,
                resolved_target=resolved_target,
            ))
    if root_relationships and not any(
            relationship.owner_part is None
            and relationship.relationship_type.endswith(_OFFICE_DOCUMENT_REL)
            for relationship in context.relationships):
        issues.append(_validation_issue(
            "opc_office_document_relationship_missing",
            "root relationships do not identify an Office document part",
            part=root_relationships,
        ))
    return issues


def _validate_office_schema(context: _ValidationContext) -> list[dict]:
    issues = _validate_part_identities(context)
    issues.extend(_parse_xml_parts(context))
    issues.extend(_validate_content_types(context))
    issues.extend(_validate_relationships(context))
    return issues


def _attribute_by_local_name(node: ElementTree.Element, wanted: str) -> str:
    for name, value in node.attrib.items():
        if _local_name(name) == wanted:
            return value
    return ""


def _content_type_for(context: _ValidationContext, part: str) -> str:
    if part in context.content_type_overrides:
        return context.content_type_overrides[part]
    extension = part.rsplit(".", 1)[1].casefold() if "." in part else ""
    return context.content_type_defaults.get(extension, "")


def _validate_threaded_comment_people(context: _ValidationContext) -> list[dict]:
    issues = []
    people = {}
    person_parts = sorted(
        name for name in context.part_names
        if name.casefold().startswith("xl/persons/") and name.casefold().endswith(".xml")
    )
    for part in person_parts:
        root = context.xml_roots.get(part)
        if root is None:
            continue
        for person in root.iter():
            if _local_name(person.tag) != "person":
                continue
            person_id = person.attrib.get("id", "").strip()
            if not person_id:
                issues.append(_validation_issue(
                    "excel_person_id_missing", "person record is missing its id",
                    part=part,
                ))
            elif person_id in people:
                issues.append(_validation_issue(
                    "excel_person_id_duplicate",
                    "person id is duplicated across the workbook",
                    part=part, person_id=person_id,
                    first_declared_in=people[person_id],
                ))
            else:
                people[person_id] = part
    threaded_parts = sorted(
        name for name in context.part_names
        if name.casefold().startswith("xl/threadedcomments/")
        and name.casefold().endswith(".xml")
    )
    for part in threaded_parts:
        root = context.xml_roots.get(part)
        if root is None:
            continue
        for comment in root.iter():
            if _local_name(comment.tag) != "threadedComment":
                continue
            person_id = comment.attrib.get("personId", "").strip()
            if not person_id:
                issues.append(_validation_issue(
                    "excel_threaded_comment_person_id_missing",
                    "threaded comment is missing its personId", part=part,
                    reference=comment.attrib.get("ref", ""),
                ))
            elif person_id not in people:
                issues.append(_validation_issue(
                    "excel_threaded_comment_person_unknown",
                    "threaded comment references an unknown person id",
                    part=part, person_id=person_id,
                    reference=comment.attrib.get("ref", ""),
                ))
    return issues


def _validate_legacy_comments(context: _ValidationContext) -> list[dict]:
    issues = []
    relationships_by_owner = {}
    for relationship in context.relationships:
        relationships_by_owner.setdefault(relationship.owner_part, []).append(relationship)
    worksheet_parts = sorted(
        name for name in context.part_names
        if name.casefold().startswith("xl/worksheets/")
        and name.casefold().endswith(".xml")
    )
    for part in worksheet_parts:
        relationships = relationships_by_owner.get(part, [])
        comments = [
            relationship for relationship in relationships
            if relationship.relationship_type.endswith(_COMMENTS_REL)
        ]
        drawings = {
            relationship.relationship_id: relationship
            for relationship in relationships
            if relationship.relationship_type.endswith(_VML_DRAWING_REL)
        }
        root = context.xml_roots.get(part)
        legacy_ids = [] if root is None else [
            _attribute_by_local_name(node, "id")
            for node in root.iter() if _local_name(node.tag) == "legacyDrawing"
        ]
        if comments and not drawings:
            issues.append(_validation_issue(
                "excel_legacy_comments_vml_relationship_missing",
                "worksheet comments require a VML drawing relationship",
                part=part,
            ))
        if comments and not any(legacy_ids):
            issues.append(_validation_issue(
                "excel_legacy_comments_drawing_reference_missing",
                "worksheet comments require a legacyDrawing reference",
                part=part,
            ))
        for relationship_id in legacy_ids:
            if not relationship_id:
                issues.append(_validation_issue(
                    "excel_legacy_drawing_id_missing",
                    "legacyDrawing element is missing its relationship id", part=part,
                ))
            elif relationship_id not in drawings:
                issues.append(_validation_issue(
                    "excel_legacy_drawing_relationship_invalid",
                    "legacyDrawing does not reference a VML drawing relationship",
                    part=part, relationship_id=relationship_id,
                ))
    return issues


def _validate_macro_coherence(context: _ValidationContext) -> list[dict]:
    issues = []
    vba_parts = sorted(
        name for name in context.part_names
        if name.casefold() == "xl/vbaproject.bin"
    )
    office_document = next((
        relationship.resolved_target for relationship in context.relationships
        if relationship.owner_part is None
        and relationship.relationship_type.endswith(_OFFICE_DOCUMENT_REL)
    ), "xl/workbook.xml")
    vba_relationships = [
        relationship for relationship in context.relationships
        if relationship.owner_part == office_document
        and relationship.relationship_type.endswith(_VBA_PROJECT_REL)
    ]
    macro_main = _content_type_for(context, office_document).casefold() \
        in _MACRO_WORKBOOK_CONTENT_TYPES
    macro_signal = bool(vba_parts or vba_relationships or macro_main)
    for part in vba_parts:
        if _content_type_for(context, part).casefold() != _VBA_CONTENT_TYPE:
            issues.append(_validation_issue(
                "excel_macro_content_type_invalid",
                "VBA project part is missing its required content type", part=part,
            ))
        if not any(
                relationship.resolved_target == part
                for relationship in vba_relationships):
            issues.append(_validation_issue(
                "excel_macro_relationship_missing",
                "VBA project part is not linked from the workbook",
                part=part,
            ))
    if vba_relationships and not vba_parts:
        issues.append(_validation_issue(
            "excel_macro_part_missing",
            "workbook declares a VBA relationship without a VBA project part",
            part=office_document,
        ))
    if macro_signal and not macro_main:
        issues.append(_validation_issue(
            "excel_macro_workbook_content_type_invalid",
            "macro-bearing workbook lacks a macro-enabled main content type",
            part=office_document,
        ))
    if context.extension == ".xlsx" and macro_signal:
        issues.append(_validation_issue(
            "excel_macro_extension_mismatch",
            "macro-bearing workbook must not use the .xlsx extension",
        ))
    if context.extension == ".xlsm" and not vba_parts:
        issues.append(_validation_issue(
            "excel_macro_declarations_missing",
            ".xlsm package does not contain a VBA project part",
        ))
    return issues


def _validate_excel_strict(context: _ValidationContext) -> list[dict]:
    if context.extension not in {".xlsx", ".xlsm"}:
        return [_validation_issue(
            "excel_strict_unsupported_extension",
            "excel-strict validation supports only .xlsx and .xlsm packages",
        )]
    issues = _validate_threaded_comment_people(context)
    issues.extend(_validate_legacy_comments(context))
    issues.extend(_validate_macro_coherence(context))
    return issues


def office_validation_capabilities(
    roundtrip_adapter: Optional[OfficeRoundtripAdapter] = None,
) -> dict:
    """Describe validation tiers and the optional native roundtrip seam."""
    roundtrip = {
        "available": False,
        "adapter": "",
        "reason_code": "native_roundtrip_adapter_unavailable",
    }
    if roundtrip_adapter is not None:
        try:
            provided = dict(roundtrip_adapter.capability())
        except Exception as error:  # adapter discovery must be fail-closed
            provided = {
                "available": False,
                "adapter": type(roundtrip_adapter).__name__,
                "reason_code": "roundtrip_adapter_capability_failed",
                "message": str(error),
            }
        roundtrip.update(provided)
    return {
        "schema": "agw-office-validation-capabilities-v1",
        "tiers": list(_VALIDATION_TIERS),
        "roundtrip": roundtrip,
    }


def validate_office_package(
    path: str,
    *,
    tier: str = "package",
    raise_on_error: bool = True,
) -> dict:
    """Validate an OOXML package using a cumulative, bounded validation tier."""
    if tier not in _VALIDATION_TIERS:
        raise ValueError(f"unknown Office validation tier: {tier}")
    path = os.path.abspath(os.path.expanduser(path))
    report = {
        "schema": "agw-office-validation-v1",
        "path": path,
        "tier": tier,
        "valid": False,
        "validators": [],
        "issues": [],
        "issue_count": 0,
    }
    if not os.path.isfile(path):
        report["issues"] = [_validation_issue(
            "office_file_missing", "Office package is not a regular file",
        )]
    else:
        try:
            _package_preflight(path, mutating=False)
        except UnsupportedOfficeFile as error:
            report["issues"] = [_preflight_issue(error)]
        report["validators"].append({
            "name": "package", "valid": not report["issues"],
            "issue_count": len(report["issues"]),
        })
    if not report["issues"] and tier != "package":
        with zipfile.ZipFile(path) as package:
            part_names = {
                item.filename.replace("\\", "/")
                for item in package.infolist() if not item.is_dir()
            }
            context = _ValidationContext(
                path=path,
                extension=os.path.splitext(path)[1].casefold(),
                package=package,
                part_names=part_names,
                xml_roots={},
                relationships=[],
                content_type_defaults={},
                content_type_overrides={},
            )
            schema_issues = _validate_office_schema(context)
            report["issues"].extend(schema_issues)
            report["validators"].append({
                "name": "office-schema", "valid": not schema_issues,
                "issue_count": len(schema_issues),
            })
            if tier == "excel-strict":
                excel_issues = _validate_excel_strict(context)
                report["issues"].extend(excel_issues)
                report["validators"].append({
                    "name": "excel-strict", "valid": not excel_issues,
                    "issue_count": len(excel_issues),
                })
    report["issue_count"] = len(report["issues"])
    report["valid"] = report["issue_count"] == 0
    if os.path.isfile(path):
        report["file_sha256"] = store.file_sha256(path)
    if raise_on_error and not report["valid"]:
        raise OfficeValidationError(report)
    return report


def _target_preflight(
    path: str,
    *,
    allow_preservation_risks: bool = False,
    allow_macro_enabled: bool = False,
) -> str:
    path = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(path):
        raise TransactionError(f"not a regular file: {path}")
    if os.path.islink(path):
        raise UnsupportedOfficeFile("symbolic-link Office targets are unsupported")
    mode = os.stat(path, follow_symlinks=False).st_mode
    if not stat.S_ISREG(mode):
        raise UnsupportedOfficeFile("Office target is not a regular file")
    if getattr(os.stat(path, follow_symlinks=False), "st_nlink", 1) > 1:
        raise UnsupportedOfficeFile("hard-linked Office targets are unsupported")
    if os.path.splitext(path)[1].lower() == ".xlsm" and not allow_macro_enabled:
        raise UnsupportedOfficeFile(".xlsm mutation is unsupported; use .xlsx")
    if profiles.is_gdoc_stub(path):
        raise UnsupportedOfficeFile("Google Docs pointer stubs have no editable local content")
    if profiles.is_placeholder(path):
        raise UnsupportedOfficeFile("file is a cloud-only placeholder; hydrate it first")
    if profiles.is_sync_artifact(path):
        raise UnsupportedOfficeFile("Office lock/conflict artifacts are not editable targets")
    owner_lock = os.path.join(os.path.dirname(path), "~$" + os.path.basename(path))
    if os.path.exists(owner_lock):
        raise TransactionConflict("Office reports that this file is currently open")
    checkouts = store.state_load().get("checkouts", {})
    normalized = os.path.normcase(path)
    if normalized in {os.path.normcase(os.path.abspath(key)) for key in checkouts}:
        raise TransactionConflict(
            "file has an open Guardrails checkout; publish or resolve it first"
        )
    _package_preflight(path, mutating=not allow_macro_enabled)
    risks = inspect_preservation_risks(path)
    if risks and not allow_preservation_risks:
        raise PreservationError(risks)
    return path


def _archive_mutation_preimage(path: str, operation: str,
                               expected_sha256: str) -> dict:
    resolved_retention = retention_config.load()
    snapshot = store.archive_file(
        path,
        mode="copy",
        dedupe=True,
        reason=f"pre-image before agw office {operation}",
        actor=f"agw office {operation}",
        retention_class="mutation_preimage",
        protected_until_ns=retention_config.protected_until_ns(
            resolved_retention
        ),
        retention_config=resolved_retention,
    )
    if snapshot.get("sha256") != expected_sha256:
        raise TransactionError("archived pre-image does not match the live source")
    return snapshot


def execute_mutation(
    path: str,
    *,
    operation: str,
    plan: Callable[[str], MutationPlan],
    apply: Callable[[str, MutationPlan], None],
    validate: Callable[[str, MutationPlan], dict],
    expected_sha256: Optional[str] = None,
    dry_run: bool = False,
    allow_preservation_risks: bool = False,
    allow_macro_enabled: bool = False,
    preservation_validator: Optional[Callable[[str, str, str], dict]] = None,
) -> dict:
    """Apply one validated Office mutation and publish it atomically."""
    if allow_macro_enabled and preservation_validator is None:
        raise TransactionError(
            "macro-enabled mutation requires an exact preservation validator"
        )
    path = os.path.abspath(os.path.expanduser(path))
    lock_name = "office-" + _target_id(path)[:32]
    stage = ""
    receipt = None
    with store.Lock(lock_name, timeout=10.0):
        path = _target_preflight(
            path, allow_preservation_risks=allow_preservation_risks,
            allow_macro_enabled=allow_macro_enabled,
        )
        before = store.file_sha256(path)
        if expected_sha256 and before.lower() != expected_sha256.lower():
            raise TransactionConflict("CONFLICT: file hash does not match expected version")
        mutation_plan = _run_capturing_warnings(lambda: plan(path), "plan")
        if not isinstance(mutation_plan, MutationPlan):
            raise TransactionError("Office adapter returned an invalid mutation plan")
        if not mutation_plan.changed:
            return {
                **mutation_plan.preview, "changed": 0, "hash": before,
                "before_hash": before, "after_hash": before,
            }
        if dry_run:
            return {
                **mutation_plan.preview,
                "dry_run": True,
                "hash": before,
                "before_hash": before,
                "after_hash": before,
            }

        suffix = os.path.splitext(path)[1]
        fd, stage = tempfile.mkstemp(
            prefix=".agw-office-", suffix=suffix, dir=os.path.dirname(path)
        )
        os.close(fd)
        try:
            shutil.copy2(path, stage)
            _run_capturing_warnings(
                lambda: apply(stage, mutation_plan), "apply"
            )
            validation = _run_capturing_warnings(
                lambda: validate(stage, mutation_plan), "validate"
            ) or {}
            _package_preflight(stage, mutating=not allow_macro_enabled)
            preservation = (
                preservation_validator(path, stage, operation)
                if preservation_validator is not None
                else verify_package_preservation(path, stage, operation)
            )
            after = store.file_sha256(stage)
            if after == before:
                return {
                    **mutation_plan.preview, **validation,
                    "preservation": preservation,
                    "changed": 0, "hash": before,
                    "before_hash": before, "after_hash": before,
                }
            if store.file_sha256(path) != before:
                raise TransactionConflict("CONFLICT: file changed while mutation was staged")

            snapshot = _archive_mutation_preimage(path, operation, before)

            mutation_id = uuid.uuid4().hex
            receipt = {
                "schema_version": 1,
                "kind": "office-mutation",
                "mutation_id": mutation_id,
                "state": "PREPARED",
                "operation": operation,
                "src": path,
                "target_id": _target_id(path),
                "before_sha256": before,
                "after_sha256": after,
                "snapshot_transaction_id": snapshot.get("transaction_id"),
                "snapshot_version": snapshot.get("version"),
                "affected": int(mutation_plan.tracking.get("affected", 0)),
            }
            manifest = _write_manifest(receipt)
            if store.file_sha256(path) != before:
                raise TransactionConflict("CONFLICT: file changed before publication")
            os.replace(stage, path)
            stage = ""
            final_hash = store.file_sha256(path)
            if final_hash != after:
                raise TransactionError("published Office file failed final hash verification")
            receipt["state"] = "COMMITTED"
            receipt["manifest"] = manifest
            _write_manifest(receipt)
            store.oplog_append({
                "op": "office-mutation",
                "transaction_id": mutation_id,
                "operation": operation,
                "before_sha256": before,
                "after_sha256": after,
                "snapshot_transaction_id": snapshot.get("transaction_id"),
                "snapshot_version": snapshot.get("version"),
                "affected": receipt["affected"],
            })
            return {
                **mutation_plan.preview,
                **validation,
                "preservation": preservation,
                "changed": receipt["affected"] or 1,
                "snapshot": snapshot.get("version"),
                "mutation": mutation_id,
                "hash": after,
                "before_hash": before,
                "after_hash": after,
            }
        except Exception:
            if receipt is not None and receipt.get("state") == "PREPARED":
                receipt["state"] = "ABORTED"
                try:
                    _write_manifest(receipt)
                except OSError:
                    pass
            raise
        finally:
            if stage and os.path.exists(stage):
                try:
                    os.unlink(stage)
                except OSError:
                    pass
