"""Shared guarded transaction lifecycle for targeted Office mutations."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import uuid
import warnings
import zipfile
from dataclasses import dataclass
from typing import Callable, Optional
from xml.etree import ElementTree

from core import profiles, store

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


class PreservationError(UnsupportedOfficeFile):
    error_code = "office_preservation_risk"

    def __init__(self, risks: list[dict]):
        self.details = {"risks": risks}
        summary = "; ".join(
            f"{risk.get('part', 'package')}: {risk.get('message', 'preservation risk')}"
            for risk in risks[:3]
        )
        super().__init__(f"Office preservation check refused the mutation: {summary}")


@dataclass(frozen=True)
class MutationPlan:
    operation: str
    preview: dict
    tracking: dict
    changed: bool = True


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
        raise UnsupportedOfficeFile(
            f"Office mutation limit is {MAX_PACKAGE_BYTES // (1024 * 1024)} MiB"
        )
    try:
        with zipfile.ZipFile(path) as package:
            infos = package.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                raise UnsupportedOfficeFile("Office package has too many ZIP entries")
            total = 0
            names = set()
            for item in infos:
                name = item.filename.replace("\\", "/")
                canonical = "/".join(part for part in name.split("/") if part not in ("", "."))
                if (name.startswith(("/", "\\")) or ":" in name.split("/", 1)[0]
                        or ".." in name.split("/") or "\x00" in name):
                    raise UnsupportedOfficeFile("Office package contains an unsafe ZIP path")
                if canonical in names:
                    raise UnsupportedOfficeFile("Office package contains duplicate ZIP paths")
                names.add(canonical)
                if item.flag_bits & 0x1:
                    raise UnsupportedOfficeFile("encrypted Office packages are unsupported")
                total += item.file_size
                if item.file_size > MAX_ENTRY_BYTES or total > MAX_UNCOMPRESSED_BYTES:
                    raise UnsupportedOfficeFile("Office package expands beyond safety limits")
                if item.file_size > 1024 * 1024:
                    ratio = item.file_size / max(1, item.compress_size)
                    if ratio > MAX_COMPRESSION_RATIO:
                        raise UnsupportedOfficeFile("Office package compression ratio is unsafe")
                if name.lower().endswith(".xml"):
                    prefix = package.open(item).read(min(item.file_size, 1024 * 1024))
                    upper = prefix.upper()
                    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
                        raise UnsupportedOfficeFile(
                            "Office package contains unsafe XML declarations"
                        )
            lower = {name.lower() for name in names}
            if mutating and any(
                    marker in name
                    for name in lower
                    for marker in (
                        "vbaproject.bin", "_xmlsignatures/", "activex/",
                        "embeddings/", "ctrlprops/",
                    )):
                raise UnsupportedOfficeFile(
                    "this Office package contains active, signed, or embedded content "
                    "that targeted mutation does not safely preserve"
                )
    except zipfile.BadZipFile as exc:
        raise UnsupportedOfficeFile("file is not a valid Office OOXML package") from exc


def _target_preflight(path: str) -> str:
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
    if os.path.splitext(path)[1].lower() == ".xlsm":
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
    _package_preflight(path)
    risks = inspect_preservation_risks(path)
    if risks:
        raise PreservationError(risks)
    return path


def execute_mutation(
    path: str,
    *,
    operation: str,
    plan: Callable[[str], MutationPlan],
    apply: Callable[[str, MutationPlan], None],
    validate: Callable[[str, MutationPlan], dict],
    expected_sha256: Optional[str] = None,
    dry_run: bool = False,
) -> dict:
    """Apply one validated Office mutation and publish it atomically."""
    path = os.path.abspath(os.path.expanduser(path))
    lock_name = "office-" + _target_id(path)[:32]
    stage = ""
    receipt = None
    with store.Lock(lock_name, timeout=10.0):
        path = _target_preflight(path)
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
            _package_preflight(stage)
            preservation = verify_package_preservation(path, stage, operation)
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

            snapshot = store.archive_file(
                path,
                mode="copy",
                dedupe=True,
                reason=f"pre-image before agw office {operation}",
                actor=f"agw office {operation}",
            )
            if snapshot.get("sha256") != before:
                raise TransactionError("archived pre-image does not match the live source")

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
