"""Shared guarded transaction lifecycle for targeted Office mutations."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
import uuid
import zipfile
from dataclasses import dataclass
from typing import Callable, Optional

from core import profiles, store

MAX_PACKAGE_BYTES = 32 * 1024 * 1024
MAX_ZIP_ENTRIES = 4096
MAX_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_ENTRY_BYTES = 128 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200


class TransactionError(Exception):
    pass


class TransactionConflict(TransactionError):
    pass


class UnsupportedOfficeFile(TransactionError):
    pass


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
        if record.get("state") != "COMMITTED":
            pending.append({
                "mutation_id": record.get("mutation_id", name[:-5]),
                "state": record.get("state", "UNKNOWN"),
                "operation": record.get("operation", ""),
                "target_id": record.get("target_id", ""),
                "snapshot_version": record.get("snapshot_version"),
            })
    return pending


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
    with store.Lock(lock_name, timeout=10.0):
        path = _target_preflight(path)
        before = store.file_sha256(path)
        if expected_sha256 and before.lower() != expected_sha256.lower():
            raise TransactionConflict("CONFLICT: file hash does not match expected version")
        mutation_plan = plan(path)
        if not isinstance(mutation_plan, MutationPlan):
            raise TransactionError("Office adapter returned an invalid mutation plan")
        if not mutation_plan.changed:
            return {**mutation_plan.preview, "changed": 0, "hash": before}
        if dry_run:
            return {
                **mutation_plan.preview,
                "dry_run": True,
                "hash": before,
            }

        suffix = os.path.splitext(path)[1]
        fd, stage = tempfile.mkstemp(
            prefix=".agw-office-", suffix=suffix, dir=os.path.dirname(path)
        )
        os.close(fd)
        try:
            shutil.copy2(path, stage)
            apply(stage, mutation_plan)
            validation = validate(stage, mutation_plan) or {}
            _package_preflight(stage)
            after = store.file_sha256(stage)
            if after == before:
                return {**mutation_plan.preview, "changed": 0, "hash": before}
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
                "changed": receipt["affected"] or 1,
                "snapshot": snapshot.get("version"),
                "mutation": mutation_id,
                "hash": after,
            }
        finally:
            if stage and os.path.exists(stage):
                try:
                    os.unlink(stage)
                except OSError:
                    pass
