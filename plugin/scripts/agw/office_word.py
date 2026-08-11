"""Compact Word body-block reads and guarded localized patch operations."""
from __future__ import annotations

import zipfile

from core import store

import office_ooxml
import office_tx

DEFAULT_LIMIT = 50
MAX_LIMIT = 500
MAX_PATCH_OPS = 100
SNIPPET_CHARS = 160


class WordError(Exception):
    pass


def _document_preflight(path: str) -> None:
    try:
        with zipfile.ZipFile(path) as package:
            xml = package.read("word/document.xml")
    except (KeyError, zipfile.BadZipFile) as exc:
        raise WordError("file is not a valid Word document") from exc
    for marker, label in (
        (b"<w:ins", "tracked revisions"),
        (b"<w:del", "tracked revisions"),
        (b"<w:sdt", "content controls"),
        (b"<w:altChunk", "altChunk content"),
    ):
        if marker in xml:
            raise WordError(f"Word mutation does not safely support {label}")


def _preservation(path: str) -> dict:
    risks = office_tx.inspect_preservation_risks(path)
    return {"safe_to_mutate": not risks, "risks": risks}


def outline(path: str, *, offset: int = 0, limit: int = DEFAULT_LIMIT) -> dict:
    if offset < 0 or limit < 1 or limit > MAX_LIMIT:
        raise WordError(f"offset must be >= 0 and limit must be 1..{MAX_LIMIT}")
    office_tx._package_preflight(path, mutating=False)
    try:
        blocks = office_ooxml.word_blocks(path)
        info = office_ooxml.word_info(path)
    except office_ooxml.OoxmlError as exc:
        raise WordError(str(exc)) from exc
    page = blocks[offset:offset + limit]
    return {
        "hash": store.file_sha256(path),
        "blocks": [
            [item["id"], item["kind"],
             item["text"][:SNIPPET_CHARS] + (
                 "..." if len(item["text"]) > SNIPPET_CHARS else ""
             )]
            for item in page
        ],
        "offset": offset,
        "returned": len(page),
        "more": offset + len(page) < len(blocks),
        "preservation": _preservation(path),
        "unsupported": {
            "tables": info["tables"],
            "headers_footers_and_nested_parts": "not enumerated",
        },
    }


def read_blocks(path: str, ids: list[str]) -> dict:
    if not ids or len(ids) > MAX_LIMIT:
        raise WordError(f"request 1..{MAX_LIMIT} block IDs")
    office_tx._package_preflight(path, mutating=False)
    try:
        mapping = {item["id"]: item for item in office_ooxml.word_blocks(path)}
    except office_ooxml.OoxmlError as exc:
        raise WordError(str(exc)) from exc
    missing = [value for value in ids if value not in mapping]
    if missing:
        raise WordError(f"stale or unknown Word block ID(s): {', '.join(missing[:5])}")
    return {
        "hash": store.file_sha256(path),
        "preservation": _preservation(path),
        "blocks": [
            {
                "id": value,
                "kind": mapping[value]["kind"],
                "style": mapping[value]["style"],
                "text": mapping[value]["text"],
            }
            for value in ids
        ],
    }


def patch(
    path: str,
    operations: list,
    *,
    expected_sha256: str,
    dry_run: bool = False,
) -> dict:
    if not expected_sha256:
        raise WordError("Word patch needs --expected-file-hash from outline/read-blocks")
    if not isinstance(operations, list) or not 1 <= len(operations) <= MAX_PATCH_OPS:
        raise WordError(f"Word patch needs 1..{MAX_PATCH_OPS} operations")
    resolved = {}

    def build_plan(live_path):
        _document_preflight(live_path)
        try:
            resolved["count"] = office_ooxml.validate_word_patch(
                live_path, operations
            )
        except office_ooxml.OoxmlError as exc:
            raise WordError(str(exc)) from exc
        return office_tx.MutationPlan(
            "patch",
            {"operations": len(operations)},
            {"affected": len(operations)},
        )

    def apply(stage, _plan):
        try:
            office_ooxml.apply_word_patch(stage, operations)
        except office_ooxml.OoxmlError as exc:
            raise WordError(str(exc)) from exc

    def validate(stage, _plan):
        _document_preflight(stage)
        try:
            office_ooxml.word_blocks(stage)
        except office_ooxml.OoxmlError as exc:
            raise WordError(str(exc)) from exc
        return {"patched": resolved["count"]}

    try:
        return office_tx.execute_mutation(
            path, operation="patch", plan=build_plan, apply=apply,
            validate=validate, expected_sha256=expected_sha256,
            dry_run=dry_run,
        )
    except office_tx.TransactionError as exc:
        raise WordError(str(exc)) from exc
