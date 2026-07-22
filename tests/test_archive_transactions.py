"""Crash-boundary and recovery tests for authoritative archive transactions."""
import json
import os
from pathlib import Path
import threading

import pytest

from core import archive_transactions as archive_tx
from core import store


def _records():
    return [item["record"] for item in store.discover_archive_transactions()
            if item.get("record")]


def test_manifest_precedes_source_mutation(tmp_path, monkeypatch):
    source = tmp_path / "important.txt"
    source.write_text("original")
    remove = archive_tx._remove
    observed = []

    def checked_remove(path, kind):
        records = _records()
        assert len(records) == 1
        observed.append(records[0]["state"])
        assert records[0]["state"] == archive_tx.ARTIFACT_VERIFIED
        assert os.path.exists(records[0]["dest"])
        remove(path, kind)

    monkeypatch.setattr(archive_tx, "_remove", checked_remove)
    entry = store.archive_file(str(source), mode="move", reason="ordering test")
    assert observed == [archive_tx.ARTIFACT_VERIFIED]
    assert not source.exists()
    assert archive_tx.load(store.agw_home(), entry["transaction_id"])["state"] == \
        archive_tx.COMMITTED


def test_crash_after_artifact_publish_is_discoverable(tmp_path):
    source = tmp_path / "published.txt"
    source.write_text("recover me")
    with pytest.raises(archive_tx.SimulatedCrash):
        store.archive_file(str(source), mode="copy", _crash_after="ARTIFACT_PUBLISHED")

    records = _records()
    assert len(records) == 1
    record = records[0]
    assert record["state"] == archive_tx.PREPARING
    assert source.exists()
    assert os.path.exists(record["dest"])

    results = store.recover_archive_transactions()
    assert results[0]["status"] == archive_tx.COMMITTED
    assert archive_tx.load(store.agw_home(), record["transaction_id"])["state"] == \
        archive_tx.COMMITTED


def test_crash_after_source_mutation_finalizes_on_recovery(tmp_path):
    source = tmp_path / "moved.txt"
    source.write_text("durable")
    with pytest.raises(archive_tx.SimulatedCrash):
        store.archive_file(str(source), mode="move", _crash_after="SOURCE_REMOVED")

    record = _records()[0]
    assert record["state"] == archive_tx.ARTIFACT_VERIFIED
    assert not source.exists()
    assert Path(record["dest"]).read_text() == "durable"

    store.recover_archive_transactions()
    committed = archive_tx.load(store.agw_home(), record["transaction_id"])
    assert committed["state"] == archive_tx.COMMITTED
    assert store.list_versions(str(source))[0]["transaction_id"] == \
        record["transaction_id"]


@pytest.mark.parametrize("point", [
    archive_tx.PREPARING,
    "ARTIFACT_PUBLISHED",
    archive_tx.ARTIFACT_VERIFIED,
    "SOURCE_REMOVED",
    archive_tx.SOURCE_MUTATED,
    archive_tx.COMMITTED,
])
def test_crash_at_every_transition_is_discoverable_and_recoverable(tmp_path, point):
    source = tmp_path / f"transition-{point}.txt"
    source.write_text(point)
    with pytest.raises(archive_tx.SimulatedCrash):
        store.archive_file(str(source), mode="move", _crash_after=point)

    discovered = store.discover_archive_transactions()
    assert len(discovered) == 1
    assert discovered[0]["error"] == ""
    result = store.recover_archive_transactions()[0]
    if point == archive_tx.PREPARING:
        assert result["status"] == "needs_attention"
        assert source.exists()
        assert _records()[0]["state"] == archive_tx.PREPARING
    else:
        assert result["status"] == archive_tx.COMMITTED
        assert not source.exists()
        assert os.path.exists(result["record"]["dest"])


def test_recovery_is_idempotent(tmp_path):
    source = tmp_path / "once.txt"
    source.write_text("one copy")
    with pytest.raises(archive_tx.SimulatedCrash):
        store.archive_file(str(source), mode="move", _crash_after="SOURCE_REMOVED")

    first = store.recover_archive_transactions()
    second = store.recover_archive_transactions()
    assert first[0]["status"] == second[0]["status"] == archive_tx.COMMITTED
    assert len(store.list_versions(str(source))) == 1
    matching_ops = [op for op in store.oplog_read()
                    if op.get("transaction_id") == first[0]["transaction_id"]]
    assert len(matching_ops) == 1


def test_corrupt_manifest_remains_discoverable(tmp_path):
    transaction_dir = Path(store.agw_home()) / "transactions"
    transaction_dir.mkdir(parents=True, exist_ok=True)
    corrupt = transaction_dir / "broken.json"
    corrupt.write_text("{not-json")

    discovered = store.discover_archive_transactions()
    assert discovered[0]["path"] == str(corrupt)
    assert discovered[0]["error"]
    recovered = store.recover_archive_transactions()
    assert recovered[0]["status"] == "corrupt_manifest"
    assert corrupt.read_text() == "{not-json"


def test_corrupt_artifact_is_preserved_for_attention(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("trusted")
    with pytest.raises(archive_tx.SimulatedCrash):
        store.archive_file(str(source), mode="move", _crash_after=archive_tx.ARTIFACT_VERIFIED)
    record = _records()[0]
    Path(record["dest"]).write_text("corrupt but preserved")

    result = store.recover_archive_transactions()[0]
    assert result["status"] == "needs_attention"
    assert "corrupt" in result["error"]
    assert source.exists()
    assert Path(record["dest"]).read_text() == "corrupt but preserved"


def test_restore_rejects_unverified_artifact(tmp_path):
    source = tmp_path / "legacy.txt"
    artifact = tmp_path / "unverified-copy.txt"
    artifact.write_text("unverified")
    file_dir = Path(store._file_dir(str(source)))
    entry = {"op": "archive", "mode": "copy", "src": str(source),
             "dest": str(artifact), "version": 1, "sha256": store.file_sha256(str(artifact))}
    with open(file_dir / "manifest.jsonl", "w", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")

    with pytest.raises(ValueError, match="not verified"):
        store.restore(str(source))
    assert not source.exists()
    assert artifact.read_text() == "unverified"


def test_absent_tombstone_rollback_restores_absence(tmp_path):
    target = tmp_path / "new-file.txt"
    tombstone = store.record_absent_tombstone(
        str(target), (str(tmp_path),), reason="before creation"
    )
    target.write_text("new work")

    result = store.rollback_absent_tombstone(tombstone["transaction_id"])
    assert result["restored"] == "ABSENT"
    assert not target.exists()
    assert result["archived"]
    assert Path(result["archived"]["dest"]).read_text() == "new work"

    again = store.rollback_absent_tombstone(tombstone["transaction_id"])
    assert again["restored"] == "ABSENT"
    assert not target.exists()


def test_windows_safe_atomic_publish_with_unicode_and_spaces(tmp_path, monkeypatch):
    source = tmp_path / "Q3 report — final.txt"
    source.write_text("portable")
    replace = archive_tx.os.replace
    replacements = []

    def observed_replace(src, dest):
        replacements.append((str(src), str(dest)))
        return replace(src, dest)

    monkeypatch.setattr(archive_tx.os, "replace", observed_replace)
    entry = store.archive_file(str(source), mode="move")
    assert Path(entry["dest"]).read_text() == "portable"
    assert any(destination == entry["dest"] for _source, destination in replacements)
    assert all("Q3 report" in entry["dest"] for _ in [0])


def test_compatibility_entry_binds_source_version_creation_and_fingerprint(tmp_path):
    source = tmp_path / "bound.txt"
    source.write_text("bound")
    entry = store.archive_file(str(source), mode="copy")
    assert archive_tx.entry_is_verified(store.agw_home(), entry, str(source))

    for field, changed in (
        ("src", str(tmp_path / "other.txt")),
        ("source_identity", archive_tx.canonical_path(tmp_path / "other.txt")),
        ("version", entry["version"] + 1),
        ("created_at_ns", entry["created_at_ns"] + 1),
        ("dest", str(tmp_path / "other-artifact.txt")),
        ("sha256", "0" * 64),
        ("size", entry["size"] + 1),
    ):
        tampered = dict(entry)
        tampered[field] = changed
        assert not archive_tx.entry_is_verified(store.agw_home(), tampered, str(source)), field


def test_entry_pointing_to_different_valid_transaction_is_rejected(tmp_path):
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text("first")
    second.write_text("second")
    first_entry = store.archive_file(str(first), mode="copy")
    second_entry = store.archive_file(str(second), mode="copy")

    redirected = dict(second_entry)
    redirected["src"] = first_entry["src"]
    redirected["source_identity"] = first_entry["source_identity"]
    assert not archive_tx.entry_is_verified(
        store.agw_home(), redirected, str(first)
    )


def test_normal_archive_then_recovery_never_duplicates_derived_records(tmp_path):
    source = tmp_path / "normal.txt"
    source.write_text("normal")
    entry = store.archive_file(str(source), mode="copy")
    record = archive_tx.load(store.agw_home(), entry["transaction_id"])
    assert record["derived_index"] is True
    assert record["derived_oplog"] is True

    store.recover_archive_transactions()
    store.recover_archive_transactions()
    assert len(store.list_versions(str(source))) == 1
    assert len([op for op in store.oplog_read()
                if op.get("transaction_id") == entry["transaction_id"]]) == 1


@pytest.mark.parametrize("point", ["DERIVED_INDEX_APPENDED", "DERIVED_OPLOG_APPENDED"])
def test_derived_append_marker_crash_window_is_idempotent(tmp_path, point):
    source = tmp_path / f"{point}.txt"
    source.write_text(point)
    with pytest.raises(archive_tx.SimulatedCrash):
        store.archive_file(str(source), mode="copy", _crash_after=point)
    transaction_id = _records()[0]["transaction_id"]

    store.recover_archive_transactions()
    store.recover_archive_transactions()
    assert len(store.list_versions(str(source))) == 1
    assert len([op for op in store.oplog_read()
                if op.get("transaction_id") == transaction_id]) == 1


def test_truncated_compatibility_jsonl_is_preserved_and_repaired(tmp_path):
    source = tmp_path / "truncated.txt"
    source.write_text("authoritative")
    entry = store.archive_file(str(source), mode="copy")
    manifest = Path(store._file_dir(str(source))) / "manifest.jsonl"
    malformed_raw = '{"transaction_id":"truncated"'
    manifest.write_text(malformed_raw, encoding="utf-8")

    first = store.recover_archive_transactions()
    second = store.recover_archive_transactions()
    assert any(result.get("status") == "malformed_compatibility" for result in first)
    assert len(store.list_versions(str(source))) == 1
    assert store.list_versions(str(source))[0]["transaction_id"] == entry["transaction_id"]
    evidence = Path(str(manifest) + ".malformed.jsonl")
    evidence_records = [json.loads(line) for line in evidence.read_text().splitlines()]
    assert len(evidence_records) == 1
    assert evidence_records[0]["raw"] == malformed_raw
    assert not any(result.get("status") == "needs_attention" for result in second)


def test_agw_home_inside_snapshot_source_is_explicitly_excluded(tmp_path, monkeypatch):
    source = tmp_path / "snapshot-root"
    source.mkdir()
    (source / "document.txt").write_text("content")
    nested_home = source / ".agw"
    monkeypatch.setenv("AGW_HOME", str(nested_home))

    entry = store.archive_file(str(source), mode="copy")
    artifact = Path(entry["dest"])
    assert source.exists()
    assert (artifact / "document.txt").read_text() == "content"
    assert not (artifact / ".agw").exists()


def test_concurrent_archives_have_unique_transaction_ids(tmp_path):
    sources = []
    for index in range(16):
        source = tmp_path / f"concurrent-{index}.txt"
        source.write_text(str(index))
        sources.append(source)
    transaction_ids = []
    errors = []

    def archive(source):
        try:
            transaction_ids.append(
                store.archive_file(str(source), mode="copy")["transaction_id"]
            )
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=archive, args=(source,)) for source in sources]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert len(transaction_ids) == len(set(transaction_ids)) == len(sources)


def test_nonregular_source_is_rejected(tmp_path, monkeypatch):
    source = tmp_path / "reported-as-link.txt"
    source.write_text("must not follow special source")
    original_islink = archive_tx.os.path.islink

    def islink(path):
        if archive_tx.canonical_path(path) == archive_tx.canonical_path(source):
            return True
        return original_islink(path)

    monkeypatch.setattr(archive_tx.os.path, "islink", islink)
    with pytest.raises(OSError, match="ordinary local file or folder"):
        store.archive_file(str(source), mode="copy")
    assert source.read_text() == "must not follow special source"
