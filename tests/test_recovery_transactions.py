"""Transaction-addressed recovery tests for file mutation records."""
from pathlib import Path
import uuid

import pytest

from core import archive_transactions as archive_tx
from core import store


def _log_file_mutation(target: Path, original: str, changed: str) -> str:
    target.write_text(original)
    before = store.file_sha256(str(target))
    snapshot = store.archive_file(str(target), mode="copy", reason="test pre-image")
    target.write_text(changed)
    after = store.file_sha256(str(target))
    store.oplog_append({
        "op": "file-mutation",
        "operation": "write",
        "src": str(target),
        "before_sha256": before,
        "after_sha256": after,
        "snapshot_transaction_id": snapshot["transaction_id"],
    })
    return snapshot["transaction_id"]


def test_undo_file_mutation_by_snapshot_transaction_id(tmp_path):
    target = tmp_path / "report.txt"
    transaction_id = _log_file_mutation(target, "original", "changed")

    result = store.undo_transaction(transaction_id)

    assert target.read_text() == "original"
    assert result["state"] == "COMMITTED"
    assert result["recovery_state"] == "COMMITTED"
    assert result["process_outcome"] == "not_applicable"
    assert result["contract_outcome"] == "satisfied"
    assert result["outcome"] == "success"
    assert result["operation_outcome"] == result["outcome"]
    assert result["publication_outcome"] == "not_applicable"
    assert result["outcome_known"] is True
    assert result["outcome_source"] == "live_evaluation"
    assert result["undid_op"] == "file-mutation"
    recovery_id = result["operations"][0]["undo_recovery_transaction_id"]
    recovery = archive_tx.load(store.agw_home(), recovery_id)
    assert recovery["state"] == archive_tx.COMMITTED
    assert Path(recovery["dest"]).read_text() == "changed"
    with pytest.raises(ValueError, match="already undone"):
        store.undo_transaction(transaction_id)


def test_undo_file_mutation_refuses_current_hash_conflict(tmp_path):
    target = tmp_path / "conflict.txt"
    transaction_id = _log_file_mutation(target, "original", "changed")
    target.write_text("newer work")

    with pytest.raises(ValueError, match="undo conflict"):
        store.undo_transaction(transaction_id)

    assert target.read_text() == "newer work"


def test_undo_new_file_restores_absence_and_preserves_created_content(tmp_path):
    target = tmp_path / "new.txt"
    tombstone = store.record_absent_tombstone(
        str(target), (str(tmp_path),), reason="before creation"
    )
    target.write_text("created content")
    after = store.file_sha256(str(target))
    store.oplog_append({
        "op": "file-mutation",
        "operation": "write",
        "src": str(target),
        "before_sha256": "absent",
        "after_sha256": after,
        "snapshot_transaction_id": tombstone["transaction_id"],
    })

    result = store.undo_transaction(tombstone["transaction_id"])

    assert not target.exists()
    recovery_id = result["operations"][0]["undo_recovery_transaction_id"]
    recovery = archive_tx.load(store.agw_home(), recovery_id)
    assert Path(recovery["dest"]).read_text() == "created content"


def test_undo_new_directory_requires_exact_identity_and_restores_absence(tmp_path):
    target = tmp_path / "generated-directory"
    tombstone = store.record_absent_tombstone(
        str(target), (str(tmp_path),), reason="before directory creation"
    )
    target.mkdir()
    (target / "result.txt").write_text("generated")
    after_identity = store.path_identity(str(target))
    store.oplog_append({
        "op": "file-mutation", "operation": "run", "src": str(target),
        "before_sha256": "absent", "after_sha256": "non-file",
        "after_identity": after_identity,
        "snapshot_transaction_id": tombstone["transaction_id"],
    })

    result = store.undo_transaction(tombstone["transaction_id"])

    assert not target.exists()
    recovery_id = result["operations"][0]["undo_recovery_transaction_id"]
    recovery = archive_tx.load(store.agw_home(), recovery_id)
    assert (Path(recovery["dest"]) / "result.txt").read_text() == "generated"


def test_undo_non_file_refuses_changed_nested_fingerprint(tmp_path):
    target = tmp_path / "changed-directory"
    tombstone = store.record_absent_tombstone(
        str(target), (str(tmp_path),), reason="before directory creation"
    )
    target.mkdir()
    child = target / "result.txt"
    child.write_text("expected")
    after_identity = store.path_identity(str(target))
    store.oplog_append({
        "op": "file-mutation", "operation": "run", "src": str(target),
        "before_sha256": "absent", "after_sha256": "non-file",
        "after_identity": after_identity,
        "snapshot_transaction_id": tombstone["transaction_id"],
    })
    child.write_text("changed later")

    with pytest.raises(ValueError, match="identity changed"):
        store.undo_transaction(tombstone["transaction_id"])

    assert child.read_text() == "changed later"


def test_undo_directory_after_state_restores_committed_file_preimage(tmp_path):
    target = tmp_path / "file-became-directory"
    target.write_text("original file")
    before = store.file_sha256(str(target))
    snapshot = store.archive_file(str(target), mode="copy", reason="before run")
    store.archive_file(str(target), mode="move", reason="test type change")
    target.mkdir()
    (target / "output.txt").write_text("tool output")
    store.oplog_append({
        "op": "file-mutation", "operation": "run", "src": str(target),
        "before_sha256": before, "after_sha256": "non-file",
        "after_identity": store.path_identity(str(target)),
        "snapshot_transaction_id": snapshot["transaction_id"],
    })

    result = store.undo_transaction(snapshot["transaction_id"])

    assert target.is_file()
    assert target.read_text() == "original file"
    displaced_id = result["operations"][0]["undo_recovery_transaction_id"]
    displaced = archive_tx.load(store.agw_home(), displaced_id)
    assert (Path(displaced["dest"]) / "output.txt").read_text() == "tool output"


def test_undo_absent_preimage_rejects_retargeted_parent_identity(
        tmp_path, monkeypatch):
    target = tmp_path / "linked-parent" / "created.txt"
    target.parent.mkdir()
    tombstone = store.record_absent_tombstone(
        str(target), (str(target.parent),), reason="before creation"
    )
    target.write_text("created")
    store.oplog_append({
        "op": "file-mutation", "operation": "write", "src": str(target),
        "before_sha256": "absent",
        "after_sha256": store.file_sha256(str(target)),
        "snapshot_transaction_id": tombstone["transaction_id"],
    })
    original_canonical = archive_tx.canonical_path

    def retargeted(path):
        resolved = original_canonical(path)
        if Path(path) == target:
            return resolved + "-retargeted"
        return resolved

    monkeypatch.setattr(archive_tx, "canonical_path", retargeted)
    with pytest.raises(ValueError, match="prior absence"):
        store.undo_transaction(tombstone["transaction_id"])
    assert target.read_text() == "created"


def test_undo_file_transaction_verifies_and_restores_every_member(tmp_path):
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    operations = []
    for target, original, changed in (
        (first, "one", "ONE"), (second, "two", "TWO")
    ):
        target.write_text(original)
        before = store.file_sha256(str(target))
        snapshot = store.archive_file(str(target), mode="copy")
        target.write_text(changed)
        operations.append({
            "path": str(target),
            "before_hash": before,
            "after_hash": store.file_sha256(str(target)),
            "snapshot_transaction_id": snapshot["transaction_id"],
        })
    transaction_id = uuid.uuid4().hex
    store.oplog_append({
        "op": "file-transaction",
        "transaction_id": transaction_id,
        "operations": operations,
    })

    result = store.undo_transaction(transaction_id)

    assert first.read_text() == "one"
    assert second.read_text() == "two"
    assert len(result["operations"]) == 2
    assert all(item["undo_recovery_transaction_id"] for item in result["operations"])


def test_failed_file_transaction_undo_rolls_back_processed_members(
        tmp_path, monkeypatch):
    first = tmp_path / "first-failure.txt"
    second = tmp_path / "second-failure.txt"
    operations = []
    for target, original, changed in (
        (first, "one", "ONE"), (second, "two", "TWO")
    ):
        target.write_text(original)
        before = store.file_sha256(str(target))
        snapshot = store.archive_file(str(target), mode="copy")
        target.write_text(changed)
        operations.append({
            "path": str(target), "before_hash": before,
            "after_hash": store.file_sha256(str(target)),
            "snapshot_transaction_id": snapshot["transaction_id"],
        })
    transaction_id = uuid.uuid4().hex
    store.oplog_append({
        "op": "file-transaction", "transaction_id": transaction_id,
        "operations": operations,
    })
    restore = store._restore_snapshot
    calls = 0

    def fail_second(member, snapshot):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated second-member restore failure")
        return restore(member, snapshot)

    monkeypatch.setattr(store, "_restore_snapshot", fail_second)
    with pytest.raises(store.TransactionUndoError) as raised:
        store.undo_transaction(transaction_id)

    assert raised.value.details["rolled_back"] is True
    assert not raised.value.details["rollback_errors"]
    assert first.read_text() == "ONE"
    assert second.read_text() == "TWO"


def test_failed_undo_rolls_back_displaced_directory_by_fingerprint(
        tmp_path, monkeypatch):
    directory = tmp_path / "generated"
    tombstone = store.record_absent_tombstone(
        str(directory), (str(tmp_path),), reason="before generation"
    )
    directory.mkdir()
    (directory / "output.txt").write_text("generated")
    file_target = tmp_path / "later.txt"
    file_target.write_text("before")
    before = store.file_sha256(str(file_target))
    file_snapshot = store.archive_file(str(file_target), mode="copy")
    file_target.write_text("after")
    transaction_id = uuid.uuid4().hex
    store.oplog_append({
        "op": "file-transaction", "transaction_id": transaction_id,
        "operations": [
            {
                "path": str(directory), "before_hash": "absent",
                "after_hash": "non-file",
                "after_identity": store.path_identity(str(directory)),
                "snapshot_transaction_id": tombstone["transaction_id"],
            },
            {
                "path": str(file_target), "before_hash": before,
                "after_hash": store.file_sha256(str(file_target)),
                "snapshot_transaction_id": file_snapshot["transaction_id"],
            },
        ],
    })
    restore = store._restore_snapshot
    calls = 0

    def fail_second(member, snapshot):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated later failure")
        return restore(member, snapshot)

    monkeypatch.setattr(store, "_restore_snapshot", fail_second)
    with pytest.raises(store.TransactionUndoError) as raised:
        store.undo_transaction(transaction_id)

    assert raised.value.details["rolled_back"] is True
    assert (directory / "output.txt").read_text() == "generated"
    assert file_target.read_text() == "after"


def test_undo_refuses_unverified_recovery_artifact(tmp_path):
    target = tmp_path / "tampered.txt"
    transaction_id = _log_file_mutation(target, "original", "changed")
    record = archive_tx.load(store.agw_home(), transaction_id)
    Path(record["dest"]).write_text("tampered recovery")

    with pytest.raises(ValueError, match="failed verification"):
        store.undo_transaction(transaction_id)

    assert target.read_text() == "changed"
