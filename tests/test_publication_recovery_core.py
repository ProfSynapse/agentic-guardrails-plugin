"""Focused contracts for crash-resumable publication rollback primitives."""
from __future__ import annotations

from contextlib import nullcontext
import hashlib
import os
from pathlib import Path

import pytest

from core import archive_transactions as archive_tx
from core import recovery_contracts
from core import retention
from core import store


PREPARED_ID = "1" * 32
AFTER_HASH = "2" * 64
PLAN_HASH = "3" * 64


def _terminal(prepared: dict, state: str, *, recovered: bool = True,
              transaction_id: str = "") -> dict:
    operation = "success" if state == "COMMITTED" or (
        recovered and state == "ROLLED_BACK"
    ) else "process_failed"
    return {
        "op": "file-transaction-state",
        "transaction_id": transaction_id or (
            recovery_contracts.publication_terminal_transaction_id(
                prepared["transaction_id"], state
            ) if recovered else "9" * 32
        ),
        "prepared_transaction_id": prepared["transaction_id"],
        "state": state, "recovery_state": state,
        "operations": prepared["operations"],
        "atomicity": prepared["atomicity"],
        "visibility": prepared["visibility"],
        "plan_sha256": prepared["plan_sha256"],
        "process_outcome": "not_applicable",
        "contract_outcome": "not_evaluated",
        "precondition_outcome": "satisfied",
        "policy_outcome": "allowed", "environment_outcome": "ready",
        "publication_outcome": state.lower(),
        "operation_outcome": operation, "outcome": operation,
        "outcome_known": True, "outcome_source": "live_evaluation",
        "recovered": recovered,
    }


def test_recovery_derivations_are_stable_bounded_and_purpose_separated(tmp_path):
    target = archive_tx.canonical_path(str(tmp_path / "target.txt"))
    displaced = recovery_contracts.publication_displaced_transaction_id(
        PREPARED_ID, 1, target
    )
    assert displaced == recovery_contracts.publication_displaced_transaction_id(
        PREPARED_ID, 1, target
    )
    assert len(displaced) == 32
    assert displaced != recovery_contracts.publication_restore_token(
        PREPARED_ID, 1, target
    )
    assert recovery_contracts.publication_rollback_capture_group(PREPARED_ID) == \
        "publication-rollback/v1:" + PREPARED_ID
    with pytest.raises(ValueError, match="exactly 32"):
        recovery_contracts.publication_restore_token("ABC", 1, target)
    with pytest.raises(ValueError, match="outside"):
        recovery_contracts.publication_restore_token(PREPARED_ID, 65, target)


@pytest.mark.parametrize(
    "state", ["COMMITTED", "ROLLED_BACK", "NEEDS_ATTENTION"]
)
def test_publication_terminal_transaction_id_is_exact_and_deterministic(state):
    expected = hashlib.sha256(
        ("agw-publication-terminal/v1\0" + PREPARED_ID + "\0" + state).encode()
    ).hexdigest()[:32]

    assert recovery_contracts.publication_terminal_transaction_id(
        PREPARED_ID, state
    ) == expected
    assert recovery_contracts.publication_terminal_transaction_id(
        PREPARED_ID, state
    ) == expected


def test_publication_terminal_transaction_id_separates_state_and_domain():
    committed = recovery_contracts.publication_terminal_transaction_id(
        PREPARED_ID, "COMMITTED"
    )
    rolled_back = recovery_contracts.publication_terminal_transaction_id(
        PREPARED_ID, "ROLLED_BACK"
    )
    member = recovery_contracts.publication_displaced_transaction_id(
        PREPARED_ID, 1, "target"
    )

    assert committed != rolled_back
    assert committed != member


@pytest.mark.parametrize("state", ["", "PREPARED", "committed", None])
def test_publication_terminal_transaction_id_refuses_invalid_state(state):
    with pytest.raises(ValueError, match="not recognized"):
        recovery_contracts.publication_terminal_transaction_id(PREPARED_ID, state)


def test_publication_terminal_transaction_id_refuses_invalid_prepared_id():
    with pytest.raises(ValueError, match="exactly 32"):
        recovery_contracts.publication_terminal_transaction_id(
            "A" * 32, "COMMITTED"
        )


def test_supplied_archive_id_must_be_exact_and_unused(tmp_path, agw_home):
    source = tmp_path / "source.txt"
    source.write_text("state")
    destination = Path(agw_home) / "archive" / "fixed.txt"
    destination.parent.mkdir(parents=True)
    fixed = "a" * 32
    entry = archive_tx.create_archive(
        agw_home, str(source), str(destination), "copy", 1,
        transaction_id=fixed,
    )
    assert entry["transaction_id"] == fixed
    with pytest.raises(FileExistsError, match="already exists"):
        archive_tx.create_archive(
            agw_home, str(source), str(destination) + ".other", "copy", 2,
            transaction_id=fixed,
        )
    with pytest.raises(ValueError, match="exactly 32"):
        archive_tx.create_archive(
            agw_home, str(source), str(destination) + ".bad", "copy", 3,
            transaction_id="A" * 32,
        )

    generated = archive_tx.create_archive(
        agw_home, str(source), str(destination) + ".generated", "copy", 4,
    )
    assert len(generated["transaction_id"]) == 32


def test_displaced_capture_reconciles_fixed_preparing_manifest(
        tmp_path, agw_home):
    target = tmp_path / "live.txt"
    target.write_text("published state")
    target_identity = archive_tx.canonical_path(str(target))
    fixed = recovery_contracts.publication_displaced_transaction_id(
        PREPARED_ID, 1, target_identity
    )
    group = recovery_contracts.publication_rollback_capture_group(PREPARED_ID)
    after_identity = store._current_ordinary_file_identity(str(target))
    after_hash = store.file_sha256(str(target))
    destination = Path(agw_home) / "archive" / "resume" / "state.txt"
    destination.parent.mkdir(parents=True)
    with pytest.raises(archive_tx.SimulatedCrash):
        archive_tx.create_archive(
            agw_home, str(target), str(destination), "move", 1,
            reason=f"displaced state before publication rollback {PREPARED_ID}",
            actor="guardrails-recovery", crash_after=archive_tx.PREPARING,
            retention_class="mutation_preimage", capture_group_id=group,
            transaction_id=fixed, recovery_source_identity=after_identity,
        )

    entry = store._capture_publication_displaced_locked(
        str(target), PREPARED_ID, 1, after_hash, after_identity
    )
    assert entry["transaction_id"] == fixed
    assert not target.exists()
    assert destination.read_text() == "published state"
    assert archive_tx.load(agw_home, fixed)["state"] == archive_tx.COMMITTED

    again = store._capture_publication_displaced_locked(
        str(target), PREPARED_ID, 1, entry["sha256"], after_identity
    )
    assert again["transaction_id"] == fixed


def test_displaced_capture_refuses_hash_match_with_wrong_identity(tmp_path):
    target = tmp_path / "live.txt"
    target.write_text("published state")
    after_hash = store.file_sha256(str(target))
    identity = list(store._current_ordinary_file_identity(str(target)))
    identity[3] += 1

    with pytest.raises(ValueError, match="identity changed before hashing"):
        store._capture_publication_displaced_locked(
            str(target), PREPARED_ID, 1, after_hash, identity
        )

    assert target.read_text() == "published state"
    assert store.discover_archive_transactions() == []


def _fixed_preparing_record(tmp_path, agw_home, transaction_id="7" * 32):
    source = tmp_path / "fixed-source.bin"
    source.write_bytes(b"x" * (256 * 1024))
    destination = Path(agw_home) / "archive" / "fixed-destination.bin"
    destination.parent.mkdir(parents=True, exist_ok=True)
    identity = store._current_ordinary_file_identity(str(source))
    with pytest.raises(archive_tx.SimulatedCrash):
        archive_tx.create_archive(
            agw_home, str(source), str(destination), "move", 1,
            actor="guardrails-recovery", retention_class="mutation_preimage",
            capture_group_id=recovery_contracts.publication_rollback_capture_group(
                PREPARED_ID
            ),
            transaction_id=transaction_id,
            recovery_source_identity=identity,
            crash_after=archive_tx.PREPARING,
        )
    return source, destination, archive_tx.load(agw_home, transaction_id)


def test_fixed_id_manifest_partial_temp_is_reused_and_bounded(tmp_path, agw_home):
    source = tmp_path / "source.txt"
    source.write_text("content")
    destination = Path(agw_home) / "archive" / "destination.txt"
    destination.parent.mkdir(parents=True)
    transaction_id = "6" * 32
    transaction_root = Path(agw_home) / "transactions"
    transaction_root.mkdir(parents=True)
    protocol_temp = transaction_root / f"{transaction_id}.json.fixed-new.tmp"
    protocol_temp.write_bytes(b'{"partial"')

    entry = archive_tx.create_archive(
        agw_home, str(source), str(destination), "copy", 1,
        transaction_id=transaction_id,
        recovery_source_identity=store._current_ordinary_file_identity(str(source)),
    )

    assert entry["transaction_id"] == transaction_id
    assert not protocol_temp.exists()
    assert not list(transaction_root.glob(f"{transaction_id}.json.*.tmp"))
    assert sorted(path.name for path in transaction_root.iterdir()) == [
        f"{transaction_id}.json"
    ]


def test_fixed_id_empty_preparation_is_adopted_then_checkpointed(
        tmp_path, agw_home):
    source, destination, record = _fixed_preparing_record(tmp_path, agw_home)
    preparation = Path(record["temp"])
    preparation.touch()

    result = archive_tx._resume_preparing_archive(agw_home, record)

    assert result["status"] == archive_tx.COMMITTED
    assert destination.read_bytes() == b"x" * (256 * 1024)
    assert not source.exists()


def test_fixed_id_repeated_partial_copy_reuses_one_checkpointed_inode(
        tmp_path, agw_home):
    source, destination, record = _fixed_preparing_record(tmp_path, agw_home)
    identity = archive_tx._allocate_fixed_preparation(agw_home, record)
    preparation = Path(record["temp"])
    for size in (200_000, 120_000, 64_000):
        with open(preparation, "r+b") as handle:
            handle.truncate(0)
            handle.write(b"p" * size)
            handle.flush()
            os.fsync(handle.fileno())
        assert archive_tx._fixed_preparation_identity(str(preparation)) == identity
        assert len(list(preparation.parent.glob("*.preparing"))) == 1
        assert not list(Path(agw_home).rglob("*quarantine*"))

    result = archive_tx._resume_preparing_archive(
        agw_home, archive_tx.load(agw_home, record["transaction_id"])
    )

    assert result["status"] == archive_tx.COMMITTED
    assert destination.stat().st_size == 256 * 1024
    assert not list(Path(agw_home).rglob("*quarantine*"))


def test_fixed_id_preparation_identity_substitution_is_preserved_and_blocks(
        tmp_path, agw_home):
    source, _destination, record = _fixed_preparing_record(tmp_path, agw_home)
    archive_tx._allocate_fixed_preparation(agw_home, record)
    checkpointed = archive_tx.load(agw_home, record["transaction_id"])
    preparation = Path(record["temp"])
    preparation.unlink()
    preparation.write_bytes(b"foreign replacement")

    with pytest.raises(ValueError, match="identity changed"):
        archive_tx._resume_preparing_archive(agw_home, checkpointed)

    assert preparation.read_bytes() == b"foreign replacement"
    assert source.exists()
    assert not list(Path(agw_home).rglob("*quarantine*"))


def test_recover_all_resumes_fixed_partial_in_place_without_quarantine(
        tmp_path, agw_home):
    source, destination, record = _fixed_preparing_record(tmp_path, agw_home)
    identity = archive_tx._allocate_fixed_preparation(agw_home, record)
    preparation = Path(record["temp"])
    preparation.write_bytes(b"partial crash")

    results = archive_tx.recover_all(agw_home)

    assert results[0]["status"] == archive_tx.COMMITTED
    assert destination.stat().st_size == 256 * 1024
    assert not source.exists()
    assert not preparation.exists()
    assert not list(Path(agw_home).rglob("*quarantine*"))
    committed = archive_tx.load(agw_home, record["transaction_id"])
    assert tuple(committed["preparation_identity"]) == identity


def test_checkpointed_missing_fixed_preparation_fails_closed(tmp_path, agw_home):
    source, _destination, record = _fixed_preparing_record(tmp_path, agw_home)
    archive_tx._allocate_fixed_preparation(agw_home, record)
    checkpointed = archive_tx.load(agw_home, record["transaction_id"])
    Path(record["temp"]).unlink()

    with pytest.raises(ValueError, match="is missing"):
        archive_tx._resume_preparing_archive(agw_home, checkpointed)

    assert source.exists()


def test_fixed_manifest_update_short_write_preserves_authoritative_manifest(
        tmp_path, agw_home, monkeypatch):
    source, _destination, record = _fixed_preparing_record(tmp_path, agw_home)
    before = archive_tx.load(agw_home, record["transaction_id"])
    original_write = archive_tx.os.write
    calls = 0

    def short_then_stop(fd, payload):
        nonlocal calls
        calls += 1
        if calls == 1:
            return original_write(fd, bytes(payload[:7]))
        return 0

    monkeypatch.setattr(archive_tx.os, "write", short_then_stop)
    changed = dict(before, preparation_identity=[1, 2])
    with pytest.raises(OSError, match="no progress"):
        archive_tx._persist_fixed_update(agw_home, changed)

    assert archive_tx.load(agw_home, record["transaction_id"]) == before
    update_temp = Path(agw_home) / "transactions" / (
        record["transaction_id"] + ".json.fixed-update.tmp"
    )
    assert update_temp.exists()
    assert update_temp.stat().st_size == 7
    assert source.exists()


def test_fixed_preparing_with_missing_source_fails_without_recursion(
        tmp_path, agw_home):
    source, _destination, record = _fixed_preparing_record(tmp_path, agw_home)
    source.unlink()

    result = archive_tx._resume_preparing_archive(agw_home, record)

    assert result["status"] == "needs_attention"
    assert "source is unavailable" in result["error"]
    assert not list(Path(agw_home).rglob("*quarantine*"))


def test_aggregate_admission_is_one_explicit_locked_call(monkeypatch):
    calls = []

    def admitted(*, policy=None, incoming_bytes=0):
        calls.append((policy, incoming_bytes))
        return {"incoming_bytes": incoming_bytes}

    monkeypatch.setattr(store, "_maintain_retention_locked", admitted)
    assert store._admit_publication_rollback_locked(123) == {"incoming_bytes": 123}
    assert calls == [(None, 123)]


def _snapshot_and_empty_target(tmp_path, agw_home):
    target = tmp_path / "live.txt"
    target.write_text("before")
    entry = store.archive_file(str(target), mode="copy", lock_context=nullcontext())
    target.unlink()
    return target, archive_tx.load(agw_home, entry["transaction_id"])


def test_publication_stage_path_is_same_parent_and_rejects_unsafe_names(tmp_path):
    target = tmp_path / "live.txt"
    basename = ".agw-publication-rollback-" + "a" * 32 + ".restore"
    assert store._publication_stage_path(str(target), basename) == str(
        tmp_path / basename
    )
    for invalid in ("../escape", "stage", ".agw-publication-rollback-/bad"):
        with pytest.raises(ValueError, match="basename is invalid"):
            store._publication_stage_path(str(target), invalid)


def test_publication_restore_stage_helpers_create_write_publish_without_sidecars(
        tmp_path, agw_home):
    target, snapshot = _snapshot_and_empty_target(tmp_path, agw_home)
    basename = ".agw-publication-rollback-" + "b" * 32 + ".restore"
    identity = store._create_publication_restore_stage_locked(str(target), basename)
    observed = store._inspect_publication_restore_stage_locked(str(target), basename)
    assert observed == {
        "state": "PRESENT", "kind": "file", "identity": identity, "size": 0,
    }

    store._write_publication_restore_stage_locked(
        snapshot, str(target), basename, identity
    )
    store._publish_publication_restore_stage_locked(
        snapshot, str(target), basename, identity
    )

    assert target.read_text() == "before"
    assert store._inspect_publication_restore_stage_locked(
        str(target), basename
    )["state"] == "ABSENT"
    assert not list(tmp_path.glob("*.intent.json"))
    assert not list(tmp_path.glob("*.quarantine"))
    assert not list(tmp_path.glob("*.updating"))


def test_publication_stage_replacement_blocks_write_and_preserves_foreign(
        tmp_path, agw_home):
    target, snapshot = _snapshot_and_empty_target(tmp_path, agw_home)
    basename = ".agw-publication-rollback-" + "c" * 32 + ".restore"
    identity = store._create_publication_restore_stage_locked(str(target), basename)
    stage = Path(store._publication_stage_path(str(target), basename))
    stage.unlink()
    stage.write_bytes(b"foreign")

    with pytest.raises(ValueError, match="identity changed"):
        store._write_publication_restore_stage_locked(
            snapshot, str(target), basename, identity
        )
    assert stage.read_bytes() == b"foreign"


def test_publication_stage_remove_requires_exact_identity(tmp_path):
    target = tmp_path / "live.txt"
    basename = ".agw-publication-rollback-" + "d" * 32 + ".restore"
    identity = store._create_publication_restore_stage_locked(str(target), basename)
    stage = Path(store._publication_stage_path(str(target), basename))
    with pytest.raises(ValueError, match="identity changed"):
        store._remove_publication_restore_stage_locked(
            str(target), basename, {**identity, "st_ino": identity["st_ino"] + 1}
        )
    assert stage.exists()
    store._remove_publication_restore_stage_locked(str(target), basename, identity)
    assert not stage.exists()


def test_publication_stage_create_and_inspect_refuse_links(tmp_path):
    target = tmp_path / "live.txt"
    basename = ".agw-publication-rollback-" + "f" * 32 + ".restore"
    stage = Path(store._publication_stage_path(str(target), basename))
    foreign = tmp_path / "foreign.txt"
    foreign.write_text("foreign")
    try:
        os.link(foreign, stage)
    except OSError:
        pytest.skip("hardlinks unavailable")

    with pytest.raises(FileExistsError):
        store._create_publication_restore_stage_locked(str(target), basename)
    observation = store._inspect_publication_restore_stage_locked(
        str(target), basename
    )
    assert observation["kind"] == "hardlink"
    assert foreign.read_text() == "foreign"


def test_publication_stage_publish_refuses_occupied_target(tmp_path, agw_home):
    target, snapshot = _snapshot_and_empty_target(tmp_path, agw_home)
    basename = ".agw-publication-rollback-" + "e" * 32 + ".restore"
    identity = store._create_publication_restore_stage_locked(str(target), basename)
    store._write_publication_restore_stage_locked(
        snapshot, str(target), basename, identity
    )
    target.write_text("foreign live")
    with pytest.raises(FileExistsError, match="must be absent"):
        store._publish_publication_restore_stage_locked(
            snapshot, str(target), basename, identity
        )
    assert target.read_text() == "foreign live"


@pytest.mark.parametrize("terminal_state", [None, "COMMITTED", "ROLLED_BACK", "NEEDS_ATTENTION"])
def test_inventory_pins_only_while_publication_is_unresolved(
        terminal_state,
        tmp_path, agw_home):
    target = tmp_path / "target.txt"
    target.write_text("before")
    snapshot_dest = Path(agw_home) / "archive" / "snapshot.txt"
    snapshot_dest.parent.mkdir(parents=True)
    snapshot_entry = archive_tx.create_archive(
        agw_home, str(target), str(snapshot_dest), "copy", 1,
        retention_class=retention.ELIGIBLE_CLASS,
    )
    before_hash = snapshot_entry["sha256"]

    target.write_text("after")
    after_identity = store._current_ordinary_file_identity(str(target))
    displaced_dest = Path(agw_home) / "archive" / "displaced.txt"
    displaced_id = recovery_contracts.publication_displaced_transaction_id(
        PREPARED_ID, 1, archive_tx.canonical_path(str(target))
    )
    displaced = archive_tx.create_archive(
        agw_home, str(target), str(displaced_dest), "move", 1,
        actor="guardrails-recovery", retention_class="mutation_preimage",
        capture_group_id=recovery_contracts.publication_rollback_capture_group(
            PREPARED_ID
        ),
        transaction_id=displaced_id, recovery_source_identity=after_identity,
    )
    prepared = {
        "op": "file-transaction-prepared", "transaction_id": PREPARED_ID,
        "state": "PREPARED", "atomicity": "recoverable-set",
        "visibility": "per-file-sequential", "plan_sha256": PLAN_HASH,
        "operations": [{
            "number": 1, "path": str(target), "before_hash": before_hash,
            "after_hash": displaced["sha256"], "changed": 1,
            "candidate_identity": list(after_identity),
            "snapshot_transaction_id": snapshot_entry["transaction_id"],
        }],
    }
    activity = [prepared]
    if terminal_state:
        activity.append(_terminal(prepared, terminal_state))
    snapshot = retention.inventory(agw_home, activity_records=activity)
    by_id = {item["transaction_id"]: item for item in snapshot["records"]}

    assert snapshot["complete"] is (terminal_state in {None, "ROLLED_BACK"})
    snapshot_reasons = by_id[snapshot_entry["transaction_id"]]["protection_reasons"]
    displaced_reasons = by_id[displaced["transaction_id"]]["protection_reasons"]
    if terminal_state != "ROLLED_BACK":
        assert recovery_contracts.UNRESOLVED_PREPARED_PUBLICATION in snapshot_reasons
        assert recovery_contracts.ACTIVE_PUBLICATION_ROLLBACK in displaced_reasons
        assert "move_archive" in retention.protection_map(snapshot)[
            displaced["transaction_id"]
        ]
    else:
        assert recovery_contracts.UNRESOLVED_PREPARED_PUBLICATION not in snapshot_reasons
        assert recovery_contracts.ACTIVE_PUBLICATION_ROLLBACK not in displaced_reasons
        assert "move_archive" not in retention.protection_map(snapshot)[
            displaced["transaction_id"]
        ]


def test_inventory_fails_closed_on_ambiguous_prepared_evidence(tmp_path, agw_home):
    target = tmp_path / "target.txt"
    target.write_text("before")
    prepared = {
        "op": "file-transaction-prepared", "transaction_id": PREPARED_ID,
        "state": "PREPARED", "atomicity": "recoverable-set",
        "visibility": "per-file-sequential", "plan_sha256": PLAN_HASH,
        "operations": [{
            "number": 1, "path": str(target), "before_hash": "absent",
            "after_hash": AFTER_HASH, "changed": 1,
            "candidate_identity": [1, 2, 3, 4],
            "snapshot_transaction_id": "f" * 32,
        }],
    }
    snapshot = retention.inventory(agw_home, activity_records=[prepared])
    assert snapshot["complete"] is False
    assert any("evidence is incomplete" in error for error in snapshot["errors"])


def test_inventory_refuses_capture_group_only_displaced_linkage(tmp_path, agw_home):
    target = tmp_path / "target.txt"
    target.write_text("before")
    snapshot_dest = Path(agw_home) / "archive" / "snapshot.txt"
    snapshot_dest.parent.mkdir(parents=True)
    snapshot_entry = archive_tx.create_archive(
        agw_home, str(target), str(snapshot_dest), "copy", 1,
        retention_class=retention.ELIGIBLE_CLASS,
    )
    target.write_text("after")
    after_hash = store.file_sha256(str(target))
    after_identity = store._current_ordinary_file_identity(str(target))
    wrong_id = recovery_contracts.publication_displaced_transaction_id(
        PREPARED_ID, 2, archive_tx.canonical_path(str(target))
    )
    displaced_dest = Path(agw_home) / "archive" / "displaced.txt"
    archive_tx.create_archive(
        agw_home, str(target), str(displaced_dest), "move", 2,
        actor="guardrails-recovery", retention_class=retention.ELIGIBLE_CLASS,
        capture_group_id=recovery_contracts.publication_rollback_capture_group(
            PREPARED_ID
        ),
        transaction_id=wrong_id, recovery_source_identity=after_identity,
    )
    prepared = {
        "op": "file-transaction-prepared", "transaction_id": PREPARED_ID,
        "state": "PREPARED", "atomicity": "recoverable-set",
        "visibility": "per-file-sequential", "plan_sha256": PLAN_HASH,
        "operations": [{
            "number": 1, "path": str(target),
            "before_hash": snapshot_entry["sha256"], "after_hash": after_hash,
            "changed": 1, "candidate_identity": list(after_identity),
            "snapshot_transaction_id": snapshot_entry["transaction_id"],
        }],
    }

    inventory = retention.inventory(agw_home, activity_records=[prepared])

    assert inventory["complete"] is False
    assert any("member is ambiguous" in error for error in inventory["errors"])


def test_terminal_requires_exact_binding_and_deterministic_recovery_id(tmp_path, agw_home):
    target = tmp_path / "target.txt"
    target.write_text("before")
    destination = Path(agw_home) / "archive" / "snapshot.txt"
    destination.parent.mkdir(parents=True)
    snapshot = archive_tx.create_archive(
        agw_home, str(target), str(destination), "copy", 1,
        retention_class=retention.ELIGIBLE_CLASS,
    )
    identity = store._current_ordinary_file_identity(str(target))
    prepared = {
        "op": "file-transaction-prepared", "transaction_id": PREPARED_ID,
        "state": "PREPARED", "atomicity": "recoverable-set",
        "visibility": "per-file-sequential", "plan_sha256": PLAN_HASH,
        "operations": [{
            "number": 1, "path": str(target),
            "before_hash": snapshot["sha256"], "after_hash": AFTER_HASH,
            "changed": 1, "candidate_identity": list(identity),
            "snapshot_transaction_id": snapshot["transaction_id"],
        }],
    }
    invalid = _terminal(
        prepared, "ROLLED_BACK", transaction_id="8" * 32
    )

    inventory = retention.inventory(agw_home, activity_records=[prepared, invalid])

    assert inventory["complete"] is False
    record = next(item for item in inventory["records"]
                  if item["transaction_id"] == snapshot["transaction_id"])
    assert recovery_contracts.UNRESOLVED_PREPARED_PUBLICATION in \
        record["protection_reasons"]


def test_fully_bound_legacy_terminal_resolves_without_displaced_capture(
        tmp_path, agw_home):
    target = tmp_path / "target.txt"
    target.write_text("before")
    destination = Path(agw_home) / "archive" / "snapshot.txt"
    destination.parent.mkdir(parents=True)
    snapshot = archive_tx.create_archive(
        agw_home, str(target), str(destination), "copy", 1,
        retention_class=retention.ELIGIBLE_CLASS,
    )
    identity = store._current_ordinary_file_identity(str(target))
    prepared = {
        "op": "file-transaction-prepared", "transaction_id": PREPARED_ID,
        "state": "PREPARED", "atomicity": "recoverable-set",
        "visibility": "per-file-sequential", "plan_sha256": PLAN_HASH,
        "operations": [{
            "number": 1, "path": str(target),
            "before_hash": snapshot["sha256"], "after_hash": AFTER_HASH,
            "changed": 1, "candidate_identity": list(identity),
            "snapshot_transaction_id": snapshot["transaction_id"],
        }],
    }
    terminal = _terminal(prepared, "COMMITTED", recovered=False)

    inventory = retention.inventory(agw_home, activity_records=[prepared, terminal])

    assert inventory["complete"] is True
    record = next(item for item in inventory["records"]
                  if item["transaction_id"] == snapshot["transaction_id"])
    assert recovery_contracts.UNRESOLVED_PREPARED_PUBLICATION not in \
        record["protection_reasons"]


def test_terminal_authentication_accepts_real_oplog_round_trip(tmp_path, agw_home):
    target = tmp_path / "target.txt"
    target.write_text("before")
    destination = Path(agw_home) / "archive" / "snapshot.txt"
    destination.parent.mkdir(parents=True)
    snapshot = archive_tx.create_archive(
        agw_home, str(target), str(destination), "copy", 1,
        retention_class=retention.ELIGIBLE_CLASS,
    )
    identity = store._current_ordinary_file_identity(str(target))
    prepared = {
        "op": "file-transaction-prepared", "transaction_id": PREPARED_ID,
        "state": "PREPARED", "atomicity": "recoverable-set",
        "visibility": "per-file-sequential", "plan_sha256": PLAN_HASH,
        "operations": [{
            "number": 1, "path": str(target),
            "before_hash": snapshot["sha256"], "after_hash": AFTER_HASH,
            "changed": 1, "candidate_identity": list(identity),
            "snapshot_transaction_id": snapshot["transaction_id"],
        }],
    }
    store.oplog_append(prepared)
    store.oplog_append(_terminal(prepared, "COMMITTED"))

    inventory = retention.inventory(agw_home)

    assert inventory["complete"] is True
    record = next(item for item in inventory["records"]
                  if item["transaction_id"] == snapshot["transaction_id"])
    assert recovery_contracts.UNRESOLVED_PREPARED_PUBLICATION not in \
        record["protection_reasons"]


def test_conflicting_terminal_duplicates_fail_closed(tmp_path, agw_home):
    target = tmp_path / "target.txt"
    target.write_text("before")
    destination = Path(agw_home) / "archive" / "snapshot.txt"
    destination.parent.mkdir(parents=True)
    snapshot = archive_tx.create_archive(
        agw_home, str(target), str(destination), "copy", 1,
        retention_class=retention.ELIGIBLE_CLASS,
    )
    identity = store._current_ordinary_file_identity(str(target))
    prepared = {
        "op": "file-transaction-prepared", "transaction_id": PREPARED_ID,
        "state": "PREPARED", "atomicity": "recoverable-set",
        "visibility": "per-file-sequential", "plan_sha256": PLAN_HASH,
        "operations": [{
            "number": 1, "path": str(target),
            "before_hash": snapshot["sha256"], "after_hash": AFTER_HASH,
            "changed": 1, "candidate_identity": list(identity),
            "snapshot_transaction_id": snapshot["transaction_id"],
        }],
    }

    inventory = retention.inventory(
        agw_home,
        activity_records=[prepared, _terminal(prepared, "COMMITTED"),
                          _terminal(prepared, "NEEDS_ATTENTION")],
    )

    assert inventory["complete"] is False
    assert any("terminal evidence is invalid" in item for item in inventory["errors"])


def test_ordinary_move_keeps_generic_move_protection(tmp_path, agw_home):
    target = tmp_path / "ordinary.txt"
    target.write_text("ordinary")
    destination = Path(agw_home) / "archive" / "ordinary.txt"
    destination.parent.mkdir(parents=True)
    moved = archive_tx.create_archive(
        agw_home, str(target), str(destination), "move", 1,
        retention_class=retention.ELIGIBLE_CLASS,
    )
    inventory = retention.inventory(agw_home, activity_records=[])
    assert "move_archive" in retention.protection_map(inventory)[
        moved["transaction_id"]
    ]
