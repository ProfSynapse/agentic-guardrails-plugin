"""Focused crash and performance contracts for PREPARED rollback."""
import json
import os
from pathlib import Path

import pytest

from core import recovery_contracts, store
import file_ops
import publication
import publication_recovery


def _operation(stage: Path, target: Path) -> dict:
    return {
        "stage": str(stage), "target": str(target),
        "expected_hash": store.file_sha256(str(target)), "validation": "raw",
    }


def _prepared(tmp_path, monkeypatch, *, interrupt_call=2):
    stages = [tmp_path / "stage-a.bin", tmp_path / "stage-b.bin"]
    targets = [tmp_path / "target-a.bin", tmp_path / "target-b.bin"]
    for path, content in zip(stages, (b"new-a", b"new-b")):
        path.write_bytes(content)
    for path, content in zip(targets, (b"old-a", b"old-b")):
        path.write_bytes(content)
    plan = publication.build_publish_plan([
        _operation(stages[0], targets[0]), _operation(stages[1], targets[1]),
    ])
    original = file_ops.replace_with_retry
    calls = 0

    def interrupt(source, target, retry_seconds):
        nonlocal calls
        calls += 1
        if calls == interrupt_call:
            raise KeyboardInterrupt("simulated publication crash")
        return original(source, target, retry_seconds)

    monkeypatch.setattr(file_ops, "replace_with_retry", interrupt)
    with pytest.raises(KeyboardInterrupt):
        publication.publish_staged_batch(
            plan, expected_plan_hash=plan["plan_sha256"],
        )
    monkeypatch.setattr(file_ops, "replace_with_retry", original)
    prepared = next(
        record for record in reversed(store.oplog_read())
        if record.get("op") == "file-transaction-prepared"
    )
    return prepared, stages, targets


def _journal(prepared):
    path = publication_recovery.manifest_path(prepared["transaction_id"])
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _obsolete_mixed_rollback_is_bounded_and_retry_is_terminal_noop(tmp_path, monkeypatch):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch)
    calls = {"admit": 0, "capture": 0, "restore": 0}
    original_admit = store._admit_publication_rollback_locked
    original_capture = store._capture_publication_displaced_locked
    original_restore = store._restore_publication_snapshot_locked

    def counted(name, function):
        def invoke(*args, **kwargs):
            calls[name] += 1
            return function(*args, **kwargs)
        return invoke

    monkeypatch.setattr(store, "_admit_publication_rollback_locked", counted("admit", original_admit))
    monkeypatch.setattr(store, "_capture_publication_displaced_locked", counted("capture", original_capture))
    monkeypatch.setattr(store, "_restore_publication_snapshot_locked", counted("restore", original_restore))

    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert terminal["state"] == "ROLLED_BACK"
    assert [path.read_bytes() for path in targets] == [b"old-a", b"old-b"]
    manifest = _journal(prepared)
    assert set(manifest) == publication_recovery._TOP_KEYS
    assert manifest["schema"] == "agw-publication-rollback/v1"
    assert manifest["state"] == "ROLLED_BACK"
    assert manifest["revision"] == 4
    assert [member["state"] for member in manifest["members"]] == [
        "RESTORED", "ALREADY_BEFORE",
    ]
    assert os.path.getsize(publication_recovery.manifest_path(
        prepared["transaction_id"]
    )) <= 64 * 1024
    assert calls == {"admit": 1, "capture": 1, "restore": 1}

    again = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert again["state"] == terminal["state"]
    assert again["prepared_transaction_id"] == terminal["prepared_transaction_id"]
    assert calls == {"admit": 1, "capture": 1, "restore": 1}


def test_all_before_rollback_creates_no_journal_archive_or_stage(tmp_path, monkeypatch):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch, interrupt_call=1)
    monkeypatch.setattr(
        store, "_admit_publication_rollback_locked",
        lambda *_a, **_k: pytest.fail("capacity admission must stay lazy"),
    )
    monkeypatch.setattr(
        store, "_capture_publication_displaced_locked",
        lambda *_a, **_k: pytest.fail("all-before recovery must not capture"),
    )
    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert terminal["state"] == "ROLLED_BACK"
    assert [path.read_bytes() for path in targets] == [b"old-a", b"old-b"]
    assert not os.path.lexists(publication_recovery.manifest_path(
        prepared["transaction_id"]
    ))
    assert not list(tmp_path.glob(".agw-publication-rollback-*.restore*"))


def test_inspect_is_lock_free_and_rollback_lock_order_is_deterministic(tmp_path, monkeypatch):
    prepared, _stages, _targets = _prepared(tmp_path, monkeypatch, interrupt_call=1)
    original_lock = store.Lock
    acquired = []

    class RecordingLock:
        def __init__(self, name, timeout=10.0):
            self.name = name
            self.delegate = original_lock(name, timeout=timeout)

        def __enter__(self):
            acquired.append(self.name)
            return self.delegate.__enter__()

        def __exit__(self, *args):
            return self.delegate.__exit__(*args)

    monkeypatch.setattr(store, "Lock", RecordingLock)
    inspected = publication.inspect_prepared_transaction(prepared["transaction_id"])
    assert inspected["classification"] == "before"
    assert acquired == []

    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    expected_files = [name for _identity, name in publication_recovery._lock_paths(
        publication_recovery.authenticate_prepared(prepared)
    )]
    assert terminal["state"] == "ROLLED_BACK"
    assert acquired == [
        "publication-recovery-" + prepared["transaction_id"],
        *expected_files, "recovery-store",
        "publication-recovery-manifest-store", "oplog",
    ]


def _obsolete_rollback_restores_prior_absence_without_live_restore_stage(tmp_path, monkeypatch):
    stage = tmp_path / "stage.bin"
    target = tmp_path / "new-target.bin"
    stage.write_bytes(b"published")
    plan = publication.build_publish_plan([{
        "stage": str(stage), "target": str(target),
        "expected_hash": "absent", "validation": "raw",
    }])
    original_replace = file_ops.replace_with_retry

    def crash_after_replace(source, destination, retry_seconds):
        original_replace(source, destination, retry_seconds)
        raise KeyboardInterrupt("crash after publishing new file")

    monkeypatch.setattr(file_ops, "replace_with_retry", crash_after_replace)
    with pytest.raises(KeyboardInterrupt):
        publication.publish_staged_batch(
            plan, expected_plan_hash=plan["plan_sha256"],
        )
    prepared = next(record for record in reversed(store.oplog_read())
                    if record.get("op") == "file-transaction-prepared")
    monkeypatch.setattr(
        store, "_restore_publication_snapshot_locked",
        lambda *_a, **_k: pytest.fail("prior absence needs no restore copy"),
    )

    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert terminal["state"] == "ROLLED_BACK"
    assert not target.exists()
    assert _journal(prepared)["members"] == [{"number": 1, "state": "RESTORED"}]
    assert not list(tmp_path.glob(".agw-publication-rollback-*.restore*"))


def test_crash_after_capture_resumes_without_duplicate_archive(tmp_path, monkeypatch):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch)
    original_persist = publication_recovery._persist
    crashed = False

    def crash_before_restore_intent(record):
        nonlocal crashed
        if not crashed and record["members"][0]["state"] == "RESTORE_INTENT":
            crashed = True
            raise KeyboardInterrupt("crash after displaced capture")
        return original_persist(record)

    monkeypatch.setattr(publication_recovery, "_persist", crash_before_restore_intent)
    with pytest.raises(KeyboardInterrupt):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    assert not targets[0].exists()
    assert _journal(prepared)["members"][0]["state"] == "CAPTURE_INTENT"

    monkeypatch.setattr(publication_recovery, "_persist", original_persist)
    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert terminal["state"] == "ROLLED_BACK"
    assert targets[0].read_bytes() == b"old-a"
    capture_group = "publication-rollback/v1:" + prepared["transaction_id"]
    archives = [record for record in store.oplog_read()
                if record.get("capture_group_id") == capture_group]
    assert len({record["transaction_id"] for record in archives}) == 1


def test_resume_rechecks_capacity_after_initial_manifest_crash(tmp_path, monkeypatch):
    prepared, _stages, _targets = _prepared(tmp_path, monkeypatch)
    original_admit = store._admit_publication_rollback_locked
    original_capture = store._capture_publication_displaced_locked
    admitted = []

    def admit(incoming, *args, **kwargs):
        admitted.append(incoming)
        return original_admit(incoming, *args, **kwargs)

    monkeypatch.setattr(store, "_admit_publication_rollback_locked", admit)
    monkeypatch.setattr(
        store, "_capture_publication_displaced_locked",
        lambda *_a, **_k: (_ for _ in ()).throw(
            KeyboardInterrupt("crash after initial manifest")
        ),
    )
    with pytest.raises(KeyboardInterrupt):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    assert len(admitted) == 1
    assert _journal(prepared)["members"][0]["state"] == "CAPTURE_INTENT"

    monkeypatch.setattr(store, "_capture_publication_displaced_locked", original_capture)
    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert terminal["state"] == "ROLLED_BACK"
    assert admitted == [5, 5]


def test_resume_excludes_authenticated_capture_from_capacity(tmp_path, monkeypatch):
    prepared, _stages, _targets = _prepared(tmp_path, monkeypatch)
    original_admit = store._admit_publication_rollback_locked
    original_persist = publication_recovery._persist
    admitted = []
    crashed = False

    def admit(incoming, *args, **kwargs):
        admitted.append(incoming)
        return original_admit(incoming, *args, **kwargs)

    def crash_before_restore_intent(record):
        nonlocal crashed
        if not crashed and record["members"][0]["state"] == "RESTORE_INTENT":
            crashed = True
            raise KeyboardInterrupt("capture committed before progress persist")
        return original_persist(record)

    monkeypatch.setattr(store, "_admit_publication_rollback_locked", admit)
    monkeypatch.setattr(publication_recovery, "_persist", crash_before_restore_intent)
    with pytest.raises(KeyboardInterrupt):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    assert admitted == [5]

    monkeypatch.setattr(publication_recovery, "_persist", original_persist)
    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert terminal["state"] == "ROLLED_BACK"
    assert admitted == [5]


def _obsolete_manifest_persist_uses_one_deterministic_temp(tmp_path, monkeypatch):
    prepared, _stages, _targets = _prepared(tmp_path, monkeypatch)
    expected = publication_recovery._manifest_temp_path(prepared["transaction_id"])
    original_replace = publication_recovery.os.replace
    sources = []

    def observe(source, destination):
        if destination == publication_recovery.manifest_path(prepared["transaction_id"]):
            sources.append(source)
        return original_replace(source, destination)

    monkeypatch.setattr(publication_recovery.os, "replace", observe)
    publication.recover_prepared_transaction(prepared["transaction_id"])
    assert sources
    assert set(sources) == {expected}
    assert not Path(expected).exists()
    assert not list(Path(expected).parent.glob(
        prepared["transaction_id"] + ".json.*.tmp"
    ))


def _obsolete_core_owned_restore_preparing_leftover_resumes_end_to_end(tmp_path, monkeypatch):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch)
    original_restore = store._restore_publication_snapshot_locked
    crashed = False

    def leave_owned_preparing(snapshot, target, stage):
        nonlocal crashed
        if not crashed:
            crashed = True
            preparing = stage + ".preparing"
            source = snapshot["dest"]
            Path(preparing).write_bytes(Path(source).read_bytes())
            intent = {
                "schema": "publication-restore-stage/v1",
                "snapshot_transaction_id": snapshot.get("transaction_id"),
                "snapshot_sha256": snapshot.get("sha256"),
                "snapshot_size": snapshot.get("size"),
                "target": os.path.abspath(target),
                "stage": os.path.abspath(stage),
                "preparing": preparing,
            }
            store._create_publication_restore_intent(
                preparing + ".intent.json", intent,
            )
            raise KeyboardInterrupt("core crash left authenticated restore preparation")
        return original_restore(snapshot, target, stage)

    monkeypatch.setattr(store, "_restore_publication_snapshot_locked", leave_owned_preparing)
    with pytest.raises(KeyboardInterrupt):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    monkeypatch.setattr(store, "_restore_publication_snapshot_locked", original_restore)
    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert terminal["state"] == "ROLLED_BACK"
    assert targets[0].read_bytes() == b"old-a"


def _obsolete_restore_intent_live_before_cleanup_precedes_restored_progress(
    tmp_path, monkeypatch,
):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch)
    original_persist = publication_recovery._persist
    crashed = False

    def crash_before_restored(record):
        nonlocal crashed
        if not crashed and record["members"][0]["state"] == "RESTORED":
            crashed = True
            raise KeyboardInterrupt("target restored before progress persist")
        return original_persist(record)

    monkeypatch.setattr(publication_recovery, "_persist", crash_before_restored)
    with pytest.raises(KeyboardInterrupt):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    member = publication_recovery.authenticate_prepared(prepared)[0]
    stage = store._publication_restore_stage_path(
        member["path"], prepared["transaction_id"], member["number"],
    )
    intent = Path(stage + ".preparing.intent.json")
    assert targets[0].read_bytes() == b"old-a"
    assert not intent.exists()
    quarantine = Path(stage + ".preparing.quarantine")

    monkeypatch.setattr(publication_recovery, "_persist", original_persist)
    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert terminal["state"] == "ROLLED_BACK"
    assert targets[0].read_bytes() == b"old-a"
    assert not intent.exists()
    assert not quarantine.exists()
    assert not Path(stage).exists()
    assert not Path(stage + ".preparing").exists()


def _obsolete_crash_after_owned_write_container_before_temp_resumes(
    tmp_path, monkeypatch,
):
    prepared, _stages, _targets = _prepared(tmp_path, monkeypatch, interrupt_call=1)
    write_dir = Path(publication_recovery._manifest_write_dir(
        prepared["transaction_id"]
    ))
    write_dir.mkdir(parents=True)
    assert list(write_dir.iterdir()) == []
    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert terminal["state"] == "ROLLED_BACK"
    assert not write_dir.exists()


def _obsolete_foreign_legacy_temp_is_preserved_and_blocks_retry(
    tmp_path, monkeypatch,
):
    prepared, _stages, _targets = _prepared(tmp_path, monkeypatch)
    original_capture = store._capture_publication_displaced_locked
    monkeypatch.setattr(
        store, "_capture_publication_displaced_locked",
        lambda *_a, **_k: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    with pytest.raises(KeyboardInterrupt):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    temporary = Path(publication_recovery.manifest_path(
        prepared["transaction_id"]
    ) + ".tmp")
    temporary.write_text('{"forged":true}', encoding="utf-8")
    monkeypatch.setattr(store, "_capture_publication_displaced_locked", original_capture)
    with pytest.raises(file_ops.PreparedRecoveryBlocked):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    assert temporary.read_text(encoding="utf-8") == '{"forged":true}'


def _obsolete_valid_next_revision_temp_is_promoted_before_recovery(tmp_path, monkeypatch):
    prepared, _stages, _targets = _prepared(tmp_path, monkeypatch, interrupt_call=1)
    members = publication_recovery.authenticate_prepared(prepared)
    states = [publication_recovery.classify_member(member) for member in members]
    candidate = publication_recovery._initial_manifest(prepared, states)
    now = 1
    candidate.update({"revision": 1, "created_at_ns": now, "updated_at_ns": now})
    candidate = publication_recovery._bound_manifest(candidate)
    payload = publication_recovery._serialized(candidate)
    temporary = Path(publication_recovery._manifest_temp_path(
        prepared["transaction_id"]
    ))
    intent_path = Path(publication_recovery._manifest_intent_path(
        prepared["transaction_id"]
    ))
    Path(publication_recovery._manifest_write_dir(
        prepared["transaction_id"]
    )).mkdir(parents=True)
    temporary.write_bytes(payload)
    info = temporary.stat()
    intent_path.write_bytes(publication_recovery._serialized(
        publication_recovery._intent(
            candidate, payload, (int(info.st_dev), int(info.st_ino)),
        )
    ))
    admissions = []
    original_admit = store._admit_publication_rollback_locked

    def admit(incoming, *args, **kwargs):
        admissions.append(incoming)
        return original_admit(incoming, *args, **kwargs)

    monkeypatch.setattr(store, "_admit_publication_rollback_locked", admit)
    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert terminal["state"] == "ROLLED_BACK"
    assert not temporary.exists()
    assert not intent_path.exists()
    assert admissions == []


def _obsolete_authenticated_duplicate_temp_is_preserved_and_refused(tmp_path, monkeypatch):
    prepared, _stages, _targets = _prepared(tmp_path, monkeypatch)
    original_capture = store._capture_publication_displaced_locked
    monkeypatch.setattr(
        store, "_capture_publication_displaced_locked",
        lambda *_a, **_k: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    with pytest.raises(KeyboardInterrupt):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    current = _journal(prepared)
    payload = publication_recovery._serialized(current)
    temporary = Path(publication_recovery._manifest_temp_path(
        prepared["transaction_id"]
    ))
    intent_path = Path(publication_recovery._manifest_intent_path(
        prepared["transaction_id"]
    ))
    Path(publication_recovery._manifest_write_dir(
        prepared["transaction_id"]
    )).mkdir(parents=True)
    temporary.write_bytes(payload)
    info = temporary.stat()
    stale_intent = publication_recovery._intent(
        current, payload, (int(info.st_dev), int(info.st_ino)),
    )
    stale_intent["current_revision"] = current["revision"] - 1
    stale_intent["next_revision"] = current["revision"]
    stale_intent.pop("intent_sha256")
    stale_intent["intent_sha256"] = recovery_contracts.canonical_sha256(stale_intent)
    intent_path.write_bytes(publication_recovery._serialized(stale_intent))
    monkeypatch.setattr(store, "_capture_publication_displaced_locked", original_capture)
    with pytest.raises(file_ops.PreparedRecoveryBlocked):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    assert json.loads(temporary.read_text(encoding="utf-8")) == current


def _obsolete_owned_partial_temp_moves_once_to_bounded_evidence_and_retries(
    tmp_path, monkeypatch,
):
    prepared, _stages, _targets = _prepared(tmp_path, monkeypatch, interrupt_call=1)
    members = publication_recovery.authenticate_prepared(prepared)
    states = [publication_recovery.classify_member(member) for member in members]
    candidate = publication_recovery._initial_manifest(prepared, states)
    candidate.update({"revision": 1, "created_at_ns": 1, "updated_at_ns": 1})
    candidate = publication_recovery._bound_manifest(candidate)
    intended = publication_recovery._serialized(candidate)
    base = publication_recovery.manifest_path(prepared["transaction_id"])
    write_dir = Path(publication_recovery._manifest_write_dir(
        prepared["transaction_id"]
    ))
    write_dir.mkdir(parents=True)
    temporary = Path(publication_recovery._manifest_temp_path(
        prepared["transaction_id"]
    ))
    intent_path = Path(publication_recovery._manifest_intent_path(
        prepared["transaction_id"]
    ))
    temporary.write_bytes(intended[:20])
    info = temporary.stat()
    intent_path.write_bytes(publication_recovery._serialized(
        publication_recovery._intent(
            candidate, intended, (int(info.st_dev), int(info.st_ino)),
        )
    ))

    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert terminal["state"] == "ROLLED_BACK"
    assert not temporary.exists()
    assert not intent_path.exists()
    assert not write_dir.exists()
    assert Path(base + ".evidence").read_bytes() == intended[:20]


def _obsolete_second_owned_partial_preserves_first_bounded_evidence_and_retries(
    tmp_path, monkeypatch,
):
    prepared, _stages, _targets = _prepared(tmp_path, monkeypatch, interrupt_call=1)
    members = publication_recovery.authenticate_prepared(prepared)
    states = [publication_recovery.classify_member(member) for member in members]
    candidate = publication_recovery._initial_manifest(prepared, states)
    candidate.update({"revision": 1, "created_at_ns": 1, "updated_at_ns": 1})
    candidate = publication_recovery._bound_manifest(candidate)
    intended = publication_recovery._serialized(candidate)
    base = publication_recovery.manifest_path(prepared["transaction_id"])
    evidence = Path(base + ".evidence")
    evidence.parent.mkdir(parents=True)
    evidence.write_bytes(b"first-owned-partial")
    write_dir = Path(publication_recovery._manifest_write_dir(
        prepared["transaction_id"]
    ))
    write_dir.mkdir(parents=True)
    temporary = Path(publication_recovery._manifest_temp_path(
        prepared["transaction_id"]
    ))
    intent_path = Path(publication_recovery._manifest_intent_path(
        prepared["transaction_id"]
    ))
    temporary.write_bytes(b"second-owned-partial")
    info = temporary.stat()
    intent_path.write_bytes(publication_recovery._serialized(
        publication_recovery._intent(
            candidate, intended, (int(info.st_dev), int(info.st_ino)),
        )
    ))
    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert terminal["state"] == "ROLLED_BACK"
    assert evidence.read_bytes() == b"first-owned-partial"
    assert not temporary.exists()
    assert not intent_path.exists()
    assert not write_dir.exists()


def _obsolete_foreign_temp_racing_before_owned_create_is_preserved_and_blocks(
    tmp_path, monkeypatch,
):
    prepared, _stages, _targets = _prepared(tmp_path, monkeypatch)
    base = publication_recovery.manifest_path(prepared["transaction_id"])
    foreign = Path(publication_recovery._manifest_write_dir(
        prepared["transaction_id"]
    ))
    foreign.mkdir(parents=True)
    (foreign / "foreign").write_bytes(b"foreign-race")
    with pytest.raises(file_ops.PreparedRecoveryBlocked):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    assert (foreign / "foreign").read_bytes() == b"foreign-race"
    assert not Path(base + ".evidence").exists()


@pytest.mark.parametrize("snapshot_id", ["../outside", "A" * 32, "0" * 31])
def test_malformed_snapshot_id_refuses_before_archive_load(
    tmp_path, monkeypatch, snapshot_id,
):
    prepared, _stages, _targets = _prepared(tmp_path, monkeypatch, interrupt_call=1)
    forged = dict(prepared)
    forged["operations"] = [dict(item) for item in prepared["operations"]]
    forged["operations"][0]["snapshot_transaction_id"] = snapshot_id
    monkeypatch.setattr(
        store, "_verified_snapshot",
        lambda *_a, **_k: pytest.fail("malformed snapshot id reached archive load"),
    )
    with pytest.raises(publication_recovery.RecoveryEvidenceError):
        publication_recovery.authenticate_prepared(forged)


def test_out_of_root_snapshot_destination_refuses_before_mutation(tmp_path, monkeypatch):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch, interrupt_call=1)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    monkeypatch.setattr(
        store, "_verified_snapshot", lambda _member: {
            "dest": str(outside), "state": "COMMITTED", "kind": "archive",
        },
    )
    before = [target.read_bytes() for target in targets]
    with pytest.raises(publication_recovery.RecoveryEvidenceError):
        publication_recovery.authenticate_prepared(prepared)
    assert [target.read_bytes() for target in targets] == before
    assert outside.read_bytes() == b"outside"


@pytest.mark.parametrize("transaction_id", ["../escape", "A" * 32, "0" * 31])
def test_malformed_prepared_id_refuses_before_lock_path(
    monkeypatch, transaction_id,
):
    monkeypatch.setattr(
        store, "Lock", lambda *_a, **_k: pytest.fail("invalid id reached lock path"),
    )
    with pytest.raises(file_ops.FileOperationError):
        publication.recover_prepared_transaction(transaction_id)


def test_corrupt_or_conflicting_terminal_evidence_is_refused(tmp_path, monkeypatch):
    prepared, _stages, _targets = _prepared(tmp_path, monkeypatch, interrupt_call=1)
    valid = publication._recovery_terminal(
        prepared, "ROLLED_BACK", rollback_errors=[],
    )
    records = store.oplog_read()
    corrupt = dict(valid)
    corrupt["transaction_id"] = "f" * 32
    conflicting = dict(valid)
    conflicting["state"] = "COMMITTED"
    conflicting["transaction_id"] = \
        recovery_contracts.publication_terminal_transaction_id(
            prepared["transaction_id"], "COMMITTED",
        )
    monkeypatch.setattr(store, "oplog_read", lambda: [
        *[record for record in records
          if record.get("prepared_transaction_id") != prepared["transaction_id"]],
        corrupt, conflicting,
    ])
    with pytest.raises(file_ops.FileTransactionError, match="conflicting or invalid"):
        publication._prepared_transaction(prepared["transaction_id"])


def test_terminal_append_collision_accepts_only_exact_authenticated_duplicate(
    tmp_path, monkeypatch,
):
    prepared, _stages, _targets = _prepared(tmp_path, monkeypatch, interrupt_call=1)
    captured = {}

    def collision(record):
        captured["terminal"] = dict(record)
        return False, []

    monkeypatch.setattr(store, "oplog_append", collision)
    monkeypatch.setattr(store, "oplog_read", lambda: [prepared, captured["terminal"]])
    duplicate = publication._recovery_terminal(
        prepared, "ROLLED_BACK", rollback_errors=[],
    )
    assert duplicate == captured["terminal"]

    def conflicting_records():
        collision_record = dict(captured["terminal"])
        collision_record["publication_outcome"] = "committed"
        return [prepared, collision_record]

    monkeypatch.setattr(store, "oplog_read", conflicting_records)
    with pytest.raises(file_ops.FileTransactionError):
        publication._recovery_terminal(
            prepared, "ROLLED_BACK", rollback_errors=[],
        )


def _obsolete_crash_after_restore_resumes_without_second_live_restore(tmp_path, monkeypatch):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch)
    original_persist = publication_recovery._persist
    original_restore = store._restore_publication_snapshot_locked
    restore_calls = 0
    crashed = False

    def counted_restore(*args, **kwargs):
        nonlocal restore_calls
        restore_calls += 1
        return original_restore(*args, **kwargs)

    def crash_before_restored(record):
        nonlocal crashed
        if not crashed and record["members"][0]["state"] == "RESTORED":
            crashed = True
            raise KeyboardInterrupt("crash after restore")
        return original_persist(record)

    monkeypatch.setattr(store, "_restore_publication_snapshot_locked", counted_restore)
    monkeypatch.setattr(publication_recovery, "_persist", crash_before_restored)
    with pytest.raises(KeyboardInterrupt):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    assert targets[0].read_bytes() == b"old-a"
    assert _journal(prepared)["members"][0]["state"] == "RESTORE_INTENT"

    monkeypatch.setattr(publication_recovery, "_persist", original_persist)
    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert terminal["state"] == "ROLLED_BACK"
    assert restore_calls == 1


def test_progressed_failure_is_durably_blocked(tmp_path, monkeypatch):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch)
    original = store._capture_publication_displaced_locked
    calls = 0

    def fail_capture(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise OSError("injected capture failure")

    monkeypatch.setattr(store, "_capture_publication_displaced_locked", fail_capture)
    with pytest.raises(file_ops.PreparedRecoveryBlocked) as caught:
        publication.recover_prepared_transaction(prepared["transaction_id"])
    assert caught.value.error_code == "prepared_recovery_blocked"
    assert _journal(prepared)["state"] == "BLOCKED"
    monkeypatch.setattr(store, "_capture_publication_displaced_locked", original)
    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert terminal["state"] == "ROLLED_BACK"
    assert [path.read_bytes() for path in targets] == [b"old-a", b"old-b"]
    assert _journal(prepared)["state"] == "ROLLED_BACK"


def test_finalize_mixed_refuses_nonterminal_and_all_after_commits(tmp_path, monkeypatch):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch)
    with pytest.raises(file_ops.PreparedFinalizeNotAllAfter) as caught:
        publication.recover_prepared_transaction(
            prepared["transaction_id"], "finalize-observed",
        )
    assert caught.value.error_code == "prepared_finalize_not_all_after"
    assert not [record for record in store.oplog_read()
                if record.get("prepared_transaction_id") == prepared["transaction_id"]]

    os.replace(prepared["operations"][1]["candidate"], targets[1])
    terminal = publication.recover_prepared_transaction(
        prepared["transaction_id"], "finalize-observed",
    )
    assert terminal["state"] == "COMMITTED"
    assert terminal["transaction_id"] == \
        recovery_contracts.publication_terminal_transaction_id(
            prepared["transaction_id"], "COMMITTED",
        )


def test_terminal_append_occurs_inside_full_lock_boundary(tmp_path, monkeypatch):
    prepared, _stages, _targets = _prepared(tmp_path, monkeypatch)
    original_lock = store.Lock
    original_append = store.oplog_append
    active = []
    observed = []

    class TrackingLock:
        def __init__(self, name, timeout=10.0):
            self.name = name
            self.delegate = original_lock(name, timeout=timeout)

        def __enter__(self):
            result = self.delegate.__enter__()
            active.append(self.name)
            return result

        def __exit__(self, *args):
            active.remove(self.name)
            return self.delegate.__exit__(*args)

    def append(record):
        if record.get("prepared_transaction_id") == prepared["transaction_id"]:
            observed.append(tuple(active))
        return original_append(record)

    monkeypatch.setattr(store, "Lock", TrackingLock)
    monkeypatch.setattr(store, "oplog_append", append)
    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert terminal["transaction_id"] == \
        recovery_contracts.publication_terminal_transaction_id(
            prepared["transaction_id"], "ROLLED_BACK",
        )
    assert len(observed) == 1
    held = observed[0]
    assert "publication-recovery-" + prepared["transaction_id"] in held
    assert "recovery-store" in held
    assert len([name for name in held if name.startswith("file-")]) == 4


def test_authoritative_prepared_is_reread_after_transaction_lock(tmp_path, monkeypatch):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch, interrupt_call=1)
    original = publication._prepared_transaction
    calls = 0

    def stale_then_authoritative(transaction_id):
        nonlocal calls
        calls += 1
        authoritative, terminal = original(transaction_id)
        if calls == 1:
            stale = dict(authoritative)
            stale["operations"] = [dict(item) for item in authoritative["operations"]]
            stale["operations"][0]["path"] = str(tmp_path / "stale-target.bin")
            return stale, terminal
        return authoritative, terminal

    monkeypatch.setattr(publication, "_prepared_transaction", stale_then_authoritative)
    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert calls >= 2
    assert terminal["state"] == "ROLLED_BACK"
    assert [path.read_bytes() for path in targets] == [b"old-a", b"old-b"]


def test_waiting_recovery_returns_terminal_written_before_lock_entry(tmp_path, monkeypatch):
    prepared, _stages, _targets = _prepared(tmp_path, monkeypatch, interrupt_call=1)
    original = publication._prepared_transaction
    calls = 0
    winner = {
        "op": "file-transaction-state",
        "transaction_id": recovery_contracts.publication_terminal_transaction_id(
            prepared["transaction_id"], "ROLLED_BACK",
        ),
        "prepared_transaction_id": prepared["transaction_id"],
        "state": "ROLLED_BACK",
    }

    def winner_appears(transaction_id):
        nonlocal calls
        calls += 1
        authoritative, terminal = original(transaction_id)
        return (authoritative, winner) if calls >= 2 else (authoritative, terminal)

    monkeypatch.setattr(publication, "_prepared_transaction", winner_appears)
    monkeypatch.setattr(
        publication_recovery, "rollback",
        lambda *_a, **_k: pytest.fail("waiting caller must not repeat rollback"),
    )
    assert publication.recover_prepared_transaction(
        prepared["transaction_id"]
    ) is winner


@pytest.mark.parametrize("action", ["rollback", "finalize-observed"])
def test_path_lock_waiter_returns_publisher_terminal_without_recovery_mutation(
    tmp_path, monkeypatch, action,
):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch)
    if action == "finalize-observed":
        os.replace(prepared["operations"][1]["candidate"], targets[1])
    original_read = publication._prepared_transaction
    original_lock = store.Lock
    read_calls = 0
    publisher_terminal = {
        "op": "file-transaction-state",
        "transaction_id": recovery_contracts.publication_terminal_transaction_id(
            prepared["transaction_id"], "COMMITTED",
        ),
        "prepared_transaction_id": prepared["transaction_id"],
        "state": "COMMITTED", "publication_outcome": "committed",
    }
    first_file_lock_seen = False

    class PublisherWinsAtPathLock:
        def __init__(self, name, timeout=10.0):
            self.name = name
            self.delegate = original_lock(name, timeout=timeout)

        def __enter__(self):
            nonlocal first_file_lock_seen
            result = self.delegate.__enter__()
            if self.name.startswith("file-"):
                first_file_lock_seen = True
            return result

        def __exit__(self, *args):
            return self.delegate.__exit__(*args)

    def authoritative(transaction_id):
        nonlocal read_calls
        read_calls += 1
        current, terminal = original_read(transaction_id)
        if first_file_lock_seen:
            return current, publisher_terminal
        return current, terminal

    monkeypatch.setattr(store, "Lock", PublisherWinsAtPathLock)
    monkeypatch.setattr(publication, "_prepared_transaction", authoritative)
    monkeypatch.setattr(
        store, "_admit_publication_rollback_locked",
        lambda *_a, **_k: pytest.fail("winner terminal must precede admission"),
    )
    monkeypatch.setattr(
        store, "_capture_publication_displaced_locked",
        lambda *_a, **_k: pytest.fail("winner terminal must precede capture"),
    )
    for attribute in (
        "_create_publication_restore_stage_locked",
        "_write_publication_restore_stage_locked",
        "_publish_publication_restore_stage_locked",
    ):
        monkeypatch.setattr(
            store, attribute,
            lambda *_a, **_k: pytest.fail(
                "winner terminal must precede restore staging"
            ),
        )
    monkeypatch.setattr(
        publication, "_recovery_terminal",
        lambda *_a, **_k: pytest.fail("winner terminal must not be rewritten"),
    )

    result = publication.recover_prepared_transaction(
        prepared["transaction_id"], action,
    )
    assert result is publisher_terminal
    assert read_calls >= 3
    assert not os.path.exists(publication_recovery.manifest_path(
        prepared["transaction_id"]
    ))


def test_changed_prepared_after_path_locks_refuses_before_store_or_mutation(
    tmp_path, monkeypatch,
):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch, interrupt_call=1)
    original_read = publication._prepared_transaction
    original_lock = store.Lock
    first_file_lock_seen = False

    class ChangeAtPathLock:
        def __init__(self, name, timeout=10.0):
            self.name = name
            self.delegate = original_lock(name, timeout=timeout)

        def __enter__(self):
            nonlocal first_file_lock_seen
            result = self.delegate.__enter__()
            if self.name.startswith("file-"):
                first_file_lock_seen = True
            return result

        def __exit__(self, *args):
            return self.delegate.__exit__(*args)

    def authoritative(transaction_id):
        current, terminal = original_read(transaction_id)
        if not first_file_lock_seen:
            return current, terminal
        changed = dict(current)
        changed["operations"] = [dict(item) for item in current["operations"]]
        changed["operations"][0]["path"] = str(tmp_path / "different-target.bin")
        return changed, terminal

    monkeypatch.setattr(store, "Lock", ChangeAtPathLock)
    monkeypatch.setattr(publication, "_prepared_transaction", authoritative)
    monkeypatch.setattr(
        store, "_admit_publication_rollback_locked",
        lambda *_a, **_k: pytest.fail("changed authority must precede admission"),
    )
    before = [target.read_bytes() for target in targets]
    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert terminal["state"] == "NEEDS_ATTENTION"
    assert [target.read_bytes() for target in targets] == before


def test_capture_intent_reconciles_exact_before_without_archive(tmp_path, monkeypatch):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch)
    original_capture = store._capture_publication_displaced_locked

    def crash_before_capture(*_args, **_kwargs):
        raise KeyboardInterrupt("crash after initial intent")

    monkeypatch.setattr(store, "_capture_publication_displaced_locked", crash_before_capture)
    with pytest.raises(KeyboardInterrupt):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    assert _journal(prepared)["members"][0]["state"] == "CAPTURE_INTENT"
    targets[0].write_bytes(b"old-a")
    monkeypatch.setattr(
        store, "_capture_publication_displaced_locked",
        lambda *_a, **_k: pytest.fail("exact-before without archive must not capture"),
    )
    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert terminal["state"] == "ROLLED_BACK"
    monkeypatch.setattr(store, "_capture_publication_displaced_locked", original_capture)


def test_trusted_active_manifest_drift_becomes_durably_blocked(tmp_path, monkeypatch):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch)
    monkeypatch.setattr(
        store, "_capture_publication_displaced_locked",
        lambda *_a, **_k: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    with pytest.raises(KeyboardInterrupt):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    targets[0].write_bytes(b"drift")
    with pytest.raises(file_ops.PreparedRecoveryBlocked):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    assert _journal(prepared)["state"] == "BLOCKED"
    assert _journal(prepared)["blocked"]["code"] == "revalidation_failed"


def test_finalize_refuses_after_durable_rollback_intent(tmp_path, monkeypatch):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch)
    monkeypatch.setattr(
        store, "_capture_publication_displaced_locked",
        lambda *_a, **_k: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    with pytest.raises(KeyboardInterrupt):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    os.replace(prepared["operations"][1]["candidate"], targets[1])
    with pytest.raises(file_ops.PreparedFinalizeAfterRollbackStarted) as caught:
        publication.recover_prepared_transaction(
            prepared["transaction_id"], "finalize-observed",
        )
    assert caught.value.error_code == "prepared_finalize_after_rollback_started"


def test_manifest_rejects_illegal_terminal_member_combination(tmp_path, monkeypatch):
    prepared, _stages, _targets = _prepared(tmp_path, monkeypatch)
    publication.recover_prepared_transaction(prepared["transaction_id"])
    path = publication_recovery.manifest_path(prepared["transaction_id"])
    record = _journal(prepared)
    record["members"][0]["state"] = "CAPTURE_INTENT"
    record.pop("manifest_sha256")
    record["manifest_sha256"] = recovery_contracts.canonical_sha256(record)
    path_obj = Path(path)
    path_obj.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(publication_recovery.RecoveryManifestError):
        publication_recovery.load_manifest(prepared)


def test_normal_publication_has_zero_recovery_module_calls(tmp_path, monkeypatch):
    stage = tmp_path / "stage.bin"
    target = tmp_path / "target.bin"
    stage.write_bytes(b"new")
    target.write_bytes(b"old")
    plan = publication.build_publish_plan([_operation(stage, target)])
    monkeypatch.setattr(
        publication_recovery, "rollback",
        lambda *_a, **_k: pytest.fail("normal publication called recovery"),
    )
    monkeypatch.setattr(
        publication_recovery, "finalize_observed",
        lambda *_a, **_k: pytest.fail("normal publication called recovery"),
    )
    result = publication.publish_staged_batch(
        plan, expected_plan_hash=plan["plan_sha256"],
    )
    assert result["state"] == "COMMITTED"


@pytest.mark.parametrize("crash_state", [
    "RESTORE_INTENT", "STAGE_ALLOCATE_INTENT", "STAGE_OWNED",
    "STAGE_READY", "RESTORED",
])
def test_single_journal_stage_crash_boundaries_resume(
    tmp_path, monkeypatch, crash_state,
):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch)
    original = publication_recovery._persist
    crashed = False

    def crash(record):
        nonlocal crashed
        if not crashed and record["members"][0]["state"] == crash_state:
            crashed = True
            raise KeyboardInterrupt(crash_state)
        return original(record)

    monkeypatch.setattr(publication_recovery, "_persist", crash)
    with pytest.raises(KeyboardInterrupt):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    monkeypatch.setattr(publication_recovery, "_persist", original)
    publishes = 0
    original_publish = store._publish_publication_restore_stage_locked

    def publish(*args, **kwargs):
        nonlocal publishes
        publishes += 1
        return original_publish(*args, **kwargs)

    monkeypatch.setattr(store, "_publish_publication_restore_stage_locked", publish)
    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert terminal["state"] == "ROLLED_BACK"
    assert targets[0].read_bytes() == b"old-a"
    assert publishes <= 1
    manifest = publication_recovery.load_manifest(prepared)
    assert manifest["members"][0] == {
        "number": 1, "state": "RESTORED",
        "stage_basename": "", "stage_identity": None,
    }
    assert not list(tmp_path.glob(".agw-publication-rollback-*.restore"))


def test_stage_allocate_intent_adopts_empty_exact_stage(tmp_path, monkeypatch):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch)
    original = publication_recovery._persist
    crashed = False

    def crash(record):
        nonlocal crashed
        if not crashed and record["members"][0]["state"] == "STAGE_OWNED":
            crashed = True
            raise KeyboardInterrupt()
        return original(record)

    monkeypatch.setattr(publication_recovery, "_persist", crash)
    with pytest.raises(KeyboardInterrupt):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    journal = publication_recovery.load_manifest(prepared)["members"][0]
    assert journal["state"] == "STAGE_ALLOCATE_INTENT"
    stage = targets[0].parent / journal["stage_basename"]
    assert stage.is_file() and stage.stat().st_size == 0
    monkeypatch.setattr(publication_recovery, "_persist", original)
    monkeypatch.setattr(
        store, "_create_publication_restore_stage_locked",
        lambda *_a, **_k: pytest.fail("empty stage should be adopted"),
    )
    assert publication.recover_prepared_transaction(
        prepared["transaction_id"]
    )["state"] == "ROLLED_BACK"


def test_blocked_unsafe_allocation_stage_does_not_reactivate(tmp_path, monkeypatch):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch)
    original = publication_recovery._persist
    crashed = False

    def crash(record):
        nonlocal crashed
        if not crashed and record["members"][0]["state"] == "STAGE_OWNED":
            crashed = True
            raise KeyboardInterrupt()
        return original(record)

    monkeypatch.setattr(publication_recovery, "_persist", crash)
    with pytest.raises(KeyboardInterrupt):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    monkeypatch.setattr(publication_recovery, "_persist", original)
    member = publication_recovery.load_manifest(prepared)["members"][0]
    stage = targets[0].parent / member["stage_basename"]
    stage.write_bytes(b"foreign-nonempty")
    with pytest.raises(file_ops.PreparedRecoveryBlocked):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    blocked = publication_recovery.load_manifest(prepared)
    assert blocked["state"] == "BLOCKED"
    revision = blocked["revision"]
    with pytest.raises(file_ops.PreparedRecoveryBlocked):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    assert publication_recovery.load_manifest(prepared)["revision"] == revision
    assert stage.read_bytes() == b"foreign-nonempty"


def test_stage_ready_live_before_removes_only_owned_leftover(tmp_path, monkeypatch):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch)
    original_publish = store._publish_publication_restore_stage_locked
    monkeypatch.setattr(
        store, "_publish_publication_restore_stage_locked",
        lambda *_a, **_k: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    with pytest.raises(KeyboardInterrupt):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    member = publication_recovery.load_manifest(prepared)["members"][0]
    assert member["state"] == "STAGE_READY"
    stage = targets[0].parent / member["stage_basename"]
    targets[0].write_bytes(b"old-a")
    removed = 0
    original_remove = store._remove_publication_restore_stage_locked

    def remove(*args, **kwargs):
        nonlocal removed
        removed += 1
        return original_remove(*args, **kwargs)

    monkeypatch.setattr(store, "_publish_publication_restore_stage_locked", original_publish)
    monkeypatch.setattr(store, "_remove_publication_restore_stage_locked", remove)
    assert publication.recover_prepared_transaction(
        prepared["transaction_id"]
    )["state"] == "ROLLED_BACK"
    assert removed == 1
    assert not stage.exists()


def test_stage_basename_allocation_is_bounded_to_four_attempts(tmp_path, monkeypatch):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch)
    token = "a" * 32
    collision = targets[0].parent / (
        ".agw-publication-rollback-" + token + ".restore"
    )
    collision.write_bytes(b"foreign")
    calls = 0
    original_inspect = store._inspect_publication_restore_stage_locked

    def inspect(target, basename):
        nonlocal calls
        if basename == collision.name:
            calls += 1
        return original_inspect(target, basename)

    monkeypatch.setattr(publication_recovery.secrets, "token_hex", lambda _n: token)
    monkeypatch.setattr(store, "_inspect_publication_restore_stage_locked", inspect)
    with pytest.raises(file_ops.PreparedRecoveryBlocked):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    assert calls == 4
    assert collision.read_bytes() == b"foreign"


def test_single_journal_schema_and_sequential_stage_call_counts(tmp_path, monkeypatch):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch)
    calls = {"allocate": 0, "write": 0, "publish": 0}
    for key, attribute in (
        ("allocate", "_create_publication_restore_stage_locked"),
        ("write", "_write_publication_restore_stage_locked"),
        ("publish", "_publish_publication_restore_stage_locked"),
    ):
        original = getattr(store, attribute)
        def counted(*args, _key=key, _original=original, **kwargs):
            calls[_key] += 1
            return _original(*args, **kwargs)
        monkeypatch.setattr(store, attribute, counted)
    terminal = publication.recover_prepared_transaction(prepared["transaction_id"])
    assert terminal["state"] == "ROLLED_BACK"
    assert calls == {"allocate": 1, "write": 1, "publish": 1}
    manifest = publication_recovery.load_manifest(prepared)
    assert set(manifest["members"][0]) == {
        "number", "state", "stage_basename", "stage_identity",
    }
    assert len(publication_recovery._serialized(manifest)) <= 65536
    assert [path.read_bytes() for path in targets] == [b"old-a", b"old-b"]


def test_manifest_temp_store_promotes_one_and_refuses_two_or_unknown(
    tmp_path, monkeypatch,
):
    prepared, _stages, _targets = _prepared(tmp_path, monkeypatch, interrupt_call=1)
    candidate = publication_recovery._bound_manifest({
        **publication_recovery._initial_manifest(prepared, ["before", "before"]),
        "revision": 1, "created_at_ns": 1, "updated_at_ns": 1,
    })
    temp_dir = Path(publication_recovery._manifest_temp_dir())
    temp_dir.mkdir(parents=True)
    valid = temp_dir / f"{prepared['transaction_id']}.1.{'1' * 32}.tmp"
    valid.write_bytes(publication_recovery._serialized(candidate))
    publication_recovery._reconcile_manifest_temps(prepared)
    assert publication_recovery.load_manifest(prepared)["revision"] == 1
    assert not valid.exists()
    unknown = temp_dir / "unknown"
    unknown.write_bytes(b"foreign")
    with pytest.raises(publication_recovery.RecoveryManifestError):
        publication_recovery._reconcile_manifest_temps(prepared)
    second = temp_dir / "second"
    second.write_bytes(b"foreign")
    with pytest.raises(publication_recovery.RecoveryManifestError):
        publication_recovery._reconcile_manifest_temps(prepared)
    assert unknown.exists() and second.exists()


def test_protocol_shaped_partial_manifest_temp_is_only_bounded_cleanup(
    tmp_path, monkeypatch,
):
    prepared, _stages, _targets = _prepared(tmp_path, monkeypatch, interrupt_call=1)
    temp_dir = Path(publication_recovery._manifest_temp_dir())
    temp_dir.mkdir(parents=True)
    partial = temp_dir / f"{prepared['transaction_id']}.1.{'2' * 32}.tmp"
    partial.write_bytes(b'{"partial"')
    publication_recovery._reconcile_manifest_temps(prepared)
    assert not partial.exists()


def test_finalize_refuses_when_any_rollback_manifest_exists(tmp_path, monkeypatch):
    prepared, _stages, targets = _prepared(tmp_path, monkeypatch)
    original_capture = store._capture_publication_displaced_locked
    monkeypatch.setattr(
        store, "_capture_publication_displaced_locked",
        lambda *_a, **_k: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    with pytest.raises(KeyboardInterrupt):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    monkeypatch.setattr(store, "_capture_publication_displaced_locked", original_capture)
    os.replace(prepared["operations"][1]["candidate"], targets[1])
    with pytest.raises(file_ops.PreparedFinalizeAfterRollbackStarted):
        publication.recover_prepared_transaction(
            prepared["transaction_id"], "finalize-observed",
        )


def test_finalize_manifest_refusal_precedes_mixed_state_refusal(tmp_path, monkeypatch):
    prepared, _stages, _targets = _prepared(tmp_path, monkeypatch)
    monkeypatch.setattr(
        store, "_capture_publication_displaced_locked",
        lambda *_a, **_k: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    with pytest.raises(KeyboardInterrupt):
        publication.recover_prepared_transaction(prepared["transaction_id"])
    with pytest.raises(file_ops.PreparedFinalizeAfterRollbackStarted):
        publication.recover_prepared_transaction(
            prepared["transaction_id"], "finalize-observed",
        )
