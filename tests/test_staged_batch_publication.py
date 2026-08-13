from pathlib import Path
import os
import time

import pytest

from core import recovery_contracts, store
import file_ops
import publication


def _operation(stage: Path, target: Path, validation="raw") -> dict:
    return {
        "stage": str(stage),
        "target": str(target),
        "expected_stage_hash": store.file_sha256(str(stage)),
        "expected_hash": (
            store.file_sha256(str(target)) if target.exists() else "absent"
        ),
        "validation": validation,
    }


def _two_file_plan(tmp_path):
    stages = tmp_path / "stages"
    live = tmp_path / "live"
    stages.mkdir()
    live.mkdir()
    stage_a, stage_b = stages / "a.bin", stages / "b.bin"
    target_a, target_b = live / "a.bin", live / "b.bin"
    stage_a.write_bytes(b"new-a")
    stage_b.write_bytes(b"new-b")
    target_a.write_bytes(b"old-a")
    target_b.write_bytes(b"old-b")
    plan = publication.build_publish_plan([
        _operation(stage_a, target_a), _operation(stage_b, target_b),
    ])
    return plan, (stage_a, stage_b), (target_a, target_b)


def _parent_bound_plan(tmp_path):
    stage = tmp_path / "stage.bin"
    target = tmp_path / "target.bin"
    stage.write_bytes(b"built")
    target.write_bytes(b"old")
    validation = {
        "kind": "raw", "tier": "binary",
        "preserve_against": "", "preserve_against_sha256": "",
    }
    now = int(time.time())
    parent = recovery_contracts.bind_plan_hash({
        "schema": "agw-run-plan/v1",
        "mode": "run",
        "freshness": {
            "plan_id": "parent-1", "issued_at_utc": now - 5,
            "expires_at_utc": now + 300, "max_uses": 1,
        },
        "cwd": str(tmp_path),
        "command": ["builder"],
        "artifacts": [{
            "number": 1, "staged": str(stage), "staged_before": "absent",
            "target": str(target),
            "target_before": store.file_sha256(str(target)),
            "validation": validation,
        }],
        "observed_roots": [],
        "execution": {"provider": "test"},
    })
    binding = {
        "schema": "agw-run-plan/v1", "plan_id": "parent-1",
        "plan_sha256": parent["plan_sha256"], "claim_id": "claim-1",
    }
    child = publication.build_publish_plan([{
        "stage": str(stage), "target": str(target),
        "expected_hash": store.file_sha256(str(target)),
        "validation": validation,
    }], parent=binding)
    claim = {
        "claim_id": "claim-1", "plan_id": "parent-1",
        "plan_sha256": parent["plan_sha256"], "state": "CLAIMED",
    }
    return child, parent, claim, target


def _accepting_claim_validator(phases):
    def validate(parent, claim, child, phase):
        assert parent["schema"] == "agw-run-plan/v1"
        assert claim["state"] == "CLAIMED"
        assert child["schema"] == "agw-publish-plan/v1"
        phases.append(phase)
        return True
    return validate


def test_publish_plan_is_canonical_hash_bound_and_bounded(tmp_path):
    stage = tmp_path / "stage.bin"
    target = tmp_path / "target.bin"
    stage.write_bytes(b"new")
    plan = publication.build_publish_plan([_operation(stage, target)])

    assert plan["schema"] == "agw-publish-plan/v1"
    assert recovery_contracts.plan_hash_valid(plan)
    assert publication.validate_publish_plan(
        plan, expected_plan_hash=plan["plan_sha256"]
    )["operations"][0]["target_before"] == "absent"

    tampered = {**plan, "cwd": str(tmp_path / "elsewhere")}
    with pytest.raises(file_ops.FileOperationError, match="self-hash"):
        publication.validate_publish_plan(tampered)
    with pytest.raises(file_ops.FileOperationError, match="1 to 64"):
        publication.build_publish_plan([])


def test_plan_rejects_stage_target_and_unicode_collisions(tmp_path):
    stage = tmp_path / "same.bin"
    stage.write_bytes(b"new")
    with pytest.raises(file_ops.FileOperationError, match="distinct files"):
        publication.build_publish_plan([{
            "stage": str(stage), "target": str(stage),
            "expected_hash": store.file_sha256(str(stage)),
        }])

    first = tmp_path / "caf\N{LATIN SMALL LETTER E WITH ACUTE}.bin"
    second = tmp_path / "cafe\N{COMBINING ACUTE ACCENT}.bin"
    source_a, source_b = tmp_path / "a.stage", tmp_path / "b.stage"
    source_a.write_bytes(b"a")
    source_b.write_bytes(b"b")
    with pytest.raises(file_ops.FileOperationError, match="Unicode normalization"):
        publication.build_publish_plan([
            _operation(source_a, first), _operation(source_b, second),
        ])


def test_validation_finishes_before_any_preimage(tmp_path, monkeypatch):
    stage = tmp_path / "book.xlsx"
    target = tmp_path / "live.xlsx"
    stage.write_bytes(b"not-an-office-package")
    target.write_bytes(b"old")
    plan = publication.build_publish_plan([
        _operation(stage, target, validation="office")
    ])
    snapshots_called = False

    def snapshots(*_args, **_kwargs):
        nonlocal snapshots_called
        snapshots_called = True
        raise AssertionError("preimages must follow validation")

    monkeypatch.setattr(file_ops, "_snapshots", snapshots)
    with pytest.raises(file_ops.FileOperationError, match="failed validation"):
        publication.publish_staged_batch(
            plan, expected_plan_hash=plan["plan_sha256"],
            candidate_validator=lambda _path, _item: {"valid": False},
        )
    assert snapshots_called is False
    assert store.oplog_read() == []


def test_batch_publish_commits_parent_and_retains_original_stages(tmp_path):
    plan, stages, targets = _two_file_plan(tmp_path)
    result = publication.publish_staged_batch(
        plan, expected_plan_hash=plan["plan_sha256"]
    )

    assert [path.read_bytes() for path in targets] == [b"new-a", b"new-b"]
    assert [path.read_bytes() for path in stages] == [b"new-a", b"new-b"]
    assert result["state"] == "COMMITTED"
    assert result["changed"] == 2
    assert result["atomicity"] == "recoverable-set"
    assert result["visibility"] == "per-file-sequential"
    assert result["process_outcome"] == "not_applicable"
    assert result["publication_outcome"] == "committed"
    assert result["operation_outcome"] == result["outcome"] == "success"
    assert all(item["snapshot_transaction_id"] for item in result["operations"])
    prepared = next(
        item for item in store.oplog_read()
        if item.get("transaction_id") == result["transaction_id"]
    )
    terminal = next(
        item for item in store.oplog_read()
        if item.get("prepared_transaction_id") == result["transaction_id"]
    )
    assert prepared["state"] == "PREPARED"
    assert terminal["state"] == "COMMITTED"


def test_committed_batch_uses_existing_parent_transaction_undo(tmp_path):
    plan, _stages, targets = _two_file_plan(tmp_path)
    result = publication.publish_staged_batch(
        plan, expected_plan_hash=plan["plan_sha256"]
    )

    undone = store.undo_transaction(result["transaction_id"])

    assert undone["state"] == "COMMITTED"
    assert [path.read_bytes() for path in targets] == [b"old-a", b"old-b"]


def test_second_publish_failure_rolls_back_first_target(tmp_path, monkeypatch):
    plan, _stages, targets = _two_file_plan(tmp_path)
    original_replace = file_ops.replace_with_retry

    def fail_second(source, target, retry_seconds):
        if target == str(targets[1]):
            raise OSError("injected second publication failure")
        return original_replace(source, target, retry_seconds)

    monkeypatch.setattr(file_ops, "replace_with_retry", fail_second)
    with pytest.raises(file_ops.FileTransactionError) as caught:
        publication.publish_staged_batch(
            plan, expected_plan_hash=plan["plan_sha256"]
        )

    assert caught.value.details["state"] == "ROLLED_BACK"
    assert [path.read_bytes() for path in targets] == [b"old-a", b"old-b"]
    terminal = next(
        item for item in store.oplog_read()
        if item.get("prepared_transaction_id") == caught.value.details["transaction_id"]
    )
    assert terminal["state"] == "ROLLED_BACK"


def _interrupt_after_first_publish(plan, targets, monkeypatch):
    original_replace = file_ops.replace_with_retry
    calls = 0

    def interrupt_second(source, target, retry_seconds):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise KeyboardInterrupt("simulated crash")
        return original_replace(source, target, retry_seconds)

    monkeypatch.setattr(file_ops, "replace_with_retry", interrupt_second)
    with pytest.raises(KeyboardInterrupt):
        publication.publish_staged_batch(
            plan, expected_plan_hash=plan["plan_sha256"]
        )
    monkeypatch.setattr(file_ops, "replace_with_retry", original_replace)
    prepared = next(
        item for item in reversed(store.oplog_read())
        if item.get("op") == "file-transaction-prepared"
    )
    assert targets[0].read_bytes() == b"new-a"
    assert targets[1].read_bytes() == b"old-b"
    return prepared


def test_prepared_inspection_and_rollback_restore_without_candidate_reads(
    tmp_path, monkeypatch,
):
    plan, stages, targets = _two_file_plan(tmp_path)
    prepared = _interrupt_after_first_publish(plan, targets, monkeypatch)
    forbidden = {str(path) for path in stages} | {
        str(item["candidate"]) for item in prepared["operations"]
    }
    original_hash = store.file_sha256

    def guarded_hash(path, *args, **kwargs):
        assert str(path) not in forbidden
        return original_hash(path, *args, **kwargs)

    monkeypatch.setattr(store, "file_sha256", guarded_hash)
    inspected = publication.inspect_prepared_transaction(prepared["transaction_id"])
    assert inspected["classification"] == "mixed"
    terminal = publication.recover_prepared_transaction(
        prepared["transaction_id"], "rollback",
    )
    assert terminal["state"] == "ROLLED_BACK"
    assert terminal["publication_outcome"] == "rolled_back"
    assert terminal["rolled_back"] is True
    assert [path.read_bytes() for path in targets] == [b"old-a", b"old-b"]


def test_roll_forward_compatibility_shim_fails_before_mutation(tmp_path, monkeypatch):
    plan, _stages, targets = _two_file_plan(tmp_path)
    prepared = _interrupt_after_first_publish(plan, targets, monkeypatch)
    before = [path.read_bytes() for path in targets]
    with pytest.raises(file_ops.PreparedRollForwardUnavailable) as caught:
        publication.recover_staged_batch_publication(prepared["transaction_id"])
    assert caught.value.error_code == "prepared_roll_forward_unavailable"
    assert [path.read_bytes() for path in targets] == before
    assert not [item for item in store.oplog_read()
                if item.get("prepared_transaction_id") == prepared["transaction_id"]]


def test_finalize_all_after_is_metadata_only(
    tmp_path, monkeypatch,
):
    plan, _stages, targets = _two_file_plan(tmp_path)
    prepared = _interrupt_after_first_publish(plan, targets, monkeypatch)
    os.replace(prepared["operations"][1]["candidate"], targets[1])
    monkeypatch.setattr(store, "_restore_snapshot", lambda *_: pytest.fail("target write"))
    terminal = publication.recover_prepared_transaction(
        prepared["transaction_id"], "finalize-observed",
    )
    assert terminal["state"] == "COMMITTED"
    assert terminal["publication_outcome"] == "committed"

def test_finalize_ambiguous_prepared_state_becomes_needs_attention_without_write(
    tmp_path, monkeypatch,
):
    plan, _stages, targets = _two_file_plan(tmp_path)
    prepared = _interrupt_after_first_publish(plan, targets, monkeypatch)
    targets[1].write_bytes(b"unrelated")
    before = [path.read_bytes() for path in targets]
    monkeypatch.setattr(store, "_restore_snapshot", lambda *_: pytest.fail("target write"))
    terminal = publication.recover_prepared_transaction(
        prepared["transaction_id"], "finalize-observed",
    )
    assert terminal["state"] == "NEEDS_ATTENTION"
    assert terminal["publication_outcome"] == "needs_attention"
    assert terminal["rolled_back"] is False
    assert [path.read_bytes() for path in targets] == before


def test_finalize_invalid_preimage_becomes_needs_attention_without_target_write(
    tmp_path, monkeypatch,
):
    plan, _stages, targets = _two_file_plan(tmp_path)
    prepared = _interrupt_after_first_publish(plan, targets, monkeypatch)
    before = [path.read_bytes() for path in targets]
    monkeypatch.setattr(
        store, "_verified_snapshot",
        lambda *_: (_ for _ in ()).throw(ValueError("forged preimage")),
    )
    monkeypatch.setattr(store, "_restore_snapshot", lambda *_: pytest.fail("target write"))
    inspected = publication.inspect_prepared_transaction(prepared["transaction_id"])
    assert inspected["classification"] == "invalid"
    terminal = publication.recover_prepared_transaction(
        prepared["transaction_id"], "finalize-observed",
    )
    assert terminal["state"] == "NEEDS_ATTENTION"
    assert terminal["rolled_back"] is False
    assert [path.read_bytes() for path in targets] == before


def test_mutating_batch_requires_expected_plan_hash_but_dry_run_does_not(tmp_path):
    stage = tmp_path / "stage.bin"
    target = tmp_path / "target.bin"
    stage.write_bytes(b"new")
    plan = publication.build_publish_plan([_operation(stage, target)])

    with pytest.raises(file_ops.FileOperationError, match="expected-plan-hash"):
        publication.publish_staged_batch(plan)
    result = publication.publish_staged_batch(plan, dry_run=True)
    assert result["dry_run"] is True
    assert result["changed"] == 1
    assert not target.exists()
    assert store.oplog_read() == []


def test_parent_bound_publication_requires_and_revalidates_durable_claim(tmp_path):
    child, parent, claim, target = _parent_bound_plan(tmp_path)
    phases = []

    result = publication.publish_staged_batch(
        child, expected_plan_hash=child["plan_sha256"],
        parent_plan=parent, parent_claim=claim,
        claim_validator=_accepting_claim_validator(phases),
    )

    assert target.read_bytes() == b"built"
    assert phases == ["pre_lock", "under_lock"]
    assert result["plan_sha256"] == child["plan_sha256"]
    assert result["parent_plan_id"] == "parent-1"
    assert result["parent_plan_sha256"] == parent["plan_sha256"]
    assert result["claim_id"] == "claim-1"
    prepared = next(
        record for record in store.oplog_read()
        if record.get("transaction_id") == result["transaction_id"]
    )
    terminal = next(
        record for record in store.oplog_read()
        if record.get("prepared_transaction_id") == result["transaction_id"]
    )
    for record in (prepared, terminal):
        assert record["plan_sha256"] == child["plan_sha256"]
        assert record["parent_plan_sha256"] == parent["plan_sha256"]
        assert record["claim_id"] == "claim-1"


@pytest.mark.parametrize("missing", ["parent_plan", "parent_claim", "claim_validator"])
def test_parent_bound_publication_rejects_missing_authority(tmp_path, missing):
    child, parent, claim, _target = _parent_bound_plan(tmp_path)
    arguments = {
        "parent_plan": parent, "parent_claim": claim,
        "claim_validator": lambda *_args: True,
    }
    arguments[missing] = None
    with pytest.raises(file_ops.PublishParentBindingInvalid) as caught:
        publication.publish_staged_batch(
            child, expected_plan_hash=child["plan_sha256"], **arguments,
        )
    assert caught.value.error_code == "publish_parent_binding_invalid"


def test_standalone_rejects_parent_inputs(tmp_path):
    stage = tmp_path / "stage.bin"
    target = tmp_path / "target.bin"
    stage.write_bytes(b"new")
    child = publication.build_publish_plan([_operation(stage, target)])
    with pytest.raises(file_ops.PublishParentBindingInvalid):
        publication.publish_staged_batch(
            child, expected_plan_hash=child["plan_sha256"],
            parent_plan={},
        )


@pytest.mark.parametrize("forgery", ["claim_hash", "terminal", "projection", "parent_hash"])
def test_parent_bound_publication_rejects_forged_or_mismatched_binding(
    tmp_path, forgery,
):
    child, parent, claim, _target = _parent_bound_plan(tmp_path)
    if forgery == "claim_hash":
        claim = {**claim, "plan_sha256": "0" * 64}
    elif forgery == "terminal":
        claim = {**claim, "publication_id": "already-used"}
    elif forgery == "projection":
        changed = dict(parent)
        changed["artifacts"] = [dict(parent["artifacts"][0])]
        changed["artifacts"][0]["target_before"] = "absent"
        parent = recovery_contracts.bind_plan_hash(changed)
        binding = dict(child["parent"])
        binding["plan_sha256"] = parent["plan_sha256"]
        child = recovery_contracts.bind_plan_hash({**child, "parent": binding})
        claim = {**claim, "plan_sha256": parent["plan_sha256"]}
    else:
        parent = {**parent, "cwd": str(tmp_path / "forged")}
    with pytest.raises(file_ops.PublishParentBindingInvalid) as caught:
        publication.publish_staged_batch(
            child, expected_plan_hash=child["plan_sha256"],
            parent_plan=parent, parent_claim=claim,
            claim_validator=lambda *_args: True,
        )
    assert caught.value.error_code == "publish_parent_binding_invalid"


def test_parent_claim_cannot_be_replayed_after_publication(tmp_path):
    child, parent, claim, _target = _parent_bound_plan(tmp_path)
    arguments = {
        "expected_plan_hash": child["plan_sha256"], "parent_plan": parent,
        "parent_claim": claim, "claim_validator": lambda *_args: True,
    }
    publication.publish_staged_batch(child, **arguments)

    with pytest.raises(file_ops.PublishParentBindingInvalid, match="already used"):
        publication.publish_staged_batch(child, **arguments)


def test_parent_claim_is_authoritatively_revalidated_under_locks(tmp_path):
    child, parent, claim, target = _parent_bound_plan(tmp_path)
    phases = []

    def becomes_terminal(_parent, _claim, _child, phase):
        phases.append(phase)
        return phase == "pre_lock"

    with pytest.raises(file_ops.PublishParentBindingInvalid) as caught:
        publication.publish_staged_batch(
            child, expected_plan_hash=child["plan_sha256"],
            parent_plan=parent, parent_claim=claim,
            claim_validator=becomes_terminal,
        )
    assert caught.value.error_code == "publish_parent_binding_invalid"
    assert phases == ["pre_lock", "under_lock"]
    assert target.read_bytes() == b"old"
    assert store.oplog_read() == []


def _office_plan(tmp_path, suffix=".xlsx", preserve=True):
    stage = tmp_path / f"stage{suffix}"
    target = tmp_path / f"target{suffix}"
    baseline = tmp_path / f"baseline{suffix}"
    stage.write_bytes(b"candidate")
    target.write_bytes(b"old")
    baseline.write_bytes(b"baseline")
    validation = {
        "kind": "office", "tier": "package",
        "preserve_against": str(baseline) if preserve else "",
        "preserve_against_sha256": (
            store.file_sha256(str(baseline)) if preserve else ""
        ),
    }
    plan = publication.build_publish_plan([{
        "stage": str(stage), "target": str(target),
        "expected_hash": store.file_sha256(str(target)),
        "validation": validation,
    }])
    return plan, stage, target, baseline, validation


def _office_receipt(candidate, item, *, preservation=True):
    validation = item["validation"]
    baseline = validation["preserve_against"]
    actual = store.file_sha256(baseline) if baseline else ""
    return {
        "valid": True,
        "candidate_sha256": store.file_sha256(candidate),
        "tier": validation["tier"],
        "package_validation": True,
        "baseline_path": baseline,
        "baseline_expected_sha256": validation["preserve_against_sha256"],
        "baseline_actual_sha256": actual,
        "preservation_validation": preservation if baseline else False,
    }


def test_office_receipt_authenticates_package_and_preservation_before_preimages(
    tmp_path, monkeypatch,
):
    plan, _stage, target, baseline, _validation = _office_plan(tmp_path)
    snapshots_called = False

    def snapshots(*_args, **_kwargs):
        nonlocal snapshots_called
        snapshots_called = True
        raise AssertionError("receipt validation must precede preimages")

    monkeypatch.setattr(file_ops, "_snapshots", snapshots)
    invalid = _office_receipt
    with pytest.raises(file_ops.FileOperationError, match="preservation"):
        publication.publish_staged_batch(
            plan, expected_plan_hash=plan["plan_sha256"],
            candidate_validator=lambda candidate, item: invalid(
                candidate, item, preservation=False,
            ),
        )
    assert snapshots_called is False
    assert target.read_bytes() == b"old"
    assert baseline.read_bytes() == b"baseline"


def test_office_receipt_is_persisted_with_exact_hash_evidence(tmp_path):
    plan, _stage, _target, baseline, validation = _office_plan(tmp_path)
    result = publication.publish_staged_batch(
        plan, expected_plan_hash=plan["plan_sha256"],
        candidate_validator=_office_receipt,
    )
    receipt = result["operations"][0]["validation_report"]
    assert receipt == {
        "valid": True,
        "candidate_sha256": result["operations"][0]["after_hash"],
        "tier": "package", "package_validation": True,
        "baseline_path": str(baseline),
        "baseline_expected_sha256": validation["preserve_against_sha256"],
        "baseline_actual_sha256": store.file_sha256(str(baseline)),
        "preservation_validation": True,
    }


def test_xlsm_requires_explicit_authenticated_preservation_baseline(tmp_path):
    plan, _stage, target, _baseline, _validation = _office_plan(
        tmp_path, suffix=".xlsm", preserve=False,
    )
    with pytest.raises(file_ops.FileOperationError, match="preservation baseline"):
        publication.publish_staged_batch(
            plan, expected_plan_hash=plan["plan_sha256"],
            candidate_validator=_office_receipt,
        )
    assert target.read_bytes() == b"old"
    assert store.oplog_read() == []


def test_office_baseline_drift_is_refused_before_preimages(tmp_path, monkeypatch):
    plan, _stage, target, baseline, _validation = _office_plan(tmp_path)
    baseline.write_bytes(b"drift")
    snapshots_called = False

    def snapshots(*_args, **_kwargs):
        nonlocal snapshots_called
        snapshots_called = True
        return []

    monkeypatch.setattr(file_ops, "_snapshots", snapshots)
    with pytest.raises(file_ops.PreimageHashConflict):
        publication.publish_staged_batch(
            plan, expected_plan_hash=plan["plan_sha256"],
            candidate_validator=_office_receipt,
        )
    assert snapshots_called is False
    assert target.read_bytes() == b"old"


def test_plan_rejects_unknown_top_keys_and_noncanonical_cwd(tmp_path):
    stage = tmp_path / "stage.bin"
    target = tmp_path / "target.bin"
    stage.write_bytes(b"new")
    plan = publication.build_publish_plan([_operation(stage, target)])
    unknown = recovery_contracts.bind_plan_hash({**plan, "surprise": True})
    with pytest.raises(file_ops.FileOperationError, match="top-level"):
        publication.validate_publish_plan(unknown)
    noncanonical = recovery_contracts.bind_plan_hash({**plan, "cwd": str(tmp_path / ".") + "\\"})
    with pytest.raises(file_ops.FileOperationError, match="cwd"):
        publication.validate_publish_plan(noncanonical)


def test_nonprocess_outcomes_and_public_aliases(tmp_path):
    stage = tmp_path / "stage.bin"
    target = tmp_path / "target.bin"
    stage.write_bytes(b"new")
    plan = publication.build([_operation(stage, target)])
    assert publication.validate(plan)["plan_sha256"] == plan["plan_sha256"]
    dry_run = publication.publish_staged_batch(plan, dry_run=True)
    assert dry_run["process_outcome"] == "not_applicable"
    assert dry_run["publication_outcome"] == "validated"
    assert dry_run["operation_outcome"] == dry_run["outcome"] == "success"
    assert publication.recover is publication.recover_prepared_transaction
