"""Core activity-aware recovery-store retention tests."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from core import archive_transactions as archive_tx
from core import retention
from core import retention_policy


DAY = retention.DAY_NS
NOW = 1_800_000_000_000_000_000


def _source_mtime(path: Path, age_days: int):
    stamp = (NOW - age_days * DAY) / 1_000_000_000
    os.utime(path, (stamp, stamp))


def _archive(home: str, source: Path, version: int, age_days: int, *,
             classification: str = retention.ELIGIBLE_CLASS,
             mode: str = "copy", last_referenced_age: int | None = None,
             protected_until_ns: int = 0) -> dict:
    source.write_bytes((f"version-{version}-" + ("x" * 64)).encode())
    directory = Path(home) / "archive" / "fixture" / source.name
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"v{version:03d}_{source.name}"
    entry = archive_tx.create_archive(
        home, str(source), str(destination), mode, version, reason="test"
    )
    fields = {
        "retention_class": classification,
        "created_at_ns": NOW - age_days * DAY,
        "protected_until_ns": protected_until_ns,
    }
    if last_referenced_age is not None:
        fields["last_referenced_at_ns"] = NOW - last_referenced_age * DAY
    archive_tx.update(home, entry["transaction_id"], **fields)
    return archive_tx.load(home, entry["transaction_id"])


def _policy(current: int, *, min_days: int = 7, inactive_days: int = 30,
            max_candidates: int = 256,
            max_reclaim: int = 1 << 30):
    maximum = max(1, current)
    return retention_policy.RetentionPolicy(
        max_bytes=maximum,
        high_water_bytes=max(0, maximum * 9 // 10),
        low_water_bytes=max(0, maximum // 10),
        min_protected_age_days=min_days,
        inactive_collapse_age_days=inactive_days,
        max_candidates=max_candidates,
        max_reclaim_bytes=max_reclaim,
    )


def _pressured_plan(home: str, *, activity_records=None, now_ns=NOW,
                    max_candidates=256, max_reclaim=1 << 30):
    snapshot = retention.inventory(home, activity_records=activity_records or [])
    policy = _policy(
        snapshot["known_allocated_bytes"], max_candidates=max_candidates,
        max_reclaim=max_reclaim,
    )
    return retention.build_plan(
        home, policy=policy, now_ns=now_ns,
        activity_records=activity_records or [],
    )


def _candidate_ids(plan: dict) -> set[str]:
    return {item["transaction_id"] for item in plan["candidates"]}


def test_only_explicit_mutation_preimages_are_eligible(tmp_path, agw_home):
    source = tmp_path / "protected.txt"
    classified = _archive(agw_home, source, 1, 60)
    manual = _archive(
        agw_home, source, 2, 59, classification="manual_snapshot"
    )
    moved = _archive(
        agw_home, source, 3, 58, classification=retention.ELIGIBLE_CLASS,
        mode="move",
    )
    # Recreate the source after the move so it cannot look recently active.
    source.write_text("later")
    _source_mtime(source, 60)

    snapshot = retention.inventory(agw_home, activity_records=[])
    selected = retention.select_candidates(snapshot, 1 << 20, now_ns=NOW)
    selected_ids = {item["transaction_id"] for item in selected}

    assert classified["transaction_id"] in selected_ids
    assert manual["transaction_id"] not in selected_ids
    assert moved["transaction_id"] not in selected_ids


def test_unclassified_legacy_inventory_is_protected_without_blocking_plan(
        tmp_path, agw_home):
    source = tmp_path / "legacy.txt"
    legacy = _archive(
        agw_home, source, 1, 60, classification="legacy_unclassified"
    )
    unclassified = _archive(agw_home, source, 2, 50)
    manifest = archive_tx.load(agw_home, unclassified["transaction_id"])
    manifest.pop("retention_class")
    # Use the transaction layer's atomic writer through update, then remove the
    # classification by writing the authoritative fixture manifest directly.
    manifest_path = Path(agw_home) / "transactions" / (
        unclassified["transaction_id"] + ".json"
    )
    manifest_path.write_text(
        __import__("json").dumps(manifest, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _source_mtime(source, 60)

    plan = _pressured_plan(agw_home)

    assert plan["applicable"] is True
    assert plan["candidates"] == []
    assert unclassified["transaction_id"] in plan["unclassified_transaction_ids"]
    assert Path(legacy["dest"]).exists()
    assert Path(unclassified["dest"]).exists()


def test_recent_and_active_daily_generations_are_preserved(tmp_path, agw_home):
    source = tmp_path / "active.txt"
    records = [
        _archive(agw_home, source, 1, 20),
        _archive(agw_home, source, 2, 10),
        _archive(agw_home, source, 3, 10),
        _archive(agw_home, source, 4, 9),
        _archive(agw_home, source, 5, 9),
        _archive(agw_home, source, 6, 2),
        _archive(agw_home, source, 7, 1),
    ]
    _source_mtime(source, 10)
    activity = [{
        "op": "file-mutation", "src": str(source),
        "created_at_ns": NOW - 10 * DAY,
    }]

    plan = _pressured_plan(agw_home, activity_records=activity)
    selected = _candidate_ids(plan)

    # Older member of each same-UTC-day pair is prunable. The newest daily
    # member, newest three overall, and every <=7-day generation are preserved.
    assert records[1]["transaction_id"] in selected
    assert records[3]["transaction_id"] in selected
    assert records[0]["transaction_id"] not in selected  # only generation that day
    assert records[5]["transaction_id"] not in selected
    assert records[6]["transaction_id"] not in selected


def test_inactive_source_collapses_to_newest_usable_generation(tmp_path, agw_home):
    source = tmp_path / "inactive.txt"
    records = [
        _archive(agw_home, source, 1, 60),
        _archive(agw_home, source, 2, 50),
        _archive(agw_home, source, 3, 40),
    ]
    _source_mtime(source, 40)

    plan = _pressured_plan(agw_home)
    selected = _candidate_ids(plan)

    assert records[0]["transaction_id"] in selected
    assert records[1]["transaction_id"] in selected
    assert records[2]["transaction_id"] not in selected


def test_last_reference_extends_source_activity(tmp_path, agw_home):
    source = tmp_path / "deduped-office.docx"
    record = _archive(
        agw_home, source, 1, 50, last_referenced_age=2,
        protected_until_ns=NOW + DAY,
    )
    _source_mtime(source, 60)
    snapshot = retention.inventory(agw_home, activity_records=[])
    source_key = archive_tx.canonical_path(str(source))

    assert snapshot["activity_by_source"][source_key] == NOW - 2 * DAY
    reasons = retention.protection_map(snapshot, now_ns=NOW)
    assert "active_hold" in reasons[record["transaction_id"]]


def test_selection_is_deterministic_and_bounded_to_256(tmp_path, agw_home):
    source = tmp_path / "many.txt"
    records = [
        _archive(agw_home, source, version, 400 - version)
        for version in range(1, 260)
    ]
    _source_mtime(source, 100)
    snapshot = retention.inventory(agw_home, activity_records=[])
    candidates = retention.select_candidates(
        snapshot, 1 << 60, now_ns=NOW, max_candidates=10_000,
        max_reclaim_bytes=1 << 60,
    )

    assert len(candidates) == retention.MAX_CANDIDATES
    assert [item["transaction_id"] for item in candidates] == [
        item["transaction_id"] for item in sorted(
            candidates,
            key=lambda item: (
                -item["allocated_bytes"], item["created_at_ns"],
                item["version"], item["transaction_id"]
            ),
        )
    ]
    assert records[-1]["transaction_id"] not in {
        item["transaction_id"] for item in candidates
    }


def test_plan_binds_policy_store_inventory_and_expires(tmp_path, agw_home):
    source = tmp_path / "bound.txt"
    _archive(agw_home, source, 1, 60)
    _archive(agw_home, source, 2, 40)
    _source_mtime(source, 40)
    plan = _pressured_plan(agw_home)

    assert retention.plan_hash_valid(plan)
    tampered = dict(plan)
    tampered["budget_bytes"] += 1
    assert not retention.plan_hash_valid(tampered)
    with pytest.raises(retention.InvalidPlanError, match="expired"):
        retention.apply_plan(
            agw_home, plan, expected_plan_hash=plan["plan_sha256"],
            now_ns=plan["expires_at_ns"] + 1, activity_records=[],
        )

    other = tmp_path / "other-home"
    with pytest.raises(retention.InvalidPlanError, match="different store"):
        retention.apply_plan(
            str(other), plan, expected_plan_hash=plan["plan_sha256"],
            now_ns=NOW, activity_records=[],
        )


def test_apply_rejects_manifest_or_artifact_tamper(tmp_path, agw_home):
    source = tmp_path / "tamper.txt"
    old = _archive(agw_home, source, 1, 60)
    _archive(agw_home, source, 2, 40)
    _source_mtime(source, 40)
    plan = _pressured_plan(agw_home)
    assert old["transaction_id"] in _candidate_ids(plan)

    Path(old["dest"]).write_text("tampered")
    with pytest.raises((retention.InventoryIncompleteError,
                        retention.StalePlanError)):
        retention.apply_plan(
            agw_home, plan, expected_plan_hash=plan["plan_sha256"],
            now_ns=NOW, activity_records=[],
        )


def test_apply_can_shrink_for_new_reference_hold_but_never_expand(
        tmp_path, agw_home):
    source = tmp_path / "shrink.txt"
    old = _archive(agw_home, source, 1, 60)
    _archive(agw_home, source, 2, 40)
    _source_mtime(source, 40)
    plan = _pressured_plan(agw_home)
    archive_tx.update(
        agw_home, old["transaction_id"], last_referenced_at_ns=NOW,
        protected_until_ns=NOW + DAY,
    )

    result = retention.apply_plan(
        agw_home, plan, expected_plan_hash=plan["plan_sha256"],
        now_ns=NOW, activity_records=[],
    )

    assert result["purged_candidates"] == 0
    assert result["skipped"][0]["transaction_id"] == old["transaction_id"]
    assert Path(old["dest"]).exists()


def test_inventory_rejects_path_escape_and_root_symlink(tmp_path, agw_home):
    source = tmp_path / "escape.txt"
    escaped = _archive(agw_home, source, 1, 60)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside")
    archive_tx.update(agw_home, escaped["transaction_id"], dest=str(outside))

    snapshot = retention.inventory(agw_home, activity_records=[])
    assert snapshot["complete"] is False
    assert retention.select_candidates(snapshot, 100, now_ns=NOW) == []
    assert outside.read_text() == "outside"

    # A link at the artifact root is equally ineligible and is never followed.
    linked_source = tmp_path / "linked.txt"
    linked = _archive(agw_home, linked_source, 2, 60)
    artifact = Path(linked["dest"])
    artifact.unlink()
    try:
        artifact.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation unavailable on this platform")
    snapshot = retention.inventory(agw_home, activity_records=[])
    assert snapshot["complete"] is False
    assert outside.read_text() == "outside"


def test_missing_protected_artifact_is_reported_without_blocking_safe_candidates(
        tmp_path, agw_home):
    missing_source = tmp_path / "missing.txt"
    missing = _archive(
        agw_home, missing_source, 1, 60,
        classification="legacy_unclassified", mode="move",
    )
    Path(missing["dest"]).unlink()
    candidate_source = tmp_path / "candidate.txt"
    old = _archive(agw_home, candidate_source, 1, 60)
    _archive(agw_home, candidate_source, 2, 40)
    _source_mtime(candidate_source, 40)

    snapshot = retention.inventory(agw_home, activity_records=[])
    selected = retention.select_candidates(snapshot, 1, now_ns=NOW)

    assert snapshot["complete"] is True
    assert any(error.startswith("missing artifact:") for error in snapshot["errors"])
    assert old["transaction_id"] in {
        item["transaction_id"] for item in selected
    }

def test_partial_staging_crash_rolls_back_without_deletion(tmp_path, agw_home):
    source = tmp_path / "stage-crash.txt"
    old = _archive(agw_home, source, 1, 60)
    _archive(agw_home, source, 2, 40)
    _source_mtime(source, 40)
    plan = _pressured_plan(agw_home)

    with pytest.raises(retention.SimulatedCrash):
        retention.apply_plan(
            agw_home, plan, expected_plan_hash=plan["plan_sha256"],
            now_ns=NOW, activity_records=[], crash_after="STAGED_ITEM",
        )
    assert not Path(old["dest"]).exists()

    recovered = retention.recover_journal(agw_home, plan["plan_id"])
    assert recovered["state"] == retention.PREPARED
    assert recovered["recovery_action"] == "rolled_back_staging"
    assert Path(old["dest"]).exists()
    assert archive_tx.load(
        agw_home, old["transaction_id"]
    ).get("artifact_state", "PRESENT") == "PRESENT"


@pytest.mark.parametrize("crash_after", [retention.STAGED, "PURGED_ITEM"])
def test_staged_or_partial_purge_crash_resumes_to_purged(
        tmp_path, agw_home, crash_after):
    source = tmp_path / f"purge-{crash_after}.txt"
    old = _archive(agw_home, source, 1, 60)
    _archive(agw_home, source, 2, 40)
    _source_mtime(source, 40)
    plan = _pressured_plan(agw_home)

    with pytest.raises(retention.SimulatedCrash):
        retention.apply_plan(
            agw_home, plan, expected_plan_hash=plan["plan_sha256"],
            now_ns=NOW, activity_records=[], crash_after=crash_after,
        )
    recovered = retention.recover_journal(agw_home, plan["plan_id"])

    assert recovered["state"] == retention.PURGED
    assert not Path(old["dest"]).exists()
    manifest = archive_tx.load(agw_home, old["transaction_id"])
    assert manifest["artifact_state"] == "PURGED"
    assert manifest["retention_plan_id"] == plan["plan_id"]
