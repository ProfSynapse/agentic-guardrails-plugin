"""Opt-in retention exercise against a disposable copy of a real AGW store."""
from __future__ import annotations

from collections import Counter
import json
import os
import time

import pytest

from core import retention
from core import retention_policy
from core import archive_transactions as archive_tx
from core import store


def _fixture_path() -> str:
    return os.environ.get("AGW_RETENTION_FIXTURE", "")


def _rebase_disposable_clone(home: str) -> int:
    source_home = os.environ.get("AGW_RETENTION_SOURCE_HOME", "")
    if not source_home:
        return 0
    source_home = os.path.abspath(source_home)
    changed = 0
    for item in archive_tx.discover(home):
        record = item.get("record")
        if not isinstance(record, dict):
            continue
        updates = {}
        for field in ("dest", "temp", "quarantine"):
            value = str(record.get(field) or "")
            try:
                within = value and os.path.commonpath(
                    (os.path.abspath(value), source_home)
                ) == source_home
            except ValueError:
                within = False
            if within:
                updates[field] = os.path.join(
                    home, os.path.relpath(value, source_home)
                )
        if updates:
            archive_tx.update(home, record["transaction_id"], **updates)
            changed += 1
    return changed


@pytest.mark.skipif(not _fixture_path(), reason="requires AGW_RETENTION_FIXTURE")
def test_real_retention_fixture(monkeypatch):
    home = os.path.abspath(_fixture_path())
    assert os.path.isdir(home)
    monkeypatch.setenv("AGW_HOME", home)

    started = time.monotonic()
    before_bytes = store.archive_size_bytes()
    rebased_records = _rebase_disposable_clone(home)
    migration = retention.migrate_legacy_cache_records(home, protected_days=7)
    snapshot = retention.inventory(home)
    protections = retention.protection_map(snapshot)
    reasons = Counter(
        reason for record_reasons in protections.values()
        for reason in record_reasons
    )
    classes = Counter(item["retention_class"] for item in snapshot["records"])
    modes = Counter(item["mode"] for item in snapshot["records"])
    eligible = [
        item for item in snapshot["records"]
        if not protections[item["transaction_id"]]
    ]

    maximum = max(1, before_bytes)
    policy = retention_policy.RetentionPolicy(
        max_bytes=maximum,
        high_water_bytes=maximum * 9 // 10,
        low_water_bytes=maximum * 8 // 10,
        min_protected_age_days=7,
        inactive_collapse_age_days=30,
        max_candidates=256,
        max_reclaim_bytes=1 << 30,
    )
    plan = retention.build_plan(
        home, policy=policy, current_bytes=before_bytes,
    )
    result = None
    if plan["applicable"] and plan["candidates"]:
        result = retention.apply_plan(
            home, plan, expected_plan_hash=plan["plan_sha256"],
            policy=policy, lock_context=store.Lock("recovery-store", timeout=30.0),
        )
    after_bytes = store.archive_size_bytes()

    report = {
        "before_bytes": before_bytes,
        "after_bytes": after_bytes,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "inventory_complete": snapshot["complete"],
        "inventory_error_count": len(snapshot["errors"]),
        "transaction_record_count": len(snapshot["records"]),
        "unclassified_count": len(snapshot["unclassified_transaction_ids"]),
        "migrated_legacy_count": migration["migrated"],
        "rebased_record_count": rebased_records,
        "retention_classes": dict(sorted(classes.items())),
        "archive_modes": dict(sorted(modes.items())),
        "protection_reasons": dict(sorted(reasons.items())),
        "eligible_count": len(eligible),
        "eligible_allocated_bytes": sum(
            item["allocated_bytes"] for item in eligible
        ),
        "plan_applicable": plan["applicable"],
        "candidate_count": len(plan["candidates"]),
        "planned_reclaim_bytes": plan["planned_reclaim_bytes"],
        "capacity_satisfied_by_plan": plan["capacity_satisfied_by_plan"],
        "purged_count": 0 if result is None else result["purged_candidates"],
        "actual_reclaimed_bytes": 0 if result is None else result["reclaimed_bytes"],
    }
    print("REAL_RETENTION_REPORT=" + json.dumps(report, sort_keys=True))
    if snapshot["errors"]:
        print("REAL_RETENTION_ERRORS=" + json.dumps(snapshot["errors"], sort_keys=True))

    assert after_bytes <= before_bytes
    assert len(plan["candidates"]) <= policy.max_candidates
    if not snapshot["complete"]:
        assert result is None
    if result is not None:
        assert result["purged_candidates"] <= policy.max_candidates
