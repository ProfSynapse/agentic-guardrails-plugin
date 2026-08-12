"""Store-level automatic retention integration tests."""
from __future__ import annotations

import os
import json
import time
from pathlib import Path

import pytest

from core import archive_transactions as archive_tx
from core import retention
from core import retention_policy
from core import store


DAY_NS = 24 * 60 * 60 * 1_000_000_000


def _policy(maximum: int, low: int) -> retention_policy.RetentionPolicy:
    return retention_policy.RetentionPolicy(
        max_bytes=maximum,
        high_water_bytes=maximum * 9 // 10,
        low_water_bytes=low,
        min_protected_age_days=7,
        inactive_collapse_age_days=30,
        max_candidates=256,
        max_reclaim_bytes=1 << 30,
    )


def _age(entry: dict, source: Path, days: int):
    now = time.time_ns()
    created = now - days * DAY_NS
    archive_tx.update(
        store.agw_home(), entry["transaction_id"],
        created_at_ns=created, protected_until_ns=0,
        last_referenced_at_ns=0,
    )
    oplog = Path(store.agw_home()) / "oplog.jsonl"
    records = [json.loads(line) for line in oplog.read_text(encoding="utf-8").splitlines()]
    for record in records:
        if record.get("transaction_id") == entry["transaction_id"]:
            record["created_at_ns"] = created
    oplog.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )
    stamp = created / 1_000_000_000
    os.utime(source, (stamp, stamp))


def test_archive_publication_prunes_only_expired_classified_cache(tmp_path):
    source = tmp_path / "inactive.bin"
    source.write_bytes(b"a" * 20_000)
    oldest = store.archive_file(
        str(source), mode="copy", retention_class="mutation_preimage"
    )
    source.write_bytes(b"b" * 20_000)
    newest = store.archive_file(
        str(source), mode="copy", retention_class="mutation_preimage"
    )
    _age(oldest, source, 45)
    _age(newest, source, 40)

    manual_source = tmp_path / "manual.bin"
    manual_source.write_bytes(b"m" * 10_000)
    manual = store.archive_file(
        str(manual_source), mode="copy", retention_class="manual_snapshot"
    )
    _age(manual, manual_source, 90)

    incoming = tmp_path / "incoming.bin"
    incoming.write_bytes(b"n" * 2_000)
    before = store.archive_size_bytes()
    policy = _policy(before + 2_000, before // 2)
    created = store.archive_file(
        str(incoming), mode="copy", retention_class="mutation_preimage",
        retention_config=policy,
    )

    assert not Path(oldest["dest"]).exists()
    assert Path(newest["dest"]).exists()
    assert Path(manual["dest"]).exists()
    assert Path(created["dest"]).exists()
    purged = archive_tx.load(store.agw_home(), oldest["transaction_id"])
    assert purged["artifact_state"] == "PURGED"


def test_capacity_blocks_when_only_recent_or_manual_records_exist(tmp_path):
    source = tmp_path / "recent.bin"
    source.write_bytes(b"r" * 12_000)
    recent = store.archive_file(
        str(source), mode="copy", retention_class="mutation_preimage",
        protected_until_ns=time.time_ns() + DAY_NS,
    )
    incoming = tmp_path / "blocked.bin"
    incoming.write_bytes(b"x" * 5_000)
    before = store.archive_size_bytes()
    policy = _policy(before + 1, before // 2)

    with pytest.raises(store.ArchiveCapacityError) as failure:
        store.archive_file(
            str(incoming), mode="copy", retention_class="mutation_preimage",
            retention_config=policy,
        )

    assert Path(recent["dest"]).exists()
    assert not any(
        item.get("record", {}).get("src") == str(incoming)
        for item in store.discover_archive_transactions()
        if item.get("record")
    )
    assert failure.value.error_code == "archive_capacity_exceeded"


def test_legacy_migration_requires_exact_trusted_producer_signature(tmp_path):
    trusted_source = tmp_path / "trusted.txt"
    trusted_source.write_text("trusted")
    trusted = store.archive_file(
        str(trusted_source), mode="copy", actor="guardrails-hook",
        reason="verified pre-image before Edit",
    )
    archive_tx.update(
        store.agw_home(), trusted["transaction_id"],
        policy_revision="policy-1",
    )
    result = retention.migrate_legacy_cache_records(store.agw_home())
    unknown_source = tmp_path / "unknown.txt"
    unknown_source.write_text("unknown")
    unknown = store.archive_file(
        str(unknown_source), mode="copy", actor="agent",
        reason="verified pre-image before Edit",
    )

    assert trusted["transaction_id"] in result["transaction_ids"]
    trusted_record = archive_tx.load(store.agw_home(), trusted["transaction_id"])
    unknown_record = archive_tx.load(store.agw_home(), unknown["transaction_id"])
    assert trusted_record["retention_class"] == "mutation_preimage"
    assert trusted_record["retention_migrated_from"] == "legacy_trusted_producer"
    assert unknown_record["retention_class"] == ""
