"""Hook-path store behavior: lock budget, one-pass capture, batched fsync."""
from __future__ import annotations

import os
import time

import pytest

from core import preimages, retention_policy, store


HOST_HOOK_TIMEOUT_S = 15.0


def _unlimited():
    return retention_policy.resolve_retention_policy({"archive_max_bytes": 0}, {})


def test_hook_lock_budget_is_strictly_inside_the_host_deadline(monkeypatch):
    assert store.HOOK_LOCK_BUDGET_S < HOST_HOOK_TIMEOUT_S
    monkeypatch.delenv("AGW_HOOK_LOCK_BUDGET_S", raising=False)
    assert store.hook_lock_budget_s() == store.HOOK_LOCK_BUDGET_S
    monkeypatch.setenv("AGW_HOOK_LOCK_BUDGET_S", "0.25")
    assert store.hook_lock_budget_s() == 0.25
    # The override can only shorten the wait, never exceed the hook budget.
    monkeypatch.setenv("AGW_HOOK_LOCK_BUDGET_S", "600")
    assert store.hook_lock_budget_s() == store.HOOK_LOCK_BUDGET_S
    monkeypatch.setenv("AGW_HOOK_LOCK_BUDGET_S", "garbage")
    assert store.hook_lock_budget_s() == store.HOOK_LOCK_BUDGET_S
    assert store.hook_lock().timeout == store.HOOK_LOCK_BUDGET_S


def test_busy_store_refuses_legibly_inside_the_hook_budget(tmp_path, monkeypatch):
    monkeypatch.setenv("AGW_HOOK_LOCK_BUDGET_S", "0.3")
    target = tmp_path / "busy.txt"
    target.write_text("keep me", encoding="utf-8")
    holder = store.Lock("recovery-store", timeout=1.0)
    with holder:
        started = time.monotonic()
        result = preimages.prepare(
            [str(target)], "Edit", 1 << 20, policy_revision="rev-1",
            retention_config=_unlimited(),
        )
        elapsed = time.monotonic() - started
    assert elapsed < 5.0, f"prepare waited {elapsed:.1f}s on a held store lock"
    assert result.ok is False
    assert result.error_code == preimages.ERROR_STORE_BUSY
    assert result.failed_target == str(target)
    assert "busy" in result.reason
    assert "Retry" in result.reason
    assert "Nothing was changed" in result.reason
    # No partial recovery state: nothing was archived for the refused target.
    assert store.list_versions(str(target)) == []
    assert target.read_text(encoding="utf-8") == "keep me"


def test_free_store_still_captures_under_the_hook_budget(tmp_path, monkeypatch):
    monkeypatch.setenv("AGW_HOOK_LOCK_BUDGET_S", "0.3")
    target = tmp_path / "free.txt"
    target.write_text("snapshot me", encoding="utf-8")
    result = preimages.prepare(
        [str(target)], "Edit", 1 << 20, policy_revision="rev-1",
        retention_config=_unlimited(),
    )
    assert result.ok, result.reason
    assert result.error_code == ""
    receipt = result.receipts[0]
    assert os.path.isfile(receipt.artifact)
    assert preimages.receipt_valid(receipt, "rev-1")


# --- F9: running size counter, single admission, dedupe ------------------------

def _prepare(target, revision="rev-1"):
    return preimages.prepare(
        [str(target)], "Edit", 1 << 20, policy_revision=revision,
        retention_config=_unlimited(),
    )


def test_archive_size_counter_matches_walk_and_falls_back_when_stale(
        tmp_path, monkeypatch):
    first = tmp_path / "a.txt"
    first.write_text("a" * 3000, encoding="utf-8")
    second = tmp_path / "b.txt"
    second.write_text("b" * 5000, encoding="utf-8")
    store.archive_file(str(first), mode="copy", retention_config=_unlimited())
    store.archive_file(str(second), mode="copy", retention_config=_unlimited())
    walked = store._archive_size_walk()
    assert walked >= 8000
    assert store.archive_size_bytes() == walked

    def no_walk(*_args, **_kwargs):
        raise AssertionError("archive_size_bytes walked although the counter was fresh")

    with monkeypatch.context() as scoped:
        scoped.setattr(store.os, "walk", no_walk)
        assert store.archive_size_bytes() == walked

    # A manifest the counter never saw (crash mid-write, older process) makes
    # the counter stale: one walk, then the counter is fresh again.
    stray = os.path.join(store.agw_home(), "transactions", "0" * 32 + ".json")
    with open(stray, "w", encoding="utf-8") as handle:
        handle.write("{}")
    assert store._cached_archive_size() is None
    assert store.archive_size_bytes() == walked
    assert store._cached_archive_size() == walked

    for bad in ('{"bytes": -1, "manifest_count": 3}', '{"bytes": "x"}', "garbage"):
        with open(store._archive_size_state_path(), "w", encoding="utf-8") as handle:
            handle.write(bad)
        assert store._cached_archive_size() is None
        assert store.archive_size_bytes() == walked
    os.unlink(store._archive_size_state_path())
    assert store.archive_size_bytes() == walked


def test_prepare_admits_once_without_walking_or_locking(tmp_path, monkeypatch):
    seed = tmp_path / "seed.txt"
    seed.write_text("seed", encoding="utf-8")
    store.archive_file(str(seed), mode="copy", retention_config=_unlimited())
    assert store._cached_archive_size() is not None
    walks = []
    locked_maintenance = []
    real_walk = store._archive_size_walk
    real_locked = store._maintain_retention_locked

    def counting_walk():
        walks.append(1)
        return real_walk()

    def counting_locked(**kwargs):
        locked_maintenance.append(kwargs)
        return real_locked(**kwargs)

    monkeypatch.setattr(store, "_archive_size_walk", counting_walk)
    monkeypatch.setattr(store, "_maintain_retention_locked", counting_locked)
    target = tmp_path / "edited.txt"
    target.write_text("v1", encoding="utf-8")
    result = _prepare(target)
    assert result.ok, result.reason
    assert walks == [], "a routine prepare must not walk the archive"
    assert locked_maintenance == [], "a routine prepare must not take the prune path"
    # The write advanced the counter instead of invalidating it.
    assert store._cached_archive_size() == store._archive_size_walk()


def test_size_check_does_not_need_the_store_lock_but_a_prune_does(
        tmp_path, monkeypatch):
    monkeypatch.setenv("AGW_HOOK_LOCK_BUDGET_S", "0.2")
    seed = tmp_path / "seed.txt"
    seed.write_text("s" * 2048, encoding="utf-8")
    store.archive_file(str(seed), mode="copy", retention_class="mutation_preimage",
                       retention_config=_unlimited())
    current = store.archive_size_bytes()
    roomy = retention_policy.RetentionPolicy(
        max_bytes=current * 10, high_water_bytes=current * 9,
        low_water_bytes=current * 8, min_protected_age_days=7,
        inactive_collapse_age_days=30, max_candidates=256,
        max_reclaim_bytes=1 << 30,
    )
    pressured = retention_policy.RetentionPolicy(
        max_bytes=current + 1, high_water_bytes=current, low_water_bytes=1,
        min_protected_age_days=7, inactive_collapse_age_days=30,
        max_candidates=256, max_reclaim_bytes=1 << 30,
    )
    with store.Lock("recovery-store", timeout=1.0):
        result = store.maintain_retention(
            policy=roomy, incoming_bytes=10, lock_context=store.hook_lock()
        )
        assert result["lock_taken"] is False
        assert result["applied"] is False
        with pytest.raises(TimeoutError):
            store.maintain_retention(
                policy=pressured, incoming_bytes=1, lock_context=store.hook_lock()
            )


def test_prepare_dedupes_unchanged_content_and_extends_its_hold(tmp_path):
    from core import archive_transactions as archive_tx
    from core import retention

    target = tmp_path / "stable.txt"
    target.write_text("unchanged", encoding="utf-8")
    first = _prepare(target)
    assert first.ok, first.reason
    first_record = archive_tx.load(store.agw_home(), first.receipts[0].transaction_id)
    second = _prepare(target)
    assert second.ok, second.reason
    assert second.receipts[0].transaction_id == first.receipts[0].transaction_id
    assert len(store.list_versions(str(target))) == 1
    second_record = archive_tx.load(store.agw_home(), second.receipts[0].transaction_id)
    assert second_record["protected_until_ns"] >= first_record["protected_until_ns"]
    assert second_record["last_referenced_at_ns"] > 0
    # The deduped entry is the newest version, so retention protects it at
    # least as strongly as a fresh copy would have been protected.
    snapshot = retention.inventory(store.agw_home())
    reasons = retention.protection_map(snapshot)[first.receipts[0].transaction_id]
    assert "active_hold" in reasons
    assert any(reason.startswith("newest_") for reason in reasons)
    # ...and it remains restorable through the verified path.
    assert preimages.receipt_valid(second.receipts[0], "rev-1")
    target.write_text("changed", encoding="utf-8")
    store.restore(str(target))
    assert target.read_text(encoding="utf-8") == "unchanged"

    # A real change stores a new version; only the newest version dedupes.
    target.write_text("different", encoding="utf-8")
    third = _prepare(target)
    assert third.ok, third.reason
    assert third.receipts[0].transaction_id != first.receipts[0].transaction_id


def test_dedupe_never_crosses_policy_revisions(tmp_path):
    target = tmp_path / "policy.txt"
    target.write_text("same bytes", encoding="utf-8")
    old = _prepare(target, "rev-old")
    assert old.ok, old.reason
    new = _prepare(target, "rev-new")
    assert new.ok, new.reason
    assert new.receipts[0].transaction_id != old.receipts[0].transaction_id
    assert new.receipts[0].policy_revision == "rev-new"
    assert preimages.receipt_valid(new.receipts[0], "rev-new")
    # A stale index must not make an older version look newest.
    versions = [entry["version"] for entry in store.list_versions(str(target))]
    assert versions == [1, 2]


# --- single-pass capture -------------------------------------------------------

def _count_read_opens(monkeypatch, target: str):
    import builtins

    real_open = builtins.open
    counts = {"source": 0, "artifact": 0}
    archive_root = os.path.join(store.agw_home(), "archive")

    def counting_open(file, mode="r", *args, **kwargs):
        if isinstance(file, str) and "r" in mode and "+" not in mode:
            if os.path.abspath(file) == target:
                counts["source"] += 1
            elif os.path.abspath(file).startswith(archive_root + os.sep) \
                    and not os.path.basename(file).endswith(".jsonl"):
                counts["artifact"] += 1
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", counting_open)
    return counts


def test_prepare_reads_the_source_once_and_the_artifact_once(tmp_path, monkeypatch):
    target = tmp_path / "once.txt"
    target.write_bytes(b"x" * 70_000)
    counts = _count_read_opens(monkeypatch, str(target))
    result = _prepare(target)
    during_prepare = dict(counts)
    assert result.ok, result.reason
    assert during_prepare == {"source": 1, "artifact": 1}, during_prepare
    receipt = result.receipts[0]
    assert receipt.sha256 == store.file_sha256(str(target))
    assert store.file_sha256(receipt.artifact) == receipt.sha256
    assert preimages.receipt_valid(receipt, "rev-1")


def test_prepare_refuses_a_source_that_changes_while_it_is_copied(
        tmp_path, monkeypatch):
    from core import archive_transactions as archive_tx

    target = tmp_path / "moving.txt"
    target.write_text("first draft", encoding="utf-8")
    real_copy = archive_tx._copy_file_hashed

    def copy_then_mutate(source, destination):
        result = real_copy(source, destination)
        with open(source, "a", encoding="utf-8") as handle:
            handle.write(" plus a late write")
        return result

    monkeypatch.setattr(archive_tx, "_copy_file_hashed", copy_then_mutate)
    result = _prepare(target)
    assert result.ok is False
    assert "changed while its recovery copy was being verified" in result.reason
    assert result.failed_target == str(target)
    assert target.read_text(encoding="utf-8") == "first draft plus a late write"


def test_streamed_capture_refuses_a_digest_hint_that_no_longer_matches(tmp_path):
    from core import archive_transactions as archive_tx

    source = tmp_path / "hinted.txt"
    source.write_text("current bytes", encoding="utf-8")
    dest = tmp_path / "store" / "v001_hinted.txt"
    dest.parent.mkdir()
    with pytest.raises(OSError, match="source changed before capture"):
        archive_tx.create_archive(
            store.agw_home(), str(source), str(dest), "copy", 1,
            source_sha256="0" * 64,
        )
    assert source.read_text(encoding="utf-8") == "current bytes"
    assert not dest.exists()
