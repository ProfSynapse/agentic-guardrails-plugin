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
