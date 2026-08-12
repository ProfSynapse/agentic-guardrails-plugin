"""Store-level regressions for retention recovery and locked restores."""
from __future__ import annotations

from contextlib import nullcontext
import json
import os
from pathlib import Path
import sys
import threading
import time

import pytest

from core import archive_transactions as archive_tx
from core import retention
from core import retention_policy
from core import store


DAY_NS = 24 * 60 * 60 * 1_000_000_000


def _unlimited_policy():
    return retention_policy.RetentionPolicy(
        max_bytes=0, high_water_bytes=0, low_water_bytes=0,
        min_protected_age_days=7, inactive_collapse_age_days=30,
        max_candidates=256, max_reclaim_bytes=1 << 30,
    )


def _interrupted_plan(tmp_path: Path, crash_after: str):
    source = tmp_path / f"journal-{crash_after}.txt"
    source.write_text("old")
    oldest = store.archive_file(
        str(source), mode="copy", retention_class="mutation_preimage"
    )
    source.write_text("new")
    newest = store.archive_file(
        str(source), mode="copy", retention_class="mutation_preimage"
    )
    now = time.time_ns()
    for entry, days in ((oldest, 60), (newest, 40)):
        archive_tx.update(
            store.agw_home(), entry["transaction_id"],
            created_at_ns=now - days * DAY_NS,
            last_referenced_at_ns=0, protected_until_ns=0,
        )
    stamp = (now - 40 * DAY_NS) / 1_000_000_000
    os.utime(source, (stamp, stamp))
    snapshot = retention.inventory(store.agw_home(), activity_records=[])
    current = snapshot["known_allocated_bytes"]
    policy = retention_policy.RetentionPolicy(
        max_bytes=current, high_water_bytes=current * 9 // 10,
        low_water_bytes=max(0, current // 10), min_protected_age_days=7,
        inactive_collapse_age_days=30, max_candidates=256,
        max_reclaim_bytes=1 << 30,
    )
    plan = retention.build_plan(
        store.agw_home(), policy=policy, current_bytes=current,
        now_ns=now, activity_records=[],
    )
    assert oldest["transaction_id"] in {
        item["transaction_id"] for item in plan["candidates"]
    }
    with pytest.raises(retention.SimulatedCrash):
        retention.apply_plan(
            store.agw_home(), plan,
            expected_plan_hash=plan["plan_sha256"], now_ns=now,
            activity_records=[], crash_after=crash_after,
        )
    return oldest, plan


@pytest.mark.parametrize(
    ("crash_after", "artifact_survives"),
    [("STAGED_ITEM", True), (retention.STAGED, False)],
)
def test_maintenance_recovers_incomplete_journals_before_planning(
        tmp_path, monkeypatch, crash_after, artifact_survives):
    oldest, plan = _interrupted_plan(tmp_path, crash_after)
    planned = False

    def unexpected_plan(*_args, **_kwargs):
        nonlocal planned
        planned = True
        raise AssertionError("maintenance planned before journal recovery")

    monkeypatch.setattr(retention, "build_plan", unexpected_plan)
    result = store.maintain_retention(policy=_unlimited_policy())

    assert planned is False
    assert result["journal_recovery"]["recovered"] == 1
    assert result["journal_recovery"]["plan_ids"] == [plan["plan_id"]]
    assert Path(oldest["dest"]).exists() is artifact_survives
    journal = retention.load_journal(store.agw_home(), plan["plan_id"])
    if artifact_survives:
        assert journal["recovery_action"] == "rolled_back_staging"
    else:
        assert journal["state"] == retention.PURGED


@pytest.mark.parametrize("kind", ["corrupt_journal", "orphan_staging"])
def test_maintenance_fails_closed_before_planning_for_unknown_recovery_state(
        tmp_path, monkeypatch, kind):
    plan_id = "a" * 32
    if kind == "corrupt_journal":
        root = Path(store.agw_home()) / "retention" / "transactions"
        root.mkdir(parents=True)
        (root / f"{plan_id}.json").write_text("{not-json", encoding="utf-8")
    else:
        root = Path(store.agw_home()) / "retention" / "staging" / plan_id
        root.mkdir(parents=True)
        (root / "untracked.bin").write_bytes(b"evidence")
    planned = False

    def unexpected_plan(*_args, **_kwargs):
        nonlocal planned
        planned = True
        return {}

    monkeypatch.setattr(retention, "build_plan", unexpected_plan)
    with pytest.raises(retention.InventoryIncompleteError):
        store.maintain_retention(policy=_unlimited_policy())
    assert planned is False


def test_list_versions_filters_purged_and_missing_authoritative_artifacts(tmp_path):
    source = tmp_path / "versions.txt"
    source.write_text("one")
    purged = store.archive_file(str(source), mode="copy")
    source.write_text("two")
    missing = store.archive_file(str(source), mode="copy")
    assert len(store.list_versions(str(source))) == 2

    archive_tx.update(
        store.agw_home(), purged["transaction_id"], artifact_state="PURGED",
        retention_plan_id="b" * 32,
    )
    Path(missing["dest"]).unlink()

    assert store.list_versions(str(source)) == []
    with pytest.raises(FileNotFoundError, match="no archived versions"):
        store.restore(str(source), retention_config=_unlimited_policy())


class _TrackingLock:
    def __init__(self, real_lock, held, name, *args, **kwargs):
        self.name = name
        self.held = held
        self.inner = real_lock(name, *args, **kwargs)

    def __enter__(self):
        self.inner.__enter__()
        if self.name == "recovery-store":
            self.held["recovery-store"] += 1
        return self

    def __exit__(self, *exc):
        if self.name == "recovery-store":
            self.held["recovery-store"] -= 1
        return self.inner.__exit__(*exc)


def test_restore_holds_global_lock_and_threads_retention_policy(
        tmp_path, monkeypatch):
    source = tmp_path / "restore-lock.txt"
    source.write_text("before")
    store.archive_file(str(source), mode="copy")
    source.write_text("after")
    policy = _unlimited_policy()
    real_lock = store.Lock
    real_archive = store.archive_file
    real_publish = archive_tx.publish_restore
    held = {"recovery-store": 0}
    nested = []

    monkeypatch.setattr(
        store, "Lock",
        lambda name, *args, **kwargs: _TrackingLock(
            real_lock, held, name, *args, **kwargs
        ),
    )

    def checked_archive(*args, **kwargs):
        assert held["recovery-store"] == 1
        assert kwargs["retention_config"] is policy
        assert isinstance(kwargs["lock_context"], type(nullcontext()))
        nested.append(True)
        return real_archive(*args, **kwargs)

    def checked_publish(*args, **kwargs):
        assert held["recovery-store"] == 1
        return real_publish(*args, **kwargs)

    monkeypatch.setattr(store, "archive_file", checked_archive)
    monkeypatch.setattr(archive_tx, "publish_restore", checked_publish)
    result = store.restore(str(source), retention_config=policy)

    assert nested == [True]
    assert source.read_text() == "before"
    assert held["recovery-store"] == 0
    logged = [item for item in store.oplog_read() if item.get("op") == "restore"]
    assert logged[-1]["timestamp_ns"] > 0
    assert result["from"]


def test_undo_holds_global_lock_through_failure_rollback_and_threads_policy(
        tmp_path, monkeypatch):
    target = tmp_path / "undo-lock.txt"
    target.write_text("before")
    snapshot = store.archive_file(
        str(target), mode="copy", retention_class="mutation_preimage"
    )
    target.write_text("after")
    store.oplog_append({
        "op": "file-mutation", "operation": "write", "src": str(target),
        "before_sha256": snapshot["sha256"],
        "after_sha256": store.file_sha256(str(target)),
        "snapshot_transaction_id": snapshot["transaction_id"],
    })
    policy = _unlimited_policy()
    real_lock = store.Lock
    real_capture = store._capture_undo_prestate
    real_rollback = store._rollback_undo_member
    held = {"recovery-store": 0}
    calls = {"capture": 0, "rollback": 0}

    monkeypatch.setattr(
        store, "Lock",
        lambda name, *args, **kwargs: _TrackingLock(
            real_lock, held, name, *args, **kwargs
        ),
    )

    def checked_capture(*args, **kwargs):
        assert held["recovery-store"] == 1
        assert kwargs["retention_config"] is policy
        assert isinstance(kwargs["lock_context"], type(nullcontext()))
        calls["capture"] += 1
        return real_capture(*args, **kwargs)

    def checked_rollback(*args, **kwargs):
        assert held["recovery-store"] == 1
        assert kwargs["retention_config"] is policy
        assert isinstance(kwargs["lock_context"], type(nullcontext()))
        calls["rollback"] += 1
        return real_rollback(*args, **kwargs)

    monkeypatch.setattr(store, "_capture_undo_prestate", checked_capture)
    monkeypatch.setattr(store, "_rollback_undo_member", checked_rollback)
    monkeypatch.setattr(
        store, "_restore_snapshot",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("publish failed")),
    )

    with pytest.raises(store.TransactionUndoError):
        store.undo_transaction(
            snapshot["transaction_id"], retention_config=policy
        )

    assert calls == {"capture": 1, "rollback": 1}
    assert held["recovery-store"] == 0
    assert target.read_text() == "after"
    failures = [
        item for item in store.oplog_read()
        if item.get("op") == "transaction-undo-failed"
    ]
    assert failures[-1]["timestamp_ns"] > 0


def test_lock_contention_windows_sharing_branch_is_reachable(monkeypatch):
    error = PermissionError(13, "sharing")
    error.winerror = 32
    monkeypatch.setattr(store.os, "name", "nt")
    assert store._lock_contention(error, "unused") is True


def _malformed_lock(name: str, content: bytes) -> Path:
    path = Path(store.agw_home()) / "locks" / f"{name}.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


@pytest.mark.parametrize("content", [b"", b"12345", b"12345:"])
def test_fresh_empty_or_truncated_lock_is_never_stolen(content):
    path = _malformed_lock("fresh-malformed", content)

    with pytest.raises(TimeoutError):
        with store.Lock("fresh-malformed", timeout=0):
            pass

    assert path.exists()
    assert path.read_bytes() == content


def test_stale_empty_lock_from_creation_write_crash_is_recovered():
    path = _malformed_lock("stale-empty", b"")
    old = time.time() - store._MALFORMED_LOCK_STALE_SECONDS - 5
    os.utime(path, (old, old))

    with store.Lock("stale-empty", timeout=0) as acquired:
        assert acquired.path == str(path)
        owner = store._lock_owner(str(path))
        assert owner == (os.getpid(), acquired.token)

    assert not path.exists()


def test_stale_truncated_lock_with_dead_pid_is_recovered(monkeypatch):
    path = _malformed_lock("stale-truncated-dead", b"424242:")
    old = time.time() - store._MALFORMED_LOCK_STALE_SECONDS - 5
    os.utime(path, (old, old))
    monkeypatch.setattr(store, "_process_is_alive", lambda pid: False)

    with store.Lock("stale-truncated-dead", timeout=0):
        assert store._lock_owner(str(path))[1]

    assert not path.exists()


def test_stale_truncated_lock_with_live_pid_preserves_owner(monkeypatch):
    content = b"424242"
    path = _malformed_lock("stale-truncated-live", content)
    old = time.time() - store._MALFORMED_LOCK_STALE_SECONDS - 5
    os.utime(path, (old, old))
    monkeypatch.setattr(store, "_process_is_alive", lambda pid: pid == 424242)

    with pytest.raises(TimeoutError):
        with store.Lock("stale-truncated-live", timeout=0):
            pass

    assert path.exists()
    assert path.read_bytes() == content


def test_concurrent_stale_lock_reclaimers_never_overlap(monkeypatch):
    path = _malformed_lock(
        "concurrent-reclaim", b"424242:" + (b"a" * 32)
    )
    old = time.time() - store._MALFORMED_LOCK_STALE_SECONDS - 5
    os.utime(path, (old, old))
    monkeypatch.setattr(store, "_process_is_alive", lambda _pid: False)
    barrier = threading.Barrier(3)
    state_lock = threading.Lock()
    state = {"active": 0, "maximum": 0, "entered": 0, "errors": []}

    def contender():
        try:
            barrier.wait(timeout=2)
            with store.Lock("concurrent-reclaim", timeout=2):
                with state_lock:
                    state["active"] += 1
                    state["entered"] += 1
                    state["maximum"] = max(state["maximum"], state["active"])
                time.sleep(0.05)
                with state_lock:
                    state["active"] -= 1
        except Exception as exc:  # pragma: no cover - asserted below
            with state_lock:
                state["errors"].append(repr(exc))

    threads = [threading.Thread(target=contender) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait(timeout=2)
    for thread in threads:
        thread.join(timeout=5)

    assert state["errors"] == []
    assert state["entered"] == 2
    assert state["maximum"] == 1
    assert state["active"] == 0
    assert all(not thread.is_alive() for thread in threads)
    assert not path.exists()


def test_windows_open_process_access_denied_is_treated_as_live(monkeypatch):
    observed = {}

    class Function:
        def __init__(self, result):
            self.result = result
            self.argtypes = None
            self.restype = None

        def __call__(self, *_args):
            return self.result

    class Kernel32:
        OpenProcess = Function(0)
        GetExitCodeProcess = Function(0)
        CloseHandle = Function(1)

    class FakeCtypes:
        c_ulong = int
        c_int = int
        c_void_p = int

        @staticmethod
        def WinDLL(name, *, use_last_error=False):
            observed["name"] = name
            observed["use_last_error"] = use_last_error
            return Kernel32()

        @staticmethod
        def get_last_error():
            return 5  # ERROR_ACCESS_DENIED

    monkeypatch.setattr(store.os, "name", "nt")
    monkeypatch.setitem(sys.modules, "ctypes", FakeCtypes)

    assert store._process_is_alive(424242) is True
    assert observed == {"name": "kernel32", "use_last_error": True}
