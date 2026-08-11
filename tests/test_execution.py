import os
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
AGW = ROOT / "plugin" / "scripts" / "agw"
sys.path.insert(0, str(AGW))

import execution  # noqa: E402
import file_ops  # noqa: E402
from core import store  # noqa: E402


def test_observed_runner_captures_output_and_metadata(tmp_path):
    result = execution.run(execution.ExecutionRequest(
        command=[sys.executable, "-c", "print('bounded output')"],
        cwd=str(tmp_path), timeout_seconds=5,
    ))
    assert result.exit_code == 0
    assert result.stdout_tail.strip() == "bounded output"
    assert result.timed_out is False
    assert result.isolation_mode == "observed"
    assert result.duration_seconds >= 0


@pytest.mark.parametrize(
    "isolation",
    [
        execution.IsolationRequest(mode="read-only"),
        execution.IsolationRequest(mode="strict"),
        execution.IsolationRequest(mode="observed", network="deny"),
    ],
)
def test_unavailable_isolation_never_downgrades(tmp_path, isolation):
    with pytest.raises(execution.IsolationUnavailable) as caught:
        execution.run(execution.ExecutionRequest(
            command=[sys.executable, "-c", "print('must not run')"],
            cwd=str(tmp_path), timeout_seconds=5, isolation=isolation,
        ))
    assert caught.value.details["fallback_performed"] is False


def test_timeout_terminates_process(tmp_path):
    result = execution.run(execution.ExecutionRequest(
        command=[sys.executable, "-c", "import time; time.sleep(30)"],
        cwd=str(tmp_path), timeout_seconds=0.05,
    ))
    assert result.timed_out is True
    assert result.exit_code != 0


def test_non_file_output_keeps_addressable_transaction_and_can_be_undone(tmp_path):
    target = tmp_path / "output.txt"
    target.write_text("before\n", encoding="utf-8")
    command = [
        sys.executable, "-c",
        "import os,sys; os.unlink(sys.argv[1]); os.mkdir(sys.argv[1])",
        str(target),
    ]
    with pytest.raises(file_ops.FileTransactionError) as caught:
        file_ops.run_declared(
            command, [str(target)],
            expected_hashes=[store.file_sha256(str(target))], cwd=str(tmp_path),
        )
    transaction_id = caught.value.details["transaction_id"]
    assert target.is_dir()
    restored = store.undo_transaction(transaction_id)
    assert restored["state"] == "COMMITTED"
    assert target.read_text(encoding="utf-8") == "before\n"


def test_observation_failure_still_returns_addressable_recovery(tmp_path, monkeypatch):
    target = tmp_path / "output.txt"
    target.write_text("before\n", encoding="utf-8")
    root = tmp_path / "observed"
    root.mkdir()

    class Provider:
        def run(self, request):
            target.write_text("after\n", encoding="utf-8")
            return execution.ExecutionResult(
                exit_code=0, stdout_tail="", stderr_tail="",
                capture_truncated=False, timed_out=False, duration_seconds=0.01,
                isolation_mode="observed", network_policy="inherit",
            )

    original = file_ops._observe_requested_roots
    calls = 0

    def fail_after_launch(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("observation failed")
        return original(*args, **kwargs)

    monkeypatch.setattr(file_ops, "_observe_requested_roots", fail_after_launch)
    with pytest.raises(file_ops.FileTransactionError) as caught:
        file_ops.run_declared(
            ["test-provider"], [str(target)],
            expected_hashes=[store.file_sha256(str(target))], cwd=str(tmp_path),
            output_roots=[str(root)], execution_provider=Provider(),
        )
    transaction_id = caught.value.details["transaction_id"]
    store.undo_transaction(transaction_id)
    assert target.read_text(encoding="utf-8") == "before\n"


def test_post_state_capture_failure_keeps_prepared_recovery_record(tmp_path, monkeypatch):
    target = tmp_path / "output.txt"
    target.write_text("before\n", encoding="utf-8")

    class Provider:
        def run(self, request):
            target.write_text("after\n", encoding="utf-8")
            return execution.ExecutionResult(
                exit_code=0, stdout_tail="", stderr_tail="",
                capture_truncated=False, timed_out=False, duration_seconds=0.01,
                isolation_mode="observed", network_policy="inherit",
            )

    def fail_identity(_path):
        raise OSError("identity unavailable")

    monkeypatch.setattr(file_ops, "_post_execution_state", fail_identity)
    with pytest.raises(file_ops.FileTransactionError) as caught:
        file_ops.run_declared(
            ["test-provider"], [str(target)],
            expected_hashes=[store.file_sha256(str(target))], cwd=str(tmp_path),
            execution_provider=Provider(),
        )
    transaction_id = caught.value.details["transaction_id"]
    records = store.oplog_read()
    assert any(
        item.get("op") == "file-transaction-prepared"
        and item.get("transaction_id") == transaction_id for item in records
    )
    with pytest.raises(store.TransactionUndoError) as undo_error:
        store.undo_transaction(transaction_id)
    assert undo_error.value.details["state"] == "NEEDS_ATTENTION"
