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
    assert result.process_outcome == "succeeded"
    assert result.operation_outcome == result.outcome == "success"
    assert result.ok is True
    assert result.exit == 0
    serialized = result.to_dict()
    assert serialized["execution_started"] is True
    assert serialized["operation_outcome"] == serialized["outcome"] == "success"
    assert serialized["publication_outcome"] == "not_applicable"
    assert serialized["provider_identity"] == "observed-process-runner"
    assert serialized["script_execution_integrity"] == "none"
    assert serialized["filesystem_enforcement"] is False
    assert serialized["network_enforcement"] is False
    assert execution.DEFAULT_RUNNER.capabilities.filesystem_enforcement is False
    assert execution.DEFAULT_RUNNER.capabilities.network_enforcement is False
    assert execution.DEFAULT_RUNNER.capabilities.bounded_tail_capture is True
    assert execution.DEFAULT_RUNNER.capabilities.provider_identity == \
        "observed-process-runner"
    assert execution.DEFAULT_RUNNER.capabilities.script_execution_integrity == "none"


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
    assert caught.value.details["execution_started"] is False


def test_timeout_terminates_process(tmp_path):
    result = execution.run(execution.ExecutionRequest(
        command=[sys.executable, "-c", "import time; time.sleep(30)"],
        cwd=str(tmp_path), timeout_seconds=0.05,
    ))
    assert result.timed_out is True
    assert result.exit_code != 0
    assert result.process_outcome == "timed_out"
    assert result.operation_outcome == result.outcome == "process_failed"
    assert result.to_dict()["operation_outcome"] == "process_failed"


def test_start_failure_reports_provenance(tmp_path):
    with pytest.raises(execution.ExecutionError) as caught:
        execution.run(execution.ExecutionRequest(
            command=[str(tmp_path / "missing-command")], cwd=str(tmp_path),
        ))
    assert caught.value.details == {
        "execution_started": False, "fallback_performed": False,
    }


def test_custom_result_defaults_make_no_provider_or_enforcement_claims():
    result = execution.ExecutionResult(
        exit_code=0, stdout_tail="", stderr_tail="", capture_truncated=False,
        timed_out=False, duration_seconds=0, isolation_mode="observed",
        network_policy="inherit",
    )
    serialized = result.to_dict()
    assert serialized["provider_identity"] == ""
    assert serialized["script_execution_integrity"] == "none"
    assert serialized["filesystem_enforcement"] is False
    assert serialized["network_enforcement"] is False


def test_verified_immutable_provider_attestations_are_representable():
    capabilities = execution.ProviderCapabilities(
        isolation_modes=("strict",), network_policies=("deny",),
        filesystem_enforcement=True, network_enforcement=True,
        bounded_tail_capture=True, provider_identity="verified-provider",
        script_execution_integrity="verified-immutable",
    )
    assert capabilities.script_execution_integrity == "verified-immutable"

    result = execution.ExecutionResult(
        exit_code=0, stdout_tail="", stderr_tail="", capture_truncated=False,
        timed_out=False, duration_seconds=0, isolation_mode="strict",
        network_policy="deny", provider_identity=capabilities.provider_identity,
        script_execution_integrity=capabilities.script_execution_integrity,
        filesystem_enforcement=capabilities.filesystem_enforcement,
        network_enforcement=capabilities.network_enforcement,
    )
    serialized = result.to_dict()
    assert serialized["script_execution_integrity"] == "verified-immutable"
    assert serialized["provider_identity"] == "verified-provider"
    assert serialized["filesystem_enforcement"] is True
    assert serialized["network_enforcement"] is True


@pytest.mark.parametrize("constructor, kwargs", [
    (execution.ProviderCapabilities, {
        "isolation_modes": ("observed",), "network_policies": ("inherit",),
    }),
    (execution.ExecutionResult, {
        "exit_code": 0, "stdout_tail": "", "stderr_tail": "",
        "capture_truncated": False, "timed_out": False,
        "duration_seconds": 0, "isolation_mode": "observed",
        "network_policy": "inherit",
    }),
])
def test_unknown_integrity_attestations_are_rejected(constructor, kwargs):
    with pytest.raises(ValueError, match="unknown script execution integrity"):
        constructor(**kwargs, script_execution_integrity="best-effort")


def _result(**overrides):
    values = {
        "exit_code": 0, "stdout_tail": "", "stderr_tail": "",
        "capture_truncated": False, "timed_out": False,
        "duration_seconds": 0, "isolation_mode": "observed",
        "network_policy": "inherit", "process_outcome": "succeeded",
        "execution_started": True, "fallback_performed": False,
    }
    values.update(overrides)
    return execution.ExecutionResult(**values)


@pytest.mark.parametrize("overrides", [
    {"process_outcome": "succeeded", "execution_started": False},
    {"process_outcome": "succeeded", "timed_out": True},
    {"process_outcome": "succeeded", "exit_code": 4},
    {"process_outcome": "succeeded", "fallback_performed": True},
    {"process_outcome": "not_started", "execution_started": True,
     "exit_code": -1},
    {"process_outcome": "not_started", "execution_started": False,
     "exit_code": 0},
    {"process_outcome": "timed_out", "timed_out": False, "exit_code": -1},
    {"process_outcome": "timed_out", "timed_out": True, "exit_code": 0},
    {"process_outcome": "failed", "exit_code": 0},
    {"process_outcome": "failed", "exit_code": 2, "timed_out": True},
    {"process_outcome": "failed", "exit_code": 2,
     "execution_started": False},
])
def test_contradictory_process_results_are_rejected(overrides):
    with pytest.raises(ValueError):
        _result(**overrides)


@pytest.mark.parametrize("enforcement", [
    {"filesystem_enforcement": True},
    {"network_enforcement": True},
])
def test_fallback_cannot_attest_requested_enforcement(enforcement):
    with pytest.raises(ValueError, match="fallback.*enforcement"):
        _result(
            process_outcome="unknown", exit_code=-1,
            fallback_performed=True, **enforcement,
        )


def test_conservative_unknown_result_remains_representable():
    result = _result(
        process_outcome="unknown", exit_code=-1, execution_started=False,
    )
    assert result.process_outcome == "unknown"
    assert result.ok is False
    assert result.filesystem_enforcement is False
    assert result.network_enforcement is False


def test_capture_failure_reports_that_execution_started(tmp_path, monkeypatch):
    def fail_capture(_handle):
        raise OSError("capture unavailable")

    monkeypatch.setattr(execution, "_captured", fail_capture)
    with pytest.raises(execution.ExecutionError) as caught:
        execution.run(execution.ExecutionRequest(
            command=[sys.executable, "-c", "pass"], cwd=str(tmp_path),
        ))
    assert caught.value.details == {
        "execution_started": True, "fallback_performed": False,
    }


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
