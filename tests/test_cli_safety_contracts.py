import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

import file_ops
import publication
from core import store


PLUGIN = Path(__file__).resolve().parents[1] / "plugin"
AGW = PLUGIN / "scripts" / "agw" / "agw.py"


def _run(*args, check=True):
    result = subprocess.run(
        [sys.executable, str(AGW), *map(str, args)],
        capture_output=True, text=True, encoding="utf-8", env=dict(os.environ),
    )
    if check and result.returncode:
        raise AssertionError(result.stderr)
    return result


def test_schema_projects_narrow_apply_plan_contract():
    result = _run("--json", "schema", "file", "apply-plan")
    data = json.loads(result.stdout)
    assert data["schema"] == "agw-command-schema/v1"
    assert data["command"] == ["agw", "file", "apply-plan"]
    by_name = {item["name"]: item for item in data["arguments"]}
    assert "--plan-file" in by_name["plan_file_option"]["options"]
    assert by_name["expected_plan_hash"]["required"] is True


def test_schema_serializes_list_defaults_for_run():
    result = _run("--json", "schema", "run")
    data = json.loads(result.stdout)
    by_name = {item["name"]: item for item in data["arguments"]}
    assert by_name["output"]["default"] == []
    assert by_name["timeout_seconds"]["default"] == 300.0


def test_schema_projects_plan_create_and_apply_contracts():
    created = json.loads(_run("--json", "schema", "run-plan", "create").stdout)
    by_name = {item["name"]: item for item in created["arguments"]}
    assert created["schema"] == "agw-command-schema/v1"
    assert by_name["spec_file"]["required"] is True
    assert by_name["expected_plan_file_hash"]["default"] == "absent"

    applied = json.loads(_run("--json", "schema", "publish-plan", "apply").stdout)
    by_name = {item["name"]: item for item in applied["arguments"]}
    assert by_name["expected_plan_hash"]["required"] is True
    assert by_name["dry_run"]["default"] is False

    recovery = json.loads(_run(
        "--json", "schema", "publish-plan", "recover"
    ).stdout)
    by_name = {item["name"]: item for item in recovery["arguments"]}
    assert by_name["recovery_action"]["required"] is True
    assert by_name["recovery_action"]["choices"] == [
        "inspect", "rollback", "finalize-observed",
    ]


def test_json_argument_errors_have_a_stable_envelope():
    result = _run("--json", "file", "apply-plan", check=False)
    assert result.returncode == 2
    error = json.loads(result.stderr)["error"]
    assert error["code"] == "argument_error"
    assert "required" in error["message"]


def test_unknown_office_operation_keeps_json_error_envelope():
    result = _run("--json", "office", "not-an-operation", check=False)
    assert result.returncode == 2
    error = json.loads(result.stderr)["error"]
    assert error["code"] == "argument_error"
    assert error["details"]["command"] == "agw office"


def test_doctor_reports_typed_automatic_retention_state(monkeypatch):
    monkeypatch.setenv("AGW_ARCHIVE_MAX_BYTES", "1024")
    data = json.loads(_run("--json", "doctor").stdout)
    assert data["archive_automatic_prune"] is True
    assert data["archive_required_free_bytes"] >= 0
    assert data["retention"]["max_bytes"] == 1024
    assert data["retention"]["schema"] == "agw.retention-state/v1"


def test_apply_plan_accepts_named_plan_file(tmp_path):
    target = tmp_path / "target.txt"
    plan_path = tmp_path / "plan.json"
    created = file_ops.create_file_plan(
        {"operations": [{"op": "write", "path": str(target), "content": "safe\n"}]},
        str(plan_path), cwd=str(tmp_path),
    )
    result = _run(
        "--json", "file", "apply-plan", "--plan-file", plan_path,
        "--expected-plan-hash", created["plan_hash"],
    )
    data = json.loads(result.stdout)
    assert data["changed"] == 1
    assert target.read_text(encoding="utf-8") == "safe\n"
    assert data["operations"][0]["recovery"]["rollback_available"] is True


def test_publish_plan_create_and_apply_are_hash_bound_and_recoverable(tmp_path):
    staged = tmp_path / "staged.bin"
    target = tmp_path / "target.bin"
    operations = tmp_path / "operations.json"
    plan_file = tmp_path / "publish-plan.json"
    staged.write_bytes(b"new bytes")
    operations.write_text(json.dumps([{
        "staged": str(staged), "target": str(target),
        "expected_hash": "absent", "validation": "raw",
    }]), encoding="utf-8")

    created = json.loads(_run(
        "--json", "publish-plan", "create",
        "--operations-file", operations, "--plan-file", plan_file,
        "--expected-plan-file-hash", "absent",
    ).stdout)
    assert created["plan_file_recovery"]["rollback_available"] is True

    applied = json.loads(_run(
        "--json", "publish-plan", "apply", "--plan-file", plan_file,
        "--expected-plan-hash", created["plan_sha256"],
    ).stdout)
    assert applied["state"] == "COMMITTED"
    assert applied["atomicity"] == "recoverable-set"
    assert applied["visibility"] == "per-file-sequential"
    assert target.read_bytes() == b"new bytes"


def test_publish_plan_recovery_requires_explicit_safe_action(tmp_path):
    result = _run(
        "--json", "publish-plan", "recover", "prepared-id", check=False,
    )
    assert result.returncode == 2
    assert "--action" in result.stderr


def test_publish_plan_recovery_dispatches_inspect_and_explicit_actions(
        monkeypatch, capsys):
    import agw as agw_cli

    calls = []
    monkeypatch.setattr(
        agw_cli.publication, "inspect_prepared_transaction",
        lambda transaction_id: {
            "transaction_id": transaction_id, "state": "PREPARED",
            "classification": "mixed", "recoverable": True,
        },
    )
    monkeypatch.setattr(
        agw_cli.publication, "recover_prepared_transaction",
        lambda transaction_id, action: calls.append((transaction_id, action)) or {
            "transaction_id": transaction_id,
            "state": "ROLLED_BACK" if action == "rollback" else "COMMITTED",
        },
    )
    for action in ("inspect", "finalize-observed"):
        args = type("Args", (), {
            "plan_op": "recover", "transaction_id": "prepared-id",
            "recovery_action": action, "json": True,
        })()
        agw_cli.cmd_publish_plan(args)
        assert json.loads(capsys.readouterr().out)["transaction_id"] == "prepared-id"
    assert calls == [("prepared-id", "finalize-observed")]


@pytest.mark.parametrize(("action", "state", "expected"), [
    ("rollback", "ROLLED_BACK", "ROLLED_BACK; exact before-state restored"),
    ("finalize-observed", "COMMITTED", "COMMITTED; authenticated all-after"),
    ("rollback", "NEEDS_ATTENTION", "NEEDS_ATTENTION; manual review required"),
])
def test_publish_plan_recovery_human_success_states_are_truthful(
        monkeypatch, capsys, action, state, expected):
    import agw as agw_cli

    monkeypatch.setattr(
        agw_cli.publication, "recover_prepared_transaction",
        lambda *_args, **_kwargs: {"transaction_id": "prepared-id", "state": state},
    )
    args = type("Args", (), {
        "plan_op": "recover", "transaction_id": "prepared-id",
        "recovery_action": action, "json": False,
    })()
    agw_cli.cmd_publish_plan(args)
    output = capsys.readouterr().out
    assert expected in output
    assert "simultaneous" not in output
    assert "power-loss" not in output


@pytest.mark.parametrize(("exc", "expected"), [
    (file_ops.PreparedFinalizeNotAllAfter("not all after"),
     "remains PREPARED; finalize-observed refused"),
    (file_ops.PreparedFinalizeAfterRollbackStarted("rollback started"),
     "remains PREPARED; finalize-observed refused"),
    (file_ops.PreparedRecoveryBlocked("capture failed", {"recovery_state": "BLOCKED"}),
     "durably BLOCKED; manual attention"),
    (OSError("busy"), "did not complete; inspect before retrying"),
])
def test_publish_plan_recovery_human_failures_distinguish_next_state(
        monkeypatch, capsys, exc, expected):
    import agw as agw_cli

    def fail(*_args, **_kwargs):
        raise exc

    monkeypatch.setattr(agw_cli.publication, "recover_prepared_transaction", fail)
    args = type("Args", (), {
        "plan_op": "recover", "transaction_id": "prepared-id",
        "recovery_action": "finalize-observed", "json": False,
    })()
    with pytest.raises(SystemExit) as caught:
        agw_cli.cmd_publish_plan(args)
    assert caught.value.code == 1
    assert expected in capsys.readouterr().err


def test_publish_plan_non_recovery_os_error_keeps_generic_plan_error(
        monkeypatch, capsys):
    import agw as agw_cli

    monkeypatch.setattr(
        agw_cli, "_load_json_payload",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("read failed")),
    )
    args = type("Args", (), {
        "plan_op": "create", "operations_file": "ops.json", "json": False,
    })()
    with pytest.raises(SystemExit):
        agw_cli.cmd_publish_plan(args)
    error = capsys.readouterr().err
    assert "read failed" in error
    assert "inspect before retrying" not in error


def test_publish_plan_cli_rollback_restores_all_state(
        tmp_path, monkeypatch, capsys):
    import agw as agw_cli

    stages = [tmp_path / "stage-a.bin", tmp_path / "stage-b.bin"]
    targets = [tmp_path / "target-a.bin", tmp_path / "target-b.bin"]
    for index, (stage, target) in enumerate(zip(stages, targets)):
        stage.write_bytes(f"new-{index}".encode())
        target.write_bytes(f"old-{index}".encode())
    plan = publication.build_publish_plan([{
        "stage": str(stage), "target": str(target),
        "expected_hash": store.file_sha256(str(target)), "validation": "raw",
    } for stage, target in zip(stages, targets)])
    original_replace = file_ops.replace_with_retry
    calls = 0

    def interrupt_second(source, target, retry_seconds=5.0):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise KeyboardInterrupt()
        return original_replace(source, target, retry_seconds)

    monkeypatch.setattr(file_ops, "replace_with_retry", interrupt_second)
    with pytest.raises(KeyboardInterrupt):
        publication.publish_staged_batch(
            plan, expected_plan_hash=plan["plan_sha256"],
        )
    prepared = next(
        item for item in reversed(store.oplog_read())
        if item.get("op") == "file-transaction-prepared"
    )

    home = Path(store.agw_home())
    args = type("Args", (), {
        "plan_op": "recover", "transaction_id": prepared["transaction_id"],
        "recovery_action": "rollback", "json": True,
    })()
    agw_cli.cmd_publish_plan(args)
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "ROLLED_BACK"
    assert result["visibility"] == "per-file-sequential"
    assert [path.read_bytes() for path in targets] == [b"old-0", b"old-1"]
    assert (home / "publication-recovery" /
            f"{prepared['transaction_id']}.json").is_file()


def test_run_plan_immutable_execution_unavailable_is_structured_and_unclaimed(tmp_path):
    script = tmp_path / "reader.py"
    spec_file = tmp_path / "run-spec.json"
    plan_file = tmp_path / "run-plan.json"
    script.write_text("print('read only')\n", encoding="utf-8")
    spec_file.write_text(json.dumps({
        "command": [sys.executable, str(script)],
        "mode": "stdout-read-only", "cwd": str(tmp_path),
        "isolation": "read-only", "provider": "installed",
    }), encoding="utf-8")
    created = json.loads(_run(
        "--json", "run-plan", "create", "--spec-file", spec_file,
        "--plan-file", plan_file, "--expected-plan-file-hash", "absent",
    ).stdout)

    result = _run(
        "--json", "run-plan", "apply", "--plan-file", plan_file,
        "--expected-plan-hash", created["plan_sha256"], check=False,
    )
    assert result.returncode == 4
    data = json.loads(result.stdout)
    assert data["outcome"] == "environment_failure"
    assert data["error_code"] == "immutable_execution_unavailable"
    assert data["execution_started"] is False
    assert "claim_id" not in data


def test_workflow_match_omits_nested_raw_diagnostic_duplicates(monkeypatch, capsys):
    import agw as agw_cli

    private = "private-runtime-value"
    diagnostics = {
        "matches": ["example.private"], "candidate_count": 1,
        "recommended_argv": ["agw", "run", "--workflow", "example.private",
                             "--", "python", "script.py", private],
        "candidates": [{
            "id": "example.private", "candidate_class": "parameterizable",
            "inferred_parameters": [{"name": "mode", "value_sha256": "a" * 64}],
        }],
    }
    monkeypatch.setattr(
        agw_cli.workflows, "diagnose_matching_workflows",
        lambda command, cwd: diagnostics,
    )
    args = type("Args", (), {
        "workflow_op": "match", "command": ["--", "python", "script.py", private],
        "cwd": "", "json": True,
    })()
    agw_cli.cmd_workflow(args)
    data = json.loads(capsys.readouterr().out)
    assert data["recommended_argv"][-1] == private
    assert data["suggested_argv"] == {
        "deprecated": True,
        "replacement": "recommended_argv",
        "value_included": False,
    }
    assert "command" not in data
    assert "normalized" not in data
    assert "diagnostics" not in data
    assert json.dumps(data["candidates"]).count(private) == 0
    assert json.dumps(data).count(private) == 1


def test_plan_json_rejects_duplicate_keys(tmp_path):
    operations = tmp_path / "operations.json"
    operations.write_text('[{"staged":"a","staged":"b","target":"c"}]', encoding="utf-8")
    result = _run(
        "--json", "publish-plan", "create", "--operations-file", operations,
        "--plan-file", tmp_path / "plan.json", check=False,
    )
    assert result.returncode != 0
    assert "duplicate JSON key" in json.loads(result.stderr)["error"]["message"]


def test_transaction_undo_cli_restores_exact_file_mutation(tmp_path):
    target = tmp_path / "report.txt"
    target.write_text("before\n", encoding="utf-8")
    changed = file_ops.write_text(
        str(target), "after\n", expected_hash=store.file_sha256(str(target)),
        operation="test-write",
    )
    transaction = changed["recovery"]["transaction_id"]
    result = _run("--json", "undo", "--transaction", transaction)
    data = json.loads(result.stdout)
    assert data["undid_transaction_id"] == transaction
    assert target.read_text(encoding="utf-8") == "before\n"


def test_workflow_propose_is_inert_and_explicit(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    output = tmp_path / "result.txt"
    result = _run(
        "--json", "workflow", "propose", "--id", "example.writer",
        "--cwd", tmp_path, "--output", output, "--expected", "absent",
        "--allowed-root", tmp_path, "--", sys.executable, script,
    )
    proposal = json.loads(result.stdout)
    assert proposal["schema"] == "agw.workflow/v2"
    assert proposal["id"] == "example.writer"
    assert proposal["outputs"][0]["expected"] == "absent"
    assert not (tmp_path / ".agw-workflow-proposal.json").exists()


def test_checkout_close_and_reopen_preserve_working_copy(tmp_path):
    source = tmp_path / "source.txt"
    working = tmp_path / "working.txt"
    source.write_text("source\n", encoding="utf-8")
    working.write_text("draft\n", encoding="utf-8")
    state = store.state_load()
    state["checkouts"][str(source)] = {
        "working": str(working), "workings": [str(working)],
        "base_sha256": store.file_sha256(str(source)), "mode": "copy",
        "checkout_mode": "data", "workspace": str(tmp_path),
    }
    store.state_save(state)

    closed = json.loads(_run("--json", "checkout", "close", source).stdout)
    assert working.read_text(encoding="utf-8") == "draft\n"
    assert str(source) not in store.state_load()["checkouts"]

    _run("--json", "checkout", "reopen", closed["transaction_id"])
    assert store.state_load()["checkouts"][str(source)]["working"] == str(working)
    replay = _run(
        "--json", "checkout", "reopen", closed["transaction_id"], check=False,
    )
    assert replay.returncode != 0
    assert "already reopened" in json.loads(replay.stderr)["error"]["message"]
