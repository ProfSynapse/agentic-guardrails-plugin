import json
import os
from pathlib import Path
import subprocess
import sys

import file_ops
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
