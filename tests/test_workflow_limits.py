"""Reviewed run time limits for trusted workflows (`limits.timeout_seconds`).

An unreviewed `agw run` keeps its fixed 300-second bound. A trusted workflow may
declare a longer limit, capped at four hours, inside its hashed manifest, so a
longer limit always traces back to an explicit `agw workflow trust` decision.
"""
import json
import os
import sys

import pytest

import agw
import execution
from core import store, workflows


SLEEPER = (
    "import sys, time\n"
    "time.sleep(float(sys.argv[2]))\n"
    "open(sys.argv[1], 'w').write('done')\n"
)


def _manifest(tmp_path, *, limits=None, schema="agw.workflow/v3", name="workflow.json"):
    script = tmp_path / "sleeper.py"
    if not script.exists():
        script.write_text(SLEEPER, encoding="utf-8")
    manifest = {
        "schema": schema,
        "id": "example.sleeper",
        "description": "sleep, then write one declared output",
        "command": {
            "runtime": "python",
            "script": script.name,
            "script_sha256": store.file_sha256(str(script)),
            "args": [{"parameter": "output"}, {"parameter": "seconds"}],
        },
        "parameters": {
            "output": {"type": "path", "root": "{cwd}", "must_exist": False,
                       "kind": "file"},
            "seconds": {"type": "regex", "pattern": "[0-9]+[.]?[0-9]*"},
        },
        "allowed_roots": ["{cwd}"],
        "outputs": [{"path": "{param:output}", "expected": "any"}],
        "observed_roots": [],
    }
    if schema == "agw.workflow/v2":
        manifest["command"]["args"] = ["out.txt", "0"]
        manifest.pop("parameters")
        manifest["outputs"] = [{"path": "{cwd}/out.txt", "expected": "any"}]
    if limits is not None:
        manifest["limits"] = limits
    path = tmp_path / name
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path, store.file_sha256(str(path)), script


def _trust(path, digest, replace=False):
    return workflows.trust_manifest(str(path), digest, replace=replace)


# --- manifest validation -------------------------------------------------------

@pytest.mark.parametrize("schema", ["agw.workflow/v2", "agw.workflow/v3"])
def test_limits_validate_and_normalize(tmp_path, schema):
    path, digest, _ = _manifest(tmp_path, limits={"timeout_seconds": 7200}, schema=schema)
    validated = workflows.validate_manifest_file(str(path), digest)
    assert validated["timeout_seconds"] == 7200
    assert validated["manifest"]["limits"] == {"timeout_seconds": 7200}


def test_absent_limits_stay_absent_so_old_records_are_unchanged(tmp_path):
    path, digest, _ = _manifest(tmp_path)
    validated = workflows.validate_manifest_file(str(path), digest)
    assert "limits" not in validated["manifest"]
    assert validated["timeout_seconds"] is None
    _trust(path, digest)
    assert workflows.manifest_status(str(path))["status"] == "trusted_exact"


@pytest.mark.parametrize("limits", [
    {"timeout_seconds": 0},
    {"timeout_seconds": -5},
    {"timeout_seconds": workflows.MAX_WORKFLOW_TIMEOUT_SECONDS + 1},
    {"timeout_seconds": 600.5},
    {"timeout_seconds": True},
    {"timeout_seconds": "600"},
    {"timeout_seconds": 600, "memory_mb": 10},
    {},
    [],
])
def test_out_of_policy_limits_are_rejected(tmp_path, limits):
    path, digest, _ = _manifest(tmp_path, limits=limits)
    with pytest.raises(workflows.WorkflowError):
        workflows.validate_manifest_file(str(path), digest)


def test_four_hour_ceiling_is_accepted(tmp_path):
    path, digest, _ = _manifest(
        tmp_path, limits={"timeout_seconds": workflows.MAX_WORKFLOW_TIMEOUT_SECONDS})
    assert workflows.validate_manifest_file(str(path), digest)["timeout_seconds"] == 14400


def test_v1_manifests_cannot_declare_limits(tmp_path):
    script = tmp_path / "sleeper.py"
    script.write_text(SLEEPER, encoding="utf-8")
    manifest = {
        "schema": "agw.workflow/v1", "id": "example.v1", "description": "",
        "command": {"runtime": "python", "script": script.name,
                    "script_sha256": store.file_sha256(str(script))},
        "allowed_roots": ["{cwd}"],
        "outputs": [{"path": "{arg:0}", "expected": "any"}],
        "observed_roots": [], "limits": {"timeout_seconds": 600},
    }
    path = tmp_path / "v1.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(workflows.WorkflowError, match="unknown|unexpected|limits"):
        workflows.validate_manifest_file(str(path))


# --- trust and re-trust ------------------------------------------------------

def test_raising_the_limit_changes_the_manifest_hash_and_needs_new_trust(tmp_path):
    path, digest, _ = _manifest(tmp_path, limits={"timeout_seconds": 600})
    trusted = _trust(path, digest)
    assert trusted["timeout_seconds"] == 600
    assert workflows.resolve_run(
        "example.sleeper", [], str(tmp_path),
        parameters={"output": "out.txt", "seconds": "0"},
    )["timeout_seconds"] == 600

    raised, raised_digest, _ = _manifest(tmp_path, limits={"timeout_seconds": 3600})
    assert raised == path and raised_digest != digest
    # The old trust still governs, and nothing silently adopts the new limit.
    assert workflows.manifest_status(str(path))["status"] == "trusted_record_differs"
    assert workflows.resolve_run(
        "example.sleeper", [], str(tmp_path),
        parameters={"output": "out.txt", "seconds": "0"},
    )["timeout_seconds"] == 600
    with pytest.raises(workflows.WorkflowConflict, match="--replace"):
        _trust(path, raised_digest)
    # An explicit, approved replacement is the only way in.
    _trust(path, raised_digest, replace=True)
    assert workflows.manifest_status(str(path))["status"] == "trusted_exact"
    assert workflows.resolve_run(
        "example.sleeper", [], str(tmp_path),
        parameters={"output": "out.txt", "seconds": "0"},
    )["timeout_seconds"] == 3600


def test_tampering_with_a_stored_limit_breaks_the_seal(tmp_path):
    path, digest, _ = _manifest(tmp_path, limits={"timeout_seconds": 600})
    _trust(path, digest)
    record_path = workflows._record_path("example.sleeper")
    record = json.loads(open(record_path, encoding="utf-8").read())
    record["manifest"]["limits"]["timeout_seconds"] = 14400
    with open(record_path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(record))
    with pytest.raises(workflows.WorkflowTrustError, match="tampered"):
        workflows.load_trusted("example.sleeper")


def test_refresh_cannot_change_a_limit(tmp_path):
    path, digest, _ = _manifest(tmp_path, limits={"timeout_seconds": 600})
    _trust(path, digest)
    record = workflows.load_trusted("example.sleeper")
    before = workflows._contract_sha256(record["manifest"])
    changed = dict(record["manifest"], limits={"timeout_seconds": 900})
    assert workflows._contract_sha256(changed) != before


# --- the run-time bound ------------------------------------------------------

def test_default_bound_is_untouched():
    assert execution.DEFAULT_TIMEOUT_SECONDS == 300.0
    assert agw._run_timeout(None, None) == (300.0, "default")
    assert agw._run_timeout(None, {"timeout_seconds": None}) == (300.0, "default")


def test_explicit_timeout_may_only_shorten_an_unreviewed_run():
    assert agw._run_timeout(120, None) == (120.0, "explicit")
    assert agw._run_timeout(300, None) == (300.0, "explicit")
    for value in (300.5, 3600, 86400):
        with pytest.raises(workflows.WorkflowError, match="unreviewed run"):
            agw._run_timeout(value, None)
    for value in (0, -1, float("nan"), float("inf")):
        with pytest.raises(workflows.WorkflowError):
            agw._run_timeout(value, None)


def test_workflow_limit_is_honoured_and_caps_explicit_values():
    workflow = {"timeout_seconds": 7200}
    assert agw._run_timeout(None, workflow) == (7200.0, "workflow")
    assert agw._run_timeout(900, workflow) == (900.0, "explicit")
    with pytest.raises(workflows.WorkflowError, match="reviewed limit"):
        agw._run_timeout(7201, workflow)


def _cli(capsys, *args):
    try:
        agw.main(["--json", *args])
        code = 0
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    text = captured.out.strip() or captured.err.strip()
    return code, json.loads(text.splitlines()[-1]) if text else {}


def test_cli_rejects_an_unreviewed_long_timeout_before_running(tmp_path, capsys):
    target = tmp_path / "never.txt"
    code, data = _cli(
        capsys, "run", "--output", str(target), "--expected-hash", "absent",
        "--timeout-seconds", "3600", "--cwd", str(tmp_path),
        "--", sys.executable, "-c", "open('never.txt','w').write('x')",
    )
    assert code != 0
    assert "unreviewed run" in json.dumps(data)
    assert not target.exists()


def test_workflow_outlives_the_shortened_default_that_kills_the_same_command(
        tmp_path, capsys, monkeypatch):
    """Fast model of the long-run smoke: default 1 s, reviewed limit 6 s."""
    monkeypatch.setattr(execution, "DEFAULT_TIMEOUT_SECONDS", 1.0)
    path, digest, script = _manifest(tmp_path, limits={"timeout_seconds": 6})
    _trust(path, digest)

    untrusted_out = tmp_path / "untrusted.txt"
    code, data = _cli(
        capsys, "run", "--output", str(untrusted_out), "--expected-hash", "absent",
        "--cwd", str(tmp_path), "--",
        sys.executable, str(script), str(untrusted_out), "2.5",
    )
    assert code != 0
    assert data["timed_out"] is True
    assert data["execution_policy"]["timeout_seconds"] == 1.0
    assert data["execution_policy"]["timeout_source"] == "default"
    assert not untrusted_out.exists()

    trusted_out = tmp_path / "trusted.txt"
    code, data = _cli(
        capsys, "run", "--workflow", "example.sleeper",
        "--param", f"output={trusted_out}", "--param", "seconds=2.5",
        "--cwd", str(tmp_path),
    )
    assert code == 0, data
    assert data["ok"] is True and data["timed_out"] is False
    assert data["execution_policy"]["timeout_seconds"] == 6.0
    assert data["execution_policy"]["timeout_source"] == "workflow"
    assert data["duration_seconds"] >= 2.5
    assert trusted_out.read_text() == "done"
    # The declared output still has its recovery receipt.
    assert data["outputs"][0]["snapshot_transaction_id"]


def test_workflow_without_limits_keeps_the_default(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(execution, "DEFAULT_TIMEOUT_SECONDS", 1.0)
    path, digest, script = _manifest(tmp_path)
    _trust(path, digest)
    out = tmp_path / "out.txt"
    code, data = _cli(
        capsys, "run", "--workflow", "example.sleeper",
        "--param", f"output={out}", "--param", "seconds=2.5", "--cwd", str(tmp_path),
    )
    assert code != 0
    assert data["timed_out"] is True
    assert data["execution_policy"]["timeout_source"] == "default"


def test_workflow_info_and_list_report_the_limit(tmp_path, capsys):
    path, digest, _ = _manifest(tmp_path, limits={"timeout_seconds": 7200})
    _trust(path, digest)
    code, data = _cli(capsys, "workflow", "info", "example.sleeper")
    assert code == 0
    assert data["limits"] == {"timeout_seconds": 7200}
    assert data["timeout_seconds"] == 7200
    listed = {item["id"]: item for item in workflows.list_trusted()}
    assert listed["example.sleeper"]["timeout_seconds"] == 7200


def test_propose_and_init_can_declare_a_limit(tmp_path):
    script = tmp_path / "sleeper.py"
    script.write_text(SLEEPER, encoding="utf-8")
    proposal = workflows.build_workflow_proposal(
        [sys.executable, str(script), "out.txt", "1"], str(tmp_path),
        workflow_id="example.proposed", outputs=["{cwd}/out.txt"],
        allowed_roots=["{cwd}"], expected_states=["any"], timeout_seconds=1800,
    )
    assert proposal["limits"] == {"timeout_seconds": 1800}
    built = workflows.initialize_manifest(
        str(script), str(tmp_path / "m.json"), workflow_id="example.init",
        args=["out.txt", "1"], outputs=["{cwd}/out.txt"], allowed_roots=["{cwd}"],
        timeout_seconds=900,
    )
    assert built["normalized"]["limits"] == {"timeout_seconds": 900}
    with pytest.raises(workflows.WorkflowError):
        workflows.initialize_manifest(
            str(script), str(tmp_path / "m2.json"), workflow_id="example.init2",
            args=[], outputs=["{cwd}/out.txt"], allowed_roots=["{cwd}"],
            timeout_seconds=workflows.MAX_WORKFLOW_TIMEOUT_SECONDS + 1,
        )
