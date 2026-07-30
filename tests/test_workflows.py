import hashlib
import json
import os
import subprocess
import sys

import pytest

import file_ops
from core import archive_transactions, engine, mutations, store, workflows
from core.events import ALLOW, ASK, EXEC, ToolEvent


PLUGIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugin")


def _write_manifest(tmp_path, script, *, workflow_id="example.writer", outputs=None,
                    roots=None, observed=None):
    manifest = {
        "schema": "agw.workflow/v1",
        "id": workflow_id,
        "description": "test writer",
        "command": {
            "runtime": "python",
            "script": script.name,
            "script_sha256": store.file_sha256(str(script)),
        },
        "allowed_roots": roots or ["{cwd}"],
        "outputs": outputs or [
            {"path": "{arg:0}", "expected": "absent"},
        ],
        "observed_roots": observed or [],
    }
    path = tmp_path / "workflow.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    digest = store.file_sha256(str(path))
    return path, digest, manifest


def _trust(path, digest, *, replace=False):
    return workflows.trust_manifest(str(path), digest, replace=replace)


def _run_resolved(workflow_id, command, cwd, *, dry_run=False):
    declaration = workflows.resolve_run(workflow_id, command, str(cwd))
    result = file_ops.run_declared(
        command,
        declaration["outputs"],
        expected_hashes=declaration["expected_hashes"],
        cwd=declaration["cwd"],
        output_roots=declaration["output_roots"],
        output_patterns=declaration["output_patterns"],
        allow_missing_output_parents=True,
        dry_run=dry_run,
    )
    result["workflow"] = declaration["workflow"]
    return result


def test_arbitrary_opaque_python_script_remains_blocked(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text(
        "from pathlib import Path\nPath('out.txt').write_text('x')\n",
        encoding="utf-8",
    )
    event = ToolEvent(
        kind=EXEC, tool="Bash", command=f'python "{script}"', cwd=str(tmp_path),
    )
    plan = mutations.plan([event], engine.clobber_targets)
    assert plan.mutating is True
    assert plan.complete is False
    assert "no pre-execution output contract" in plan.reason
    assert "agw workflow trust --help" in plan.reason


@pytest.mark.parametrize(
    ("launcher", "name", "source"),
    [
        ("node", "writer.js", "require('fs').writeFileSync('out.txt', 'x')\n"),
        ("powershell -File", "writer.ps1", "Set-Content -LiteralPath out.txt -Value x\n"),
        ("bash", "writer.sh", "#!/bin/sh\ntouch out.txt\n"),
    ],
)
def test_other_opaque_write_capable_scripts_remain_blocked(
        tmp_path, launcher, name, source):
    script = tmp_path / name
    script.write_text(source, encoding="utf-8")
    event = ToolEvent(
        kind=EXEC, tool="PowerShell" if "powershell" in launcher else "Bash",
        command=f'{launcher} "{script}"', cwd=str(tmp_path),
    )
    plan = mutations.plan([event], engine.clobber_targets)
    assert plan.mutating is True
    assert plan.complete is False
    assert "pre-execution output contract" in plan.reason


def test_trusted_matching_script_executes_and_existing_output_has_preimage(tmp_path):
    output = tmp_path / "out.txt"
    output.write_text("before", encoding="utf-8")
    script = tmp_path / "writer.py"
    script.write_text(
        "from pathlib import Path\nimport sys\nPath(sys.argv[1]).write_text('after')\n",
        encoding="utf-8",
    )
    manifest_path, digest, _ = _write_manifest(
        tmp_path, script,
        outputs=[{"path": "{arg:0}", "expected": "present"}],
    )
    _trust(manifest_path, digest)
    command = [sys.executable, str(script), str(output)]
    result = _run_resolved("example.writer", command, tmp_path)
    assert result["ok"] is True
    assert result["workflow"] == "example.writer"
    assert output.read_text(encoding="utf-8") == "after"
    tracked = result["outputs"][0]
    assert tracked["snapshot_state"] == "PRESENT"
    assert tracked["snapshot_transaction_id"]
    versions = store.list_versions(str(output))
    assert versions and open(versions[-1]["dest"], encoding="utf-8").read() == "before"


def test_absent_nested_output_gets_preexecution_tombstone(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text(
        "from pathlib import Path\n"
        "target = Path('state') / 'marker.txt'\n"
        "target.parent.mkdir(parents=True, exist_ok=True)\n"
        "target.write_text('created')\n",
        encoding="utf-8",
    )
    manifest_path, digest, _ = _write_manifest(
        tmp_path, script,
        roots=["{cwd}/state"],
        outputs=[{"path": "{cwd}/state/marker.txt", "expected": "absent"}],
    )
    _trust(manifest_path, digest)
    result = _run_resolved("example.writer", [sys.executable, str(script)], tmp_path)
    tracked = result["outputs"][0]
    assert result["ok"] is True
    assert tracked["snapshot_state"] == "ABSENT"
    record = archive_transactions.load(
        store.agw_home(), tracked["snapshot_transaction_id"]
    )
    assert record["kind"] == "absent_tombstone"
    assert (tmp_path / "state" / "marker.txt").is_file()


def test_changed_script_hash_blocks_execution(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('original')\n", encoding="utf-8")
    manifest_path, digest, _ = _write_manifest(tmp_path, script)
    _trust(manifest_path, digest)
    script.write_text(
        "from pathlib import Path\nPath('out.txt').write_text('tampered')\n",
        encoding="utf-8",
    )
    with pytest.raises(workflows.WorkflowTrustError, match="trusted script changed"):
        workflows.resolve_run(
            "example.writer", [sys.executable, str(script), "out.txt"], str(tmp_path)
        )
    assert not (tmp_path / "out.txt").exists()


def test_untrusted_repository_manifest_is_inert(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('x')\n", encoding="utf-8")
    _write_manifest(tmp_path, script)
    with pytest.raises(workflows.WorkflowTrustError, match="is not trusted"):
        workflows.resolve_run(
            "example.writer", [sys.executable, str(script), "out.txt"], str(tmp_path)
        )


def test_trusted_record_tampering_is_rejected(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('x')\n", encoding="utf-8")
    manifest_path, digest, _ = _write_manifest(tmp_path, script)
    _trust(manifest_path, digest)
    record_path = next((tmp_path / "agw-home" / "trusted-workflows").glob("*.json"))
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["manifest"]["description"] = "tampered"
    record_path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(workflows.WorkflowTrustError, match="tampered"):
        workflows.load_trusted("example.writer")


def test_manifest_hash_precondition_is_required_and_checked(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('x')\n", encoding="utf-8")
    manifest_path, _, _ = _write_manifest(tmp_path, script)
    with pytest.raises(workflows.WorkflowConflict, match="manifest hash"):
        workflows.trust_manifest(str(manifest_path), "0" * 64)


def test_output_path_traversal_and_outside_root_are_rejected(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('x')\n", encoding="utf-8")
    manifest_path, digest, _ = _write_manifest(
        tmp_path, script,
        roots=["{cwd}/safe"],
        outputs=[{"path": "{cwd}/safe/{arg:0}", "expected": "absent"}],
    )
    _trust(manifest_path, digest)
    with pytest.raises(workflows.WorkflowTrustError, match="outside"):
        workflows.resolve_run(
            "example.writer", [sys.executable, str(script), "../../escape.txt"],
            str(tmp_path),
        )


def test_output_may_not_replace_the_permitted_root_itself(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('x')\n", encoding="utf-8")
    manifest_path, digest, _ = _write_manifest(
        tmp_path, script,
        roots=["{cwd}/safe"],
        outputs=[{"path": "{cwd}/safe", "expected": "absent"}],
    )
    _trust(manifest_path, digest)
    with pytest.raises(workflows.WorkflowTrustError, match="outside"):
        workflows.resolve_run(
            "example.writer", [sys.executable, str(script)], str(tmp_path)
        )


@pytest.mark.parametrize("template", ["{unknown}/out.txt", "{arg}/out.txt", "{{cwd}}/x"])
def test_unresolved_or_ambiguous_placeholders_are_rejected(tmp_path, template):
    script = tmp_path / "writer.py"
    script.write_text("print('x')\n", encoding="utf-8")
    manifest_path, _, manifest = _write_manifest(tmp_path, script)
    manifest["outputs"] = [{"path": template, "expected": "absent"}]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest = store.file_sha256(str(manifest_path))
    with pytest.raises(workflows.WorkflowError, match="placeholder"):
        _trust(manifest_path, digest)


def test_missing_argument_and_duplicate_resolved_outputs_are_rejected(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('x')\n", encoding="utf-8")
    manifest_path, digest, _ = _write_manifest(
        tmp_path, script,
        outputs=[
            {"path": "{cwd}/{arg:1}", "expected": "absent"},
            {"path": "{cwd}/{arg:0}", "expected": "absent"},
        ],
    )
    _trust(manifest_path, digest)
    with pytest.raises(workflows.WorkflowError, match="missing command argument 1"):
        workflows.resolve_run(
            "example.writer", [sys.executable, str(script), "same.txt"], str(tmp_path)
        )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["outputs"][0]["path"] = "{cwd}/{arg:0}"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    _trust(manifest_path, store.file_sha256(str(manifest_path)), replace=True)
    with pytest.raises(workflows.WorkflowError, match="duplicates"):
        workflows.resolve_run(
            "example.writer", [sys.executable, str(script), "same.txt"], str(tmp_path)
        )


def test_windows_py_version_selector_normalizes_to_python(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('x')\n", encoding="utf-8")
    normalized = workflows.normalize_command(
        ["py.exe", "-3.12", str(script), "value"], str(tmp_path)
    )
    assert normalized["runtime"] == "python"
    assert normalized["script"] == os.path.realpath(script)
    assert normalized["args"] == ["value"]


def test_node_and_powershell_file_launchers_normalize_without_execution(tmp_path):
    node_script = tmp_path / "writer.js"
    ps_script = tmp_path / "writer.ps1"
    node_script.write_text("console.log('x')\n", encoding="utf-8")
    ps_script.write_text("Write-Output x\n", encoding="utf-8")
    node = workflows.normalize_command(["node", str(node_script), "a"], str(tmp_path))
    powershell = workflows.normalize_command(
        ["pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
         str(ps_script), "b"],
        str(tmp_path),
    )
    assert node["runtime"] == "node" and node["args"] == ["a"]
    assert powershell["runtime"] == "powershell" and powershell["args"] == ["b"]


def test_existing_explicit_run_contract_remains_compatible(tmp_path):
    script = tmp_path / "writer.py"
    output = tmp_path / "out.txt"
    script.write_text(
        "from pathlib import Path\nPath('out.txt').write_text('ok')\n",
        encoding="utf-8",
    )
    result = file_ops.run_declared(
        [sys.executable, str(script)], [str(output)],
        expected_hashes=["absent"], cwd=str(tmp_path),
    )
    assert result["ok"] is True
    assert result["output_observation"]["mode"] == "exact_outputs"


def test_unclaimed_change_in_observed_root_fails_workflow(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text(
        "from pathlib import Path\n"
        "Path('declared.txt').write_text('ok')\n"
        "Path('surprise.txt').write_text('unexpected')\n",
        encoding="utf-8",
    )
    manifest_path, digest, _ = _write_manifest(
        tmp_path, script,
        outputs=[{"path": "{cwd}/declared.txt", "expected": "absent"}],
        observed=[{"path": "{cwd}", "patterns": []}],
    )
    _trust(manifest_path, digest)
    result = _run_resolved("example.writer", [sys.executable, str(script)], tmp_path)
    assert result["ok"] is False
    assert any(item["path"].endswith("surprise.txt")
               for item in result["unclaimed_observed_changes"])


def test_direct_script_with_trusted_contract_is_still_blocked_with_wrapper_hint(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text(
        "from pathlib import Path\nPath('out.txt').write_text('x')\n",
        encoding="utf-8",
    )
    manifest_path, digest, _ = _write_manifest(tmp_path, script)
    _trust(manifest_path, digest)
    event = ToolEvent(
        kind=EXEC, tool="PowerShell",
        command=f'py -3.12 "{script}" out.txt', cwd=str(tmp_path),
    )
    plan = mutations.plan([event], engine.clobber_targets)
    assert plan.complete is False
    assert "agw run --workflow example.writer" in plan.reason


def test_engine_requires_confirmation_to_install_trust_but_allows_inspection(policy):
    launcher = os.path.join(PLUGIN, "bin", "agw.cmd" if os.name == "nt" else "agw")
    trust = engine.evaluate(
        ToolEvent(kind=EXEC, tool="Bash",
                  command=f'"{launcher}" workflow trust contract.json --approve-trust',
                  cwd=os.getcwd()),
        policy, PLUGIN,
    )
    listing = engine.evaluate(
        ToolEvent(kind=EXEC, tool="Bash", command=f'"{launcher}" workflow list',
                  cwd=os.getcwd()),
        policy, PLUGIN,
    )
    assert trust.action == ASK
    assert trust.rule_id == "builtin:agw-workflow-trust"
    assert listing.action == ALLOW


def test_manifest_placeholders_are_data_not_code(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('x')\n", encoding="utf-8")
    manifest_path, digest, _ = _write_manifest(
        tmp_path, script,
        outputs=[{"path": "{cwd}/{arg:0:sha256}.txt", "expected": "absent"}],
    )
    _trust(manifest_path, digest)
    payload = "$(touch should-not-exist)"
    result = workflows.resolve_run(
        "example.writer", [sys.executable, str(script), payload], str(tmp_path)
    )
    expected = hashlib.sha256(payload.encode("utf-8")).hexdigest() + ".txt"
    assert result["outputs"] == [str(tmp_path / expected)]
    assert not (tmp_path / "should-not-exist").exists()


def test_real_cli_trust_and_run_workflow_end_to_end(tmp_path):
    script = tmp_path / "cli_writer.py"
    output = tmp_path / "cli-output.txt"
    script.write_text(
        "from pathlib import Path\nimport sys\nPath(sys.argv[1]).write_text('cli-ok')\n",
        encoding="utf-8",
    )
    manifest_path, digest, _ = _write_manifest(
        tmp_path, script, workflow_id="example.cli",
    )
    cli = os.path.join(PLUGIN, "scripts", "agw", "agw.py")
    env = dict(os.environ, AGW_HOME=str(tmp_path / "cli-agw-home"))
    trusted = subprocess.run(
        [sys.executable, cli, "workflow", "trust", str(manifest_path),
         "--expected-manifest-hash", digest, "--approve-trust", "--json"],
        cwd=str(tmp_path), env=env, text=True, capture_output=True, timeout=30,
    )
    assert trusted.returncode == 0, trusted.stderr
    trust_data = json.loads(trusted.stdout)
    assert trust_data["workflow"] == "example.cli"
    executed = subprocess.run(
        [sys.executable, cli, "run", "--workflow", "example.cli", "--json",
         "--", sys.executable, str(script), str(output)],
        cwd=str(tmp_path), env=env, text=True, capture_output=True, timeout=30,
    )
    assert executed.returncode == 0, executed.stderr
    run_data = json.loads(executed.stdout)
    assert run_data["ok"] is True
    assert run_data["workflow"] == "example.cli"
    assert run_data["outputs"][0]["snapshot_state"] == "ABSENT"
    assert output.read_text(encoding="utf-8") == "cli-ok"
