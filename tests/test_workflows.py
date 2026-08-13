import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile

import pytest

import file_ops
from core import archive_transactions, engine, mutations, store, workflows
from core.events import ALLOW, ASK, EXEC, ToolEvent


PLUGIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugin")
AGW_SOURCE = os.path.join(PLUGIN, "scripts", "agw", "agw.py")


def _write_manifest(tmp_path, script, *, workflow_id="example.writer", outputs=None,
                    roots=None, observed=None, schema="agw.workflow/v1", args=None,
                    parameters=None):
    manifest = {
        "schema": schema,
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
    if schema in {"agw.workflow/v2", "agw.workflow/v3"}:
        manifest["command"]["args"] = list(args or [])
    if schema == "agw.workflow/v3":
        manifest["parameters"] = dict(parameters or {})
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
        ("python3.12", "writer.py", "open('out.txt', 'w').write('x')\n"),
        ("ruby3.2", "writer.rb", "File.write('out.txt', 'x')\n"),
        ("php8.3", "writer.php", "<?php file_put_contents('out.txt', 'x'); ?>\n"),
        ("pwsh7 -File", "writer.ps1", "Set-Content -LiteralPath out.txt -Value x\n"),
        ("bash5", "writer.sh", "#!/bin/sh\ntouch out.txt\n"),
        ("dash", "writer.sh", "#!/bin/sh\ntouch out.txt\n"),
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


def test_versioned_ruby_read_only_script_is_not_misclassified(tmp_path):
    script = tmp_path / "reader.rb"
    script.write_text("File.open('input.txt', 'r') { |file| file.read }\n", encoding="utf-8")
    event = ToolEvent(
        kind=EXEC, tool="PowerShell", command=f'ruby3.2 "{script}"', cwd=str(tmp_path)
    )
    plan = mutations.plan([event], engine.clobber_targets, plugin_root=PLUGIN)
    assert plan.mutating is False
    assert plan.complete is True


def test_python_comments_docstrings_and_strings_do_not_trigger_output_gate(tmp_path):
    script = tmp_path / "reader.py"
    script.write_text(
        '"""Example only: Path("out.txt").write_text("x")"""\n'
        "# open('out.txt', 'w').write('x')\n"
        "print('.save( is documentation, not a call')\n",
        encoding="utf-8",
    )
    event = ToolEvent(
        kind=EXEC, tool="PowerShell",
        command=f'python "{script}"', cwd=str(tmp_path),
    )
    plan = mutations.plan([event], engine.clobber_targets)
    assert plan.complete is True
    assert plan.mutating is False
    assert plan.evidence == {}


@pytest.mark.parametrize("launcher,name,source", [
    ("node", "reader.js",
     "// writeFileSync('out.txt', 'x')\n"
     "/* writeFileSync('out.txt', 'x') */\n"
     "console.log(\"writeFileSync('out.txt', 'x')\")\n"),
    ("ruby", "reader.rb",
     "# File.write('out.txt', 'x')\n"
     "=begin\nFile.write('out.txt', 'x')\n=end\n"
     "puts \"File.write('out.txt', 'x')\"\n"),
    ("php", "reader.php",
     "<?php // file_put_contents('out.txt', 'x')\n"
     "/* file_put_contents('out.txt', 'x') */\n"
     "echo \"file_put_contents('out.txt', 'x')\"; ?>\n"),
    ("powershell -File", "reader.ps1",
     "# Set-Content -LiteralPath out.txt -Value x\n"
     "<# Set-Content -LiteralPath out.txt -Value x #>\n"
     "Write-Output \"Set-Content -LiteralPath out.txt -Value x\"\n"),
    ("bash", "reader.sh",
     "# touch out.txt\n"
     "cat <<'EOF'\ntouch heredoc-is-data.txt\nEOF\n"
     "cat <<'EOF'\n$(touch literal-substitution.txt)\nEOF\n"
     "cat <<EOF\ntouch expanded-heredoc-is-still-data.txt\nEOF\n"
     "printf '%s\\n' '; touch out.txt'\n"),
])
def test_non_python_comments_and_strings_do_not_trigger_output_gate(
        tmp_path, launcher, name, source):
    script = tmp_path / name
    script.write_text(source, encoding="utf-8")
    event = ToolEvent(
        kind=EXEC, tool="PowerShell" if name.endswith(".ps1") else "Bash",
        command=f'{launcher} "{script}"', cwd=str(tmp_path),
    )
    plan = mutations.plan([event], engine.clobber_targets)
    assert plan.complete is True
    assert plan.mutating is False
    assert plan.evidence == {}


@pytest.mark.parametrize("launcher,name,source", [
    ("node", "dynamic.js", "eval(\"writeFileSync('out.txt', 'x')\")\n"),
    ("ruby", "dynamic.rb", "eval \"File.write('out.txt', 'x')\"\n"),
    ("php", "dynamic.php", "<?php eval(\"file_put_contents('out.txt', 'x')\"); ?>\n"),
    ("powershell -File", "dynamic.ps1",
     "Invoke-Expression \"Set-Content -LiteralPath out.txt -Value x\"\n"),
    ("bash", "dynamic.sh", "eval '; touch out.txt'\n"),
])
def test_non_python_dynamic_evaluation_keeps_write_evidence(
        tmp_path, launcher, name, source):
    script = tmp_path / name
    script.write_text(source, encoding="utf-8")
    plan = mutations.plan([
        ToolEvent(
            kind=EXEC, tool="PowerShell" if name.endswith(".ps1") else "Bash",
            command=f'{launcher} "{script}"', cwd=str(tmp_path),
        )
    ], engine.clobber_targets)
    assert plan.complete is False
    assert plan.review_required is False
    assert plan.evidence["confidence"] == "high"


@pytest.mark.parametrize("launcher,name,source", [
    ("node", "interpolated.js",
     "console.log(`${writeFileSync('out.txt', 'x')}`)\n"),
    ("ruby", "interpolated.rb", "puts \"#{File.write('out.txt', 'x')}\"\n"),
    ("powershell -File", "interpolated.ps1",
     "Write-Output \"$(Set-Content -LiteralPath out.txt -Value x)\"\n"),
    ("bash", "interpolated.sh", "printf '%s\\n' \"$(touch out.txt)\"\n"),
])
def test_interpolated_expressions_keep_write_evidence(
        tmp_path, launcher, name, source):
    script = tmp_path / name
    script.write_text(source, encoding="utf-8")
    plan = mutations.plan([
        ToolEvent(
            kind=EXEC, tool="PowerShell" if name.endswith(".ps1") else "Bash",
            command=f'{launcher} "{script}"', cwd=str(tmp_path),
        )
    ], engine.clobber_targets)
    assert plan.complete is False
    assert plan.review_required is False
    assert plan.evidence["confidence"] == "high"


def test_unquoted_shell_heredoc_command_substitution_keeps_write_evidence(tmp_path):
    script = tmp_path / "dynamic-heredoc.sh"
    script.write_text(
        "cat <<EOF\n$(touch out.txt)\nEOF\n",
        encoding="utf-8",
    )
    plan = mutations.plan([
        ToolEvent(kind=EXEC, tool="Bash", command=f'bash "{script}"',
                  cwd=str(tmp_path))
    ], engine.clobber_targets)
    assert plan.complete is False
    assert plan.review_required is False
    assert plan.evidence["confidence"] == "high"


def test_generic_python_save_is_reviewable_and_reports_exact_evidence(tmp_path):
    script = tmp_path / "model.py"
    script.write_text(
        "class Model:\n"
        "    def save(self):\n"
        "        return True\n"
        "Model().save()\n",
        encoding="utf-8",
    )
    event = ToolEvent(
        kind=EXEC, tool="PowerShell",
        command=f'python "{script}"', cwd=str(tmp_path),
    )
    plan = mutations.plan([event], engine.clobber_targets)
    assert plan.mutating is True
    assert plan.complete is False
    assert plan.review_required is True
    assert plan.evidence["confidence"] == "low"
    assert plan.evidence["primitive"] == "save"
    assert plan.evidence["line"] == 4
    assert plan.evidence["sha256"] in plan.reason


def test_confirmed_python_write_reports_line_and_primitive(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text(
        "from pathlib import Path\n"
        "Path('out.txt').write_text('x')\n",
        encoding="utf-8",
    )
    event = ToolEvent(
        kind=EXEC, tool="PowerShell",
        command=f'python "{script}"', cwd=str(tmp_path),
    )
    plan = mutations.plan([event], engine.clobber_targets)
    assert plan.mutating is True
    assert plan.complete is False
    assert plan.review_required is False
    assert plan.evidence["confidence"] == "high"
    assert plan.evidence["primitive"] == "write_text"
    assert plan.evidence["line"] == 2
    assert "write_text" in plan.reason


@pytest.mark.parametrize("source,primitive", [
    ("from pathlib import Path\nPath('out.txt').open('w')\n", "open"),
    ("exec(\"open('out.txt', 'w').write('x')\")\n", "exec"),
])
def test_python_indirect_write_forms_remain_confirmed(tmp_path, source, primitive):
    script = tmp_path / "writer.py"
    script.write_text(source, encoding="utf-8")
    plan = mutations.plan([
        ToolEvent(kind=EXEC, tool="PowerShell",
                  command=f'python "{script}"', cwd=str(tmp_path))
    ], engine.clobber_targets)
    assert plan.complete is False
    assert plan.review_required is False
    assert plan.evidence["confidence"] == "high"
    assert primitive in plan.evidence["primitive"]


@pytest.mark.parametrize("args", [
    ["--help"],
    ["checkout", "--help"],
    ["office", "validate-preservation", "--help"],
])
def test_active_agw_python_entrypoint_help_is_read_only(args):
    command = subprocess.list2cmdline([sys.executable, AGW_SOURCE, *args]) \
        if os.name == "nt" else shlex.join([sys.executable, AGW_SOURCE, *args])
    event = ToolEvent(kind=EXEC, tool="PowerShell" if os.name == "nt" else "Bash",
                      command=command, cwd=PLUGIN)
    plan = mutations.plan(
        [event], engine.clobber_targets, plugin_root=PLUGIN
    )
    assert plan.mutating is False
    assert plan.complete is True
    assert plan.targets == []


@pytest.mark.parametrize("launcher", ["py -3.12", "python3.12", "pythonw3.12"])
def test_versioned_python_launcher_normalizes_for_active_agw_help(launcher):
    event = ToolEvent(
        kind=EXEC, tool="PowerShell",
        command=f'{launcher} "{AGW_SOURCE}" checkout --help', cwd=PLUGIN,
    )
    plan = mutations.plan(
        [event], engine.clobber_targets, plugin_root=PLUGIN
    )
    assert plan.mutating is False
    assert plan.complete is True


def test_copied_agw_help_and_active_nonhelp_remain_blocked(tmp_path):
    copied = tmp_path / "agw.py"
    copied.write_text(open(AGW_SOURCE, encoding="utf-8").read(), encoding="utf-8")
    for command in (
        f'python "{copied}" --help',
        f'python "{AGW_SOURCE}" status',
        f'python "{AGW_SOURCE}" --agw-argv-b64 --help',
    ):
        event = ToolEvent(kind=EXEC, tool="PowerShell", command=command, cwd=PLUGIN)
        plan = mutations.plan(
            [event], engine.clobber_targets, plugin_root=PLUGIN
        )
        assert plan.mutating is True
        assert plan.complete is False
        assert "pre-execution output contract" in plan.reason


def test_active_agw_help_chained_with_another_command_remains_blocked(tmp_path):
    writer = tmp_path / "writer.py"
    writer.write_text("open('out.txt', 'w').write('x')\n", encoding="utf-8")
    event = ToolEvent(
        kind=EXEC, tool="PowerShell",
        command=f'python "{AGW_SOURCE}" --help; python "{writer}"', cwd=PLUGIN,
    )
    plan = mutations.plan(
        [event], engine.clobber_targets, plugin_root=PLUGIN
    )
    assert plan.mutating is True
    assert plan.complete is False


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


def test_trusted_workflow_separates_exact_state_from_observed_cache(tmp_path):
    state = tmp_path / "state"
    cache = tmp_path / "cache"
    state.mkdir()
    cache.mkdir()
    marker = state / "session.json"
    marker.write_text("before", encoding="utf-8")
    script = tmp_path / "summon.py"
    script.write_text(
        "from pathlib import Path\n"
        "Path('state/session.json').write_text('after')\n"
        "Path('cache/summon-a1b2c3.py').write_text('# runner')\n",
        encoding="utf-8",
    )
    manifest_path, digest, _ = _write_manifest(
        tmp_path, script,
        roots=["{cwd}/state", "{cwd}/cache"],
        outputs=[{
            "path": "{cwd}/state/session.json", "expected": "present",
        }],
        observed=[{
            "path": "{cwd}/cache", "patterns": ["summon-*.py"],
        }],
    )
    _trust(manifest_path, digest)

    result = _run_resolved(
        "example.writer", [sys.executable, str(script)], tmp_path,
    )

    assert result["ok"] is True
    assert result["output_roots"] == [str(cache)]
    assert result["unclaimed_observed_changes"] == []
    assert result["unchanged_outputs"] == []
    assert result["ignored_sidecar_changes"] == [{
        "path": str(cache / "summon-a1b2c3.py"),
        "change": "created", "kind": "file",
        "output_root": str(cache),
        "relative_path": "summon-a1b2c3.py",
        "matched_pattern": "summon-*.py",
    }]
    assert marker.read_text(encoding="utf-8") == "after"
    assert store.list_versions(str(marker))


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


def test_matching_workflow_is_ambiguity_safe(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text(
        "from pathlib import Path\nPath('out.txt').write_text('x')\n",
        encoding="utf-8",
    )
    for workflow_id in ("example.alpha", "example.beta"):
        manifest_path, digest, _ = _write_manifest(
            tmp_path, script, workflow_id=workflow_id,
            schema="agw.workflow/v2", args=["out.txt"],
            outputs=[{"path": "{cwd}/out.txt", "expected": "absent"}],
        )
        _trust(manifest_path, digest)
    command = [sys.executable, str(script), "out.txt"]
    assert set(workflows.matching_workflows(command, str(tmp_path))) == {
        "example.alpha", "example.beta",
    }
    assert workflows.matching_workflow(command, str(tmp_path)) == ""
    shell_command = subprocess.list2cmdline(command) if os.name == "nt" \
        else shlex.join(command)
    plan = mutations.plan([
        ToolEvent(kind=EXEC, tool="PowerShell" if os.name == "nt" else "Bash",
                  command=shell_command, cwd=str(tmp_path))
    ], engine.clobber_targets)
    assert plan.complete is False
    assert "multiple trusted output contracts" in plan.reason
    assert "example.alpha" in plan.reason and "example.beta" in plan.reason


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
    matching = engine.evaluate(
        ToolEvent(kind=EXEC, tool="Bash",
                  command=f'"{launcher}" workflow match -- python writer.py',
                  cwd=os.getcwd()),
        policy, PLUGIN,
    )
    assert trust.action == ASK
    assert trust.rule_id == "builtin:agw-workflow-trust"
    assert trust.presentation_details["targets"] == ["contract.json"]
    assert trust.presentation_details["target_kind"] == "file"
    assert listing.action == ALLOW
    assert matching.action == ALLOW


def test_workflow_match_cli_returns_one_authoritative_recommendation(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text(
        "from pathlib import Path\nPath('out.txt').write_text('x')\n",
        encoding="utf-8",
    )
    manifest_path, digest, _ = _write_manifest(
        tmp_path, script, workflow_id="example.cli-match",
        schema="agw.workflow/v2", args=["out.txt"],
        outputs=[{"path": "{cwd}/out.txt", "expected": "absent"}],
    )
    _trust(manifest_path, digest)
    command = [sys.executable, str(script), "out.txt"]
    result = subprocess.run(
        [sys.executable, AGW_SOURCE, "workflow", "match", "--json",
         "--cwd", str(tmp_path), "--", *command],
        text=True, encoding="utf-8", capture_output=True, check=True,
    )
    payload = json.loads(result.stdout)
    assert payload["count"] == 1
    assert payload["matches"][0]["id"] == "example.cli-match"
    assert payload["matches"][0]["description"] == "test writer"
    assert payload["recommended_argv"] == [
        "agw", "run", "--workflow", "example.cli-match", "--", *command,
    ]
    assert payload["suggested_argv"] == {
        "deprecated": True, "replacement": "recommended_argv",
        "value_included": False,
    }
    assert "command" not in payload

    listing = subprocess.run(
        [sys.executable, AGW_SOURCE, "workflow", "list"],
        text=True, capture_output=True, check=True,
    )
    assert "example.cli-match - test writer" in listing.stdout


def test_workflow_match_cli_reports_zero_matches(tmp_path):
    script = tmp_path / "reader.py"
    script.write_text("print('read only')\n", encoding="utf-8")
    command = [sys.executable, str(script), "🗺 no-match"]
    result = subprocess.run(
        [sys.executable, AGW_SOURCE, "workflow", "match", "--json",
         "--cwd", str(tmp_path), "--", *command],
        text=True, encoding="utf-8", capture_output=True, check=True,
    )
    payload = json.loads(result.stdout)
    assert payload["matches"] == []
    assert payload["count"] == 0
    assert payload["recommended_argv"] == []
    assert payload["suggested_argv"]["value_included"] is False
    assert "command" not in payload


def test_workflow_match_cli_preserves_unicode_arguments(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text(
        "from pathlib import Path\nPath('out.txt').write_text('x')\n",
        encoding="utf-8",
    )
    unicode_arg = "🗺 clients/日本語"
    manifest_path, digest, _ = _write_manifest(
        tmp_path, script, workflow_id="example.unicode-match",
        schema="agw.workflow/v2", args=[unicode_arg],
        outputs=[{"path": "{cwd}/out.txt", "expected": "absent"}],
    )
    _trust(manifest_path, digest)
    command = [sys.executable, str(script), unicode_arg]
    result = subprocess.run(
        [sys.executable, AGW_SOURCE, "workflow", "match", "--json",
         "--cwd", str(tmp_path), "--", *command],
        text=True, encoding="utf-8", capture_output=True, check=True,
    )
    payload = json.loads(result.stdout)
    assert payload["count"] == 1
    assert payload["recommended_argv"][-len(command):] == command
    assert payload["suggested_argv"]["replacement"] == "recommended_argv"
    assert "command" not in payload
    assert json.dumps(payload, ensure_ascii=False).count(unicode_arg) == 1


def test_workflow_match_cli_keeps_multiple_matches_explicit(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text(
        "from pathlib import Path\nPath('out.txt').write_text('x')\n",
        encoding="utf-8",
    )
    for workflow_id in ("example.cli-alpha", "example.cli-beta"):
        manifest_path, digest, _ = _write_manifest(
            tmp_path, script, workflow_id=workflow_id,
            schema="agw.workflow/v2", args=["out.txt"],
            outputs=[{"path": "{cwd}/out.txt", "expected": "absent"}],
        )
        _trust(manifest_path, digest)
    command = [sys.executable, str(script), "out.txt"]
    result = subprocess.run(
        [sys.executable, AGW_SOURCE, "workflow", "match", "--json",
         "--cwd", str(tmp_path), "--", *command],
        text=True, capture_output=True, check=True,
    )
    payload = json.loads(result.stdout)
    assert {item["id"] for item in payload["matches"]} == {
        "example.cli-alpha", "example.cli-beta",
    }
    assert payload["count"] == 2
    assert payload["recommended_argv"] == []
    assert payload["suggested_argv"]["value_included"] is False
    assert "command" not in payload


def test_workflow_match_cli_rejects_missing_command(tmp_path):
    result = subprocess.run(
        [sys.executable, AGW_SOURCE, "workflow", "match", "--json",
         "--cwd", str(tmp_path), "--"],
        text=True, encoding="utf-8", capture_output=True,
    )
    assert result.returncode != 0
    assert "requires a literal script command" in result.stderr


def test_auto_route_rechecks_script_hash_before_execution(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text(
        "from pathlib import Path\nPath('out.txt').write_text('trusted')\n",
        encoding="utf-8",
    )
    manifest_path, digest, _ = _write_manifest(
        tmp_path, script, workflow_id="example.hash-race",
        schema="agw.workflow/v2", args=["out.txt"],
        outputs=[{"path": "{cwd}/out.txt", "expected": "absent"}],
    )
    _trust(manifest_path, digest)
    command = [sys.executable, str(script), "out.txt"]
    assert workflows.matching_workflows(command, str(tmp_path)) == [
        "example.hash-race"
    ]

    script.write_text(
        "from pathlib import Path\nPath('out.txt').write_text('changed')\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, AGW_SOURCE, "run", "--json", "--workflow",
         "example.hash-race", "--", *command],
        cwd=str(tmp_path), text=True, capture_output=True,
    )
    assert result.returncode != 0
    assert "trusted script changed" in result.stderr
    assert not (tmp_path / "out.txt").exists()


def test_v2_binds_exact_arguments_and_can_build_its_own_command(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text(
        "import argparse\nfrom pathlib import Path\n"
        "p=argparse.ArgumentParser(); p.add_argument('--output'); a=p.parse_args()\n"
        "Path(a.output).write_text('bound', encoding='utf-8')\n",
        encoding="utf-8",
    )
    output = tmp_path / "out.txt"
    manifest_path, digest, _ = _write_manifest(
        tmp_path, script, schema="agw.workflow/v2",
        args=["--output", "out.txt"],
        outputs=[{"path": "{cwd}/out.txt", "expected": "absent"}],
    )
    _trust(manifest_path, digest)
    resolved = workflows.resolve_run("example.writer", [], str(tmp_path))
    assert resolved["command"][1:] == [
        str(script), "--output", "out.txt",
    ]
    result = file_ops.run_declared(
        resolved["command"], resolved["outputs"],
        expected_hashes=resolved["expected_hashes"], cwd=resolved["cwd"],
    )
    assert result["ok"] is True
    assert output.read_text(encoding="utf-8") == "bound"

    with pytest.raises(workflows.WorkflowTrustError, match="arguments"):
        workflows.resolve_run(
            "example.writer",
            [sys.executable, str(script), "--output", "other.txt"],
            str(tmp_path),
        )


def test_workflow_init_validate_and_machine_local_status(tmp_path):
    script = tmp_path / "index.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    manifest_path = tmp_path / "client-workflow.json"
    built = workflows.initialize_manifest(
        str(script), str(manifest_path), workflow_id="example.index",
        args=["--path", "3 👥 Clients", "--output", "3 👥 Clients/_index.md"],
        outputs=["{cwd}/3 👥 Clients/_index.md"], expected=["any"],
        allowed_roots=["{cwd}/3 👥 Clients"],
    )
    serialized = json.dumps(built["manifest"], ensure_ascii=True) + "\n"
    manifest_path.write_text(serialized, encoding="utf-8")
    assert "👥" not in serialized
    assert "\\ud83d\\udc65" in serialized

    validated = workflows.validate_manifest_file(str(manifest_path))
    assert validated["valid"] is True
    assert validated["arguments_bound"] is True
    assert validated["argument_count"] == 4
    assert workflows.manifest_status(str(manifest_path))["status"] == \
        "not_trusted_on_this_machine"
    _trust(manifest_path, validated["manifest_sha256"])
    assert workflows.manifest_status(str(manifest_path))["status"] == "trusted_exact"


def test_workflow_validation_reports_wildcard_positions(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    manifest_path, _digest, manifest = _write_manifest(
        tmp_path, script, outputs=[{"path": "folder/??/out.txt", "expected": "any"}],
    )
    with pytest.raises(workflows.WorkflowError) as caught:
        workflows.validate_manifest(manifest, str(manifest_path))
    assert caught.value.details["field"] == "outputs[0].path"
    assert caught.value.details["wildcard"] == "??"
    assert caught.value.details["positions"] == [7, 8]
    assert "position(s) 7, 8" in str(caught.value)


def test_trust_result_reports_phases(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    manifest_path, digest, _ = _write_manifest(tmp_path, script)
    seen = []
    result = workflows.trust_manifest(
        str(manifest_path), digest, phase_callback=seen.append,
    )
    names = [item["phase"] for item in result["phases"]]
    assert names == [
        "acquiring_lock", "reading_manifest",
        "hashing_script_and_validating_contract", "writing_record", "complete",
    ]
    assert seen == result["phases"]


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


def test_real_cli_v2_init_validate_status_and_bound_run(tmp_path):
    script = tmp_path / "bound_writer.py"
    output = tmp_path / "👥 output.txt"
    script.write_text(
        "from pathlib import Path\nimport sys\nPath(sys.argv[1]).write_text('v2-ok')\n",
        encoding="utf-8",
    )
    manifest = tmp_path / "bound-workflow.json"
    cli = os.path.join(PLUGIN, "scripts", "agw", "agw.py")
    env = dict(os.environ, AGW_HOME=str(tmp_path / "v2-agw-home"))

    initialized = subprocess.run(
        [sys.executable, cli, "workflow", "init",
         "--script", str(script), "--manifest", str(manifest),
         "--id", "example.bound", "--arg", output.name,
         "--output", "{cwd}/" + output.name, "--expected", "absent",
         "--allowed-root", "{cwd}", "--json"],
        cwd=str(tmp_path), env=env, text=True, capture_output=True, timeout=30,
    )
    assert initialized.returncode == 0, initialized.stderr
    init_data = json.loads(initialized.stdout)
    assert init_data["schema"] == "agw.workflow/v2"
    assert "👥" not in manifest.read_text(encoding="utf-8")

    validated = subprocess.run(
        [sys.executable, cli, "workflow", "validate", str(manifest), "--json"],
        cwd=str(tmp_path), env=env, text=True, capture_output=True, timeout=30,
    )
    assert validated.returncode == 0, validated.stderr
    assert json.loads(validated.stdout)["arguments_bound"] is True

    trusted = subprocess.run(
        [sys.executable, cli, "workflow", "trust", str(manifest),
         "--expected-manifest-hash", init_data["manifest_sha256"],
         "--approve-trust", "--json"],
        cwd=str(tmp_path), env=env, text=True, capture_output=True, timeout=30,
    )
    assert trusted.returncode == 0, trusted.stderr

    status = subprocess.run(
        [sys.executable, cli, "workflow", "status", str(manifest), "--json"],
        cwd=str(tmp_path), env=env, text=True, capture_output=True, timeout=30,
    )
    assert json.loads(status.stdout)["status"] == "trusted_exact"

    executed = subprocess.run(
        [sys.executable, cli, "run", "--workflow", "example.bound",
         "--cwd", str(tmp_path), "--json"],
        cwd=str(tmp_path), env=env, text=True, capture_output=True, timeout=30,
    )
    assert executed.returncode == 0, executed.stderr
    assert output.read_text(encoding="utf-8") == "v2-ok"


def test_v3_enum_parameter_binds_one_reviewed_argument_slot(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    script = tmp_path / "summon.py"
    script.write_text(
        "from pathlib import Path\nimport sys\n"
        "assert sys.argv[1] == '--agent' and sys.argv[3] == '--read-only'\n"
        "Path('state', sys.argv[2] + '.txt').write_text('loaded')\n",
        encoding="utf-8",
    )
    manifest_path, digest, _ = _write_manifest(
        tmp_path, script, schema="agw.workflow/v3",
        parameters={"agent": {"type": "enum", "values": ["alpha", "beta"]}},
        args=["--agent", {"parameter": "agent"}, "--read-only"],
        roots=["{cwd}/state"],
        outputs=[{"path": "{cwd}/state/{param:agent}.txt", "expected": "absent"}],
    )
    _trust(manifest_path, digest)

    resolved = workflows.resolve_run(
        "example.writer", [], str(tmp_path), parameters={"agent": "beta"},
    )
    assert resolved["command"][-3:] == ["--agent", "beta", "--read-only"]
    assert resolved["outputs"] == [str(state / "beta.txt")]
    result = file_ops.run_declared(
        resolved["command"], resolved["outputs"],
        expected_hashes=resolved["expected_hashes"], cwd=resolved["cwd"],
        optional_outputs=resolved["optional_outputs"],
        allow_missing_output_parents=True,
    )
    assert result["ok"] is True
    assert (state / "beta.txt").read_text(encoding="utf-8") == "loaded"

    with pytest.raises(workflows.WorkflowTrustError, match="approved enum"):
        workflows.resolve_run(
            "example.writer", [], str(tmp_path), parameters={"agent": "query text"},
        )
    with pytest.raises(workflows.WorkflowTrustError, match="missing"):
        workflows.resolve_run("example.writer", [], str(tmp_path), parameters={})
    with pytest.raises(workflows.WorkflowTrustError, match="unknown"):
        workflows.resolve_run(
            "example.writer", [], str(tmp_path),
            parameters={"agent": "alpha", "query": "anything"},
        )


def test_v3_rejects_extra_or_repositioned_explicit_arguments(tmp_path):
    script = tmp_path / "summon.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    manifest_path, digest, _ = _write_manifest(
        tmp_path, script, schema="agw.workflow/v3",
        parameters={"agent": {"type": "enum", "values": ["alpha"]}},
        args=["--agent", {"parameter": "agent"}, "--read-only"],
        outputs=[{"path": "{cwd}/marker.json", "expected": "any", "optional": True}],
    )
    _trust(manifest_path, digest)
    with pytest.raises(workflows.WorkflowTrustError, match="count"):
        workflows.resolve_run(
            "example.writer",
            [sys.executable, str(script), "--agent", "alpha", "--read-only", "query"],
            str(tmp_path),
        )
    with pytest.raises(workflows.WorkflowTrustError, match="reviewed literal"):
        workflows.resolve_run(
            "example.writer",
            [sys.executable, str(script), "alpha", "--agent", "--read-only"],
            str(tmp_path),
        )
    assert workflows.matching_workflow(
        [sys.executable, str(script), "--agent", "alpha", "--read-only"],
        str(tmp_path),
    ) == "example.writer"
    assert workflows.matching_workflow(
        [sys.executable, str(script), "--agent", "query", "--read-only"],
        str(tmp_path),
    ) == ""


def test_v3_hash_bound_enum_file_is_compiled_into_trusted_record(tmp_path):
    registry = tmp_path / "agents.txt"
    registry.write_text("# reviewed slugs\nalpha\nbeta\n", encoding="utf-8")
    script = tmp_path / "summon.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    parameter = {
        "type": "enum-file", "source": registry.name,
        "source_sha256": store.file_sha256(str(registry)), "format": "lines",
    }
    manifest_path, digest, _ = _write_manifest(
        tmp_path, script, schema="agw.workflow/v3",
        parameters={"agent": parameter}, args=[{"parameter": "agent"}],
        outputs=[{"path": "{cwd}/marker.json", "expected": "any", "optional": True}],
    )
    _trust(manifest_path, digest)
    record = workflows.load_trusted("example.writer")
    compiled = record["manifest"]["parameters"]["agent"]
    assert compiled["type"] == "enum"
    assert compiled["values"] == ["alpha", "beta"]

    registry.write_text("alpha\ngamma\n", encoding="utf-8")
    with pytest.raises(workflows.WorkflowConflict, match="source hash"):
        workflows.validate_manifest_file(str(manifest_path))
    resolved = workflows.resolve_run(
        "example.writer", [], str(tmp_path), parameters={"agent": "beta"},
    )
    assert resolved["command"][-1] == "beta"


def test_v3_regex_integer_and_bounded_path_parameters(tmp_path):
    agents = tmp_path / "agents"
    agents.mkdir()
    agent_file = agents / "alpha.txt"
    agent_file.write_text("x", encoding="utf-8")
    script = tmp_path / "typed.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    manifest_path, digest, _ = _write_manifest(
        tmp_path, script, schema="agw.workflow/v3",
        parameters={
            "slug": {"type": "regex", "pattern": "[a-z][a-z0-9-]{0,31}"},
            "count": {"type": "integer", "minimum": 1, "maximum": 10},
            "agent-file": {
                "type": "path", "root": "{cwd}/agents",
                "must_exist": True, "kind": "file",
            },
        },
        args=[
            "--slug", {"parameter": "slug"}, "--count", {"parameter": "count"},
            "--file", {"parameter": "agent-file"},
        ],
        outputs=[{"path": "{cwd}/marker.json", "expected": "any", "optional": True}],
    )
    _trust(manifest_path, digest)
    resolved = workflows.resolve_run(
        "example.writer", [], str(tmp_path), parameters={
            "slug": "agent-7", "count": "3", "agent-file": "agents/alpha.txt",
        },
    )
    assert resolved["command"][-6:] == [
        "--slug", "agent-7", "--count", "3", "--file", "agents/alpha.txt",
    ]
    with pytest.raises(workflows.WorkflowTrustError, match="outside"):
        workflows.resolve_run(
            "example.writer", [], str(tmp_path), parameters={
                "slug": "agent-7", "count": "3", "agent-file": "../outside.txt",
            },
        )
    with pytest.raises(workflows.WorkflowTrustError, match="range"):
        workflows.resolve_run(
            "example.writer", [], str(tmp_path), parameters={
                "slug": "agent-7", "count": "99", "agent-file": "agents/alpha.txt",
            },
        )


def test_optional_output_may_remain_absent_but_existing_output_may_not_disappear(tmp_path):
    output = tmp_path / "optional.txt"
    script = tmp_path / "optional.py"
    script.write_text("pass\n", encoding="utf-8")
    manifest_path, digest, _ = _write_manifest(
        tmp_path, script, schema="agw.workflow/v3",
        parameters={"mode": {"type": "enum", "values": ["skip"]}},
        args=[{"parameter": "mode"}],
        outputs=[{"path": output.name, "expected": "any", "optional": True}],
    )
    _trust(manifest_path, digest)
    resolved = workflows.resolve_run(
        "example.writer", [], str(tmp_path), parameters={"mode": "skip"},
    )
    result = file_ops.run_declared(
        resolved["command"], resolved["outputs"],
        expected_hashes=resolved["expected_hashes"], cwd=resolved["cwd"],
        optional_outputs=resolved["optional_outputs"],
        allow_missing_output_parents=True,
    )
    assert result["ok"] is True
    assert result["declared_outputs_missing"] == []

    output.write_text("preserve", encoding="utf-8")
    remover = tmp_path / "remover.py"
    remover.write_text("from pathlib import Path\nPath('optional.txt').unlink()\n", encoding="utf-8")
    second_path, second_digest, _ = _write_manifest(
        tmp_path, remover, workflow_id="example.remover", schema="agw.workflow/v3",
        parameters={"mode": {"type": "enum", "values": ["remove"]}},
        args=[{"parameter": "mode"}],
        outputs=[{"path": output.name, "expected": "present", "optional": True}],
    )
    _trust(second_path, second_digest)
    resolved = workflows.resolve_run(
        "example.remover", [], str(tmp_path), parameters={"mode": "remove"},
    )
    result = file_ops.run_declared(
        resolved["command"], resolved["outputs"],
        expected_hashes=resolved["expected_hashes"], cwd=resolved["cwd"],
        optional_outputs=resolved["optional_outputs"],
        allow_missing_output_parents=True,
    )
    assert result["ok"] is False
    assert result["declared_outputs_missing"] == [str(output)]
    assert store.list_versions(str(output))


def test_real_cli_v3_compact_parameter_invocation(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    script = tmp_path / "summon.py"
    script.write_text(
        "from pathlib import Path\nimport sys\n"
        "Path('state', sys.argv[1] + '.json').write_text('ok')\n",
        encoding="utf-8",
    )
    manifest_path, digest, _ = _write_manifest(
        tmp_path, script, schema="agw.workflow/v3", workflow_id="example.parameterized",
        parameters={"agent": {"type": "enum", "values": ["alpha", "beta"]}},
        args=[{"parameter": "agent"}], roots=["{cwd}/state"],
        outputs=[{"path": "{cwd}/state/{param:agent}.json", "expected": "absent"}],
    )
    cli = os.path.join(PLUGIN, "scripts", "agw", "agw.py")
    env = dict(os.environ, AGW_HOME=str(tmp_path / "v3-agw-home"))
    trusted = subprocess.run(
        [sys.executable, cli, "workflow", "trust", str(manifest_path),
         "--expected-manifest-hash", digest, "--approve-trust", "--json"],
        cwd=str(tmp_path), env=env, text=True, capture_output=True, timeout=30,
    )
    assert trusted.returncode == 0, trusted.stderr
    executed = subprocess.run(
        [sys.executable, cli, "run", "--workflow", "example.parameterized",
         "--param", "agent=beta", "--cwd", str(tmp_path), "--json"],
        cwd=str(tmp_path), env=env, text=True, capture_output=True, timeout=30,
    )
    assert executed.returncode == 0, executed.stderr
    data = json.loads(executed.stdout)
    assert data["workflow_parameters"] == {"agent": "beta"}
    assert (state / "beta.json").read_text(encoding="utf-8") == "ok"

    duplicate = subprocess.run(
        [sys.executable, cli, "run", "--workflow", "example.parameterized",
         "--param", "agent=alpha", "--param", "agent=beta",
         "--cwd", str(tmp_path), "--json"],
        cwd=str(tmp_path), env=env, text=True, capture_output=True, timeout=30,
    )
    assert duplicate.returncode != 0
    assert json.loads(duplicate.stderr)["error"]["code"] == "workflow_error"
    assert not (state / "alpha.json").exists()


def test_v3_rejects_parameter_dependent_roots_and_unsafe_regex(tmp_path):
    script = tmp_path / "typed.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    manifest_path, _digest, manifest = _write_manifest(
        tmp_path, script, schema="agw.workflow/v3",
        parameters={"slug": {"type": "regex", "pattern": "(a+)+"}},
        args=[{"parameter": "slug"}], roots=["{cwd}"],
        outputs=[{"path": "{cwd}/out.txt", "expected": "any"}],
    )
    with pytest.raises(workflows.WorkflowError, match="grouping"):
        workflows.validate_manifest(manifest, str(manifest_path))

    manifest["parameters"]["slug"] = {"type": "enum", "values": ["alpha"]}
    manifest["allowed_roots"] = ["{cwd}/{param:slug}"]
    with pytest.raises(workflows.WorkflowError, match="may not depend"):
        workflows.validate_manifest(manifest, str(manifest_path))


def test_v3_temp_placeholder_is_compiled_into_machine_local_trust(tmp_path):
    script = tmp_path / "typed.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    manifest_path, digest, _ = _write_manifest(
        tmp_path, script, schema="agw.workflow/v3",
        parameters={"slug": {"type": "enum", "values": ["alpha"]}},
        args=[{"parameter": "slug"}], roots=["{temp}/agw-v3-cache"],
        outputs=[{
            "path": "{temp}/agw-v3-cache/{param:slug}.txt",
            "expected": "any", "optional": True,
        }],
    )
    _trust(manifest_path, digest)
    record = workflows.load_trusted("example.writer")
    serialized = json.dumps(record["manifest"])
    assert "{temp}" not in serialized
    assert os.path.realpath(tempfile.gettempdir()) in record["manifest"]["allowed_roots"][0]


def test_source_run_help_discloses_only_compact_parameter_option():
    completed = subprocess.run(
        [sys.executable, AGW_SOURCE, "run", "--help"],
        text=True, capture_output=True, timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert "--param NAME=VALUE" in completed.stdout
    assert "typed value; repeat" in completed.stdout
