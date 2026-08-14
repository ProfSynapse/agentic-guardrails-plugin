import json
import os
import subprocess
import sys

import pytest

from core import store, workflows


PLUGIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugin")
AGW_SOURCE = os.path.join(PLUGIN, "scripts", "agw", "agw.py")


def _manifest(tmp_path, script, *, workflow_id="example.refresh"):
    value = {
        "schema": "agw.workflow/v2",
        "id": workflow_id,
        "description": "refresh test",
        "command": {
            "runtime": "python",
            "script": script.name,
            "script_sha256": store.file_sha256(str(script)),
            "args": ["out.txt"],
        },
        "allowed_roots": ["{cwd}"],
        "outputs": [{"path": "{cwd}/out.txt", "expected": "any"}],
        "observed_roots": [],
    }
    path = tmp_path / "workflow.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path, value


def _trust(path, *, source_name="tests", source_version="1.0"):
    return workflows.trust_manifest(
        str(path), store.file_sha256(str(path)),
        source_name=source_name, source_version=source_version,
    )


def _write_plan(tmp_path, plan):
    path = tmp_path / "refresh-plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    return path


def test_trust_records_authenticated_provenance_and_bounded_snapshot(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('approved')\n", encoding="utf-8")
    manifest_path, _manifest_value = _manifest(tmp_path, script)
    result = _trust(manifest_path, source_name="professor-synapse", source_version="3.6.0")

    record = workflows.load_trusted("example.refresh")
    assert record["schema"] == workflows.RECORD_SCHEMA
    provenance = record["provenance"]
    assert provenance["source_manifest_path"] == os.path.realpath(str(manifest_path))
    assert provenance["source_manifest_sha256"] == store.file_sha256(str(manifest_path))
    assert provenance["script_path"] == os.path.realpath(str(script))
    assert provenance["script_sha256"] == store.file_sha256(str(script))
    assert provenance["source"] == {
        "name": "professor-synapse", "version": "3.6.0", "attested": False,
    }
    assert provenance["approval"]["identity"] == "local-user-confirmation"
    assert provenance["approval"]["identity_attested"] is False
    assert provenance["script_snapshot"]["available"] is True
    assert result["provenance"] == provenance

    exported = workflows.export_trusted("example.refresh")
    assert exported["legacy_reconstruction"] is False
    assert exported["manifest"]["command"]["script_sha256"] == store.file_sha256(str(script))
    assert exported["manifest_sha256"] == workflows._sha256_bytes(
        exported["content"].encode("utf-8")
    )

    unchanged = workflows.trust_manifest(
        str(manifest_path), store.file_sha256(str(manifest_path)),
    )
    assert unchanged["changed"] is False
    replaced = workflows.trust_manifest(
        str(manifest_path), store.file_sha256(str(manifest_path)), replace=True,
        source_name="professor-synapse", source_version="3.6.1",
    )
    assert replaced["changed"] is True
    assert workflows.load_trusted("example.refresh")["provenance"]["source"][
        "version"
    ] == "3.6.1"


def test_legacy_record_exports_but_refresh_requires_new_provenance(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('approved')\n", encoding="utf-8")
    manifest_path, _manifest_value = _manifest(tmp_path, script)
    _trust(manifest_path)
    record = workflows.load_trusted("example.refresh")
    legacy = {
        "schema": workflows.RECORD_SCHEMA_V1,
        "manifest_sha256": record["manifest_sha256"],
        "trusted_at": record["trusted_at"],
        "manifest": record["manifest"],
    }
    legacy["seal"] = workflows._seal(legacy, workflows._trust_key(create=False))
    workflows._atomic_write(
        workflows._record_path("example.refresh"),
        workflows._canonical_json(legacy) + b"\n",
    )

    exported = workflows.export_trusted("example.refresh")
    assert exported["legacy_reconstruction"] is True
    assert exported["source_manifest_path"] == ""
    with pytest.raises(workflows.WorkflowProvenanceError) as caught:
        workflows.build_refresh_plan("example.refresh")
    assert caught.value.details["reason_code"] == "workflow_provenance_missing"
    migrated = _trust(manifest_path, source_name="legacy-project", source_version="2")
    assert migrated["migrated"] is True
    assert workflows.load_trusted("example.refresh")["schema"] == workflows.RECORD_SCHEMA


def test_hash_bound_refresh_updates_only_script_identity_and_is_single_use(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('approved')\n", encoding="utf-8")
    manifest_path, source_manifest = _manifest(tmp_path, script)
    _trust(manifest_path)
    prior = workflows.load_trusted("example.refresh")

    script.write_text("print('current')\n", encoding="utf-8")
    plan = workflows.build_refresh_plan("example.refresh")
    assert plan["apply_allowed"] is True
    assert plan["contract_changed"] is False
    assert plan["script_diff"]["available"] is True
    assert "-print('approved')" in plan["script_diff"]["diff"]
    assert "+print('current')" in plan["script_diff"]["diff"]
    plan_path = _write_plan(tmp_path, plan)

    result = workflows.apply_refresh_plan(str(plan_path), plan["plan_sha256"])
    assert result["script_sha256"] == store.file_sha256(str(script))
    refreshed = workflows.load_trusted("example.refresh")
    assert refreshed["manifest"]["command"]["script_sha256"] == result["script_sha256"]
    assert refreshed["manifest"]["allowed_roots"] == prior["manifest"]["allowed_roots"]
    assert refreshed["manifest"]["outputs"] == prior["manifest"]["outputs"]
    assert refreshed["provenance"]["refresh"]["plan_sha256"] == plan["plan_sha256"]
    trust_dir = workflows._trust_dir()
    assert sorted(path.name for path in os.scandir(trust_dir)) == [
        os.path.basename(workflows._record_path("example.refresh")),
    ]
    assert source_manifest["command"]["script_sha256"] == json.loads(
        manifest_path.read_text(encoding="utf-8")
    )["command"]["script_sha256"]

    with pytest.raises(workflows.WorkflowConflict) as replay:
        workflows.apply_refresh_plan(str(plan_path), plan["plan_sha256"])
    assert replay.value.details["reason_code"] == "workflow_trusted_record_changed"


def test_refresh_plan_exposes_contract_change_but_apply_refuses(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('approved')\n", encoding="utf-8")
    manifest_path, source_manifest = _manifest(tmp_path, script)
    _trust(manifest_path)
    script.write_text("print('current')\n", encoding="utf-8")
    source_manifest["outputs"][0]["path"] = "{cwd}/different.txt"
    manifest_path.write_text(json.dumps(source_manifest), encoding="utf-8")

    plan = workflows.build_refresh_plan("example.refresh")
    assert plan["apply_allowed"] is False
    assert plan["contract_changed"] is True
    assert "/outputs" in plan["contract_changed_fields"]
    plan_path = _write_plan(tmp_path, plan)
    with pytest.raises(workflows.WorkflowRefreshError) as caught:
        workflows.apply_refresh_plan(str(plan_path), plan["plan_sha256"])
    assert caught.value.details["reason_code"] == "workflow_contract_changed"
    assert workflows.load_trusted("example.refresh")["manifest"]["outputs"][0]["path"] \
        != "{cwd}/different.txt"


def test_refresh_refuses_script_or_manifest_drift_after_review(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('approved')\n", encoding="utf-8")
    manifest_path, _source_manifest = _manifest(tmp_path, script)
    _trust(manifest_path)
    script.write_text("print('reviewed')\n", encoding="utf-8")
    plan = workflows.build_refresh_plan("example.refresh")
    plan_path = _write_plan(tmp_path, plan)
    script.write_text("print('changed-after-review')\n", encoding="utf-8")

    with pytest.raises(workflows.WorkflowConflict) as caught:
        workflows.apply_refresh_plan(str(plan_path), plan["plan_sha256"])
    assert caught.value.details["reason_code"] == "workflow_refresh_source_changed"


def test_refresh_plan_is_review_evidence_not_authority(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('approved')\n", encoding="utf-8")
    manifest_path, _source_manifest = _manifest(tmp_path, script)
    _trust(manifest_path)
    script.write_text("print('reviewed')\n", encoding="utf-8")
    plan = workflows.build_refresh_plan("example.refresh")
    plan["candidate"]["script_sha256"] = "f" * 64
    plan["plan_sha256"] = workflows._refresh_plan_hash(plan)
    plan_path = _write_plan(tmp_path, plan)

    with pytest.raises(workflows.WorkflowConflict) as caught:
        workflows.apply_refresh_plan(str(plan_path), plan["plan_sha256"])
    assert caught.value.details["reason_code"] == "workflow_refresh_source_changed"
    assert workflows.load_trusted("example.refresh")["manifest"]["command"][
        "script_sha256"
    ] != "f" * 64


def test_refresh_plan_expires_without_changing_trust(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('approved')\n", encoding="utf-8")
    manifest_path, _source_manifest = _manifest(tmp_path, script)
    _trust(manifest_path)
    script.write_text("print('reviewed')\n", encoding="utf-8")
    plan = workflows.build_refresh_plan("example.refresh", now_ns=1)
    plan_path = _write_plan(tmp_path, plan)
    before = workflows.load_trusted("example.refresh")["seal"]
    with pytest.raises(workflows.WorkflowRefreshError) as caught:
        workflows.apply_refresh_plan(
            str(plan_path), plan["plan_sha256"], now_ns=plan["expires_at_ns"] + 1,
        )
    assert caught.value.details["reason_code"] == "workflow_refresh_plan_expired"
    assert workflows.load_trusted("example.refresh")["seal"] == before


def test_oversized_approved_script_is_hash_bound_without_snapshot_bloat(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("#" * (workflows.MAX_SCRIPT_SNAPSHOT_BYTES + 1), encoding="utf-8")
    manifest_path, _source_manifest = _manifest(tmp_path, script)
    _trust(manifest_path)
    record = workflows.load_trusted("example.refresh")
    assert record["provenance"]["script_snapshot"] == {
        "available": False,
        "reason": "script_too_large",
        "content_sha256": store.file_sha256(str(script)),
        "bytes": workflows.MAX_SCRIPT_SNAPSHOT_BYTES + 1,
    }
    script.write_text("#" * workflows.MAX_SCRIPT_SNAPSHOT_BYTES + "x", encoding="utf-8")
    plan = workflows.build_refresh_plan("example.refresh")
    assert plan["script_diff"] == {
        "available": False, "reason": "script_too_large", "truncated": False,
    }


def test_cli_refresh_plan_apply_and_export(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('approved')\n", encoding="utf-8")
    manifest_path, _source_manifest = _manifest(tmp_path, script, workflow_id="example.cli-refresh")
    env = dict(os.environ, AGW_HOME=str(tmp_path / "cli-home"))
    trusted = subprocess.run(
        [sys.executable, AGW_SOURCE, "workflow", "trust", str(manifest_path),
         "--expected-manifest-hash", store.file_sha256(str(manifest_path)),
         "--approve-trust", "--source-name", "tests", "--source-version", "1", "--json"],
        cwd=str(tmp_path), env=env, text=True, capture_output=True, timeout=30,
    )
    assert trusted.returncode == 0, trusted.stderr
    script.write_text("print('current')\n", encoding="utf-8")
    plan_path = tmp_path / "cli-plan.json"
    planned = subprocess.run(
        [sys.executable, AGW_SOURCE, "workflow", "refresh-plan", "example.cli-refresh",
         "--plan-file", str(plan_path), "--json"],
        cwd=str(tmp_path), env=env, text=True, capture_output=True, timeout=30,
    )
    assert planned.returncode == 0, planned.stderr
    plan_data = json.loads(planned.stdout)
    applied = subprocess.run(
        [sys.executable, AGW_SOURCE, "workflow", "refresh", str(plan_path),
         "--expected-plan-hash", plan_data["plan_sha256"], "--approve-refresh", "--json"],
        cwd=str(tmp_path), env=env, text=True, capture_output=True, timeout=30,
    )
    assert applied.returncode == 0, applied.stderr
    exported = subprocess.run(
        [sys.executable, AGW_SOURCE, "workflow", "export", "example.cli-refresh", "--json"],
        cwd=str(tmp_path), env=env, text=True, capture_output=True, timeout=30,
    )
    assert exported.returncode == 0, exported.stderr
    export_data = json.loads(exported.stdout)
    assert export_data["manifest"]["command"]["script_sha256"] == store.file_sha256(str(script))
