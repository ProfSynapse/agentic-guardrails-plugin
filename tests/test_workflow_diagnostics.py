import hashlib
import json
import os
import sys

import pytest

from core import store, workflows


def _trust_manifest(tmp_path, script, *, workflow_id="example.diagnostic",
                    schema=workflows.MANIFEST_SCHEMA, args=None, parameters=None):
    manifest = {
        "schema": schema,
        "id": workflow_id,
        "description": "diagnostic fixture",
        "command": {
            "runtime": "python",
            "script": script.name,
            "script_sha256": store.file_sha256(str(script)),
            "args": list(args or []),
        },
        "allowed_roots": ["{cwd}"],
        "outputs": [{
            "path": "{cwd}/out.txt",
            "expected": "absent",
            **({"optional": False} if schema == workflows.PARAMETERIZED_SCHEMA else {}),
        }],
        "observed_roots": [],
    }
    if schema == workflows.PARAMETERIZED_SCHEMA:
        manifest["parameters"] = dict(parameters or {})
    path = tmp_path / f"{workflow_id}.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    workflows.trust_manifest(str(path), store.file_sha256(str(path)))
    return manifest


def _reason_codes(diagnostic, workflow_id="example.diagnostic"):
    candidate = next(
        item for item in diagnostic["candidates"] if item.get("id") == workflow_id
    )
    return {reason["code"] for reason in candidate["mismatch_reasons"]}


def test_build_workflow_proposal_is_inert_and_serializable(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    output = tmp_path / "résultat.txt"
    trust_dir = tmp_path / "agw-home" / "trusted-workflows"

    proposal = workflows.build_workflow_proposal(
        [sys.executable, str(script), "--label", "日本語"],
        str(tmp_path),
        workflow_id="example.proposed",
        description="inert proposal",
        outputs=[str(output)],
        allowed_roots=[str(tmp_path)],
        expected_states=["absent"],
    )

    assert proposal["schema"] == workflows.MANIFEST_SCHEMA
    assert proposal["command"] == {
        "runtime": "python",
        "script": os.path.realpath(script),
        "script_sha256": store.file_sha256(str(script)),
        "args": ["--label", "日本語"],
    }
    assert proposal["outputs"] == [{"path": str(output), "expected": "absent"}]
    assert proposal["allowed_roots"] == [str(tmp_path)]
    assert not trust_dir.exists()

    serialized = tmp_path / "proposal.json"
    serialized.write_text(json.dumps(proposal), encoding="utf-8")
    validated = workflows.validate_manifest_file(str(serialized))
    assert validated["valid"] is True
    assert validated["manifest"]["id"] == "example.proposed"
    assert not trust_dir.exists()


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"outputs": []}, "outputs must be an explicitly supplied"),
        ({"allowed_roots": []}, "allowed_roots must be an explicitly supplied"),
        ({"expected_states": []}, "expected_states must be an explicitly supplied"),
        ({"expected_states": ["absent", "any"]}, "exactly one entry per output"),
        ({"expected_states": ["guess"]}, "must be any, absent, present, or a SHA-256"),
    ],
)
def test_build_workflow_proposal_requires_explicit_valid_contracts(
        tmp_path, overrides, message):
    script = tmp_path / "writer.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    kwargs = {
        "workflow_id": "example.proposed",
        "outputs": [str(tmp_path / "out.txt")],
        "allowed_roots": [str(tmp_path)],
        "expected_states": ["absent"],
    }
    kwargs.update(overrides)
    with pytest.raises(workflows.WorkflowError, match=message):
        workflows.build_workflow_proposal(
            [sys.executable, str(script)], str(tmp_path), **kwargs,
        )


def test_diagnostics_retain_normalization_failure_and_verified_candidates(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    _trust_manifest(tmp_path, script)

    diagnostic = workflows.diagnose_matching_workflows(
        [sys.executable, "-c", "print('not a script workflow')"], str(tmp_path),
    )

    assert diagnostic["schema"] == workflows.DIAGNOSTIC_SCHEMA
    assert diagnostic["ok"] is False
    assert diagnostic["normalized"] is None
    assert diagnostic["normalization_error"]["code"] == "command_normalization_failed"
    assert diagnostic["candidate_count"] == 1
    candidate = diagnostic["candidates"][0]
    assert candidate["id"] == "example.diagnostic"
    assert candidate["verified"] is True
    assert candidate["matched"] is False
    assert _reason_codes(diagnostic) == {"command_normalization_failed"}
    assert workflows.matching_workflows(
        [sys.executable, "-c", "print('not a script workflow')"], str(tmp_path),
    ) == []


def test_diagnostics_report_runtime_path_hash_and_argument_mismatches(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('same bytes')\n", encoding="utf-8")
    _trust_manifest(tmp_path, script, args=["trusted-value"])

    argument_diagnostic = workflows.diagnose_matching_workflows(
        [sys.executable, str(script), "private-value"], str(tmp_path),
    )
    assert _reason_codes(argument_diagnostic) == {"arguments_mismatch"}
    argument_reason = argument_diagnostic["candidates"][0]["mismatch_reasons"][0]
    assert argument_reason["expected_count"] == 1
    assert argument_reason["actual_count"] == 1
    assert "private-value" not in json.dumps(argument_reason)
    assert "args" not in argument_diagnostic["normalized"]
    assert argument_diagnostic["normalized"]["argument_hashes"] == [{
        "index": 0,
        "sha256": hashlib.sha256(b"private-value").hexdigest(),
    }]
    assert "private-value" not in json.dumps(argument_diagnostic)

    runtime_diagnostic = workflows.diagnose_matching_workflows(
        ["node", str(script), "trusted-value"], str(tmp_path),
    )
    assert _reason_codes(runtime_diagnostic) == {"runtime_mismatch"}

    same_bytes = tmp_path / "other.py"
    same_bytes.write_bytes(script.read_bytes())
    path_diagnostic = workflows.diagnose_matching_workflows(
        [sys.executable, str(same_bytes), "trusted-value"], str(tmp_path),
    )
    assert _reason_codes(path_diagnostic) == {"script_path_mismatch"}

    script.write_text("print('changed')\n", encoding="utf-8")
    hash_diagnostic = workflows.diagnose_matching_workflows(
        [sys.executable, str(script), "trusted-value"], str(tmp_path),
    )
    assert _reason_codes(hash_diagnostic) == {"script_hash_mismatch"}


def test_parameter_mismatch_diagnostics_do_not_echo_candidate_values(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    _trust_manifest(
        tmp_path,
        script,
        schema=workflows.PARAMETERIZED_SCHEMA,
        args=[{"parameter": "mode"}],
        parameters={"mode": {"type": "enum", "values": ["approved"]}},
    )

    diagnostic = workflows.diagnose_matching_workflows(
        [sys.executable, str(script), "private-unapproved-value"], str(tmp_path),
    )

    assert _reason_codes(diagnostic) == {"parameters_mismatch"}
    reason = diagnostic["candidates"][0]["mismatch_reasons"][0]
    assert reason["cause_code"] == "workflow_trust_error"
    assert "private-unapproved-value" not in json.dumps(reason)
    assert "approved" not in json.dumps(reason)


def test_diagnostics_include_unverified_records_without_hiding_valid_matches(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    _trust_manifest(tmp_path, script, args=["same"])
    trust_dir = tmp_path / "agw-home" / "trusted-workflows"
    (trust_dir / "broken.json").write_text("not json", encoding="utf-8")

    command = [sys.executable, str(script), "same"]
    diagnostic = workflows.diagnose_matching_workflows(command, str(tmp_path))

    assert diagnostic["ok"] is True
    assert diagnostic["candidate_count"] == 2
    assert diagnostic["matches"] == ["example.diagnostic"]
    assert workflows.matching_workflows(command, str(tmp_path)) == [
        "example.diagnostic"
    ]
    invalid = next(item for item in diagnostic["candidates"] if not item["verified"])
    assert invalid["record"] == "broken.json"
    assert invalid["mismatch_reasons"] == [{
        "code": "unverified_record",
        "message": "trusted workflow record could not be verified",
    }]


def test_diagnostics_preserve_ambiguity_for_legacy_match_helpers(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    command = [sys.executable, str(script), "same"]
    for workflow_id in ("example.alpha", "example.beta"):
        _trust_manifest(tmp_path, script, workflow_id=workflow_id, args=["same"])

    diagnostic = workflows.diagnose_matching_workflows(command, str(tmp_path))

    assert diagnostic["matches"] == ["example.alpha", "example.beta"]
    assert workflows.matching_workflows(command, str(tmp_path)) == diagnostic["matches"]
    assert workflows.matching_workflow(command, str(tmp_path)) == ""
    assert diagnostic["recommended_argv"] == []
    assert diagnostic["suggested_argv"] == {
        "deprecated": True,
        "replacement": "recommended_argv",
        "value_included": False,
    }


def test_diagnostics_classify_and_rank_candidates_deterministically(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    other = tmp_path / "other.py"
    other.write_text("print('other')\n", encoding="utf-8")
    _trust_manifest(
        tmp_path, script, workflow_id="z.exact", args=["approved"],
    )
    _trust_manifest(
        tmp_path, script, workflow_id="a.parameterizable",
        schema=workflows.PARAMETERIZED_SCHEMA,
        args=[{"parameter": "mode"}],
        parameters={"mode": {"type": "enum", "values": ["approved"]}},
    )
    _trust_manifest(
        tmp_path, script, workflow_id="a.near", args=["different"],
    )
    _trust_manifest(
        tmp_path, other, workflow_id="a.incompatible", args=["approved"],
    )

    diagnostic = workflows.diagnose_matching_workflows(
        [sys.executable, str(script), "approved"], str(tmp_path),
    )

    assert [item["id"] for item in diagnostic["candidates"]] == [
        "z.exact", "a.parameterizable", "a.near", "a.incompatible",
    ]
    assert [item["candidate_class"] for item in diagnostic["candidates"]] == [
        "exact", "parameterizable", "near", "incompatible",
    ]
    assert [item["rank"] for item in diagnostic["candidates"]] == [1, 2, 3, 4]
    assert [item["rank_key"] for item in diagnostic["candidates"]] == [
        [0, 0, "z.exact"],
        [1, 0, "a.parameterizable"],
        [2, 1, "a.near"],
        [3, 2, "a.incompatible"],
    ]
    assert [item["confidence"] for item in diagnostic["candidates"]] == [
        "high", "high", "medium", "none",
    ]
    near = diagnostic["candidates"][2]
    assert near["remaining_differences"] == ["arguments_mismatch"]
    assert near["remaining_difference_count"] == 1
    # Two equally valid candidates remain explicit; ranking is not authorization.
    assert diagnostic["recommended_argv"] == []
    assert diagnostic["suggested_argv"]["replacement"] == "recommended_argv"


def test_parameterized_recommendation_is_revalidated_and_candidate_is_private(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    private_value = "private-approved-value"
    _trust_manifest(
        tmp_path, script, workflow_id="example.parameterized",
        schema=workflows.PARAMETERIZED_SCHEMA,
        args=["--mode", {"parameter": "mode"}],
        parameters={"mode": {"type": "enum", "values": [private_value]}},
    )
    command = [
        sys.executable, str(script), "--mode", private_value,
    ]

    diagnostic = workflows.diagnose_matching_workflows(command, str(tmp_path))

    candidate = diagnostic["candidates"][0]
    assert candidate["candidate_class"] == "parameterizable"
    assert candidate["confidence"] == "high"
    assert candidate["remaining_differences"] == []
    assert candidate["inferred_parameters"] == [{
        "name": "mode",
        "source_indexes": [1],
        "constraints": {"type": "enum", "allowed_count": 1},
        "value_sha256": hashlib.sha256(private_value.encode("utf-8")).hexdigest(),
    }]
    assert private_value not in json.dumps(candidate)
    assert diagnostic["recommended_argv"] == [
        "agw", "run", "--workflow", "example.parameterized", "--", *command,
    ]
    assert diagnostic["suggested_argv"] == {
        "deprecated": True,
        "replacement": "recommended_argv",
        "value_included": False,
    }
    assert json.dumps(diagnostic).count(private_value) == 1


def test_recommendation_requires_equivalent_second_resolution(tmp_path, monkeypatch):
    script = tmp_path / "writer.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    _trust_manifest(tmp_path, script, args=["approved"])
    command = [sys.executable, str(script), "approved"]
    original = workflows.resolve_run
    calls = 0

    def changing_resolver(*args, **kwargs):
        nonlocal calls
        calls += 1
        resolved = original(*args, **kwargs)
        if calls == 2:
            resolved = dict(resolved)
            resolved["output_patterns"] = ["unexpected-*.txt"]
        return resolved

    monkeypatch.setattr(workflows, "resolve_run", changing_resolver)
    diagnostic = workflows.diagnose_matching_workflows(command, str(tmp_path))

    candidate = diagnostic["candidates"][0]
    assert calls == 2
    assert candidate["matched"] is True  # diagnostic-v1 compatibility
    assert candidate["candidate_class"] == "exact"
    assert candidate["confidence"] == "none"
    assert candidate["remaining_differences"] == ["identity_changed"]
    assert diagnostic["recommended_argv"] == []
    assert diagnostic["suggested_argv"]["value_included"] is False
