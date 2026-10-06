"""Per-run observed roots for generators (render folders, bundle directories).

Exact outputs (`outputs[].path`, which may use `{param:...}`) keep verified
pre-images. A generator's incidental files are declared with `observed_roots`
plus relative `patterns`: they are inventoried as `ignored_sidecar_changes`
rather than silently accepted, and anything else that changes under the root
is reported as unclaimed and fails the run. A v3 manifest may now take that
root from a reviewed directory `path` parameter, so one workflow can serve many
project folders without observing (or trusting) all of them at once.
"""
import json
import sys

import pytest

import file_ops
from core import store, workflows


GENERATOR = (
    "import os, sys\n"
    "out, renders, extra = sys.argv[1], sys.argv[2], sys.argv[3]\n"
    "os.makedirs(os.path.join(renders, 'frames'), exist_ok=True)\n"
    "open(os.path.join(renders, 'frames', 'f001.png'), 'w').write('frame')\n"
    "open(out, 'w').write('video')\n"
    "if extra != 'none':\n"
    "    open(os.path.join(renders, extra), 'w').write('stray')\n"
)


def _manifest(tmp_path, *, observed_path="{param:renders}", renders_spec=None,
              allowed=None, schema="agw.workflow/v3", output_spec=None):
    script = tmp_path / "generator.py"
    script.write_text(GENERATOR, encoding="utf-8")
    manifest = {
        "schema": schema,
        "id": "example.generator",
        "description": "write one exact output plus pattern-matched sidecars",
        "command": {
            "runtime": "python", "script": script.name,
            "script_sha256": store.file_sha256(str(script)),
            "args": [{"parameter": "output"}, {"parameter": "renders"},
                     {"parameter": "extra"}],
        },
        "parameters": {
            "output": output_spec or {"type": "path", "root": "{cwd}/projects",
                                      "must_exist": False, "kind": "file"},
            "renders": renders_spec or {"type": "path", "root": "{cwd}/projects",
                                        "must_exist": True, "kind": "directory"},
            "extra": {"type": "regex", "pattern": "[a-z.]+"},
        },
        "allowed_roots": allowed or ["{cwd}/projects"],
        "outputs": [{"path": "{param:output}", "expected": "any"}],
        "observed_roots": [{"path": observed_path, "patterns": ["frames/*", "frames"]}],
    }
    path = tmp_path / "generator.workflow.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path, store.file_sha256(str(path))


def _run(tmp_path, renders, output, extra="none"):
    resolved = workflows.resolve_run(
        "example.generator", [], str(tmp_path),
        parameters={"output": str(output), "renders": str(renders), "extra": extra},
    )
    return resolved, file_ops.run_declared(
        resolved["command"], resolved["outputs"],
        expected_hashes=resolved["expected_hashes"], cwd=resolved["cwd"],
        output_roots=resolved["output_roots"],
        output_patterns=resolved["output_patterns"],
        optional_outputs=resolved["optional_outputs"],
        allow_missing_output_parents=True,
    )


def _project(tmp_path, slug="alpha"):
    renders = tmp_path / "projects" / slug / "renders"
    renders.mkdir(parents=True)
    return renders


def test_parameter_root_inventories_sidecars_and_preimages_the_exact_output(tmp_path):
    renders = _project(tmp_path)
    output = renders / "short.mp4"
    output.write_text("previous render", encoding="utf-8")
    other = _project(tmp_path, "beta")
    (other / "untouched.mp4").write_text("other project", encoding="utf-8")
    path, digest = _manifest(tmp_path)
    workflows.trust_manifest(str(path), digest)

    resolved, result = _run(tmp_path, renders, output)
    assert resolved["output_roots"] == [str(renders)]
    assert result["ok"] is True, result
    assert output.read_text() == "video"
    # The overwritten exact output has a verified pre-image to restore from.
    assert result["outputs"][0]["before_hash"] != "absent"
    assert result["outputs"][0]["snapshot_transaction_id"]
    ignored = {item["relative_path"] for item in result["ignored_sidecar_changes"]}
    assert ignored == {"frames", "frames/f001.png"}
    assert result["unclaimed_observed_changes"] == []


def test_unmatched_change_under_the_parameter_root_fails_the_run(tmp_path):
    renders = _project(tmp_path)
    path, digest = _manifest(tmp_path)
    workflows.trust_manifest(str(path), digest)
    _, result = _run(tmp_path, renders, renders / "short.mp4", extra="stray.txt")
    assert result["ok"] is False
    assert [item["path"] for item in result["unclaimed_observed_changes"]] == \
        [str(renders / "stray.txt")]


def test_parameter_root_must_stay_inside_allowed_roots(tmp_path):
    renders = _project(tmp_path)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    path, digest = _manifest(
        tmp_path,
        renders_spec={"type": "path", "root": "{cwd}", "must_exist": True,
                      "kind": "directory"},
    )
    workflows.trust_manifest(str(path), digest)
    with pytest.raises(workflows.WorkflowTrustError, match="outside permitted roots"):
        _run(tmp_path, outside, renders / "short.mp4")


@pytest.mark.parametrize("observed_path, renders_spec, match", [
    ("{param:extra}", None, "path` parameter"),
    ("{param:output}", None, "path` parameter"),
    ("{param:renders:basename}", None, "path` parameter"),
])
def test_only_unmodified_directory_path_parameters_may_name_a_root(
        tmp_path, observed_path, renders_spec, match):
    path, digest = _manifest(tmp_path, observed_path=observed_path,
                             renders_spec=renders_spec)
    with pytest.raises(workflows.WorkflowError, match=match):
        workflows.validate_manifest_file(str(path), digest)


RENDER_PATTERN = "[a-z0-9][a-z0-9-]*/renders/[A-Za-z0-9][A-Za-z0-9._-]*[.]mp4"


def test_path_pattern_confines_an_output_to_one_kind_of_file(tmp_path):
    renders = _project(tmp_path)
    (tmp_path / "projects" / "alpha" / "source.json").write_text("{}")
    path, digest = _manifest(tmp_path, output_spec={
        "type": "path", "root": "{cwd}/projects", "must_exist": False,
        "kind": "file", "pattern": RENDER_PATTERN,
    })
    validated = workflows.validate_manifest_file(str(path), digest)
    assert validated["manifest"]["parameters"]["output"]["pattern"] == RENDER_PATTERN
    workflows.trust_manifest(str(path), digest)

    _, result = _run(tmp_path, renders, renders / "short-v2.mp4")
    assert result["ok"] is True
    for bad in (tmp_path / "projects" / "alpha" / "source.json",
                renders / "short.mov",
                renders / "nested" / "short.mp4",
                renders / ".." / ".." / "beta" / "renders" / "x.txt"):
        with pytest.raises(workflows.WorkflowTrustError, match="path pattern"):
            _run(tmp_path, renders, bad)


def test_path_pattern_absent_keeps_existing_normalization(tmp_path):
    path, digest = _manifest(tmp_path)
    validated = workflows.validate_manifest_file(str(path), digest)
    assert "pattern" not in validated["manifest"]["parameters"]["output"]


def test_path_pattern_uses_the_safe_regex_rules(tmp_path):
    path, digest = _manifest(tmp_path, output_spec={
        "type": "path", "root": "{cwd}/projects", "must_exist": False,
        "kind": "file", "pattern": "(a|b)/renders/.*",
    })
    with pytest.raises(workflows.WorkflowError, match="grouping"):
        workflows.validate_manifest_file(str(path), digest)


def test_v2_observed_roots_still_cannot_use_parameters(tmp_path):
    script = tmp_path / "generator.py"
    script.write_text(GENERATOR, encoding="utf-8")
    manifest = {
        "schema": "agw.workflow/v2", "id": "example.v2", "description": "",
        "command": {"runtime": "python", "script": script.name,
                    "script_sha256": store.file_sha256(str(script)), "args": []},
        "allowed_roots": ["{cwd}"],
        "outputs": [{"path": "{cwd}/out.txt", "expected": "any"}],
        "observed_roots": [{"path": "{param:renders}", "patterns": ["*"]}],
    }
    path = tmp_path / "v2.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(workflows.WorkflowError, match="workflow parameters"):
        workflows.validate_manifest_file(str(path))
