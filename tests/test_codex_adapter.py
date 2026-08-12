"""Codex adapter contract tests: real subprocess, Codex hook JSON in, decision
JSON out. Mirrors test_adapter.py but exercises the apply_patch path that has no
Claude equivalent."""
import base64
import importlib.util
import json
import os
import shlex
import subprocess
import sys

import pytest

REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugin")
PRE = os.path.join(REPO, "scripts", "codex", "pretooluse.py")
AGW_SOURCE = os.path.join(REPO, "scripts", "agw", "agw.py")
sys.path.insert(0, os.path.join(REPO, "scripts"))


def run_hook(payload, env_extra=None):
    # Codex sets PLUGIN_ROOT (and CLAUDE_PLUGIN_ROOT for compat); use the
    # Codex-native one so we exercise the same env the real host provides.
    env = dict(os.environ, PLUGIN_ROOT=REPO, CODEX_HOME=os.path.expanduser("~/.codex"),
               AGW_APPROVAL_PROVIDER="headless", AGW_TEST_MODE="1")
    if env_extra:
        env.update(env_extra)
    payload.setdefault("hook_event_name", "PreToolUse")
    result = subprocess.run([sys.executable, PRE], input=json.dumps(payload),
                            capture_output=True, text=True, env=env, timeout=30)
    assert result.returncode == 0, f"hook crashed the wrapper: {result.stderr}"
    return json.loads(result.stdout) if result.stdout.strip() else {}


def _decision(out):
    return out.get("hookSpecificOutput", {}).get("permissionDecision", "defer")


def _reason(out):
    return out.get("hookSpecificOutput", {}).get("permissionDecisionReason", "")


def _load_codex_pretooluse_isolated():
    """Load the adapter without reusing Claude's top-level adapter_common."""
    module_path = os.path.join(REPO, "scripts", "codex", "pretooluse.py")
    previous_adapter = sys.modules.pop("adapter_common", None)
    previous_path = list(sys.path)
    try:
        spec = importlib.util.spec_from_file_location(
            "_agw_test_codex_pretooluse", module_path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path[:] = previous_path
        sys.modules.pop("adapter_common", None)
        if previous_adapter is not None:
            sys.modules["adapter_common"] = previous_adapter


# --- apply_patch envelope parser ---------------------------------------------

def test_parse_patch_add_update_delete():
    from codex.applypatch import parse_patch
    patch = (
        "*** Begin Patch\n"
        "*** Add File: new.txt\n"
        "+hello\n+world\n"
        "*** Update File: existing.py\n"
        "@@ def f():\n-    old\n+    new\n"
        "*** Delete File: gone.txt\n"
        "*** End Patch\n"
    )
    files = parse_patch(patch)
    by_path = {f["path"]: f for f in files}
    assert by_path["new.txt"]["op"] == "add"
    assert by_path["new.txt"]["added"] == "hello\nworld"
    assert by_path["existing.py"]["op"] == "update"
    assert by_path["existing.py"]["added"] == "    new"  # indentation preserved
    assert by_path["gone.txt"]["op"] == "delete"


def test_parse_patch_move_to():
    from codex.applypatch import parse_patch
    patch = ("*** Update File: a.py\n*** Move to: b.py\n+x\n")
    files = parse_patch(patch)
    assert files[0]["op"] == "update"
    assert files[0]["move_to"] == "b.py"


def test_parse_patch_garbage_is_empty():
    from codex.applypatch import parse_patch
    assert parse_patch("not a patch at all") == []
    assert parse_patch("") == []


# --- shell path (identical contract to Claude) -------------------------------

def test_bash_rm_denied():
    out = run_hook({"tool_name": "Bash", "tool_input": {"command": "rm -rf /tmp/x"},
                    "cwd": "/tmp", "session_id": "c1"})
    assert _decision(out) == "deny"
    assert "agw archive" in _reason(out)
    assert "Recommended argv (submit as a new operation" in _reason(out)


def test_active_agw_python_help_is_not_treated_as_opaque_script():
    out = run_hook({
        "tool_name": "PowerShell",
        "tool_input": {
            "command": f'"{sys.executable}" "{AGW_SOURCE}" checkout --help'
        },
        "cwd": REPO,
        "session_id": "active-agw-source-help",
    })
    assert _decision(out) != "deny"
    assert "pre-execution output contract" not in _reason(out)


@pytest.mark.parametrize("tool", ["Bash", "PowerShell"])
def test_short_agw_is_rewritten_to_active_package(tool):
    out = run_hook({
        "tool_name": tool,
        "tool_input": {"command": "agw status --json", "description": "status"},
        "cwd": REPO,
        "session_id": f"short-agw-{tool}",
    })
    specific = out["hookSpecificOutput"]
    assert specific["permissionDecision"] == "allow"
    updated = specific["updatedInput"]
    assert updated["description"] == "status"
    expected = "agw.cmd" if os.name == "nt" else os.path.join("bin", "agw")
    assert expected in updated["command"]
    assert updated["command"].endswith(" status --json")


def test_exact_trusted_workflow_is_automatically_routed(tmp_path):
    from core import launcher, store, workflows

    script = tmp_path / "writer.py"
    script.write_text(
        "from pathlib import Path\nPath('out.txt').write_text('x')\n",
        encoding="utf-8",
    )
    manifest = {
        "schema": "agw.workflow/v2",
        "id": "example.auto-route",
        "description": "automatic routing test",
        "command": {
            "runtime": "python", "script": str(script),
            "script_sha256": store.file_sha256(str(script)),
            "args": ["out.txt"],
        },
        "allowed_roots": ["{cwd}"],
        "outputs": [{"path": "{cwd}/out.txt", "expected": "absent"}],
        "observed_roots": [],
    }
    manifest_path = tmp_path / "workflow.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    workflows.trust_manifest(
        str(manifest_path), store.file_sha256(str(manifest_path)),
    )
    original_argv = [sys.executable, str(script), "out.txt"]
    command = subprocess.list2cmdline(original_argv) if os.name == "nt" \
        else shlex.join(original_argv)
    out = run_hook({
        "tool_name": "PowerShell" if os.name == "nt" else "Bash",
        "tool_input": {"command": command, "description": "build output"},
        "cwd": str(tmp_path), "session_id": "trusted-auto-route",
    })
    specific = out["hookSpecificOutput"]
    assert specific["permissionDecision"] == "allow"
    assert "example.auto-route" in specific["permissionDecisionReason"]
    updated = specific["updatedInput"]
    assert updated["description"] == "build output"
    if os.name == "nt":
        encoded = updated["command"].rsplit("'", 2)[1]
    else:
        encoded = shlex.split(updated["command"])[-1]
    assert launcher.decode_internal_argv(["--agw-argv-b64", encoded]) == [
        "run", "--workflow", "example.auto-route", "--", *original_argv,
    ]


def test_multiple_trusted_workflows_are_not_automatically_routed(tmp_path):
    from core import store, workflows

    script = tmp_path / "writer.py"
    script.write_text(
        "from pathlib import Path\nPath('out.txt').write_text('x')\n",
        encoding="utf-8",
    )
    for workflow_id in ("example.route-alpha", "example.route-beta"):
        manifest = {
            "schema": "agw.workflow/v2", "id": workflow_id,
            "description": "ambiguous routing test",
            "command": {
                "runtime": "python", "script": str(script),
                "script_sha256": store.file_sha256(str(script)),
                "args": ["out.txt"],
            },
            "allowed_roots": ["{cwd}"],
            "outputs": [{"path": "{cwd}/out.txt", "expected": "absent"}],
            "observed_roots": [],
        }
        manifest_path = tmp_path / f"{workflow_id}.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        workflows.trust_manifest(
            str(manifest_path), store.file_sha256(str(manifest_path)),
        )
    argv = [sys.executable, str(script), "out.txt"]
    command = subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv)
    out = run_hook({
        "tool_name": "PowerShell" if os.name == "nt" else "Bash",
        "tool_input": {"command": command}, "cwd": str(tmp_path),
        "session_id": "ambiguous-auto-route",
    })
    specific = out["hookSpecificOutput"]
    assert specific["permissionDecision"] == "deny"
    assert "updatedInput" not in specific
    assert "multiple trusted output contracts" in specific["permissionDecisionReason"]


def test_stale_trusted_workflow_is_not_automatically_routed(tmp_path):
    from core import store, workflows

    script = tmp_path / "writer.py"
    script.write_text(
        "from pathlib import Path\nPath('out.txt').write_text('trusted')\n",
        encoding="utf-8",
    )
    manifest = {
        "schema": "agw.workflow/v2", "id": "example.stale-route",
        "description": "stale routing test",
        "command": {
            "runtime": "python", "script": str(script),
            "script_sha256": store.file_sha256(str(script)), "args": ["out.txt"],
        },
        "allowed_roots": ["{cwd}"],
        "outputs": [{"path": "{cwd}/out.txt", "expected": "absent"}],
        "observed_roots": [],
    }
    manifest_path = tmp_path / "stale-workflow.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    workflows.trust_manifest(
        str(manifest_path), store.file_sha256(str(manifest_path)),
    )
    script.write_text(
        "from pathlib import Path\nPath('out.txt').write_text('changed')\n",
        encoding="utf-8",
    )
    argv = [sys.executable, str(script), "out.txt"]
    command = subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv)
    out = run_hook({
        "tool_name": "PowerShell" if os.name == "nt" else "Bash",
        "tool_input": {"command": command}, "cwd": str(tmp_path),
        "session_id": "stale-auto-route",
    })
    specific = out["hookSpecificOutput"]
    assert specific["permissionDecision"] == "deny"
    assert "updatedInput" not in specific
    assert "pre-execution output contract" in specific["permissionDecisionReason"]


def test_ambiguous_script_evidence_is_shadowed_in_observe_mode(tmp_path):
    script = tmp_path / "model.py"
    script.write_text(
        "class Model:\n    def save(self): return True\nModel().save()\n",
        encoding="utf-8",
    )
    argv = [sys.executable, str(script)]
    command = subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv)
    out = run_hook({
        "tool_name": "PowerShell" if os.name == "nt" else "Bash",
        "tool_input": {"command": command}, "cwd": str(tmp_path),
        "session_id": "ambiguous-observe",
    }, env_extra={"AGW_LEVEL": "observe"})
    assert "hookSpecificOutput" not in out
    assert "would have ASK" in out["systemMessage"]
    assert "ambiguous" in out["systemMessage"].lower()


@pytest.mark.skipif(os.name != "nt", reason="PowerShell launcher rewrite is Windows-only")
def test_short_agw_pipeline_receiver_is_rewritten_to_active_package(tmp_path):
    out = run_hook({
        "tool_name": "PowerShell",
        "tool_input": {
            "command": (
                "@'\nfirst row\nsecond row\n'@ | agw file write "
                "'ledger.txt' --content-file - --expected-hash absent --json"
            ),
            "description": "write ledger",
        },
        "cwd": str(tmp_path),
        "session_id": "short-agw-pipeline-codex",
    })
    specific = out["hookSpecificOutput"]
    assert specific["permissionDecision"] == "allow"
    updated = specific["updatedInput"]
    assert updated["description"] == "write ledger"
    assert "| & '" in updated["command"]
    assert "bin\\agw.cmd' file write 'ledger.txt'" in updated["command"]
    assert "| agw file write" not in updated["command"]


@pytest.mark.skipif(os.name != "nt", reason="PowerShell launcher rewrite is Windows-only")
def test_short_agw_later_statement_is_rewritten_to_active_package(tmp_path):
    out = run_hook({
        "tool_name": "PowerShell",
        "tool_input": {
            "command": (
                "$oldText = 'before'; $newText = 'after'; "
                "agw file replace 'ledger.txt' --old $oldText --new $newText "
                "--dry-run --json"
            ),
            "description": "validate replacement",
        },
        "cwd": str(tmp_path),
        "session_id": "short-agw-statement-codex",
    })
    specific = out["hookSpecificOutput"]
    assert specific["permissionDecision"] == "allow"
    updated = specific["updatedInput"]
    assert updated["description"] == "validate replacement"
    assert "; & '" in updated["command"]
    assert "bin\\agw.cmd' file replace 'ledger.txt'" in updated["command"]
    assert "; agw file replace" not in updated["command"]


@pytest.mark.skipif(os.name != "nt", reason="PowerShell launcher rewrite is Windows-only")
def test_pipeline_rewrite_never_hides_a_denied_later_statement():
    out = run_hook({
        "tool_name": "PowerShell",
        "tool_input": {
            "command": "Write-Output x | agw status; Remove-Item important.txt"
        },
        "cwd": REPO,
        "session_id": "short-agw-pipeline-compound-codex",
    })
    specific = out["hookSpecificOutput"]
    assert specific["permissionDecision"] == "deny"
    assert "updatedInput" not in specific


@pytest.mark.skipif(os.name != "nt", reason="PowerShell launcher rewrite is Windows-only")
def test_statement_rewrite_never_hides_a_denied_earlier_statement():
    out = run_hook({
        "tool_name": "PowerShell",
        "tool_input": {
            "command": "Remove-Item important.txt; agw status"
        },
        "cwd": REPO,
        "session_id": "short-agw-statement-compound-codex",
    })
    specific = out["hookSpecificOutput"]
    assert specific["permissionDecision"] == "deny"
    assert "updatedInput" not in specific


def test_short_agw_rewrite_never_hides_a_denied_compound_command():
    out = run_hook({
        "tool_name": "PowerShell",
        "tool_input": {"command": "agw status; Remove-Item important.txt"},
        "cwd": REPO,
        "session_id": "short-agw-compound-deny",
    })
    specific = out["hookSpecificOutput"]
    assert specific["permissionDecision"] == "deny"
    assert "updatedInput" not in specific


def test_bash_benign_defers():
    out = run_hook({"tool_name": "Bash", "tool_input": {"command": "git status"},
                    "cwd": "/tmp", "session_id": "c1"})
    assert _decision(out) == "defer"


def test_codex_project_keyword_search_is_allowed_without_prompt():
    out = run_hook({
        "tool_name": "PowerShell",
        "tool_input": {
            "command": r"Select-String -Path tests\*.py -Pattern credential -Recurse"
        },
        "cwd": os.path.dirname(REPO),
        "session_id": "project-diagnostic",
    })
    assert _decision(out) == "allow"


def test_codex_unknown_agw_verb_denies_without_invoking_provider(
        monkeypatch, capsys, tmp_path):
    import io
    from core.approvals import ApprovalProvider

    ptu = _load_codex_pretooluse_isolated()
    canary = "PRIVATE-CANARY-unknown-argument"
    payload = {
        "tool_name": "PowerShell" if os.name == "nt" else "Bash",
        "tool_input": {"command": f"agw future-operation {canary}"},
        "cwd": str(tmp_path), "session_id": "unknown-agw",
        "event_id": "unknown-agw-event", "hook_event_name": "PreToolUse",
    }

    class MustNotRun(ApprovalProvider):
        def request(self, request):
            raise AssertionError("unknown AGW verbs must not open an approval UI")

    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    ptu.main(MustNotRun())
    out = json.loads(capsys.readouterr().out)
    assert _decision(out) == "deny"
    reason = _reason(out)
    assert "future-operation" in reason
    assert "Use `agw --help`" in reason
    assert canary not in reason


def test_codex_native_discovery_routes_broad_and_strict_shapes(tmp_path):
    project = tmp_path / "project"
    (project / ".git").mkdir(parents=True)
    (project / "src").mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    home = tmp_path / "home"

    local = run_hook({
        "tool_name": "Grep",
        "tool_input": {"pattern": "TODO", "path": str(project / "src")},
        "cwd": str(project), "session_id": "codex-native-local",
    }, env_extra={"AGW_HOME": str(home), "AGW_LEVEL": "standard"})
    assert _decision(local) != "deny"

    broad = run_hook({
        "tool_name": "Glob",
        "tool_input": {"pattern": "**/*.py", "path": str(outside)},
        "cwd": str(project), "session_id": "codex-native-broad",
    }, env_extra={"AGW_HOME": str(home), "AGW_LEVEL": "standard"})
    assert _decision(broad) == "deny"
    assert "agw list" in _reason(broad)

    strict = run_hook({
        "tool_name": "Grep",
        "tool_input": {"pattern": "TODO", "path": str(project / "src")},
        "cwd": str(project), "session_id": "codex-native-strict",
    }, env_extra={"AGW_HOME": str(home), "AGW_LEVEL": "strict"})
    assert _decision(strict) == "deny"


def test_codex_monitor_requires_literal_command_field():
    out = run_hook({
        "tool_name": "Monitor",
        "tool_input": {"command": {"unexpected": "shape"}},
        "cwd": os.path.dirname(REPO),
        "session_id": "monitor-contract",
    })
    assert _decision(out) == "deny"


@pytest.mark.parametrize("tool", ["PowerShell", "Monitor"])
def test_codex_shell_surfaces_deny_destructive_commands(tool):
    command = "Remove-Item important.txt" if tool == "PowerShell" else "rm important.txt"
    out = run_hook({"tool_name": tool, "tool_input": {"command": command},
                    "cwd": "/tmp", "session_id": "c-shell"})
    assert _decision(out) == "deny"


# --- apply_patch behaviour ----------------------------------------------------

def test_apply_patch_delete_is_denied():
    patch = "*** Begin Patch\n*** Delete File: /tmp/whatever.txt\n*** End Patch\n"
    out = run_hook({"tool_name": "apply_patch", "tool_input": {"command": patch},
                    "cwd": "/tmp", "session_id": "c1"})
    assert _decision(out) == "deny"
    assert "agw archive" in _reason(out)


def test_apply_patch_add_defers_and_is_allowed():
    patch = "*** Begin Patch\n*** Add File: /tmp/codex_new.txt\n+content\n*** End Patch\n"
    out = run_hook({"tool_name": "apply_patch", "tool_input": {"command": patch},
                    "cwd": "/tmp", "session_id": "c1"})
    assert _decision(out) in ("defer", "allow")


def test_apply_patch_update_snapshots_pre_image(tmp_path):
    target = tmp_path / "doc.txt"
    target.write_text("precious original")
    home = tmp_path / "home"
    patch = (f"*** Begin Patch\n*** Update File: {target}\n"
             f"@@\n-precious original\n+rewritten\n*** End Patch\n")
    out = run_hook({"tool_name": "apply_patch", "tool_input": {"command": patch},
                    "cwd": str(tmp_path), "session_id": "c1"},
                   env_extra={"AGW_HOME": str(home)})
    assert _decision(out) in ("defer", "allow")
    archived = []
    for dirpath, _dirs, files in os.walk(home / "archive"):
        archived += [os.path.join(dirpath, f) for f in files if "doc.txt" in f]
    assert archived, "pre-image snapshot missing for apply_patch update"
    assert any(open(p).read() == "precious original" for p in archived
               if not p.endswith(".jsonl"))


def test_apply_patch_update_relative_path_snapshots_against_cwd(tmp_path):
    # Probe 13 regression: apply_patch carries paths RELATIVE to the patch cwd.
    # The snapshot must resolve them against the event's cwd, not the hook
    # process cwd, or no pre-image is taken and the original is lost on overwrite.
    work = tmp_path / "workspace"
    (work / "reports").mkdir(parents=True)
    target = work / "reports" / "q3-summary.txt"
    target.write_text("precious original")
    home = tmp_path / "home"
    patch = ("*** Begin Patch\n*** Update File: reports/q3-summary.txt\n"
             "@@\n-precious original\n+rewritten\n*** End Patch\n")
    out = run_hook({"tool_name": "apply_patch", "tool_input": {"command": patch},
                    "cwd": str(work), "session_id": "c1"},
                   env_extra={"AGW_HOME": str(home)})
    assert _decision(out) in ("defer", "allow")
    archived = []
    for dirpath, _dirs, files in os.walk(home / "archive"):
        archived += [os.path.join(dirpath, f) for f in files if "q3-summary" in f]
    assert archived, "pre-image snapshot missing for cwd-relative apply_patch path"
    assert any(open(p).read() == "precious original" for p in archived
               if not p.endswith(".jsonl"))


def test_codex_ask_resolves_via_injected_provider(monkeypatch, capsys, tmp_path):
    # In-process: ASK is resolved by an injected provider. No native UI is ever
    # initialized by this test.
    import io
    from core.approvals import ApprovalProvider, ApprovalResponse
    ptu = _load_codex_pretooluse_isolated()
    target = tmp_path / "board-notes.txt"
    target.write_text("CONFIDENTIAL: board planning material")
    payload = {"tool_name": "Read", "tool_input": {"file_path": str(target)},
               "cwd": str(tmp_path), "session_id": "c1",
               "hook_event_name": "PreToolUse"}

    class FixedProvider(ApprovalProvider):
        def __init__(self, approved):
            self.approved = approved

        def request(self, request):
            return ApprovalResponse(self.approved,
                                    "approved" if self.approved else "denied")

    monkeypatch.setenv("AGW_HOME", str(tmp_path / "home"))
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    ptu.main(FixedProvider(True))
    out = capsys.readouterr().out
    data = json.loads(out) if out.strip() else {}
    assert data.get("hookSpecificOutput", {}).get("permissionDecision") != "deny"

    payload["session_id"] = "c2"
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    ptu.main(FixedProvider(False))
    data = json.loads(capsys.readouterr().out)
    assert data["hookSpecificOutput"]["permissionDecision"] == "deny"
    reason = data["hookSpecificOutput"]["permissionDecisionReason"]
    assert "Do not retry the same operation" in reason
    assert "recommend the safest way to continue" in reason


def test_ambiguous_script_evidence_uses_one_run_approval(monkeypatch, capsys, tmp_path):
    import io
    from core.approvals import ApprovalProvider, ApprovalResponse

    ptu = _load_codex_pretooluse_isolated()
    script = tmp_path / "model.py"
    script.write_text(
        "class Model:\n"
        "    def save(self): return True\n"
        "Model().save()\n",
        encoding="utf-8",
    )
    payload = {
        "tool_name": "PowerShell" if os.name == "nt" else "Bash",
        "tool_input": {"command": subprocess.list2cmdline([
            sys.executable, str(script),
        ]) if os.name == "nt" else shlex.join([sys.executable, str(script)])},
        "cwd": str(tmp_path), "session_id": "ambiguous-script",
        "hook_event_name": "PreToolUse",
    }

    class CapturingApproval(ApprovalProvider):
        def __init__(self):
            self.requests = []

        def request(self, request):
            self.requests.append(request)
            return ApprovalResponse(True, "approved")

    provider = CapturingApproval()
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    ptu.main(provider)
    output = capsys.readouterr().out
    result = json.loads(output) if output.strip() else {}
    assert provider.requests
    assert result.get("hookSpecificOutput", {}).get("permissionDecision") != "deny"
    rendered = provider.requests[0].action + "\n" + provider.requests[0].primary_text()
    assert "ambiguous" in rendered.lower()

    monkeypatch.setenv("AGW_LEVEL", "strict")
    payload["session_id"] = "ambiguous-script-strict"
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    ptu.main(provider)
    strict_result = json.loads(capsys.readouterr().out)
    assert strict_result["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_codex_provider_receives_closed_human_prompt(monkeypatch, capsys, tmp_path):
    import io
    from core.approvals import ApprovalProvider, ApprovalResponse
    ptu = _load_codex_pretooluse_isolated()
    canary = "PRIVATE-CANARY-client-path-command"
    target = tmp_path / f"{canary}.txt"
    target.write_text("CONFIDENTIAL: board planning material")
    payload = {
        "tool_name": "Read", "tool_input": {"file_path": str(target)},
        "cwd": str(tmp_path), "session_id": "closed-prompt",
        "hook_event_name": "PreToolUse",
    }

    class CapturingProvider(ApprovalProvider):
        def __init__(self):
            self.request_value = None

        def request(self, request):
            self.request_value = request
            return ApprovalResponse(False, "denied")

    provider = CapturingProvider()
    monkeypatch.setenv("AGW_HOME", str(tmp_path / "home"))
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    ptu.main(provider)
    capsys.readouterr()
    request = provider.request_value
    assert request is not None
    rendered = request.action + "\n" + request.primary_text()
    assert "wants to read" in rendered
    assert "a confidentiality marking" in rendered
    assert "Choose Cancel" not in rendered
    assert "Recovery:" not in rendered
    assert request.allow_label == "Allow once"
    assert request.cancel_label == "Cancel (recommended)"
    assert f"{canary}.txt" in rendered
    assert str(tmp_path) not in rendered


def test_codex_provider_receives_specific_connected_service_prompt(
        monkeypatch, capsys, tmp_path):
    import io
    from core.approvals import ApprovalProvider, ApprovalResponse
    ptu = _load_codex_pretooluse_isolated()
    payload = {
        "tool_name": "mcp__google_drive__update_file",
        "tool_input": {
            "file_name": "Board Budget.xlsx",
            "content": "PRIVATE-CANARY-body",
            "access_token": "PRIVATE-CANARY-token",
        },
        "cwd": str(tmp_path), "session_id": "connected-prompt",
        "hook_event_name": "PreToolUse",
    }

    class CapturingProvider(ApprovalProvider):
        def __init__(self):
            self.request_value = None

        def request(self, request):
            self.request_value = request
            return ApprovalResponse(False, "denied")

    provider = CapturingProvider()
    monkeypatch.setenv("AGW_HOME", str(tmp_path / "home"))
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    ptu.main(provider)
    capsys.readouterr()
    request = provider.request_value
    assert request is not None
    rendered = request.action + "\n" + request.primary_text()
    assert "update a file in Google Drive" in rendered
    assert "Target: Google Drive file: Board Budget.xlsx" in rendered
    assert "Google Drive may create or change the specified file" in rendered
    assert "Recovery:" not in rendered
    assert "PRIVATE-CANARY" not in rendered


def test_unknown_target_patch_denies_without_provider(monkeypatch, capsys, tmp_path):
    import io
    from core.approvals import ApprovalProvider, ApprovalResponse
    ptu = _load_codex_pretooluse_isolated()

    class WouldApproveProvider(ApprovalProvider):
        def __init__(self):
            self.calls = 0

        def request(self, request):
            self.calls += 1
            return ApprovalResponse(True, "approved")

    provider = WouldApproveProvider()
    payload = {"tool_name": "apply_patch", "tool_input": {"command": "???"},
               "cwd": str(tmp_path), "session_id": "c1",
               "hook_event_name": "PreToolUse"}
    monkeypatch.setenv("AGW_HOME", str(tmp_path / "home"))
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    ptu.main(provider)
    data = json.loads(capsys.readouterr().out)
    assert data["hookSpecificOutput"]["permissionDecision"] == "deny"
    reason = data["hookSpecificOutput"]["permissionDecisionReason"]
    assert "Result: The requested action did not run" in reason
    assert "Safe next step:" in reason
    assert "file-specific operation" in reason
    assert "User communication:" in reason
    assert "toward the user's goal" in reason
    assert provider.calls == 0


def test_apply_patch_opaque_fails_closed_without_ui():
    # Unreadable patch targets are hard-denied before any approval provider.
    out = run_hook({"tool_name": "apply_patch", "tool_input": {"command": "???"},
                    "cwd": "/tmp", "session_id": "c1"})
    assert _decision(out) == "deny"


def test_mcp_shell_exfil_through_patch_tool_still_evaluated():
    # An MCP shell tool routed through EXEC must still get the rm deny.
    out = run_hook({"tool_name": "mcp__ws__bash",
                    "tool_input": {"command": "rm -rf /tmp/x"},
                    "cwd": "/tmp", "session_id": "c1"})
    assert _decision(out) == "deny"


def test_connected_service_mutation_asks_without_local_preimage(tmp_path):
    out = run_hook({
        "tool_name": "mcp__github__create_pull_request",
        "tool_input": {"head": "feature", "base": "main"},
        "cwd": str(tmp_path),
        "session_id": "connected-create",
    }, env_extra={"AGW_HOME": str(tmp_path / "home")})
    # The deterministic headless provider declines ASK decisions. The denial
    # must come from missing human approval, not from an impossible local-file
    # preimage requirement for remote service data.
    assert _decision(out) == "deny"
    reason = _reason(out)
    assert "safely obtain approval" in reason.lower()
    assert "local recovery" not in reason.lower()


def test_crash_fails_to_ask(tmp_path):
    bad_root = tmp_path / "bad-plugin"
    bad_root.mkdir()
    (bad_root / "policies").write_text("i am a file not a dir")
    env = dict(os.environ, PLUGIN_ROOT=str(bad_root), CODEX_HOME=os.path.expanduser("~/.codex"))
    result = subprocess.run(
        [sys.executable, PRE],
        input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "rm -rf /x"},
                          "cwd": "/tmp", "session_id": "c1", "hook_event_name": "PreToolUse"}),
        capture_output=True, text=True, env=env, timeout=30)
    assert result.returncode == 0
    out = json.loads(result.stdout) if result.stdout.strip() else {}
    # Either the engine still denies (policy loads with builtins) or it fails
    # closed to ask - never a silent allow/defer for an rm.
    assert _decision(out) in ("deny", "ask")


def test_apply_patch_new_file_gets_verified_absent_tombstone(tmp_path):
    target = tmp_path / "new.txt"
    patch = "*** Begin Patch\n*** Add File: new.txt\n+hello\n*** End Patch\n"
    out = run_hook({"tool_name": "apply_patch", "tool_input": {"command": patch},
                    "cwd": str(tmp_path), "session_id": "c-new"},
                   env_extra={"AGW_HOME": str(tmp_path / "home")})
    assert _decision(out) in ("defer", "allow")
    assert not target.exists()


def test_apply_patch_oversized_target_denies_in_observe_mode(tmp_path):
    target = tmp_path / "large.txt"
    target.write_text("12345")
    patch = ("*** Begin Patch\n*** Update File: large.txt\n"
             "@@\n-12345\n+new\n*** End Patch\n")
    out = run_hook({"tool_name": "apply_patch", "tool_input": {"command": patch},
                    "cwd": str(tmp_path), "session_id": "c-large"},
                   env_extra={"AGW_HOME": str(tmp_path / "home"),
                              "AGW_LEVEL": "observe", "AGW_PRESNAP_MAX_BYTES": "4"})
    assert _decision(out) == "deny"
    assert "backup limit" in _reason(out)


def test_prestate_failure_never_invokes_codex_provider(monkeypatch, capsys, tmp_path):
    import io
    from core import preimages
    from core.approvals import ApprovalProvider, ApprovalResponse
    ptu = _load_codex_pretooluse_isolated()

    class WouldApproveProvider(ApprovalProvider):
        def __init__(self):
            self.calls = 0

        def request(self, request):
            self.calls += 1
            return ApprovalResponse(True, "approved")

    target = tmp_path / "important.txt"
    target.write_text("original")
    patch = ("*** Begin Patch\n*** Update File: important.txt\n"
             "@@\n-original\n+new\n*** End Patch\n")
    payload = {"tool_name": "apply_patch", "tool_input": {"command": patch},
               "cwd": str(tmp_path), "session_id": "c-fail",
               "hook_event_name": "PreToolUse"}
    provider = WouldApproveProvider()

    def fail_capture(*args, **kwargs):
        raise OSError("simulated archive failure")

    monkeypatch.setattr(preimages.store, "archive_file", fail_capture)
    monkeypatch.setenv("AGW_HOME", str(tmp_path / "home"))
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    ptu.main(provider)
    data = json.loads(capsys.readouterr().out)
    assert data["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert provider.calls == 0


def test_codex_audit_failure_cannot_weaken_invariant_deny(tmp_path):
    target = tmp_path / "large.txt"
    target.write_text("12345")
    unusable_home = tmp_path / "home-is-a-file"
    unusable_home.write_text("not a directory")
    patch = ("*** Begin Patch\n*** Update File: large.txt\n"
             "@@\n-12345\n+new\n*** End Patch\n")
    out = run_hook({"tool_name": "apply_patch", "tool_input": {"command": patch},
                    "cwd": str(tmp_path), "session_id": "c-audit"},
                   env_extra={"AGW_HOME": str(unusable_home),
                              "AGW_PRESNAP_MAX_BYTES": "4"})
    assert _decision(out) == "deny"
    assert "backup limit" in _reason(out)


@pytest.mark.parametrize("case,expected,provider_calls", [
    ("allow", "allow", 0), ("ask", "deny", 1), ("deny", "deny", 0),
])
def test_audit_exception_leaves_codex_outcomes_identical_without_native_ui(
        case, expected, provider_calls, tmp_path, monkeypatch, capsys):
    import io
    from core import auditlog
    from core.approvals import ApprovalProvider, ApprovalResponse
    ptu = _load_codex_pretooluse_isolated()

    secret = tmp_path / ".env"
    secret.write_text("PRIVATE=codex-parity-value")
    payloads = {
        "allow": {"tool_name": "Bash", "tool_input": {"command": "agw --help"}},
        "ask": {"tool_name": "Read", "tool_input": {"file_path": str(secret)}},
        "deny": {"tool_name": "apply_patch", "tool_input": {"command": "???"}},
    }
    payload = {**payloads[case], "cwd": str(tmp_path),
               "session_id": f"codex-{case}", "event_id": f"event-{case}",
               "hook_event_name": "PreToolUse"}

    class CountingProvider(ApprovalProvider):
        def __init__(self):
            self.calls = 0

        def request(self, request):
            self.calls += 1
            return ApprovalResponse(False, "denied")

    def invoke(home, logger, suffix):
        provider = CountingProvider()
        monkeypatch.setenv("AGW_HOME", str(home))
        monkeypatch.setattr(auditlog, "log", logger)
        current = {**payload, "event_id": f"event-{case}-{suffix}"}
        monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(current)))
        ptu.main(provider)
        text = capsys.readouterr().out
        return (json.loads(text) if text.strip() else {}), provider.calls

    baseline, baseline_calls = invoke(
        tmp_path / "baseline", lambda *_args, **_kwargs: None, "baseline"
    )

    def fail(*_args, **_kwargs):
        raise OSError("simulated audit outage")

    failed, failed_calls = invoke(tmp_path / "failed", fail, "failed")
    assert failed == baseline
    assert _decision(failed) == expected
    assert baseline_calls == failed_calls == provider_calls


def test_observe_mode_keeps_known_and_unknown_patch_denies(tmp_path):
    target = tmp_path / "important.txt"
    target.write_text("verified preimage")
    known = ("*** Begin Patch\n*** Delete File: important.txt\n"
             "*** End Patch\n")
    env = {"AGW_HOME": str(tmp_path / "home"), "AGW_LEVEL": "observe"}
    for patch in (known, "???"):
        out = run_hook({"tool_name": "apply_patch",
                        "tool_input": {"command": patch},
                        "cwd": str(tmp_path), "session_id": "observe-patch"},
                       env_extra=env)
        assert _decision(out) == "deny"
    assert target.read_text() == "verified preimage"


def test_codex_observe_still_resolves_nonwaivable_ask(monkeypatch, capsys, tmp_path):
    import io
    from core.approvals import ApprovalProvider, ApprovalResponse
    ptu = _load_codex_pretooluse_isolated()

    class DenyProvider(ApprovalProvider):
        def __init__(self):
            self.calls = 0

        def request(self, request):
            self.calls += 1
            return ApprovalResponse(False, "denied")

    secret = tmp_path / ".env"
    secret.write_text("TOKEN=secret-value")
    payload = {"tool_name": "Read", "tool_input": {"file_path": str(secret)},
               "cwd": str(tmp_path), "session_id": "observe-ask",
               "hook_event_name": "PreToolUse"}
    provider = DenyProvider()
    monkeypatch.setenv("AGW_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("AGW_LEVEL", "observe")
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    ptu.main(provider)
    data = json.loads(capsys.readouterr().out)
    assert provider.calls == 1
    assert _decision(data) == "deny"


def test_codex_observe_shadows_explicit_custom_policy_deny(tmp_path):
    home = tmp_path / "home"
    policies = home / "policies.d"
    policies.mkdir(parents=True)
    (policies / "company.json").write_text(json.dumps({
        "commands": [{"pattern": "company-block-me", "action": "deny",
                      "reason": "organization policy"}]
    }))
    out = run_hook({"tool_name": "Bash",
                    "tool_input": {"command": "company-block-me"},
                    "cwd": str(tmp_path), "session_id": "observe-policy"},
                   env_extra={"AGW_HOME": str(home), "AGW_LEVEL": "observe"})
    assert _decision(out) == "defer"
    assert "observe mode" in out.get("systemMessage", "")


def test_codex_powershell_named_value_is_not_preimage_target(tmp_path):
    victim = tmp_path / "victim.txt"
    changed = tmp_path / "changed"
    victim.write_text("ORIGINAL")
    changed.write_text("UNRELATED")
    home = tmp_path / "home"
    out = run_hook({"tool_name": "PowerShell",
                    "tool_input": {"command":
                                   "Set-Content -Encoding utf8 victim.txt changed"},
                    "cwd": str(tmp_path), "session_id": "pwsh-binding"},
                   env_extra={"AGW_HOME": str(home)})
    assert _decision(out) in ("defer", "allow")
    archived = [path.name for path in (home / "archive").rglob("*") if path.is_file()]
    assert any("victim.txt" in name for name in archived)
    assert not any(name.endswith("changed") for name in archived)
    assert victim.read_text() == "ORIGINAL"
    assert changed.read_text() == "UNRELATED"


def test_codex_powershell_incomplete_binding_is_nonwaivable_deny(tmp_path):
    out = run_hook({"tool_name": "PowerShell",
                    "tool_input": {"command": "Set-Content -Pa victim.txt changed"},
                    "cwd": str(tmp_path), "session_id": "pwsh-incomplete"},
                   env_extra={"AGW_HOME": str(tmp_path / "home"),
                              "AGW_LEVEL": "observe"})
    assert _decision(out) == "deny"
    assert "unknown or ambiguous" in _reason(out).lower()


@pytest.mark.parametrize("form,observe", [
    ("direct", False),
    ("command", True),
    ("positional", False),
    ("encoded", True),
])
def test_codex_powershell_backtick_target_gets_exact_preimage(
        form, observe, tmp_path):
    script = "Set-Content victim`.txt changed"
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    command = {
        "direct": script,
        "command": f'powershell -Command "{script}"',
        "positional": f'pwsh "{script}"',
        "encoded": f"pwsh -EncodedCommand {encoded}",
    }[form]
    victim = tmp_path / "victim.txt"
    escaped_spelling = tmp_path / "victim`.txt"
    changed = tmp_path / "changed"
    victim.write_text("ORIGINAL")
    escaped_spelling.write_text("UNRELATED ESCAPED SPELLING")
    changed.write_text("UNRELATED CONTENT")
    home = tmp_path / "home"
    env = {"AGW_HOME": str(home)}
    if observe:
        env["AGW_LEVEL"] = "observe"
    out = run_hook({"tool_name": "PowerShell", "tool_input": {"command": command},
                    "cwd": str(tmp_path), "session_id": f"backtick-{form}"},
                   env_extra=env)
    assert _decision(out) in ("defer", "allow")
    archived = [path.name for path in (home / "archive").rglob("*") if path.is_file()]
    assert any(name.endswith("victim.txt") for name in archived)
    assert not any(name.endswith("victim`.txt") or name.endswith("changed")
                   for name in archived)
    assert victim.read_text() == "ORIGINAL"
    assert escaped_spelling.read_text() == "UNRELATED ESCAPED SPELLING"
    assert changed.read_text() == "UNRELATED CONTENT"


@pytest.mark.parametrize("script", [
    "Set-Content victim`n.txt changed",
    "Set-Content victim`$name changed",
    "Set-Content 'victim`.txt' changed",
])
def test_codex_powershell_ambiguous_backtick_is_nonwaivable_deny(
        script, tmp_path):
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    out = run_hook({"tool_name": "PowerShell",
                    "tool_input": {"command": f"pwsh -EncodedCommand {encoded}"},
                    "cwd": str(tmp_path), "session_id": "backtick-deny"},
                   env_extra={"AGW_HOME": str(tmp_path / "home"),
                              "AGW_LEVEL": "observe"})
    assert _decision(out) == "deny"
