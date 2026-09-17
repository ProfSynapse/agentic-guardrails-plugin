"""What the adapters carry from a refusal into the text the agent reads."""
import json
import os
import subprocess
import sys

import pytest

REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "plugin")
CLAUDE = os.path.join(REPO, "scripts", "claude", "_dispatch.py")
CODEX = os.path.join(REPO, "scripts", "codex", "pretooluse.py")


def run_hook(platform, payload, cwd, agw_home, env_extra=None):
    argv = ([sys.executable, CLAUDE, "pretooluse"] if platform == "claude"
            else [sys.executable, CODEX])
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=REPO, PLUGIN_ROOT=REPO,
               AGW_HOME=agw_home, AGW_APPROVAL_PROVIDER="headless",
               AGW_TEST_MODE="1")
    env.update(env_extra or {})
    payload.setdefault("hook_event_name", "PreToolUse")
    result = subprocess.run(argv, input=json.dumps(payload), capture_output=True,
                            text=True, env=env, cwd=cwd, timeout=60)
    assert result.returncode == 0, f"hook crashed: {result.stderr}"
    if not result.stdout.strip():
        return {}
    return json.loads(result.stdout).get("hookSpecificOutput") or {}


def write_payload(platform, target, cwd, session_id):
    """The same 'replace this file's contents' call on either host.

    Codex has no Write tool: every file mutation arrives as `apply_patch`.
    """
    if platform == "claude":
        return {"tool_name": "Write",
                "tool_input": {"file_path": str(target), "content": "new"},
                "cwd": cwd, "session_id": session_id}
    patch = ("*** Begin Patch\n"
             f"*** Update File: {target}\n"
             "@@\n-old\n+new\n"
             "*** End Patch\n")
    return {"tool_name": "apply_patch", "tool_input": {"command": patch},
            "cwd": cwd, "session_id": session_id}


def _safe_next(reason):
    """The 'Safe next step' paragraph of a rendered denial."""
    head = reason.split("Safe next step: ", 1)[1]
    return head.split("\n\n", 1)[0]


# --- capacity detail reaches render_safe_next -------------------------------

@pytest.mark.parametrize("platform", ["claude", "codex"])
def test_a_capacity_denial_names_the_cap_and_the_shortfall(platform, tmp_path,
                                                           agw_home):
    """`capacity_instruction` can size the refusal, but only if it gets details.

    `PreimageResult` carried `error_code` and dropped
    `ArchiveCapacityError.details`, and the adapters then built the Decision
    with empty `presentation_details`, so the agent read a sizeless "the cache
    is full" and had no way to tell the user how much to reclaim.
    """
    target = tmp_path / "notes.txt"
    target.write_text("x" * 5000, encoding="utf-8")
    out = run_hook(
        platform,
        write_payload(platform, target, str(tmp_path), "capacity"),
        str(tmp_path), agw_home, {"AGW_ARCHIVE_MAX_BYTES": "512"},
    )
    assert out.get("permissionDecision") == "deny"
    reason = out["permissionDecisionReason"]
    assert out["agwRefusal"]["reason_code"] == "reclaim-recovery-cache"
    instruction = _safe_next(reason)
    assert "The cap is 512 bytes" in instruction, instruction
    assert "this change needs" in instruction, instruction
    assert target.read_text(encoding="utf-8") == "x" * 5000


@pytest.mark.parametrize("platform", ["claude", "codex"])
def test_a_non_capacity_invariant_denial_carries_no_sizes(platform, tmp_path,
                                                          agw_home):
    target = tmp_path / "big.bin"
    target.write_bytes(b"12345")
    out = run_hook(
        platform,
        write_payload(platform, target, str(tmp_path), "too-big"),
        str(tmp_path), agw_home, {"AGW_PRESNAP_MAX_BYTES": "4"},
    )
    assert out.get("permissionDecision") == "deny"
    assert "The cap is" not in out["permissionDecisionReason"]


# --- inert host tools are not "mutating tools we cannot see" ----------------

INERT = ["TodoWrite", "TaskCreate", "TaskUpdate"]


@pytest.mark.parametrize("tool", INERT)
def test_claude_lets_an_inert_planning_tool_through(tool, tmp_path, agw_home):
    out = run_hook("claude",
                   {"tool_name": tool, "tool_input": {"todos": []},
                    "cwd": str(tmp_path), "session_id": "inert"},
                   str(tmp_path), agw_home)
    assert out.get("permissionDecision", "defer") in ("defer", "allow"), out


@pytest.mark.parametrize("tool", INERT + ["update_plan"])
def test_codex_lets_an_inert_planning_tool_through(tool, tmp_path, agw_home):
    out = run_hook("codex",
                   {"tool_name": tool, "tool_input": {"plan": []},
                    "cwd": str(tmp_path), "session_id": "inert"},
                   str(tmp_path), agw_home)
    assert out.get("permissionDecision", "defer") in ("defer", "allow"), out


def test_an_unmodeled_mutation_named_tool_is_still_not_available(tmp_path):
    """The name-based net is a last line and must survive the exemption."""
    from core import engine, mutations
    from core.events import ToolEvent, OTHER

    event = ToolEvent(kind=OTHER, tool="DeleteRecords", cwd=str(tmp_path))
    plan = mutations.plan([event], engine.clobber_targets,
                          inert_tools=frozenset({"TodoWrite"}))
    assert plan.mutating is True
    assert plan.complete is False

    inert = ToolEvent(kind=OTHER, tool="TodoWrite", cwd=str(tmp_path))
    exempt = mutations.plan([inert], engine.clobber_targets,
                            inert_tools=frozenset({"TodoWrite"}))
    assert exempt.mutating is False
    assert exempt.complete is True


def test_an_event_flagged_inert_is_exempt_without_a_registry(tmp_path):
    from core import engine, mutations
    from core.events import ToolEvent, OTHER

    event = ToolEvent(kind=OTHER, tool="PlanUpdater", cwd=str(tmp_path),
                      extra={"inert": True})
    plan = mutations.plan([event], engine.clobber_targets)
    assert plan.complete is True


# --- an unrecognized tool keeps its own denial text --------------------------

def test_codex_unrecognized_tool_denial_names_the_tool(monkeypatch, capsys,
                                                       tmp_path):
    """A prompt this host could not complete must not erase the tool's name.

    `build_denial_feedback` replaced the decision's reason with a generic
    "could not identify enough structured information" sentence, which drops
    the only fact that lets anyone act: which tool the plugin does not model.
    """
    import importlib.util
    import io
    from core.approvals import ApprovalProvider, ApprovalResponse

    module_path = os.path.join(REPO, "scripts", "codex", "pretooluse.py")
    previous = sys.modules.pop("adapter_common", None)
    previous_path = list(sys.path)
    try:
        spec = importlib.util.spec_from_file_location(
            "_agw_plumbing_codex_pretooluse", module_path
        )
        ptu = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ptu)
    finally:
        sys.path[:] = previous_path
        sys.modules.pop("adapter_common", None)
        if previous is not None:
            sys.modules["adapter_common"] = previous

    class IncompletePrompt(ApprovalProvider):
        def request(self, request):
            return ApprovalResponse(False, "prompt-incomplete",
                                    "validation:target-missing")

    payload = {"tool_name": "Frobnicator", "tool_input": {},
               "cwd": str(tmp_path), "session_id": "unrecognized",
               "hook_event_name": "PreToolUse"}
    monkeypatch.setenv("PLUGIN_ROOT", REPO)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    ptu.main(IncompletePrompt())
    out = json.loads(capsys.readouterr().out)["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    reason = out["permissionDecisionReason"]
    assert "Frobnicator" in reason, reason
    assert "could not identify enough structured information" not in reason
