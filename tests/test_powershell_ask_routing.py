"""A PowerShell write whose path is only known at run time is a question.

`powershell_bind` already separates "this cmdlet is recognized but its path
cannot be read without running it" (``UNRESOLVED_PATH``) from "this command
line is outside the binder's model" (``UNSUPPORTED_SHAPE``). Nothing routed on
that distinction, so splatting and here-string writes reached the host as a
non-waivable `invariant:prestate-unavailable` DENY with no door out. These rows
pin the routing end to end, including the deletes that must still deny.
"""
import json
import os
import subprocess
import sys

import pytest

from core import engine, mutations, powershell_bind

REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "plugin")
DISPATCH = os.path.join(REPO, "scripts", "claude", "_dispatch.py")

SPLAT = "$params = @{Path='out.txt';Value='hi'}; Set-Content @params"
HERE_STRING = 'Set-Content -Path $file -Value @"\nhello\n"@'


@pytest.fixture()
def project(tmp_path):
    (tmp_path / "out.txt").write_text("hi\n", encoding="utf-8")
    (tmp_path / "temp").mkdir()
    (tmp_path / "temp" / "junk.log").write_text("1\n", encoding="utf-8")
    return str(tmp_path)


def run_hook(command, project, agw_home, tool="PowerShell", level=None):
    payload = {"tool_name": tool, "tool_input": {"command": command},
               "cwd": project, "session_id": "ask-routing",
               "hook_event_name": "PreToolUse"}
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=REPO, AGW_HOME=agw_home)
    if level:
        env["AGW_LEVEL"] = level
    result = subprocess.run(
        [sys.executable, DISPATCH, "pretooluse"], input=json.dumps(payload),
        capture_output=True, text=True, env=env, cwd=project, timeout=60,
    )
    assert result.returncode == 0, f"hook crashed: {result.stderr}"
    if not result.stdout.strip():
        return "allow", ""
    out = json.loads(result.stdout).get("hookSpecificOutput") or {}
    action = out.get("permissionDecision", "allow")
    return ("allow" if action == "defer" else action,
            out.get("permissionDecisionReason", ""))


def _plan(command, cwd):
    from core.events import ToolEvent, EXEC
    event = ToolEvent(kind=EXEC, tool="PowerShell", command=command, cwd=cwd)
    return mutations.plan([event], engine.clobber_targets, plugin_root=REPO)


@pytest.mark.parametrize("command", [SPLAT, HERE_STRING])
def test_clobber_targets_reports_the_unresolved_path_kind(command, tmp_path):
    targets = engine.clobber_targets(command, str(tmp_path), include_absent=True,
                                     dialect="powershell")
    assert targets.complete is False
    assert targets.incomplete_kind == powershell_bind.UNRESOLVED_PATH


def test_unsupported_shape_keeps_its_own_kind(tmp_path):
    targets = engine.clobber_targets("Set-Content --% -Path out.txt",
                                     str(tmp_path), include_absent=True,
                                     dialect="powershell")
    assert targets.complete is False
    assert targets.incomplete_kind == powershell_bind.UNSUPPORTED_SHAPE


@pytest.mark.parametrize("command", [SPLAT, HERE_STRING])
def test_plan_routes_an_unresolved_path_to_review(command, tmp_path):
    plan = _plan(command, str(tmp_path))
    assert plan.complete is False
    assert plan.review_required is True
    assert plan.reason == mutations.UNRESOLVED_PATH_ASK


@pytest.mark.parametrize("command", [
    # A backtick escape and a wildcard are ambiguities about *which* file, not
    # a single file that is merely named later. Routing them to ASK would hand
    # a waiver to the very shapes the binder cannot read at all.
    "Set-Content 'victim`.txt' changed",
    "Set-Content -Path out*.txt -Value 'hi'",
    "Copy-Item -Path *.log -Destination out.bak",
])
def test_an_ambiguous_value_is_not_askable(command, tmp_path):
    parsed = engine.extract_commands(command, dialect="powershell")
    binding = powershell_bind.bind(parsed.commands[0].argv, "powershell")
    assert binding.recognized and not binding.complete, command
    assert binding.kind == powershell_bind.UNSUPPORTED_SHAPE, command
    assert not binding.askable, command


def test_plan_keeps_an_unsupported_shape_fail_closed(tmp_path):
    plan = _plan("Set-Content --% -Path out.txt", str(tmp_path))
    assert plan.complete is False
    assert plan.review_required is False


@pytest.mark.parametrize("command", [SPLAT, HERE_STRING])
def test_hook_asks_for_an_unresolved_write_path(command, project, agw_home):
    action, reason = run_hook(command, project, agw_home)
    assert action == "ask", reason
    assert "A file the command names at run time" in reason


@pytest.mark.parametrize("command", [SPLAT, HERE_STRING])
def test_strict_level_denies_an_unresolved_write_path(command, project, agw_home):
    action, reason = run_hook(command, project, agw_home, level="strict")
    assert action == "deny"
    assert powershell_bind.UNRESOLVED_PATH_ASK in reason
    assert "builtin:powershell-path-unresolved" in reason


@pytest.mark.parametrize("command", [
    "Remove-Item @params",
    "$params = @{Path='temp'}; Remove-Item @params",
])
def test_a_splatted_delete_still_denies(command, project, agw_home):
    action, _ = run_hook(command, project, agw_home)
    assert action == "deny"


def test_codex_routes_the_unresolved_path_to_its_approval_provider(project,
                                                                   agw_home):
    """Codex resolves ASK through a provider; the headless one denies.

    What this pins is the rule the refusal carries: an unresolved path is a
    waivable review that reached the provider, not the non-waivable
    `invariant:prestate-unavailable` that never could.
    """
    codex = os.path.join(REPO, "scripts", "codex", "pretooluse.py")
    payload = {"tool_name": "PowerShell", "tool_input": {"command": SPLAT},
               "cwd": project, "session_id": "ask-routing",
               "hook_event_name": "PreToolUse"}
    env = dict(os.environ, PLUGIN_ROOT=REPO, AGW_HOME=agw_home,
               AGW_APPROVAL_PROVIDER="headless", AGW_TEST_MODE="1")
    result = subprocess.run([sys.executable, codex], input=json.dumps(payload),
                            capture_output=True, text=True, env=env, timeout=60)
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout)["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"     # headless provider declines
    assert out["agwRefusal"]["rule_id"] == "builtin:powershell-path-unresolved"


def test_a_literal_write_is_still_untouched(project, agw_home):
    action, _ = run_hook("Set-Content -Path out.txt -Value 'hi'", project, agw_home)
    assert action == "allow"
