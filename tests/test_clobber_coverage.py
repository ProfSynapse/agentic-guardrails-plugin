"""What the exec path counts as a mutation, and what it snapshots first."""
import json
import os
import subprocess
import sys

import pytest

from core import engine

REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "plugin")
DISPATCH = os.path.join(REPO, "scripts", "claude", "_dispatch.py")


def run_hook(command, project, agw_home, tool="Bash"):
    payload = {"tool_name": tool, "tool_input": {"command": command},
               "cwd": project, "session_id": "clobber-coverage",
               "hook_event_name": "PreToolUse"}
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=REPO, AGW_HOME=agw_home)
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


@pytest.fixture()
def project(tmp_path):
    for name in ("notes.txt", "out.txt", "patterns.txt", "archive.tar"):
        (tmp_path / name).write_text("x\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.txt").write_text("a\n", encoding="utf-8")
    (tmp_path / "dst").mkdir()
    return str(tmp_path)


# --- posix -rf as indirect-command evidence ---------------------------------

@pytest.mark.parametrize("command", [
    "$RM -rf ~/My-Documents",
    "$RM -fr ~/My-Documents",
    "$deleter -Rf ~/work",
    "$tool -rfv ~/work",
])
def test_an_indirect_command_with_rf_is_a_mutation(command, project, agw_home):
    action, reason = run_hook(command, project, agw_home)
    assert action == "deny", reason
    assert "builtin:indirect-mutation" in reason


def test_an_indirect_command_without_force_flags_is_still_allowed(project,
                                                                 agw_home):
    action, reason = run_hook("$LS -la", project, agw_home)
    assert action == "allow", reason


@pytest.mark.parametrize("command", [
    # `-rf` here means "read patterns from a file" and "append to an archive".
    # The heads are known and read-only, so nothing may be snapshotted.
    "grep -rf patterns.txt .",
    "tar -rf archive.tar notes.txt",
])
def test_rf_on_a_read_only_head_schedules_no_pre_image(command, project,
                                                       agw_home):
    targets = engine.clobber_targets(command, project, include_absent=True)
    assert list(targets) == []
    action, reason = run_hook(command, project, agw_home)
    assert action == "allow", reason
