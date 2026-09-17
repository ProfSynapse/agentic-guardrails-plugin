"""Routine developer work that the shipped policy must not block.

Every row here is a command an agent runs during ordinary work that the shipped
policy once refused. Each case goes through the real hook: a subprocess of the
Claude PreToolUse dispatcher with a genuine hook payload, so the assertion
covers the adapter, the engine, the mutation planner and the pre-image
invariant together rather than one layer in isolation.

Interpreter bypasses and quoting shapes belong to the bypass corpus; this file
is only about friction.
"""
import json
import os
import subprocess
import sys

import pytest

REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "plugin")
DISPATCH = os.path.join(REPO, "scripts", "claude", "_dispatch.py")


def run_hook(tool, command, cwd, agw_home, session_id="friction"):
    """Return (decision, reason) from a real PreToolUse hook subprocess."""
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=REPO, AGW_HOME=str(agw_home))
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"command": command},
        "cwd": str(cwd),
        "session_id": session_id,
    }
    result = subprocess.run(
        [sys.executable, DISPATCH, "pretooluse"], input=json.dumps(payload),
        capture_output=True, text=True, env=env, timeout=120,
    )
    assert result.returncode == 0, f"hook crashed: {result.stderr}"
    out = json.loads(result.stdout) if result.stdout.strip() else {}
    specific = out.get("hookSpecificOutput", {})
    return (specific.get("permissionDecision", "defer"),
            specific.get("permissionDecisionReason", ""))


@pytest.fixture()
def hook(tmp_path):
    home = tmp_path / "agw-home"
    home.mkdir()

    def _run(tool, command, cwd, session_id="friction"):
        return run_hook(tool, command, cwd, home, session_id)
    return _run


def _project(tmp_path, name="proj"):
    """A directory that looks like a real checkout to the project-root walk."""
    root = tmp_path / name
    (root / ".git").mkdir(parents=True)
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    return root


def _tree(root, *relative_files):
    for relative in relative_files:
        path = root.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x\n", encoding="utf-8")


# --- F5: an ask rule must ask, not deny ---------------------------------------

OPERATION_SCOPE_ASKS = [
    ("Bash", "pip install requests", "Installing packages"),
    ("Bash", "npm install -g typescript", "Global installs"),
    ("Bash", "npm publish", "Publishing to a registry"),
    ("Bash", "kubectl delete pod web-1", "Deleting Kubernetes resources"),
    ("Bash", "docker system prune", "Prune removes"),
    ("PowerShell", "Invoke-Expression $cmd", "eval/source of dynamic content"),
    ("PowerShell", "iex $cmd", "eval/source of dynamic content"),
    ("Bash", "chmod -R 755 ./src", "Recursive permission change"),
]


@pytest.mark.parametrize("tool,command,expected_reason", OPERATION_SCOPE_ASKS)
def test_operation_scope_ask_reaches_the_human(hook, tmp_path, tool, command,
                                               expected_reason):
    decision, reason = hook(tool, command, _project(tmp_path))
    assert decision == "ask", f"{command!r} was {decision}: {reason}"
    assert expected_reason in reason
    assert "could not identify enough structured information" not in reason


# --- F6: deleting a regenerable tree that actually exists ---------------------

REGENERABLE_DELETES = [
    ("PowerShell", "Remove-Item -Recurse -Force node_modules"),
    ("PowerShell", "ri -Recurse -Force build"),
    ("PowerShell", "rm -r -fo dist"),
    ("Bash", "rm -rf node_modules"),
    ("Bash", "rm -rf build"),
]


@pytest.mark.parametrize("tool,command", REGENERABLE_DELETES)
def test_regenerable_delete_is_allowed_when_the_tree_exists(hook, tmp_path, tool,
                                                            command):
    """The allowance only ever worked because test cwds had no such directory.

    With the tree present, `mutations.plan` listed the directory and
    `preimages.prepare` refused it, so routine cleanup hit a non-waivable
    `invariant:prestate-unavailable` DENY on the PowerShell path and a
    "could not determine every file" DENY on the Bash path.
    """
    project = _project(tmp_path)
    _tree(project, "node_modules/x/a.js", "build/o.js", "dist/bundle.js",
          "src/app.py")
    decision, reason = hook(tool, command, project)
    assert decision == "allow", f"{command!r} was {decision}: {reason}"
    assert "builtin:rm-regenerable" in reason


@pytest.mark.parametrize("tool,command", [
    ("Bash", "rm -rf src"),
    ("PowerShell", "Remove-Item -Recurse -Force src"),
    ("Bash", "rm -rf node_modules src"),
])
def test_a_real_source_tree_is_still_protected(hook, tmp_path, tool, command):
    project = _project(tmp_path)
    _tree(project, "node_modules/x/a.js", "src/app.py")
    decision, reason = hook(tool, command, project)
    assert decision == "deny", f"{command!r} was {decision}"
    assert "agw archive" in reason


def test_a_real_deny_is_still_a_deny(hook, tmp_path):
    """The operation-scope prompt is a floor for ASK only; DENY must not soften."""
    project = _project(tmp_path)
    _tree(project, "src/app.py")
    decision, reason = hook("Bash", "rm -rf ./src", project)
    assert decision == "deny"
    assert "agw archive" in reason
