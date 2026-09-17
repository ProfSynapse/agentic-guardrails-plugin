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
    ("Bash", "rm -rf node_modules/x"),
    # Shapes the PowerShell binder cannot model: the allowance decides them
    # from the raw operands, so the plan has to as well.
    ("PowerShell", "del /s /q build"),
    ("PowerShell", "rd /s /q dist"),
    ("PowerShell", "Remove-Item -LiteralPath node_modules -Recurse -Force"),
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
    ("PowerShell", "del /s /q src"),
    ("PowerShell", "Remove-Item @params"),
])
def test_a_real_source_tree_is_still_protected(hook, tmp_path, tool, command):
    project = _project(tmp_path)
    _tree(project, "node_modules/x/a.js", "src/app.py")
    decision, reason = hook(tool, command, project)
    assert decision == "deny", f"{command!r} was {decision}"
    assert "agw archive" in reason


# --- G1: a project that happens to live under OneDrive ------------------------

def _synced_project(tmp_path):
    """A checkout inside a literal `OneDrive - Acme` folder."""
    return _project(tmp_path / "OneDrive - Acme", "proj")


PROJECT_LOCAL_DISCOVERY = [
    ("PowerShell", "Get-ChildItem"),
    ("PowerShell", "gci"),
    ("PowerShell", "gci -Recurse"),
    ("PowerShell", "Select-String -Path . -Pattern TODO -Recurse"),
    ("Bash", "ls"),
    ("Bash", "ls -R"),
    ("Bash", "rg -n TODO ."),
    ("Bash", "rg -n TODO src"),
]


@pytest.mark.parametrize("tool,command", PROJECT_LOCAL_DISCOVERY)
def test_discovery_inside_a_synced_project_is_project_local(hook, tmp_path, tool,
                                                            command):
    """The README markets OneDrive, and every listing in one was denied.

    A checkout is the unit of work wherever it lives; the cloud rule is about
    a scope that escapes the project, not about the project itself.
    """
    project = _synced_project(tmp_path)
    _tree(project, "src/app.py")
    decision, reason = hook(tool, command, project)
    assert decision != "deny", f"{command!r}: {reason}"
    assert "cloud-synced tree" not in reason


@pytest.mark.parametrize("tool,command", [
    ("PowerShell", 'gci "{escape}" -Recurse'),
    ("Bash", 'ls -R "{escape}"'),
    ("Bash", 'rg -n TODO "{escape}"'),
])
def test_discovery_that_escapes_the_project_into_the_cloud_is_denied(
        hook, tmp_path, tool, command):
    project = _synced_project(tmp_path)
    _tree(project, "src/app.py")
    elsewhere = _project(tmp_path, "elsewhere")
    escape = str(tmp_path / "OneDrive - Acme")
    decision, reason = hook(tool, command.format(escape=escape), elsewhere)
    assert decision == "deny"
    assert "cloud-synced tree" in reason


# --- G2: -Force on a listing only reveals hidden entries ----------------------

@pytest.mark.parametrize("tool,command", [
    ("PowerShell", "Get-ChildItem -Recurse -Force"),
    ("PowerShell", "gci -Force"),
    ("PowerShell", "gci -Recurse -Force src"),
    ("Bash", "ls -R"),
])
def test_force_on_a_listing_is_not_a_disabled_safeguard(hook, tmp_path, tool,
                                                        command):
    project = _project(tmp_path)
    _tree(project, "src/app.py")
    decision, reason = hook(tool, command, project)
    assert decision != "deny", f"{command!r}: {reason}"


@pytest.mark.parametrize("tool,command", [
    ("Bash", "fd --no-ignore TODO ."),
    ("Bash", "rg --hidden TODO ."),
    ("Bash", "find . -follow -name '*.py'"),
])
def test_a_finder_that_disables_ignore_rules_still_denies(hook, tmp_path, tool,
                                                          command):
    project = _project(tmp_path)
    _tree(project, "src/app.py")
    decision, reason = hook(tool, command, project)
    assert decision == "deny", f"{command!r} was {decision}"
    assert "agw " in reason


# --- G3: -WhatIf is a dry run -------------------------------------------------

@pytest.mark.parametrize("command", [
    "Remove-Item .\\temp -Recurse -WhatIf",
    "Remove-Item -Path temp -Recurse -Force -WhatIf",
    "ri temp -Recurse -whatif",
    "Set-Content notes.txt -Value hi -WhatIf",
])
def test_whatif_is_a_dry_run(hook, tmp_path, command):
    project = _project(tmp_path)
    _tree(project, "temp/note.txt", "notes.txt")
    decision, reason = hook("PowerShell", command, project)
    assert decision == "allow", f"{command!r} was {decision}: {reason}"
    assert "dry run (-WhatIf)" in reason


@pytest.mark.parametrize("command", [
    "Remove-Item .\\temp -Recurse -Confirm",
    "Remove-Item .\\temp -Recurse -WhatIf:$false",
    "Remove-Item .\\temp -Recurse",
])
def test_only_whatif_gets_the_dry_run_allowance(hook, tmp_path, command):
    """-Confirm still deletes once answered, and the hook never sees the answer."""
    project = _project(tmp_path)
    _tree(project, "temp/note.txt")
    decision, reason = hook("PowerShell", command, project)
    assert decision == "deny", f"{command!r} was {decision}"
    assert "agw archive" in reason


# --- G9: clobbering a cloud stub is a write ----------------------------------

@pytest.mark.parametrize("tool,template", [
    ("Bash", 'echo x > "{target}"'),
    ("Bash", 'cp notes.txt "{target}"'),
    ("PowerShell", 'Set-Content -Path "{target}" -Value hi'),
])
def test_a_clobbered_cloud_stub_is_denied_before_any_pre_image(hook, tmp_path,
                                                               tool, template):
    project = _project(tmp_path / "OneDrive", "proj")
    _tree(project, "notes.txt")
    stub = project / "plan.gdoc"
    stub.write_text('{"url": "https://docs.google.com/x"}\n', encoding="utf-8")
    decision, reason = hook(tool, template.format(target=stub), project)
    assert decision == "deny", f"{template!r} was {decision}"
    assert "pointer stub" in reason
    assert "Drive connector" in reason


def test_a_real_deny_is_still_a_deny(hook, tmp_path):
    """The operation-scope prompt is a floor for ASK only; DENY must not soften."""
    project = _project(tmp_path)
    _tree(project, "src/app.py")
    decision, reason = hook("Bash", "rm -rf ./src", project)
    assert decision == "deny"
    assert "agw archive" in reason


# --- H1: stream duplication is not a file redirect ---------------------------
# `2>&1` and `1>&2` never name a file. The planner's overwrite scan read their
# `>` as a truncating redirect, found no target, and raised the pre-image
# invariant: `pytest ... 2>&1 | tail` was denied while `pytest ... | tail` ran.

STREAM_DUPLICATIONS = [
    ("Bash", "python -m pytest -q tests 2>&1 | tail -20"),
    ("Bash", "ls 2>&1"),
    ("Bash", "echo warn 1>&2"),
    ("Bash", "echo warn >&2"),
    ("Bash", "ls >/dev/null 2>&1"),
    ("PowerShell", "Get-ChildItem 2>&1"),
    ("PowerShell", "Get-ChildItem *>&1"),
]


@pytest.mark.parametrize("tool,command", STREAM_DUPLICATIONS)
def test_stream_duplication_is_not_a_mutation(hook, tmp_path, tool, command):
    decision, reason = hook(tool, command, _project(tmp_path))
    assert decision in ("allow", "defer"), f"{command!r} was {decision}: {reason}"


def test_a_real_truncating_redirect_beside_a_duplication_still_plans(hook, tmp_path):
    """Stripping `2>&1` must not hide the `> out.txt` next to it."""
    project = _project(tmp_path)
    _tree(project, "out.txt")
    decision, reason = hook("Bash", "ls 2>&1 > out.txt", project)
    # A named, project-local target: the pre-image plan is complete.
    assert decision in ("allow", "defer"), reason
    assert "could not be identified" not in reason


# --- H2: a heredoc fed to a data consumer is data ----------------------------
# A commit message containing `->` is not a redirect. A heredoc bash itself
# executes still is inspected.

def test_a_commit_message_heredoc_with_an_arrow_is_not_a_redirect(hook, tmp_path):
    command = "git commit -q -F - <<'EOF'\nMap paths\n\n`/mnt/f/x` -> `F:\\x`.\nEOF"
    decision, reason = hook("Bash", command, _project(tmp_path))
    assert decision in ("allow", "defer"), f"was {decision}: {reason}"


def test_a_heredoc_script_bash_runs_keeps_its_redirect(hook, tmp_path):
    command = "bash <<'EOF'\necho hi > out.txt\nEOF"
    decision, reason = hook("Bash", command, _project(tmp_path))
    assert decision == "deny", f"was {decision}: {reason}"


# --- H3: branch creation never rewrites tracked files -------------------------
# `git checkout -b` is `git switch -c`; both only move HEAD, and git refuses to
# clobber local edits. Forms that can rewrite files - a pathspec, a bare
# argument that may be a file, force/merge/patch - keep their protection, and
# `git switch --discard-changes` gains it. git's global options (`-c k=v`,
# `-C dir`) no longer hide the subcommand from the classifier.

BRANCH_OPERATIONS = [
    ("Bash", "git checkout -b feature/x"),
    ("Bash", "git checkout -B feature/x"),
    ("Bash", "git checkout --orphan gh-pages"),
    ("Bash", "git checkout -b feature/x origin/main"),
    ("Bash", "git -c core.autocrlf=false checkout -b feature/x"),
    ("Bash", "git switch -c feature/x"),
    ("Bash", "git switch main"),
    ("PowerShell", "git checkout -b feature/x"),
]


@pytest.mark.parametrize("tool,command", BRANCH_OPERATIONS)
def test_branch_creation_needs_no_pre_image(hook, tmp_path, tool, command):
    decision, reason = hook(tool, command, _project(tmp_path))
    assert decision in ("allow", "defer"), f"{command!r} was {decision}: {reason}"


WORKTREE_REWRITES = [
    ("Bash", "git checkout -- README.md"),
    ("Bash", "git checkout README.md"),
    ("Bash", "git checkout -f main"),
    ("Bash", "git checkout -b feature/x -- README.md"),
    ("Bash", "git -c core.autocrlf=false checkout -- README.md"),
    ("Bash", "git -C . checkout README.md"),
    ("Bash", "git switch --discard-changes main"),
    ("Bash", "git switch -f main"),
    ("Bash", "git switch -m main"),
    ("Bash", "git restore README.md"),
]


@pytest.mark.parametrize("tool,command", WORKTREE_REWRITES)
def test_worktree_rewrites_keep_their_protection(hook, tmp_path, tool, command):
    project = _project(tmp_path)
    _tree(project, "README.md")
    decision, reason = hook(tool, command, project)
    assert decision in ("ask", "deny"), f"{command!r} was {decision}: {reason}"
