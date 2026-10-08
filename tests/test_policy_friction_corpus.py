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


# --- H1b: the null device and input redirects name no written file ------------
# `cmd >>/dev/null` was denied as a target-less write: the null-sink scan took
# only the second `>` of `>>` and left a lone `>` for the overwrite scan. A
# null redirect closed by `)` (a subshell or `$(...)`) was missed the same way.
# Every row here creates or modifies nothing, so the planner must see no
# mutation at all, not merely a complete plan.

NON_WRITING_REDIRECTS = [
    ("Bash", "nexus --help 2>&1 | head -1"),
    ("Bash", "uv run pytest -q 2>&1 | tail -3"),
    ("Bash", "ls src 2>/dev/null"),
    ("Bash", "ls 2>&-"),
    ("Bash", "ls >&-"),
    ("Bash", "exec 3>&-"),
    ("Bash", "cmd 3>&1 1>&2 2>&3"),
    ("Bash", "ls > /dev/null"),
    ("Bash", "ls &>/dev/null"),
    ("Bash", "ls >>/dev/null"),
    ("Bash", "ls 1>>/dev/null"),
    ("Bash", "ls 2>>/dev/null"),
    ("Bash", "ls &>>/dev/null"),
    ("Bash", "ls >> /dev/null 2>&1"),
    ("Bash", "ls >>/dev/null; ls"),
    ("Bash", "(ls >/dev/null)"),
    ("Bash", "x=$(ls 2>/dev/null)"),
    ("Bash", "wc -l < in.txt"),
    ("Bash", "sort <in.txt | head"),
    ("Bash", "diff <(sort in.txt) <(sort in.txt)"),
    ("Bash", "echo '2>&1' | cat"),
    ("PowerShell", "Get-ChildItem 2>>$null"),
    ("PowerShell", "Get-ChildItem >> $null"),
    ("PowerShell", "Get-ChildItem 2>$NULL"),
]


def _plan(tool, command, cwd):
    from core import engine, mutations
    from core.events import EXEC, ToolEvent
    event = ToolEvent(kind=EXEC, tool=tool, command=command, cwd=str(cwd))
    return mutations.plan([event], engine.clobber_targets, plugin_root=REPO)


@pytest.mark.parametrize("tool,command", NON_WRITING_REDIRECTS)
def test_non_writing_redirect_is_not_a_mutation(hook, tmp_path, tool, command):
    project = _project(tmp_path)
    _tree(project, "in.txt")
    plan = _plan(tool, command, project)
    assert not plan.mutating and plan.complete and not plan.targets, plan
    decision, reason = hook(tool, command, project)
    assert decision in ("allow", "defer"), f"{command!r} was {decision}: {reason}"


def test_agw_launcher_with_stream_duplication_and_pipe_is_allowed(hook, tmp_path):
    decision, reason = hook("Bash", "agw --json doctor 2>&1 | head -80",
                            _project(tmp_path))
    assert decision == "allow", reason
    assert "agw-impostor" not in reason


# A redirect into a real file must still plan a pre-image of exactly that file,
# including when it sits beside a harmless null or duplication redirect.
FILE_REDIRECT_TARGETS = [
    ("echo hi > out.txt", "out.txt"),
    ("ls 2> err.log", "err.log"),
    ("ls &> f", "f"),
    ("ls >| f", "f"),
    ("ls 3> out.txt", "out.txt"),
    ("ls >>/dev/null > out.txt", "out.txt"),
    ("ls 2>/dev/null >f", "f"),
]


@pytest.mark.parametrize("command,target", FILE_REDIRECT_TARGETS)
def test_file_redirect_plans_its_exact_target(tmp_path, command, target):
    project = _project(tmp_path)
    _tree(project, "out.txt", "err.log", "f")
    plan = _plan("Bash", command, project)
    assert plan.mutating and plan.complete, plan
    assert [os.path.basename(path) for path in plan.targets] == [target]


# Only the exact `/dev/null` is the sink. A lookalike is an ordinary target the
# planner cannot snapshot (or, for `/DEV/NULL`, a real file it must snapshot);
# `>& file` writes both streams to a file and is not a stream duplication.
@pytest.mark.parametrize("command", [
    "ls >/dev/nullx",
    "ls > /dev/null/../etc/x",
    "ls >/dev/null2 2>&1",
    "ls >& f",
])
def test_null_device_lookalikes_still_deny(hook, tmp_path, command):
    project = _project(tmp_path)
    _tree(project, "f")
    decision, reason = hook("Bash", command, project)
    assert decision == "deny", f"{command!r} was {decision}: {reason}"
    assert "invariant:prestate-unavailable" in reason


def test_uppercase_null_path_is_an_ordinary_target(tmp_path):
    plan = _plan("Bash", "ls > /DEV/NULL", _project(tmp_path))
    assert plan.mutating
    assert [os.path.normcase(path) for path in plan.targets] \
        == [os.path.normcase(os.path.realpath("/DEV/NULL"))]


# --- H1c: `$null` and NUL are null sinks only where the shell says so ---------
# PowerShell's `$null` is its null sink. To Bash, `$null` is a variable that may
# hold any path (or nothing: an ambiguous redirect), and `nul` is a file in the
# working folder; NUL is a device only to PowerShell or cmd on Windows. The
# dialect is the one the host pins by tool name, never a guess from the text.

@pytest.fixture()
def windows_nul(monkeypatch):
    from core import shellparse

    def pin(value):
        monkeypatch.setattr(shellparse, "WINDOWS_NUL_DEVICE", value)
    return pin


POSIX_DOLLAR_NULL = [
    "echo x > $null",
    "echo x >$null",
    "echo x >| $null",
    "ls 2>$null",
    "ls 2>$NULL",
    "ls &> $null",
]


@pytest.mark.parametrize("command", POSIX_DOLLAR_NULL)
def test_bash_dollar_null_is_an_unresolved_target(hook, tmp_path, command):
    project = _project(tmp_path)
    plan = _plan("Bash", command, project)
    assert plan.mutating and not plan.complete, plan
    assert "redirect target is expanded" in plan.reason
    decision, reason = hook("Bash", command, project)
    assert decision == "deny", f"{command!r} was {decision}: {reason}"
    assert "invariant:prestate-unavailable" in reason


# Windows path APIs resolve a name like `nul` to the device, so the exact
# target spelling is only checkable off Windows. The decision that matters,
# a planned write rather than a sink, is checked everywhere.
_DEVICE_NAMES_ARE_FILES = pytest.mark.skipif(
    os.name == "nt", reason="reserved device names resolve to devices on Windows")


@pytest.mark.parametrize("windows", [False, True])
@pytest.mark.parametrize("command,target", [
    ("echo x > nul", "nul"),
    ("echo x >NUL", "NUL"),
    ("echo x > NUL:", "NUL:"),
    ("ls 2>nul", "nul"),
    ("echo x > 'nul'", "nul"),
])
def test_bash_nul_is_an_ordinary_file(tmp_path, windows_nul, windows, command,
                                      target):
    windows_nul(windows)
    plan = _plan("Bash", command, _project(tmp_path))
    assert plan.mutating, plan
    if os.name != "nt":
        assert plan.complete, plan
        assert [os.path.basename(path) for path in plan.targets] == [target]


@pytest.mark.parametrize("command", [
    "Get-ChildItem > $null",
    "Get-ChildItem >$null",
    "Get-ChildItem 2>$null",
    "Get-ChildItem 2> $NULL",
    "rg -n 'version' plugin README.md 2>$null",
])
def test_powershell_dollar_null_is_the_null_sink(hook, tmp_path, command):
    project = _project(tmp_path)
    plan = _plan("PowerShell", command, project)
    assert not plan.mutating and plan.complete and not plan.targets, plan
    decision, reason = hook("PowerShell", command, project)
    assert decision in ("allow", "defer"), f"{command!r} was {decision}: {reason}"


@pytest.mark.parametrize("command", [
    "Get-ChildItem > nul",
    "Get-ChildItem 2>NUL",
    "Get-ChildItem > NUL:",
    "Get-ChildItem >> nul",
])
def test_powershell_nul_is_the_null_sink_on_windows(tmp_path, windows_nul,
                                                    command):
    windows_nul(True)
    plan = _plan("PowerShell", command, _project(tmp_path))
    assert not plan.mutating and plan.complete and not plan.targets, plan


@_DEVICE_NAMES_ARE_FILES
def test_powershell_nul_is_an_ordinary_file_off_windows(tmp_path, windows_nul):
    windows_nul(False)
    plan = _plan("PowerShell", "Get-ChildItem > nul", _project(tmp_path))
    assert plan.mutating and plan.complete, plan
    assert [os.path.basename(path) for path in plan.targets] == ["nul"]


def test_quoted_dollar_null_is_not_the_sink_even_in_powershell(tmp_path):
    # "$null" in double quotes is an empty-string path, not the null sink.
    plan = _plan("PowerShell", 'Get-ChildItem > "$null"', _project(tmp_path))
    assert plan.mutating and not plan.complete, plan


# --- H1d: a runtime-expanded redirect target is never recorded literally ------
# `> "$OUT"` used to plan a pre-image of a file literally named `$OUT` while the
# shell wrote wherever $OUT pointed. Any target the shell expands before opening
# it is unidentifiable before the command runs and takes the same fail-closed
# path as any other target that could not be identified.

UNRESOLVED_BASH_REDIRECTS = [
    'echo x > "$OUT"',
    "echo x > $OUT",
    "echo x > ${OUT}",
    'echo x > "${OUT}.txt"',
    'echo x > "$HOME/x"',
    "echo x > $HOME/x",
    "echo x > $(mktemp)",
    'echo x > "$(mktemp)"',
    "echo x > `mktemp`",
    "echo x > $((1 + 2)).txt",
    "echo x > ~root/x",
    "echo x > ~+/x",
    "echo x > *.txt",
    "echo x > out?.txt",
    "echo x > [ab].txt",
    "echo x > {a,b}.txt",
    "echo x > $'a\\tb'",
    "printf x 2> $LOG",
    "printf x &> $LOG",
    "printf x >| $LOG",
    "printf x 2>/dev/null > $OUT",
    "echo x > out.txt; echo y > $OUT",
]


@pytest.mark.parametrize("command", UNRESOLVED_BASH_REDIRECTS)
def test_bash_expanded_redirect_target_is_unresolved(hook, tmp_path, command):
    project = _project(tmp_path)
    _tree(project, "out.txt", "a.txt")
    plan = _plan("Bash", command, project)
    assert plan.mutating and not plan.complete, plan
    assert "redirect target is expanded" in plan.reason
    decision, reason = hook("Bash", command, project)
    assert decision == "deny", f"{command!r} was {decision}: {reason}"
    assert "invariant:prestate-unavailable" in reason


UNRESOLVED_POWERSHELL_REDIRECTS = [
    "Get-Date > $OUT",
    'Get-Date > "$OUT"',
    "Get-Date > ${OUT}",
    'Get-Date > "$env:TEMP\\x.txt"',
    "Get-Date > $(Get-Name)",
    'Get-Date > "$(Get-Name).txt"',
    "Get-Date > *.txt",
    "Get-Date > ~root\\x",
    "Get-Date 2> $LOG",
    "Get-Date *> $LOG",
]


@pytest.mark.parametrize("command", UNRESOLVED_POWERSHELL_REDIRECTS)
def test_powershell_expanded_redirect_target_is_unresolved(tmp_path, command):
    plan = _plan("PowerShell", command, _project(tmp_path))
    assert plan.mutating and not plan.complete, plan
    assert "redirect target is expanded" in plan.reason


def test_powershell_expanded_redirect_target_denies_through_the_hook(hook,
                                                                    tmp_path):
    decision, reason = hook("PowerShell", 'Get-Date > "$OUT"', _project(tmp_path))
    assert decision == "deny", reason
    assert "invariant:prestate-unavailable" in reason


# Quoted text without an expansion is a literal file name and stays exact. So
# does an expansion in the command's data, as long as the target is literal.
LITERAL_REDIRECT_TARGETS = [
    ("Bash", "echo x > 'a$b'", "a$b"),
    ("Bash", "echo x > 'out $(date).txt'", "out $(date).txt"),
    ("Bash", "echo x > '`x`.txt'", "`x`.txt"),
    ("Bash", 'echo x > "a\\$b"', "a$b"),
    ("Bash", "echo x > a\\$b", "a$b"),
    ("Bash", "echo x > 'my file.txt'", "my file.txt"),
    ("Bash", 'echo "$HOME" > out.txt', "out.txt"),
    ("Bash", "echo $(date) > out.txt", "out.txt"),
    ("PowerShell", "Get-Date > 'a$b'", "a$b"),
    ("PowerShell", "Get-Date > 'it''s.txt'", "it's.txt"),
    ("PowerShell", 'Get-Date "$env:USERNAME" > out.txt', "out.txt"),
]


@pytest.mark.parametrize("tool,command,target", LITERAL_REDIRECT_TARGETS)
def test_single_quoted_literal_target_stays_exact(tmp_path, tool, command, target):
    project = _project(tmp_path)
    plan = _plan(tool, command, project)
    assert plan.mutating and plan.complete, plan
    assert [os.path.basename(path) for path in plan.targets] == [target]


def test_quoted_tilde_is_a_literal_folder_not_home(tmp_path):
    project = _project(tmp_path)
    plan = _plan("Bash", "echo x > '~/notes.txt'", project)
    assert plan.complete, plan
    assert plan.targets == [os.path.normcase(os.path.realpath(
        os.path.join(str(project), "~", "notes.txt")))]


def test_unquoted_home_tilde_resolves_like_the_shell(tmp_path):
    plan = _plan("Bash", "echo x > ~/notes.txt", _project(tmp_path))
    assert plan.complete, plan
    assert plan.targets == [os.path.normcase(os.path.realpath(
        os.path.expanduser(os.path.join("~", "notes.txt"))))]


# The argv-based writers had the same flaw: `tee "$OUT"` planned `./$OUT`.
UNRESOLVED_ARGV_WRITERS = [
    'echo x | tee "$OUT"',
    "echo x | tee out.txt $(mktemp)",
    "dd if=/dev/zero of=$OUT bs=1 count=1",
    'truncate -s 0 "$F"',
    'cp notes.txt "$(pick)"',
    "cp notes.txt `pick`",
    "mv notes.txt $(pick)",
    "install notes.txt $(pick)",
]


@pytest.mark.parametrize("command", UNRESOLVED_ARGV_WRITERS)
def test_expanded_argv_write_target_is_unresolved(tmp_path, command):
    project = _project(tmp_path)
    _tree(project, "notes.txt", "out.txt")
    plan = _plan("Bash", command, project)
    assert plan.mutating and not plan.complete, plan
    assert "runtime expansion" in plan.reason


@pytest.mark.parametrize("command,targets", [
    ("echo x | tee out.txt", ["out.txt"]),
    ("dd if=/dev/zero of=out.txt bs=1 count=1", ["out.txt"]),
    ("truncate -s 0 out.txt", ["out.txt"]),
    ('truncate -s "$N" out.txt', ["out.txt"]),
    ("truncate --size=0 -c out.txt", ["out.txt"]),
])
def test_literal_argv_write_target_stays_exact(tmp_path, command, targets):
    project = _project(tmp_path)
    _tree(project, "out.txt")
    plan = _plan("Bash", command, project)
    assert plan.mutating and plan.complete, plan
    assert sorted(os.path.basename(path) for path in plan.targets) == targets


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


# --- H3: branch operations never rewrite tracked files ------------------------
# `git checkout -b` is `git switch -c`; both only move HEAD, and git refuses to
# clobber local edits. A bare `git checkout <name>` is a branch switch when
# nothing on disk has that name, which is how git reads it too. git's global
# options (`-c k=v`, `-C dir`) no longer hide the subcommand.

BRANCH_OPERATIONS = [
    ("Bash", "git checkout -b feature/x"),
    ("Bash", "git checkout -B feature/x"),
    ("Bash", "git checkout --orphan gh-pages"),
    ("Bash", "git checkout -b feature/x origin/main"),
    ("Bash", "git -c core.autocrlf=false checkout -b feature/x"),
    ("Bash", "git checkout feature/x"),
    ("Bash", "git checkout main"),
    ("Bash", "git switch -c feature/x"),
    ("Bash", "git switch main"),
    ("Bash", "git restore --staged README.md"),
    ("PowerShell", "git checkout -b feature/x"),
    ("PowerShell", "git checkout main"),
]


@pytest.mark.parametrize("tool,command", BRANCH_OPERATIONS)
def test_branch_operations_need_no_pre_image(hook, tmp_path, tool, command):
    project = _project(tmp_path)
    _tree(project, "README.md")
    decision, reason = hook(tool, command, project)
    assert decision in ("allow", "defer"), f"{command!r} was {decision}: {reason}"


# --- H4: discarding local edits is the user's call, with a pre-image ----------
# The engine always meant `git checkout -- file` to ASK (`builtin:git-checkout`),
# but the planner could not name a target and turned it into the non-waivable
# pre-image invariant, so the prompt never reached anyone. Named files now get
# a pre-image and the prompt; a force/merge/discard form, which can rewrite any
# tracked file, gets the prompt without one (a review, not an invariant).

NAMED_DISCARDS = [
    ("Bash", "git checkout -- README.md"),
    ("Bash", "git checkout README.md"),
    ("Bash", "git checkout main -- README.md"),
    ("Bash", "git -c core.autocrlf=false checkout -- README.md"),
    ("Bash", "git -C . checkout README.md"),
    ("Bash", "git restore README.md"),
    ("PowerShell", "git checkout -- README.md"),
]


@pytest.mark.parametrize("tool,command", NAMED_DISCARDS)
def test_a_named_discard_asks_after_taking_a_pre_image(tmp_path, tool, command):
    project = _project(tmp_path)
    _tree(project, "README.md")
    home = tmp_path / "agw-home"
    home.mkdir()
    decision, reason = run_hook(tool, command, project, home)
    assert decision == "ask", f"{command!r} was {decision}: {reason}"
    assert "could not be identified" not in reason
    snapshots = [path for path in home.rglob("*")
                 if path.is_file() and "readme" in path.name.lower()]
    assert snapshots, f"no pre-image of README.md under {home}"


UNBOUNDED_DISCARDS = [
    ("Bash", "git checkout -f main"),
    ("Bash", "git checkout --merge main"),
    ("Bash", "git checkout -p"),
    ("Bash", "git checkout -- src"),
    ("Bash", "git checkout -- '*.md'"),
    ("Bash", "git switch --discard-changes main"),
    ("Bash", "git switch -f main"),
    ("Bash", "git switch -m main"),
    ("PowerShell", "git switch --discard-changes main"),
]


@pytest.mark.parametrize("tool,command", UNBOUNDED_DISCARDS)
def test_an_unbounded_discard_is_a_review_not_an_invariant(hook, tmp_path, tool,
                                                          command):
    project = _project(tmp_path)
    _tree(project, "README.md", "src/app.py")
    decision, reason = hook(tool, command, project)
    assert decision == "ask", f"{command!r} was {decision}: {reason}"
    assert "could not be identified" not in reason
    assert "invariant:prestate-unavailable" not in reason


def test_git_clean_and_reset_hard_are_still_denied(hook, tmp_path):
    project = _project(tmp_path)
    _tree(project, "README.md")
    for command in ("git reset --hard", "git clean -fd"):
        decision, reason = hook("Bash", command, project)
        assert decision == "deny", f"{command!r} was {decision}: {reason}"
