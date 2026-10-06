"""Safe shell wrappers around the `agw` launcher, and the impostors that stay out.

An agent writes `cd <dir> && agw run ...`, chains `agw` calls with `;` or
newlines, loops over them, or trims output with `| tail`. Each later `agw` used
to reach the shell as a bare PATH lookup and was refused as an unverifiable
launcher. The adapter now rewrites every literal later `agw` in a plain command
position to the exact packaged path, but only when nothing in the same command
line can change what that word, or the launcher's own environment, resolves to.
"""
import json
import os
import shlex
import subprocess
import sys

import pytest

from core import engine, launcher
from core.events import ALLOW, DENY, EXEC, ToolEvent

REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugin")
PRE = os.path.join(REPO, "scripts", "claude", "pretooluse.py")
LAUNCHER = os.path.join(REPO, "bin", "agw")
QUOTED = shlex.quote(LAUNCHER)

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX shell wrappers")


def rewrite(command):
    return launcher.rewrite_shortcut(command, REPO, platform="posix", shell="posix")


# --- accepted wrappers ---------------------------------------------------------

@pytest.mark.parametrize("command, expected", [
    ('cd "/tmp/My Project" && agw run --output a.txt -- python3 x.py',
     'cd "/tmp/My Project" && {L} run --output a.txt -- python3 x.py'),
    ("cd /tmp && agw list .", "cd /tmp && {L} list ."),
    ("agw list a; agw list b", "{L} list a; {L} list b"),
    ("agw list a\nagw list b", "{L} list a\n{L} list b"),
    ("agw list a && agw list b || agw status", "{L} list a && {L} list b || {L} status"),
    ("agw run --output o -- python3 s.py 2>&1 | tail -40",
     "{L} run --output o -- python3 s.py 2>&1 | tail -40"),
    ("agw list . | head -5", "{L} list . | head -5"),
    ("agw list . | grep -c x | wc -l", "{L} list . | grep -c x | wc -l"),
    ("agw list . | cut -d/ -f1 | sort", "{L} list . | cut -d/ -f1 | sort"),
    ("R=1\nagw list .", "R=1\n{L} list ."),
    ("for r in a-1 b-2; do agw list /tmp/${r%-*}; done",
     "for r in a-1 b-2; do {L} list /tmp/${r%-*}; done"),
    ("for r in a-1 b-2; do set -- $r; agw list \"$1\"; done",
     "for r in a-1 b-2; do set -- $r; {L} list \"$1\"; done"),
    ("for r in a b\ndo\n  agw list $r\ndone", "for r in a b\ndo\n  {L} list $r\ndone"),
    ("echo data | agw file write x --content-stdin --expected-hash absent",
     "echo data | {L} file write x --content-stdin --expected-hash absent"),
])
def test_safe_wrappers_rewrite_every_literal_launcher(command, expected):
    assert rewrite(command) == expected.replace("{L}", QUOTED)


def test_leading_form_is_unchanged():
    assert rewrite("agw list .") == f"{QUOTED} list ."
    assert rewrite("  agw list .") == f"  {QUOTED} list ."


def test_launcher_words_that_are_data_are_not_rewritten():
    # An argument, a quoted string, or a path component is not a command word.
    assert rewrite("echo agw; agw list .") == f"echo agw; {QUOTED} list ."
    assert rewrite("grep 'agw list' notes.md") is None
    assert rewrite("ls /opt/agw") is None


# --- refused wrappers: the later word stays bare -----------------------------

@pytest.mark.parametrize("command", [
    "alias agw=/bin/rm\nagw list .",
    "agw() { rm -rf x; }; agw list .",
    "function agw { true; }; agw list .",
    "PATH=/tmp/evil:$PATH agw list .",
    "cd /tmp && PATH=/tmp/evil:$PATH agw list .",
    "export PATH=/tmp/evil:$PATH; agw list .",
    "PATH=/tmp/evil\nagw list .",
    "PYTHONPATH=/tmp/evil\nagw list .",
    "AGW_HOME=/tmp/other; agw list .",
    "hash -p /tmp/evil/agw agw; agw list .",
    "source ./env.sh; agw list .",
    ". ./env.sh && agw list .",
    "eval x; agw list .",
    "echo $(id); agw list .",
    "echo `id`; agw list .",
    "(agw list .)",
    "{ agw list .; }",
    "cat <<EOF | agw file write x --content-stdin\nbody\nEOF",
    "cd $HOME && agw list .",
    "cd /tmp; agw list .",
    "cd /tmp && cd /var && agw list .",
    "true && cd /tmp && agw list .",
    "case x in x) agw list .;; esac",
])
def test_unsafe_prefixes_never_vouch_for_a_later_launcher(command):
    rewritten = rewrite(command)
    if rewritten is None:
        return
    # Only the literal leading token may have been expanded (pre-existing
    # behavior); every later `agw` must remain a bare, unvouched word.
    assert rewritten.count(QUOTED) <= 1
    assert rewritten.startswith(QUOTED)


def test_leading_cd_directory_resolves_only_the_accepted_prefix(tmp_path):
    sub = tmp_path / "sub dir"
    sub.mkdir()
    assert launcher.leading_cd_directory(f'cd "{sub}" && agw list .', "/") == str(sub)
    assert launcher.leading_cd_directory('cd "sub dir" && ls', str(tmp_path)) == str(sub)
    assert launcher.leading_cd_directory(f"cd {tmp_path}/missing && ls", "/") == ""
    assert launcher.leading_cd_directory(f'cd "{sub}"; ls', "/") == ""
    assert launcher.leading_cd_directory("cd $HOME && ls", "/") == ""
    assert launcher.leading_cd_directory("ls && cd /tmp && ls", "/") == ""


# --- engine: bare names under a tampered environment ------------------------

@pytest.fixture
def packaged_on_path(monkeypatch):
    """Simulate a host whose PATH really does resolve `agw` to the package."""
    monkeypatch.setattr(engine.shutil, "which",
                        lambda name: LAUNCHER if name == "agw" else None)


def _evaluate(policy, command, cwd="/tmp"):
    return engine.evaluate(ToolEvent(kind=EXEC, tool="Bash", command=command, cwd=cwd),
                           policy, REPO)


@posix_only
def test_bare_launcher_through_genuine_path_is_still_trusted(policy, packaged_on_path):
    assert _evaluate(policy, "agw status").action == ALLOW


@posix_only
@pytest.mark.parametrize("command", [
    "alias agw=/bin/rm\nagw run --output o -- python3 s.py",
    "agw() { python3 evil.py; }; agw run --output o -- python3 s.py",
    "PATH=/tmp/evil:$PATH agw run --output o -- python3 s.py",
    "export PATH=/tmp/evil:$PATH; agw run --output o -- python3 s.py",
    "PATH=/tmp/evil\nagw run --output o -- python3 s.py",
    "$(echo agw) run --output o -- python3 s.py",
    "A=agw; $A run --output o -- python3 s.py",
    "eval agw run --output o -- python3 s.py",
    "eval \"agw run --output o -- python3 s.py\"",
    "`echo agw` list .",
])
def test_impostor_shapes_are_denied_even_when_path_is_genuine(
        policy, packaged_on_path, command):
    decision = _evaluate(policy, command)
    assert decision.action == DENY, (command, decision.rule_id, decision.reason)
    assert decision.rule_id == "builtin:agw-impostor"


@posix_only
def test_different_binary_named_agw_on_path_is_denied(policy, tmp_path, monkeypatch):
    impostor = tmp_path / "evil" / "agw"
    impostor.parent.mkdir()
    impostor.write_text("#!/bin/sh\necho pwned\n")
    monkeypatch.setattr(engine.shutil, "which", lambda name: str(impostor))
    for command in ("agw run --output o -- python3 s.py", "true; agw list ."):
        decision = _evaluate(policy, command)
        assert decision.action == DENY
        assert decision.rule_id == "builtin:agw-impostor"


# --- end to end through the real Claude hook ---------------------------------

def run_hook(command, cwd, tmp_path, path_prefix=None):
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=REPO, AGW_HOME=str(tmp_path / "home"),
               AGW_APPROVAL_PROVIDER="headless", AGW_TEST_MODE="1")
    if path_prefix:
        env["PATH"] = str(path_prefix) + os.pathsep + env.get("PATH", "")
    payload = {"tool_name": "Bash", "tool_input": {"command": command},
               "cwd": str(cwd), "session_id": "wrappers",
               "hook_event_name": "PreToolUse"}
    result = subprocess.run([sys.executable, PRE], input=json.dumps(payload),
                            capture_output=True, text=True, env=env, timeout=60)
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout) if result.stdout.strip() else {}
    return out.get("hookSpecificOutput", {})


@posix_only
@pytest.mark.parametrize("template", [
    'cd "{dir}" && agw run --output out.txt --expected-hash absent -- python3 tool.py',
    "agw list {dir}; agw list {dir}",
    "agw list {dir}\nagw list {dir}",
    "agw run --output {dir}/out.txt --expected-hash absent -- python3 {dir}/tool.py 2>&1 | tail -40",
    "for r in a-1 b-2; do agw list {dir}/${{r%-*}}; done",
])
def test_hook_allows_safe_wrappers_with_every_launcher_resolved(tmp_path, template):
    project = tmp_path / "My Project"
    project.mkdir()
    (project / "tool.py").write_text("open('out.txt', 'w').write('x')\n")
    impostors = tmp_path / "fakebin"
    impostors.mkdir()
    (impostors / "agw").write_text("#!/bin/sh\necho pwned\n")
    (impostors / "agw").chmod(0o755)
    command = template.format(dir=project)
    out = run_hook(command, tmp_path, tmp_path, path_prefix=impostors)
    assert out.get("permissionDecision") == "allow", out.get("permissionDecisionReason")
    updated = out["updatedInput"]["command"]
    assert str(impostors) not in updated
    assert updated.count(QUOTED) == command.count("agw ")


@posix_only
def test_hook_evaluates_a_cd_prefixed_script_where_it_runs(tmp_path):
    # Before, `cd sub && python3 writer.py` looked for writer.py in the session
    # folder, found nothing, and let an unprotected writer through.
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "writer.py").write_text("open('report.txt', 'w').write('x')\n")
    out = run_hook(f'cd "{sub}" && python3 writer.py', tmp_path, tmp_path)
    assert out.get("permissionDecision") == "deny"
    assert "writer.py" in out.get("permissionDecisionReason", "")
