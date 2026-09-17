"""The `agw` door must open on Codex's native tool vocabulary too.

Contract 3 says every denial names a safe alternative that works. On a build
emitting `shell`/`local_shell`/`exec_command`, every denial recommended
`agw archive` while `agw archive` itself was denied as an unverified launcher:
the launcher rewrite only fired for `Bash`/`PowerShell` and only read a string
`command`. These tests drive the real hook entry point, because the bug lived in
exactly the seam a unit test of either half would have missed.
"""
import json
import os
import subprocess
import sys

import pytest

REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "plugin")
DISPATCH = os.path.join(REPO, "scripts", "codex", "_dispatch.py")
EXPECTED_LAUNCHER = os.path.join(REPO, "bin",
                                 "agw.cmd" if os.name == "nt" else "agw")
sys.path.insert(0, os.path.join(REPO, "scripts"))


def run_hook(payload, tmp_path, project, path_prefix=None):
    """Drive the real hooks-codex.json entry point, as the host would."""
    env = dict(os.environ, PLUGIN_ROOT=REPO, CLAUDE_PLUGIN_ROOT=REPO,
               AGW_HOME=str(tmp_path / "home"),
               AGW_APPROVAL_PROVIDER="headless", AGW_TEST_MODE="1")
    if path_prefix:
        env["PATH"] = str(path_prefix) + os.pathsep + env.get("PATH", "")
    payload.setdefault("hook_event_name", "PreToolUse")
    payload.setdefault("cwd", str(project))
    result = subprocess.run([sys.executable, DISPATCH, "pretooluse"],
                            input=json.dumps(payload), capture_output=True,
                            text=True, env=env, timeout=60)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout) if result.stdout.strip() else {}


def _specific(out):
    return out.get("hookSpecificOutput", {})


def _decision(out):
    return _specific(out).get("permissionDecision", "defer")


def _reason(out):
    return _specific(out).get("permissionDecisionReason", "")


@pytest.fixture
def project(tmp_path):
    """A throwaway project holding the file the `agw archive` cases name."""
    root = tmp_path / "proj"
    root.mkdir()
    (root / "foo.txt").write_text("hello\n", encoding="utf-8")
    return root


@pytest.fixture
def impostor_path(tmp_path):
    """A directory holding a fake `agw`, to be put first on PATH."""
    fake = tmp_path / "fakebin"
    fake.mkdir()
    name = "agw.cmd" if os.name == "nt" else "agw"
    launcher = fake / name
    launcher.write_text("#!/bin/sh\necho pwned\n", encoding="utf-8")
    launcher.chmod(0o755)
    return fake


# --- the door opens on the native tools --------------------------------------

@pytest.mark.parametrize("tool", ["shell", "local_shell"])
def test_native_argv_agw_is_rewritten_and_allowed(tool, tmp_path, project):
    out = run_hook({"tool_name": tool,
                    "tool_input": {"command": ["agw", "archive", "foo.txt"],
                                   "workdir": str(project)},
                    "session_id": f"native-agw-{tool}"}, tmp_path, project)
    assert _decision(out) == "allow", _reason(out)
    updated = _specific(out)["updatedInput"]
    # Shape is preserved: Codex execs an argv list, not a command line.
    assert isinstance(updated["command"], list)
    assert updated["command"][0] == EXPECTED_LAUNCHER
    assert updated["command"][1:] == ["archive", "foo.txt"]
    # Unrelated fields ride along untouched.
    assert updated["workdir"] == str(project)


@pytest.mark.parametrize("tool", ["shell", "local_shell"])
def test_native_argv_wrapper_keeps_its_shape_and_rewrites_the_script(
        tool, tmp_path, project):
    out = run_hook({"tool_name": tool,
                    "tool_input": {"command": ["bash", "-lc",
                                               "agw archive foo.txt"]},
                    "session_id": f"native-agw-wrapped-{tool}"},
                   tmp_path, project)
    assert _decision(out) == "allow", _reason(out)
    argv = _specific(out)["updatedInput"]["command"]
    assert argv[:2] == ["bash", "-lc"]
    assert len(argv) == 3
    # The head is rewritten inside the script string; the wrapper stays.
    assert EXPECTED_LAUNCHER in argv[2]
    assert argv[2].endswith(" archive foo.txt")


def test_native_exec_command_rewrites_cmd_not_command(tmp_path, project):
    out = run_hook({"tool_name": "exec_command",
                    "tool_input": {"cmd": "agw archive foo.txt"},
                    "session_id": "native-agw-exec"}, tmp_path, project)
    assert _decision(out) == "allow", _reason(out)
    updated = _specific(out)["updatedInput"]
    assert EXPECTED_LAUNCHER in updated["cmd"]
    assert updated["cmd"].endswith(" archive foo.txt")
    # Codex reads `cmd`. Writing `command` here would leave the rewrite a
    # silent no-op while the decision still said allow.
    assert "command" not in updated


def test_bash_string_rewrite_is_unchanged(tmp_path, project):
    out = run_hook({"tool_name": "Bash",
                    "tool_input": {"command": "agw archive foo.txt",
                                   "description": "archive"},
                    "session_id": "bash-agw"}, tmp_path, project)
    assert _decision(out) == "allow", _reason(out)
    updated = _specific(out)["updatedInput"]
    assert isinstance(updated["command"], str)
    assert EXPECTED_LAUNCHER in updated["command"]
    assert updated["description"] == "archive"


# --- the wall still stands ----------------------------------------------------

@pytest.mark.parametrize("tool", ["shell", "local_shell"])
def test_native_argv_impostor_launcher_is_still_denied(
        tool, tmp_path, project, impostor_path):
    # Only a literal *leading* launcher token is rewritten. A later `agw`
    # resolves through PATH, finds the impostor, and is denied - exactly what
    # the Bash path does today. Widening the gate must not widen the trust.
    out = run_hook({"tool_name": tool,
                    "tool_input": {"command":
                                   ["bash", "-lc", "true && agw archive foo.txt"]},
                    "session_id": f"native-impostor-{tool}"},
                   tmp_path, project, path_prefix=impostor_path)
    assert _decision(out) == "deny"
    assert "could not be verified" in _reason(out)
    assert "updatedInput" not in _specific(out)


@pytest.mark.parametrize("tool", ["shell", "local_shell"])
def test_native_argv_rm_is_denied_and_names_the_door(tool, tmp_path, project):
    out = run_hook({"tool_name": tool,
                    "tool_input": {"command": ["rm", "-rf", "foo.txt"]},
                    "session_id": f"native-rm-{tool}"}, tmp_path, project)
    assert _decision(out) == "deny"
    assert "agw archive" in _reason(out)
    assert "updatedInput" not in _specific(out)


def test_write_stdin_is_never_rewritten(tmp_path, project):
    # write_stdin carries keystrokes, not a command. Rewriting them would put
    # a launcher path into a running process's input stream.
    out = run_hook({"tool_name": "write_stdin",
                    "tool_input": {"session_id": "running",
                                   "chars": "agw archive foo.txt\n"},
                    "session_id": "native-stdin"}, tmp_path, project)
    assert _decision(out) == "deny"
    assert "updatedInput" not in _specific(out)


# --- the shape-aware splice itself -------------------------------------------

def test_updated_tool_input_preserves_every_payload_shape():
    from core import launcher

    rewritten = "/pkg/bin/agw archive foo.txt"
    # A string command stays a string.
    assert launcher.updated_tool_input(
        {"tool_input": {"command": "agw archive foo.txt"}}, rewritten
    ) == {"command": rewritten}
    # An argv list stays an argv list, spliced not stringified.
    assert launcher.updated_tool_input(
        {"tool_input": {"command": ["agw", "archive", "foo.txt"]}}, rewritten
    ) == {"command": ["/pkg/bin/agw", "archive", "foo.txt"]}
    # Quoting introduced by the argv normalization is undone on the way back.
    assert launcher.updated_tool_input(
        {"tool_input": {"command": ["agw", "archive", "my file.txt"]}},
        "/pkg/bin/agw archive 'my file.txt'",
    ) == {"command": ["/pkg/bin/agw", "archive", "my file.txt"]}
    # A wrapper keeps its wrapper; only the inline script is rewritten.
    assert launcher.updated_tool_input(
        {"tool_input": {"command": ["bash", "-lc", "agw archive foo.txt"]}},
        rewritten,
    ) == {"command": ["bash", "-lc", rewritten]}
    # `cmd` is rewritten in place, and no `command` key is invented.
    assert launcher.updated_tool_input(
        {"tool_input": {"cmd": "agw archive foo.txt", "shell": "bash"}}, rewritten
    ) == {"cmd": rewritten, "shell": "bash"}


def test_updated_tool_input_refuses_an_unspliceable_argv():
    from core import launcher

    # An unbalanced quote cannot be split back into argv. Returning a string
    # there would hand Codex a shape it does not run; the caller drops the
    # rewrite instead.
    assert launcher.updated_tool_input(
        {"tool_input": {"command": ["agw", "archive", "foo.txt"]}},
        "/pkg/bin/agw archive 'unterminated",
    ) is None
