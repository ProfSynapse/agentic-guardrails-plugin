"""Code an interpreter runs without a script file is still a script.

`python - <<'EOF' ... open(path, "w") ... EOF` wrote a repo file through the
real hook with no pre-image and no prompt: the planner inspected script files
named on the command line and nothing else. Every row here goes through the
real PreToolUse hook subprocess, like the friction corpus, because the
evidence, the planner and the invariant only meet there.
"""
import os

import pytest

from core import mutations
from test_policy_friction_corpus import _project, _tree, run_hook


@pytest.fixture()
def hook(tmp_path):
    home = tmp_path / "agw-home"
    home.mkdir()

    def _run(tool, command, cwd):
        return run_hook(tool, command, cwd, home, session_id="inline")
    return _run


WRITES = [
    ("Bash", "python - <<'EOF'\nimport io\nio.open('src/x.py', 'w').write('1')\nEOF"),
    ("Bash", "python <<'EOF'\nopen('src/x.py', 'w').write('1')\nEOF"),
    ("Bash", "python3 - <<'EOF'\nfrom pathlib import Path\nPath('src/x.py').write_text('1')\nEOF"),
    ("Bash", "python -c \"open('src/x.py','w').write('1')\""),
    ("Bash", "python3.12 -c \"open('src/x.py','w').write('1')\""),
    ("Bash", "node -e \"require('fs').writeFileSync('src/x.js','1')\""),
    ("Bash", "node - <<'EOF'\nrequire('fs').writeFileSync('src/x.js','1')\nEOF"),
    ("Bash", "ruby -e \"File.write('src/x.rb', '1')\""),
    ("Bash", "bash <<'EOF'\necho hi > src/out.txt\nEOF"),
    # CRLF: what a multi-line command from a Windows host can look like.
    ("PowerShell", "python - <<'EOF'\r\nopen('src/x.py', 'w').write('1')\r\nEOF"),
    ("PowerShell", "python -c \"open('src/x.py','w').write('1')\""),
]


@pytest.mark.parametrize("tool,command", WRITES)
def test_inline_code_that_writes_is_never_silently_allowed(hook, tmp_path, tool,
                                                          command):
    project = _project(tmp_path)
    _tree(project, "src/app.py")
    decision, reason = hook(tool, command, project)
    assert decision in ("ask", "deny"), f"{command!r} was {decision}: {reason}"
    # The same remedy a script file gets: a declared, hash-bound run.
    assert "agw run" in reason or "workflow" in reason, reason
    assert not (project / "src" / "x.py").exists()


HARMLESS = [
    ("Bash", "python - <<'EOF'\ndef f() -> int:\n    return 1\nprint(f())\nEOF"),
    ("Bash", "python - <<'EOF'\nprint(open('src/app.py').read()[:10])\nEOF"),
    ("Bash", "python -c \"print(1 > 0)\""),
    ("Bash", "python -c \"import json, sys; print(json.dumps(sys.version))\""),
    ("Bash", "node -e \"console.log(1)\""),
    ("Bash", "bash <<'EOF'\necho hi\nEOF"),
    ("Bash", "git commit -q -F - <<'EOF'\nMap paths\n\n`/mnt/f/x` -> `F:\\x`.\nEOF"),
    ("PowerShell", "python - <<'EOF'\r\nprint('ok')\r\nEOF"),
]


@pytest.mark.parametrize("tool,command", HARMLESS)
def test_inline_code_that_does_not_write_still_runs(hook, tmp_path, tool, command):
    project = _project(tmp_path)
    _tree(project, "src/app.py")
    decision, reason = hook(tool, command, project)
    assert decision in ("allow", "defer"), f"{command!r} was {decision}: {reason}"


def test_inline_sources_are_found_for_flags_and_heredocs():
    from core.shellparse import extract_commands
    command = ("python -c \"print(1)\" && node - <<'EOF'\nconsole.log(2)\nEOF\n"
               "&& git commit -F - <<'MSG'\nnot code\nMSG")
    found = mutations._inline_sources(command, extract_commands(command))
    assert found == [
        ("<inline>", "print(1)", ".py"),
        ("<stdin>", "console.log(2)", ".js"),
    ]


def test_inline_evidence_is_labelled_not_pathed():
    """The label names where the code came from, never the code itself."""
    from core.shellparse import extract_commands
    command = "python - <<'EOF'\nopen('SECRET-PATH.txt', 'w')\nEOF"
    evidence = mutations._write_capable_script(command, os.getcwd())
    assert evidence is not None
    assert evidence.path == "<stdin>"
    assert evidence.line == 1
    assert evidence.confidence == "high"
    assert "SECRET-PATH" not in evidence.primitive
    assert extract_commands(command).commands[0].argv == ["python", "-"]
