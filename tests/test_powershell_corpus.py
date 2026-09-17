"""Adapter-level PowerShell/Windows corpus.

Every other Windows-shell suite calls ``engine.evaluate`` directly, so nothing
pins what the *host* actually receives: the ASK-to-DENY upgrade, the mutation
plan and the pre-image step all sit between the engine and the hook's answer.
These rows drive the real entry point — ``_dispatch.py pretooluse``, one
subprocess per row, with a Claude PreToolUse payload — against a throwaway
project, and assert the decision the user would see.

Scope: the shell-parsing and Windows-wrapper findings (F3, F4, F7, G5) plus the
benign rows that tightening them must not regress.
"""
import json
import os
import subprocess
import sys

import pytest

REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "plugin")
DISPATCH = os.path.join(REPO, "scripts", "claude", "_dispatch.py")

DENY = "deny"
ASK = "ask"
ALLOW = "allow"      # the hook does not block and does not prompt


@pytest.fixture(scope="module")
def project(tmp_path_factory):
    """A throwaway project with the files the benign rows name."""
    root = tmp_path_factory.mktemp("corpus-project")
    (root / "README.md").write_text("# Project\n", encoding="utf-8")
    (root / "README.bak").write_text("# Project\n", encoding="utf-8")
    (root / "out.txt").write_text("hi\n", encoding="utf-8")
    (root / "notes.txt").write_text("notes\n", encoding="utf-8")
    return str(root)


@pytest.fixture(scope="module")
def hook_home(tmp_path_factory):
    return str(tmp_path_factory.mktemp("corpus-agw-home"))


def run_hook(tool, command, project, hook_home):
    """Return the decision the host would act on: deny, ask, or allow."""
    payload = {
        "tool_name": tool,
        "tool_input": {"command": command},
        "cwd": project,
        "session_id": "powershell-corpus",
        "hook_event_name": "PreToolUse",
    }
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=REPO, AGW_HOME=hook_home)
    result = subprocess.run(
        [sys.executable, DISPATCH, "pretooluse"], input=json.dumps(payload),
        capture_output=True, text=True, env=env, cwd=project, timeout=60,
    )
    assert result.returncode == 0, f"hook crashed: {result.stderr}"
    if not result.stdout.strip():
        return ALLOW            # no output at all is the host's "carry on"
    decision = json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"]
    # The adapter defers rather than saying "allow" when no rule fires; both
    # mean the tool call runs without a prompt.
    return ALLOW if decision == "defer" else decision


# (tool, command, expected). Rows owned by other work packages (OneDrive
# discovery, node_modules, -Force on Get-ChildItem, -WhatIf, pip install) are
# deliberately absent.
CORPUS = [
    # --- F3: .exe-suffixed, full-path and quoted interpreters -------------
    ("Bash", 'bash.exe -c "rm -rf X"', DENY),
    ("Bash", 'sh.exe -c "rm file"', DENY),
    ("PowerShell", r"C:\Windows\System32\cmd.exe /c del X", DENY),
    ("PowerShell",
     r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
     r' -Command "Remove-Item -Recurse -Force C:\work\notes"', DENY),
    ("PowerShell",
     '"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -c '
     '"Remove-Item -Recurse -Force C:\\work\\notes"', DENY),

    # --- F4: wsl, Start-Process, robocopy, xcopy, fsutil, -File -----------
    ("Bash", "wsl rm -rf /mnt/c/Users/jo/Documents", DENY),
    ("Bash", "wsl -d Ubuntu -u root rm -rf /mnt/c/x", DENY),
    ("Bash", "wsl -e rm -rf /mnt/c/x", DENY),
    ("Bash", "wsl -- rm -rf /mnt/c/x", DENY),
    ("PowerShell",
     "Start-Process powershell -ArgumentList "
     "'-Command','Remove-Item -Recurse C:\\x'", DENY),
    ("PowerShell", 'Start-Process -FilePath cmd.exe -ArgumentList "/c del X"',
     DENY),
    ("PowerShell", "Start-Process powershell -ArgumentList $cmd", ASK),
    ("PowerShell", r"robocopy C:\src C:\dst /MIR", DENY),
    ("PowerShell", r"robocopy C:\src C:\dst /PURGE", DENY),
    ("PowerShell", r"robocopy C:\src C:\dst /MOVE", DENY),
    ("PowerShell",
     r"fsutil file setzerodata offset=0 length=4096 C:\work\notes.txt", DENY),
    ("PowerShell", r"powershell -File .\wipe.ps1", ASK),
    ("Bash", r"powershell -NoProfile -File C:\tools\build.ps1", ASK),
    # `~/` rather than `~\`: PowerShell accepts both, and only this spelling
    # resolves to a real home directory on the POSIX CI leg.
    ("PowerShell", "xcopy notes.txt ~/.ssh/id_rsa /Y", DENY),

    # --- F7: $var heads, and hyphenated words that are not cmdlets --------
    # `$RM -rf ~/My-Documents` is deliberately absent: F7 stops it vanishing
    # into the PowerShell dialect (see tests/test_shellparse.py), but whether
    # the resulting FLAG_INDIRECT denies or allows is decided by
    # `builtin:indirect-mutation`'s evidence test, which this package does not
    # own. Pinning it here would assert someone else's open finding.
    ("PowerShell", r"$deleter -Recurse -Force C:\work", DENY),

    # --- G5: multi-line PowerShell --------------------------------------
    ("PowerShell", "Remove-Item `\n  -Recurse `\n  -Force C:\\work\\notes",
     DENY),

    # --- benign: tightening the above must not touch these ---------------
    ("Bash", "git status", ALLOW),
    ("Bash", "npm test", ALLOW),
    ("PowerShell", "Copy-Item README.md README.bak -Force", ALLOW),
    ("PowerShell", "Set-Content -Path out.txt -Value 'hi'", ALLOW),
    ("PowerShell", "Get-Content README.md", ALLOW),
    ("Bash", 'git commit -m "Add Foo-Bar support"', ALLOW),
    ("Bash", 'curl -H "Content-Type: application/json" https://x.test', ALLOW),
    ("PowerShell", "wsl --list --verbose", ALLOW),
    ("PowerShell", r"robocopy C:\src C:\dst /E", ALLOW),
    ("PowerShell", "Start-Process notepad.exe README.md", ALLOW),
    ("PowerShell", r"xcopy README.md README.bak /Y", ALLOW),
    ("PowerShell", "Copy-Item README.md README.bak `\n  -Force", ALLOW),
]


@pytest.mark.parametrize("tool, command, expected", CORPUS,
                         ids=[f"{tool}:{command}" for tool, command, _ in CORPUS])
def test_powershell_corpus(project, hook_home, tool, command, expected):
    actual = run_hook(tool, command, project, hook_home)
    assert actual == expected, (
        f"{tool} {command!r}: expected {expected}, got {actual}")
