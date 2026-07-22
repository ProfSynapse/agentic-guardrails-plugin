"""Release-blocking parity contracts for maintained and planned hosts."""
import json
import os
from pathlib import Path

import pytest

from claude import adapter_common as claude_adapter
from claude.adapter_common import to_event
from codex import adapter_common as codex_adapter
from codex.adapter_common import to_events
from core import engine, events


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugin"


def _hooks(name):
    return json.loads((PLUGIN / "hooks" / name).read_text(encoding="utf-8"))["hooks"]


@pytest.mark.parametrize("manifest", ["hooks.json", "hooks-codex.json"])
@pytest.mark.parametrize("lifecycle", ["PreToolUse", "PostToolUse"])
def test_maintained_hooks_register_every_shell_surface(manifest, lifecycle):
    matcher = _hooks(manifest)[lifecycle][0]["matcher"].split("|")
    assert {"Bash", "PowerShell", "Monitor"} <= set(matcher)


@pytest.mark.parametrize("manifest,root_name", [
    ("hooks.json", "CLAUDE_PLUGIN_ROOT"),
    ("hooks-codex.json", "PLUGIN_ROOT"),
])
def test_windows_hooks_use_python3_launcher_and_plugin_root(manifest, root_name):
    for lifecycle in ("PreToolUse", "PostToolUse", "SessionStart"):
        command = _hooks(manifest)[lifecycle][0]["hooks"][0]["commandWindows"]
        assert command.startswith("py.exe -3 ")
        assert "${" + root_name + "}" in command


@pytest.mark.parametrize("tool,command", [
    ("Bash", "rm important.txt"),
    ("PowerShell", "Remove-Item important.txt"),
    ("Monitor", "rm important.txt"),
])
def test_claude_and_codex_normalize_shells_equivalently(tool, command):
    payload = {"tool_name": tool, "tool_input": {"command": command},
               "cwd": "C:/workspace", "session_id": "parity"}
    claude = to_event(payload)
    codex = to_events(payload)[0]
    assert claude.kind == codex.kind == events.EXEC
    assert (claude.command, claude.cwd, claude.session_id) == \
        (codex.command, codex.cwd, codex.session_id)


def test_monitor_normalizer_contract_is_explicit_and_literal_only():
    assert claude_adapter.MONITOR_NORMALIZER_CONTRACT == \
        codex_adapter.MONITOR_NORMALIZER_CONTRACT
    assert "literal tool_input.command string" in \
        claude_adapter.MONITOR_NORMALIZER_CONTRACT
    malformed = {"tool_name": "Monitor", "tool_input": {"command": ["echo", "hi"]}}
    assert to_event(malformed).command == ""
    assert to_events(malformed)[0].command == ""


@pytest.mark.parametrize("tool,command,expected", [
    ("Bash", "rm important.txt", events.DENY),
    ("PowerShell", "Remove-Item important.txt", events.DENY),
    ("Monitor", "rm important.txt", events.DENY),
    ("Bash", "agw status", events.ALLOW),
    ("PowerShell", "agw status", events.ALLOW),
    ("Monitor", "agw status", events.ALLOW),
])
def test_claude_and_codex_reach_same_core_decision(tool, command, expected):
    payload = {"tool_name": tool, "tool_input": {"command": command},
               "cwd": os.getcwd(), "session_id": "parity"}
    policy = engine.load_policy(str(PLUGIN))
    left = engine.evaluate(to_event(payload), policy, str(PLUGIN))
    right = engine.evaluate(to_events(payload)[0], policy, str(PLUGIN))
    assert (left.action, left.rule_id) == (right.action, right.rule_id)
    assert left.action == right.action == expected


def test_sessionstart_uses_platform_native_launcher():
    from claude import sessionstart as claude_start
    from codex import sessionstart as codex_start

    for module in (claude_start, codex_start):
        assert module._launcher("nt").endswith('bin\\agw.cmd"')
        assert module._launcher("posix").endswith('bin/agw"')
        expected = "agw.cmd" if os.name == "nt" else "bin/agw"
        assert expected in module.CONTEXT
        if os.name == "nt":
            assert "`agw <cmd>`" not in module.CONTEXT


def test_host_registry_marks_only_maintained_hosts_release_blocking():
    text = (ROOT / "docs" / "HOST_PARITY.md").read_text(encoding="utf-8").lower()
    assert "| claude code | supported | yes |" in text
    assert "| openai codex | supported | yes |" in text
    for host in ("cowork", "cursor", "gemini cli", "github copilot"):
        row = next(line for line in text.splitlines() if line.startswith(f"| {host} |"))
        assert "planned / unsupported" in row
        assert "| no |" in row
