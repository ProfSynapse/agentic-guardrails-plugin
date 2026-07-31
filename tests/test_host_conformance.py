"""Release-blocking parity contracts for maintained and planned hosts."""
import json
import os
import subprocess
from pathlib import Path

import pytest

from claude import adapter_common as claude_adapter
from claude.adapter_common import to_event
from codex import adapter_common as codex_adapter
from codex.adapter_common import to_events
from core import engine, events, launcher


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
    ("Bash", "agw status", events.DENY),
    ("PowerShell", "agw status", events.DENY),
    ("Monitor", "agw status", events.DENY),
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
        assert module._launcher("nt") == "agw"
        assert module._launcher("posix") == "agw"
        assert "Use `agw`" in module.CONTEXT
        assert "Use `agw.cmd`" not in module.CONTEXT
        assert str(PLUGIN) not in module.CONTEXT
        assert "trusted PreToolUse hook" in module.CONTEXT


def test_short_launcher_expansion_is_exact_and_boundary_aware():
    windows = launcher.rewrite_shortcut(
        "  agw.cmd status --json", str(PLUGIN), platform="nt", shell="powershell"
    )
    assert windows.startswith("  & '")
    assert "bin\\agw.cmd' status --json" in windows

    posix = launcher.rewrite_shortcut(
        "agw status --json", str(PLUGIN), platform="posix", shell="posix"
    )
    assert str(PLUGIN / "bin" / "agw") in posix
    assert posix.endswith(" status --json")

    for command in ("agwx status", "./agw status", "'agw' status",
                    "echo agw status", "MODE=test agw status"):
        assert launcher.rewrite_shortcut(
            command, str(PLUGIN), platform="posix", shell="posix"
        ) is None


def test_windows_short_launcher_encodes_unicode_arguments_losslessly():
    original = "agw file read '🗺 vault-map.md' --json"
    rewritten = launcher.rewrite_shortcut(
        original, str(PLUGIN), platform="nt", shell="powershell",
    )
    assert "--agw-argv-b64" in rewritten
    assert "🗺" not in rewritten
    payload = rewritten.rsplit("'", 2)[1]
    assert launcher.decode_internal_argv(
        ["--agw-argv-b64", payload]
    ) == ["file", "read", "🗺 vault-map.md", "--json"]


def test_windows_unicode_rewrite_fails_closed_for_compound_shell_syntax():
    for command in (
        "agw file read '🗺.md'; Remove-Item x",
        "agw file read '🗺.md' | Out-String",
        "agw file read '🗺.md' > output.txt",
    ):
        assert launcher.rewrite_shortcut(
            command, str(PLUGIN), platform="nt", shell="powershell",
        ) is None


@pytest.mark.skipif(os.name != "nt", reason="Windows launcher execution")
def test_windows_short_launcher_expansion_executes_real_cli(tmp_path):
    command = launcher.rewrite_shortcut(
        "agw status --json", str(PLUGIN), platform="nt", shell="powershell"
    )
    env = dict(os.environ, AGW_HOME=str(tmp_path / "agw-home"))
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", command],
        text=True, capture_output=True, env=env, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    status = json.loads(result.stdout)
    assert status["archive_bytes"] == 0
    assert status["incomplete_office_transactions"] == []


@pytest.mark.skipif(os.name != "nt", reason="Windows launcher execution")
def test_windows_short_launcher_reads_emoji_filename_without_mojibake(tmp_path):
    target = ROOT / "tests" / "fixtures" / "🗺 vault-map.md"
    escaped = str(target).replace("'", "''")
    command = launcher.rewrite_shortcut(
        f"agw file read '{escaped}' --json",
        str(PLUGIN), platform="nt", shell="powershell",
    )
    env = dict(os.environ, AGW_HOME=str(tmp_path / "agw-home"))
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", command],
        text=True, encoding="utf-8", capture_output=True, env=env, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert Path(payload["path"]).name == "🗺 vault-map.md"
    assert payload["content"] == "unicode launcher fixture\n"


def test_sessionstart_uses_host_approval_without_security_workarounds():
    from claude import sessionstart as claude_start
    from codex import sessionstart as codex_start

    for module in (claude_start, codex_start):
        context = module.CONTEXT.lower()
        assert "outside-workspace approval" in context
        assert "never change acls" in context
        assert "filesystem permissions" in context
        assert "path" in context


def test_host_registry_marks_only_maintained_hosts_release_blocking():
    text = (ROOT / "docs" / "HOST_PARITY.md").read_text(encoding="utf-8").lower()
    assert "| claude code | supported | yes |" in text
    assert "| openai codex | supported | yes |" in text
    for host in ("cowork", "cursor", "gemini cli", "github copilot"):
        row = next(line for line in text.splitlines() if line.startswith(f"| {host} |"))
        assert "planned / unsupported" in row
        assert "| no |" in row
