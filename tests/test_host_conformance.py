"""Release-blocking parity contracts for maintained and planned hosts."""
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from claude import adapter_common as claude_adapter
from claude.adapter_common import to_event
from codex import adapter_common as codex_adapter
from codex.adapter_common import to_events
from core import engine, events, launcher


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugin"
UNICODE_FILENAMES = (
    "\U0001f5fa map.md",                         # non-BMP map
    "\U0001f600 grin.md",                        # non-BMP face
    "\U0001f469\U0001f3fd\u200d\U0001f4bb developer.md",  # modifier + ZWJ
    "\u2615\ufe0f coffee.md",                    # BMP + variation selector
    "\U0001f1ef\U0001f1f5 flag.md",              # regional-indicator pair
    "#\ufe0f\u20e3 keycap.md",                    # variation selector + combining keycap
    ("\U0001f468\u200d\U0001f469\u200d"
     "\U0001f467\u200d\U0001f466 family.md"),     # multi-ZWJ sequence
    "\u00e9 precomposed.md",
    "e\u0301 decomposed.md",
    "\u65e5\u672c\u8a9e.md",
    "\u0394elta.md",
    "\u0645\u0631\u062d\u0628\u0627.md",
)
UNICODE_ERROR_FILENAMES = (
    UNICODE_FILENAMES[0],   # non-BMP emoji
    UNICODE_FILENAMES[2],   # modifier + ZWJ
    UNICODE_FILENAMES[9],   # multibyte BMP characters
)


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
        # Codex trusts the exact hook-definition hash. Keep the manifest command
        # stable and put runtime/encoding changes in the dispatcher instead.
        assert command.startswith("py.exe -3 ")
        assert "-X utf8" not in command
        # Microsoft Store Python and conda installs have no py.exe. A hook that
        # cannot spawn is a host hook error, and the tool call then proceeds
        # unguarded, so the launcher must fall back to a bare `python`.
        primary, _, fallback = command.partition(" || ")
        assert fallback.startswith("python "), command
        # Both legs address the same dispatcher, with the plugin root still
        # quoted so an install path containing spaces survives cmd.exe.
        target = '"${%s}\\scripts\\' % root_name
        assert primary.count(target) == 1 and fallback.count(target) == 1
        assert primary.endswith(lifecycle.lower()) and \
            fallback.endswith(lifecycle.lower())


@pytest.mark.parametrize("manifest,root_name", [
    ("hooks.json", "CLAUDE_PLUGIN_ROOT"),
    ("hooks-codex.json", "PLUGIN_ROOT"),
])
def test_posix_hook_fallback_only_fires_when_python3_is_absent(manifest, root_name):
    """A plain `||` reruns the adapter on *any* non-zero exit.

    Both legs read the same stdin, so the second one gets a drained pipe and
    appends a second JSON object to a stream that already holds a decision -
    which the host cannot parse, and an unparseable decision is an allow.
    Restrict the fallback to exit 127, the shell's "no such interpreter".
    """
    for lifecycle in ("PreToolUse", "PostToolUse", "SessionStart"):
        command = _hooks(manifest)[lifecycle][0]["hooks"][0]["command"]
        assert command.startswith("python3 ")
        assert "[ $? -eq 127 ]" in command
        assert '"${%s}/scripts/' % root_name in command
        # No bare `|| python`: that is the fail-open spelling this guards.
        assert "|| python " not in command


def _json_objects(text):
    """Split a stdout blob into the top-level JSON objects it actually holds."""
    decoder = json.JSONDecoder()
    objects, index = [], 0
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        value, index = decoder.raw_decode(text, index)
        objects.append(value)
    return objects


def _shim_path_without_python3(tmp_path):
    """A PATH directory that offers `python` but no `python3` at all."""
    shim_dir = tmp_path / "shim-bin"
    shim_dir.mkdir()
    shim = shim_dir / "python"
    shim.write_text('#!/bin/sh\nexec "%s" "$@"\n' % sys.executable, encoding="utf-8")
    shim.chmod(0o755)
    return shim_dir


@pytest.mark.skipif(os.name == "nt", reason="POSIX hook command string")
@pytest.mark.parametrize("manifest,root_name,shadow", [
    ("hooks.json", "CLAUDE_PLUGIN_ROOT", False),
    ("hooks.json", "CLAUDE_PLUGIN_ROOT", True),
    ("hooks-codex.json", "PLUGIN_ROOT", False),
    ("hooks-codex.json", "PLUGIN_ROOT", True),
])
def test_posix_hook_command_emits_exactly_one_decision(
        manifest, root_name, shadow, tmp_path):
    """Spawn the literal manifest command the way the host does.

    With `python3` present the first leg answers. With `python3` absent the
    shell reports 127 and the fallback answers. Either way the host must find
    exactly one JSON object on stdout - two would be unparseable, and an
    unparseable decision is an allow.
    """
    command = _hooks(manifest)["PreToolUse"][0]["hooks"][0]["command"]
    shell = shutil.which("sh")
    assert shell, "no POSIX shell to run the hook command with"
    env = dict(os.environ, AGW_HOME=str(tmp_path / "agw-home"),
               AGW_APPROVAL_PROVIDER="headless", AGW_TEST_MODE="1")
    env[root_name] = str(PLUGIN)
    if shadow:
        env["PATH"] = str(_shim_path_without_python3(tmp_path))
    payload = {"tool_name": "Shell", "cwd": str(tmp_path),
               "tool_input": {"command": "rm -rf ~/Documents"},
               "session_id": "one-object", "hook_event_name": "PreToolUse"}
    result = subprocess.run([shell, "-c", command], input=json.dumps(payload),
                            capture_output=True, text=True, env=env, timeout=60)
    objects = _json_objects(result.stdout)
    assert len(objects) == 1, (result.stdout, result.stderr)
    decision = objects[0]["hookSpecificOutput"]["permissionDecision"]
    # Claude asks; Codex has no hook-level ask and denies through the provider.
    assert decision in ("ask", "deny")


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
        assert "exact host-supplied `SKILL.md` location" in module.CONTEXT
        assert "never infer, shorten, search for, or expose" in module.CONTEXT
        assert "run-plan create/apply" in module.CONTEXT
        assert "single-use" in module.CONTEXT
        assert "read-only filesystem" in module.CONTEXT
        assert "per-file sequential visibility" in module.CONTEXT
        assert "inspect or all-after finalize-observed" in module.CONTEXT
        assert "Rollback awaits a crash-resumable journal" in module.CONTEXT


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


def test_trusted_workflow_rewrite_encodes_exact_original_argv():
    original = 'python "writer script.py" --profile alpha'
    posix = launcher.rewrite_trusted_workflow(
        original, "example.writer", str(PLUGIN), platform="posix", shell="posix",
    )
    argv = shlex.split(posix)
    assert argv[1] == "--agw-argv-b64"
    assert launcher.decode_internal_argv(argv[1:]) == [
        "run", "--workflow", "example.writer", "--",
        "python", "writer script.py", "--profile", "alpha",
    ]

    windows = launcher.rewrite_trusted_workflow(
        original, "example.writer", str(PLUGIN), platform="nt", shell="powershell",
    )
    payload = windows.rsplit("'", 2)[1]
    assert launcher.decode_internal_argv(["--agw-argv-b64", payload]) == [
        "run", "--workflow", "example.writer", "--",
        "python", "writer script.py", "--profile", "alpha",
    ]


def test_trusted_workflow_rewrite_refuses_compound_or_invalid_input():
    assert launcher.rewrite_trusted_workflow(
        "python writer.py; rm output.txt", "example.writer", str(PLUGIN),
        platform="posix", shell="posix",
    ) is None
    assert launcher.rewrite_trusted_workflow(
        "python writer.py", "INVALID WORKFLOW", str(PLUGIN),
        platform="posix", shell="posix",
    ) is None


def test_windows_short_launcher_rewrites_literal_pipeline_receiver():
    original = (
        "$rows = @'\nfirst row\nsecond row é\n'@\n"
        "$rows | agw file write 'temporary ledger.md' --content-file - "
        "--expected-hash absent --json"
    )
    rewritten = launcher.rewrite_shortcut(
        original, str(PLUGIN), platform="nt", shell="powershell",
    )
    assert "$rows = @'\nfirst row\nsecond row é\n'@\n" in rewritten
    assert "$rows | & '" in rewritten
    assert "bin\\agw.cmd' file write 'temporary ledger.md'" in rewritten
    assert "| agw file write" not in rewritten


def test_windows_short_launcher_rewrites_literal_later_statement():
    original = (
        "$oldText = 'before'; $newText = 'after'; "
        "agw file replace 'ledger.md' --old $oldText --new $newText "
        "--dry-run --json"
    )
    rewritten = launcher.rewrite_shortcut(
        original, str(PLUGIN), platform="nt", shell="powershell",
    )
    assert "$oldText = 'before'; $newText = 'after'; & '" in rewritten
    assert "bin\\agw.cmd' file replace 'ledger.md'" in rewritten
    assert "--old $oldText --new $newText --dry-run --json" in rewritten
    assert "; agw file replace" not in rewritten


def test_windows_short_launcher_rewrites_after_completed_here_string():
    original = (
        "$oldText = @'\nbefore\n'@\n"
        "$newText = @'\nafter\n'@\n"
        "agw file replace 'ledger.md' --old $oldText --new $newText "
        "--dry-run --json"
    )
    rewritten = launcher.rewrite_shortcut(
        original, str(PLUGIN), platform="nt", shell="powershell",
    )
    assert "$oldText = @'\nbefore\n'@\n" in rewritten
    assert "$newText = @'\nafter\n'@\n& '" in rewritten
    assert "bin\\agw.cmd' file replace 'ledger.md'" in rewritten


def test_windows_pipeline_receiver_encodes_static_unicode_arguments():
    filename = "🗺 ledger 日本語.md"
    original = (
        "Write-Output 'row' | agw file write "
        f"'{filename}' --content-file - --expected-hash absent --json"
    )
    rewritten = launcher.rewrite_shortcut(
        original, str(PLUGIN), platform="nt", shell="powershell",
    )
    assert "Write-Output 'row' | & '" in rewritten
    assert filename not in rewritten
    payload = rewritten.rsplit("'", 2)[1]
    assert launcher.decode_internal_argv(
        ["--agw-argv-b64", payload]
    ) == [
        "file", "write", filename, "--content-file", "-",
        "--expected-hash", "absent", "--json",
    ]


@pytest.mark.parametrize("command", [
    "Write-Output '| agw status'",
    "$text = @'\n| agw status\n'@\nWrite-Output $text",
    "Write-Output x | 'agw' status",
    "Write-Output x | & agw status",
    r"Write-Output x | .\agw status",
    "Write-Output x | agwx status",
    "Write-Output x | ForEach-Object { agw status }",
    "Write-Output x | agw status > status.json",
])
def test_windows_pipeline_rewrite_does_not_trust_data_or_ambiguous_heads(command):
    assert launcher.rewrite_shortcut(
        command, str(PLUGIN), platform="nt", shell="powershell",
    ) is None


@pytest.mark.parametrize("filename", UNICODE_FILENAMES)
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_windows_short_launcher_encodes_multiline_unicode_losslessly(filename, newline):
    original = (
        f"agw file read '{filename}' `{newline}"
        "  --start-line 1 --limit 2000 `" + newline
        + "  --max-bytes 262144 --json"
    )
    rewritten = launcher.rewrite_shortcut(
        original, str(PLUGIN), platform="nt", shell="powershell",
    )
    assert "--agw-argv-b64" in rewritten
    assert filename not in rewritten
    payload = rewritten.rsplit("'", 2)[1]
    assert launcher.decode_internal_argv(
        ["--agw-argv-b64", payload]
    ) == [
        "file", "read", filename, "--start-line", "1", "--limit", "2000",
        "--max-bytes", "262144", "--json",
    ]


def test_windows_short_launcher_preserves_reported_h_drive_path_exactly():
    expected = (
        "H:\\Shared drives\\Synaptic Labs\\"
        "\U0001f5fa Synaptic Labs Vault Map of Content.md"
    )
    rewritten = launcher.rewrite_shortcut(
        f'agw file read "{expected}" `\r\n'
        "  --start-line 1 --limit 2000 --max-bytes 262144 --json",
        str(PLUGIN), platform="nt", shell="powershell",
    )
    payload = rewritten.rsplit("'", 2)[1]
    assert launcher.decode_internal_argv(
        ["--agw-argv-b64", payload]
    ) == [
        "file", "read", expected, "--start-line", "1", "--limit", "2000",
        "--max-bytes", "262144", "--json",
    ]


def test_windows_unicode_rewrite_fails_closed_for_compound_shell_syntax():
    for command in (
        "agw file read '\U0001f5fa.md'; Remove-Item x",
        "agw file read '\U0001f5fa.md' | Out-String",
        "agw file read '\U0001f5fa.md' > output.txt",
        "agw file read '\U0001f5fa.md' `\n  ; Remove-Item x",
        "agw file read '\U0001f5fa.md'\n  Remove-Item x",
        "agw file read '\U0001f5fa.md' ` \n  --json",
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
def test_windows_pipeline_receiver_writes_stdin_with_recovery(tmp_path):
    target = tmp_path / "🗺 pipeline ledger 日本語.txt"
    escaped = str(target).replace("'", "''")
    command = launcher.rewrite_shortcut(
        "@'\nfirst row\nsecond row\n'@ | agw file write "
        f"'{escaped}' --content-file - --expected-hash absent --json",
        str(PLUGIN), platform="nt", shell="powershell",
    )
    home = tmp_path / "agw-home"
    env = dict(os.environ, AGW_HOME=str(home))
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", command],
        text=True, encoding="utf-8", capture_output=True, env=env, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert target.read_text(encoding="utf-8").splitlines() == [
        "first row", "second row",
    ]
    records = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in (home / "transactions").glob("*.json")
    ]
    assert len(records) == 1
    assert records[0]["kind"] == "absent_tombstone"


@pytest.mark.skipif(os.name != "nt", reason="Windows launcher execution")
def test_windows_later_statement_runs_file_replace_dry_run(tmp_path):
    target = tmp_path / "replace target.txt"
    target.write_text("before", encoding="utf-8")
    escaped = str(target).replace("'", "''")
    command = launcher.rewrite_shortcut(
        "$oldText = 'before'; $newText = 'after'; "
        f"agw file replace '{escaped}' --old $oldText --new $newText "
        "--dry-run --json",
        str(PLUGIN), platform="nt", shell="powershell",
    )
    home = tmp_path / "agw-home"
    env = dict(os.environ, AGW_HOME=str(home))
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", command],
        text=True, encoding="utf-8", capture_output=True, env=env, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["dry_run"] is True
    assert target.read_text(encoding="utf-8") == "before"
    assert not (home / "transactions").exists()


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


@pytest.mark.skipif(os.name != "nt", reason="Windows launcher execution")
def test_windows_multiline_launcher_preserves_unicode_success_and_error_paths(tmp_path):
    env = dict(os.environ, AGW_HOME=str(tmp_path / "agw-home"))
    for filename in UNICODE_FILENAMES:
        target = tmp_path / filename
        content = f"content:{filename}\n"
        target.write_text(content, encoding="utf-8", newline="")
        command = launcher.rewrite_shortcut(
            f"agw file read '{filename}' `\r\n"
            "  --start-line 1 --limit 2000 `\r\n"
            "  --max-bytes 262144 --json",
            str(PLUGIN), platform="nt", shell="powershell",
        )
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", command],
            cwd=tmp_path, text=True, encoding="utf-8", capture_output=True,
            env=env, timeout=30,
        )
        assert result.returncode == 0, (filename, result.stderr)
        payload = json.loads(result.stdout)
        assert payload["path"] == str(target)
        assert payload["content"] == content

        if filename not in UNICODE_ERROR_FILENAMES:
            continue
        missing_name = "missing-" + filename
        missing = tmp_path / missing_name
        error_command = launcher.rewrite_shortcut(
            f"agw file read '{missing_name}' `\r\n  --json",
            str(PLUGIN), platform="nt", shell="powershell",
        )
        error = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", error_command],
            cwd=tmp_path, text=True, encoding="utf-8", capture_output=True,
            env=env, timeout=30,
        )
        assert error.returncode != 0, filename
        error_payload = json.loads(error.stderr)
        assert error_payload["error"]["details"]["path"] == str(missing)
        message = error_payload["error"]["message"]
        assert repr(missing_name)[1:-1] in message
        mojibake = missing_name.encode("utf-8").decode("latin-1")
        assert mojibake not in error_payload["error"]["details"]["path"]


def test_sessionstart_uses_host_approval_without_security_workarounds():
    from claude import sessionstart as claude_start
    from codex import sessionstart as codex_start

    for module in (claude_start, codex_start):
        context = module.CONTEXT.lower()
        assert "outside-workspace approval" in context
        assert "never change acls" in context
        assert "filesystem permissions" in context
        assert "path" in context


def _gitattributes_lines():
    text = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")]


def test_batch_launchers_are_checked_out_with_crlf():
    """cmd.exe seeks through a batch file by byte offset and re-reads after
    every command, so `goto :label` and parenthesised blocks resolve against
    file positions. agw.cmd uses both, and an LF-only checkout shifts them."""
    lines = _gitattributes_lines()
    for pattern in ("*.cmd", "*.bat"):
        matches = [line for line in lines if line.split()[0] == pattern]
        assert matches, f"{pattern} has no .gitattributes rule"
        assert "eol=crlf" in matches[-1], matches
    # A broad `plugin/bin/* text eol=lf` sits above these, and the last matching
    # rule wins, so the batch rules have to come after it.
    assert lines.index([l for l in lines if l.split()[0] == "*.cmd"][-1]) > \
        lines.index([l for l in lines if l.split()[0] == "plugin/bin/*"][-1])


def test_gitattributes_only_protects_paths_that_exist():
    """A rule naming a path that does not exist protects nothing, silently.

    `synthetic/cowork-safety-lab/workspace/**` was such a rule: the real tree is
    `synthetic/safety-lab/`, so the byte-exact fixtures it claimed to protect
    were normalized like any other text on a Windows checkout.
    """
    for line in _gitattributes_lines():
        pattern = line.split()[0]
        if "/" not in pattern or pattern.startswith("*"):
            continue
        base = pattern.split("*", 1)[0].rstrip("/")
        assert (ROOT / base).exists(), f"{pattern} names a path that does not exist"


@pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
def test_git_resolves_the_batch_launcher_to_crlf():
    resolved = subprocess.run(
        ["git", "check-attr", "text", "eol", "--", "plugin/bin/agw.cmd"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=30,
    )
    if resolved.returncode != 0:  # not a work tree (packed artifact run)
        pytest.skip(resolved.stderr.strip() or "git check-attr unavailable")
    assert "eol: crlf" in resolved.stdout, resolved.stdout


def test_readme_release_banner_names_the_shipped_version():
    """The banner is the first version a human reads, and it drifted.

    It advertised `0.3.23` as the Windows-first stable release; no v0.3.23 tag
    ever existed (tags jump v0.3.6 -> v0.3.26) while every manifest said 0.4.4.
    """
    version = json.loads(
        (PLUGIN / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )["version"]
    banner = next(line for line in (ROOT / "README.md").read_text(
        encoding="utf-8").splitlines() if "**Release status:**" in line)
    assert f"`{version}`" in banner, banner
    # RELEASING.md must list the banner, or nothing makes the next bump happen.
    releasing = (ROOT / "RELEASING.md").read_text(encoding="utf-8")
    assert "Release status" in releasing and "README.md" in releasing


def test_host_registry_marks_only_maintained_hosts_release_blocking():
    text = (ROOT / "docs" / "HOST_PARITY.md").read_text(encoding="utf-8").lower()
    assert "| claude code | supported | yes |" in text
    assert "| openai codex | supported | yes |" in text
    for host in ("cowork", "cursor", "gemini cli", "github copilot"):
        row = next(line for line in text.splitlines() if line.startswith(f"| {host} |"))
        assert "planned / unsupported" in row
        assert "| no |" in row
