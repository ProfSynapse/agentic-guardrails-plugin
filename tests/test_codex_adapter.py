"""Codex adapter contract tests: real subprocess, Codex hook JSON in, decision
JSON out. Mirrors test_adapter.py but exercises the apply_patch path that has no
Claude equivalent."""
import json
import os
import subprocess
import sys

REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugin")
PRE = os.path.join(REPO, "scripts", "codex", "pretooluse.py")
sys.path.insert(0, os.path.join(REPO, "scripts"))


def run_hook(payload, env_extra=None):
    # Codex sets PLUGIN_ROOT (and CLAUDE_PLUGIN_ROOT for compat); use the
    # Codex-native one so we exercise the same env the real host provides.
    env = dict(os.environ, PLUGIN_ROOT=REPO, CODEX_HOME=os.path.expanduser("~/.codex"))
    if env_extra:
        env.update(env_extra)
    payload.setdefault("hook_event_name", "PreToolUse")
    result = subprocess.run([sys.executable, PRE], input=json.dumps(payload),
                            capture_output=True, text=True, env=env, timeout=30)
    assert result.returncode == 0, f"hook crashed the wrapper: {result.stderr}"
    return json.loads(result.stdout) if result.stdout.strip() else {}


def _decision(out):
    return out.get("hookSpecificOutput", {}).get("permissionDecision", "defer")


def _reason(out):
    return out.get("hookSpecificOutput", {}).get("permissionDecisionReason", "")


# --- apply_patch envelope parser ---------------------------------------------

def test_parse_patch_add_update_delete():
    from codex.applypatch import parse_patch
    patch = (
        "*** Begin Patch\n"
        "*** Add File: new.txt\n"
        "+hello\n+world\n"
        "*** Update File: existing.py\n"
        "@@ def f():\n-    old\n+    new\n"
        "*** Delete File: gone.txt\n"
        "*** End Patch\n"
    )
    files = parse_patch(patch)
    by_path = {f["path"]: f for f in files}
    assert by_path["new.txt"]["op"] == "add"
    assert by_path["new.txt"]["added"] == "hello\nworld"
    assert by_path["existing.py"]["op"] == "update"
    assert by_path["existing.py"]["added"] == "    new"  # indentation preserved
    assert by_path["gone.txt"]["op"] == "delete"


def test_parse_patch_move_to():
    from codex.applypatch import parse_patch
    patch = ("*** Update File: a.py\n*** Move to: b.py\n+x\n")
    files = parse_patch(patch)
    assert files[0]["op"] == "update"
    assert files[0]["move_to"] == "b.py"


def test_parse_patch_garbage_is_empty():
    from codex.applypatch import parse_patch
    assert parse_patch("not a patch at all") == []
    assert parse_patch("") == []


# --- shell path (identical contract to Claude) -------------------------------

def test_bash_rm_denied():
    out = run_hook({"tool_name": "Bash", "tool_input": {"command": "rm -rf /tmp/x"},
                    "cwd": "/tmp", "session_id": "c1"})
    assert _decision(out) == "deny"
    assert "agw archive" in _reason(out)


def test_bash_benign_defers():
    out = run_hook({"tool_name": "Bash", "tool_input": {"command": "git status"},
                    "cwd": "/tmp", "session_id": "c1"})
    assert _decision(out) == "defer"


# --- apply_patch behaviour ----------------------------------------------------

def test_apply_patch_delete_is_denied():
    patch = "*** Begin Patch\n*** Delete File: /tmp/whatever.txt\n*** End Patch\n"
    out = run_hook({"tool_name": "apply_patch", "tool_input": {"command": patch},
                    "cwd": "/tmp", "session_id": "c1"})
    assert _decision(out) == "deny"
    assert "agw archive" in _reason(out)


def test_apply_patch_add_defers_and_is_allowed():
    patch = "*** Begin Patch\n*** Add File: /tmp/codex_new.txt\n+content\n*** End Patch\n"
    out = run_hook({"tool_name": "apply_patch", "tool_input": {"command": patch},
                    "cwd": "/tmp", "session_id": "c1"})
    assert _decision(out) in ("defer", "allow")


def test_apply_patch_update_snapshots_pre_image(tmp_path):
    target = tmp_path / "doc.txt"
    target.write_text("precious original")
    home = tmp_path / "home"
    patch = (f"*** Begin Patch\n*** Update File: {target}\n"
             f"@@\n-precious original\n+rewritten\n*** End Patch\n")
    out = run_hook({"tool_name": "apply_patch", "tool_input": {"command": patch},
                    "cwd": str(tmp_path), "session_id": "c1"},
                   env_extra={"AGW_HOME": str(home)})
    assert _decision(out) in ("defer", "allow")
    archived = []
    for dirpath, _dirs, files in os.walk(home / "archive"):
        archived += [os.path.join(dirpath, f) for f in files if "doc.txt" in f]
    assert archived, "pre-image snapshot missing for apply_patch update"
    assert any(open(p).read() == "precious original" for p in archived
               if not p.endswith(".jsonl"))


def test_apply_patch_opaque_fails_to_ask():
    # apply_patch invoked but the patch text is unreadable → fail closed to ask.
    out = run_hook({"tool_name": "apply_patch", "tool_input": {"command": "???"},
                    "cwd": "/tmp", "session_id": "c1"})
    assert _decision(out) == "ask"


def test_mcp_shell_exfil_through_patch_tool_still_evaluated():
    # An MCP shell tool routed through EXEC must still get the rm deny.
    out = run_hook({"tool_name": "mcp__ws__bash",
                    "tool_input": {"command": "rm -rf /tmp/x"},
                    "cwd": "/tmp", "session_id": "c1"})
    assert _decision(out) == "deny"


def test_crash_fails_to_ask(tmp_path):
    bad_root = tmp_path / "bad-plugin"
    bad_root.mkdir()
    (bad_root / "policies").write_text("i am a file not a dir")
    env = dict(os.environ, PLUGIN_ROOT=str(bad_root), CODEX_HOME=os.path.expanduser("~/.codex"))
    result = subprocess.run(
        [sys.executable, PRE],
        input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "rm -rf /x"},
                          "cwd": "/tmp", "session_id": "c1", "hook_event_name": "PreToolUse"}),
        capture_output=True, text=True, env=env, timeout=30)
    assert result.returncode == 0
    out = json.loads(result.stdout) if result.stdout.strip() else {}
    # Either the engine still denies (policy loads with builtins) or it fails
    # closed to ask - never a silent allow/defer for an rm.
    assert _decision(out) in ("deny", "ask")
