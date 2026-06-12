"""Adapter contract tests: real subprocess, hook JSON in, decision JSON out."""
import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PRE = os.path.join(REPO, "scripts", "claude", "pretooluse.py")


def run_hook(payload, env_extra=None):
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=REPO)
    if env_extra:
        env.update(env_extra)
    result = subprocess.run([sys.executable, PRE], input=json.dumps(payload),
                            capture_output=True, text=True, env=env, timeout=30)
    assert result.returncode == 0, f"hook crashed the wrapper: {result.stderr}"
    return json.loads(result.stdout) if result.stdout.strip() else {}


def _decision(out):
    return out.get("hookSpecificOutput", {}).get("permissionDecision", "defer")


def test_bash_rm_denied():
    out = run_hook({"tool_name": "Bash", "tool_input": {"command": "rm -rf /tmp/x"},
                    "cwd": "/tmp", "session_id": "t1", "hook_event_name": "PreToolUse"})
    assert _decision(out) == "deny"
    assert "agw archive" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_bash_benign_defers():
    out = run_hook({"tool_name": "Bash", "tool_input": {"command": "git status"},
                    "cwd": "/tmp", "session_id": "t1", "hook_event_name": "PreToolUse"})
    assert _decision(out) == "defer"


def test_write_snapshots_pre_image(tmp_path):
    target = tmp_path / "doc.txt"
    target.write_text("precious original")
    home = tmp_path / "home"
    out = run_hook({"tool_name": "Write",
                    "tool_input": {"file_path": str(target), "content": "new content"},
                    "cwd": str(tmp_path), "session_id": "t1",
                    "hook_event_name": "PreToolUse"},
                   env_extra={"AGW_HOME": str(home)})
    assert _decision(out) in ("defer", "allow")
    archived = []
    for dirpath, _dirs, files in os.walk(home / "archive"):
        archived += [os.path.join(dirpath, f) for f in files if "doc.txt" in f]
    assert archived, "pre-image snapshot missing"
    assert any(open(p).read() == "precious original" for p in archived
               if not p.endswith(".jsonl"))


def test_crash_fails_to_ask(tmp_path):
    # point the hook at a plugin root whose policy dir is a FILE → load chokes,
    # adapter must still emit ask (not crash, not allow)
    bad_root = tmp_path / "bad-plugin"
    bad_root.mkdir()
    (bad_root / "policies").write_text("not a directory")
    out = run_hook({"tool_name": "Bash", "tool_input": {"command": "echo hi"},
                    "cwd": "/tmp", "session_id": "t1", "hook_event_name": "PreToolUse"},
                   env_extra={"CLAUDE_PLUGIN_ROOT": str(bad_root)})
    # engine may survive this gracefully (defer) — but it must never crash;
    # force a real crash with malformed stdin instead
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=REPO)
    result = subprocess.run([sys.executable, PRE], input="THIS IS NOT JSON",
                            capture_output=True, text=True, env=env, timeout=30)
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_mcp_delete_denied():
    out = run_hook({"tool_name": "mcp__google_drive__delete_file",
                    "tool_input": {"fileId": "abc"}, "cwd": "/tmp",
                    "session_id": "t1", "hook_event_name": "PreToolUse"})
    assert _decision(out) == "deny"


def test_audit_redaction(tmp_path):
    home = tmp_path / "home"
    run_hook({"tool_name": "Bash",
              "tool_input": {"command": "rm -rf /x && export AWS_KEY=AKIAIOSFODNN7EXAMPLE"},
              "cwd": "/tmp", "session_id": "t1", "hook_event_name": "PreToolUse"},
             env_extra={"AGW_HOME": str(home)})
    audit = (home / "audit.jsonl").read_text()
    assert "AKIAIOSFODNN7EXAMPLE" not in audit
    assert "[REDACTED]" in audit
