"""Subprocess contract tests for the two lifecycle adapters that the rest of
the suite doesn't drive: PostToolUse (records session approvals — the *write*
half of ask-once memory) and SessionStart (injects the agw vocabulary plus the
active-level note). Real subprocesses, hook JSON in, side effects out."""
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugin")
PRE = os.path.join(REPO, "scripts", "claude", "pretooluse.py")
POST = os.path.join(REPO, "scripts", "claude", "posttooluse.py")
START = os.path.join(REPO, "scripts", "claude", "sessionstart.py")


def _run(script, payload, env_extra=None, stdin=None):
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=REPO)
    if env_extra:
        env.update(env_extra)
    text = stdin if stdin is not None else json.dumps(payload)
    result = subprocess.run([sys.executable, script], input=text,
                            capture_output=True, text=True, env=env, timeout=30)
    assert result.returncode == 0, f"adapter crashed: {result.stderr}"
    return result


def _decision(result):
    out = json.loads(result.stdout) if result.stdout.strip() else {}
    return out, out.get("hookSpecificOutput", {}).get("permissionDecision", "defer")


def test_hooks_config_runs_posttooluse_for_reads():
    hooks = json.loads(Path(REPO, "hooks", "hooks.json").read_text(encoding="utf-8"))
    matcher = hooks["hooks"]["PostToolUse"][0]["matcher"]
    assert "Read" in matcher.split("|"), "Read approvals are not persisted without this hook"


# --- PostToolUse: session-approval recording ---------------------------------

def test_posttooluse_records_session_approval(tmp_path):
    secret = tmp_path / ".env"
    secret.write_text("DB_PASSWORD=hunter2hunter2")
    home = tmp_path / "home"
    payload = {"tool_name": "Read", "tool_input": {"file_path": str(secret)},
               "cwd": str(tmp_path), "session_id": "sess-post",
               "hook_event_name": "PostToolUse"}
    _run(POST, payload, env_extra={"AGW_HOME": str(home)})

    sess_file = home / "sessions" / "sess-post.json"
    assert sess_file.exists(), "PostToolUse did not persist a session record"
    approved = json.loads(sess_file.read_text())["approved"]
    assert f"secret-file:{os.path.abspath(secret)}" in approved
    # and it audit-logs the completed call
    assert "posttooluse" in (home / "audit.jsonl").read_text()


def test_posttooluse_skips_recording_on_tool_error(tmp_path):
    secret = tmp_path / ".env"
    secret.write_text("TOKEN=abc123abc123")
    home = tmp_path / "home"
    payload = {"tool_name": "Read", "tool_input": {"file_path": str(secret)},
               "cwd": str(tmp_path), "session_id": "sess-err",
               "tool_error": "permission denied", "hook_event_name": "PostToolUse"}
    _run(POST, payload, env_extra={"AGW_HOME": str(home)})
    # a failed call was never really approved, so nothing is remembered
    assert not (home / "sessions" / "sess-err.json").exists()


def test_posttooluse_noop_when_session_memory_off(tmp_path):
    secret = tmp_path / ".env"
    secret.write_text("KEY=zzz999zzz999")
    home = tmp_path / "home"
    payload = {"tool_name": "Read", "tool_input": {"file_path": str(secret)},
               "cwd": str(tmp_path), "session_id": "sess-strict",
               "hook_event_name": "PostToolUse"}
    # strict level disables session memory entirely
    _run(POST, payload, env_extra={"AGW_HOME": str(home), "AGW_LEVEL": "strict"})
    assert not (home / "sessions" / "sess-strict.json").exists()


def test_ask_once_memory_full_loop(tmp_path):
    """End to end: PreToolUse asks, PostToolUse records the approval, PreToolUse
    then stops asking — the write/read halves of the feature, wired together by
    the real adapters rather than a direct store call."""
    secret = tmp_path / ".env"
    secret.write_text("DB_PASSWORD=hunter2hunter2")
    home = tmp_path / "home"
    env = {"AGW_HOME": str(home)}
    payload = {"tool_name": "Read", "tool_input": {"file_path": str(secret)},
               "cwd": str(tmp_path), "session_id": "loop-1"}

    _, dec1 = _decision(_run(PRE, {**payload, "hook_event_name": "PreToolUse"}, env))
    assert dec1 == "ask"

    _run(POST, {**payload, "hook_event_name": "PostToolUse"}, env)  # records approval

    out2, dec2 = _decision(_run(PRE, {**payload, "hook_event_name": "PreToolUse"}, env))
    assert "hookSpecificOutput" not in out2  # no longer asks
    assert "already approved this session" in out2.get("systemMessage", "")


def test_posttooluse_never_crashes_on_garbage():
    # PostToolUse must never break the wrapper, even on malformed stdin
    result = _run(POST, None, stdin="NOT JSON AT ALL")
    assert result.returncode == 0


# --- SessionStart: context injection -----------------------------------------

def _context(result):
    return json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]


def test_sessionstart_injects_vocabulary():
    ctx = _context(_run(START, {"hook_event_name": "SessionStart"}))
    # the core verbs the agent must learn
    for verb in ("agw archive", "agw restore", "agw checkout", "agw publish"):
        assert verb in ctx
    # standard (default) level adds no extra level note
    assert "Enforcement level:" not in ctx


def test_sessionstart_appends_level_note():
    cases = {"observe": "OBSERVE", "strict": "STRICT", "relaxed": "RELAXED"}
    for level, marker in cases.items():
        ctx = _context(_run(START, {"hook_event_name": "SessionStart"},
                            env_extra={"AGW_LEVEL": level}))
        assert "Enforcement level:" in ctx
        assert marker in ctx


def test_sessionstart_survives_no_stdin():
    # SessionStart ignores stdin; empty input must still yield valid context
    result = _run(START, None, stdin="")
    assert "agentic-guardrails is active" in _context(result)
