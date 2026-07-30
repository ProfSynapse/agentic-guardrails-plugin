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


def test_hooks_config_matches_shell_exec_tools():
    # Every host shell-exec tool must be in the matchers or its commands run
    # through an unmatched tool and the guardrails never fire (fail-open).
    # PowerShell: native Windows shell tool (Git-Bash-present rollout).
    # Monitor: runs background shell scripts, shares Bash's permission format.
    hooks = json.loads(Path(REPO, "hooks", "hooks.json").read_text(encoding="utf-8"))
    for ev in ("PreToolUse", "PostToolUse"):
        matcher = hooks["hooks"][ev][0]["matcher"].split("|")
        for tool in ("Bash", "PowerShell", "Monitor"):
            assert tool in matcher, f"{ev} does not cover the {tool} shell-exec tool"


def test_pretooluse_denies_bare_remove_item_via_shell_tools(tmp_path):
    """Regression: a bare `Remove-Item <path>` arriving through a non-Bash shell
    tool (PowerShell or Monitor, with tool_input.command) must be denied, not
    fall through to OTHER. This is the exact fail-open observed on the Windows
    desktop app where Remove-Item deleted a file without a visible denial."""
    for tool in ("PowerShell", "Monitor"):
        home = tmp_path / f"home-{tool}"
        payload = {"tool_name": tool,
                   "tool_input": {"command": "Remove-Item temp\\junk.log"},
                   "cwd": str(tmp_path), "session_id": f"{tool}-1",
                   "hook_event_name": "PreToolUse"}
        out, dec = _decision(_run(PRE, payload, env_extra={"AGW_HOME": str(home)}))
        assert dec == "deny", (tool, out)
        # The host displays the denial in task history; the hook must not create
        # its retired duplicate audit ledger.
        assert not (home / "audit.jsonl").exists()


# --- PostToolUse: session-approval recording ---------------------------------

def test_posttooluse_records_session_approval(tmp_path):
    secret = tmp_path / ".env"
    secret.write_text("DB_PASSWORD=hunter2hunter2")
    home = tmp_path / "home"
    payload = {"tool_name": "Read", "tool_input": {"file_path": str(secret)},
               "cwd": str(tmp_path), "session_id": "sess-post",
               "event_id": "read-post-1"}
    env = {"AGW_HOME": str(home)}
    _run(PRE, {**payload, "hook_event_name": "PreToolUse"}, env)
    _run(POST, {**payload, "hook_event_name": "PostToolUse"}, env)

    sess_file = home / "sessions" / "sess-post.json"
    assert sess_file.exists(), "PostToolUse did not persist a session record"
    approved = json.loads(sess_file.read_text())["approved"]
    assert any(item.endswith(f":secret-file:{os.path.abspath(secret)}") for item in approved)
    # Session memory is the required recovery state. The retired duplicate
    # audit ledger remains absent.
    assert not (home / "audit.jsonl").exists()


def test_posttooluse_skips_recording_on_tool_error(tmp_path):
    secret = tmp_path / ".env"
    secret.write_text("TOKEN=abc123abc123")
    home = tmp_path / "home"
    payload = {"tool_name": "Read", "tool_input": {"file_path": str(secret)},
               "cwd": str(tmp_path), "session_id": "sess-err",
               "event_id": "read-error-1",
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
               "event_id": "read-strict-1",
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
               "cwd": str(tmp_path), "session_id": "loop-1",
               "event_id": "read-loop-1"}

    _, dec1 = _decision(_run(PRE, {**payload, "hook_event_name": "PreToolUse"}, env))
    assert dec1 == "ask"

    _run(POST, {**payload, "hook_event_name": "PostToolUse"}, env)  # records approval

    out2, dec2 = _decision(_run(PRE, {**payload, "hook_event_name": "PreToolUse"}, env))
    assert "hookSpecificOutput" not in out2  # no longer asks
    assert "already approved this session" in out2.get("systemMessage", "")

    # A second post-hook notification cannot replay the consumed approval.
    session_file = home / "sessions" / "loop-1.json"
    session_file.unlink()
    _run(POST, {**payload, "hook_event_name": "PostToolUse"}, env)
    assert not session_file.exists()


def test_pending_record_contains_no_raw_path_or_memo_key(tmp_path):
    secret = tmp_path / "customer-private.env"
    secret.write_text("DB_PASSWORD=hunter2hunter2")
    home = tmp_path / "home"
    payload = {"tool_name": "Read", "tool_input": {"file_path": str(secret)},
               "cwd": str(tmp_path), "session_id": "privacy-session",
               "event_id": "privacy-event"}
    _, decision = _decision(_run(
        PRE, {**payload, "hook_event_name": "PreToolUse"}, {"AGW_HOME": str(home)}
    ))
    assert decision == "ask"
    pending = list((home / "pending-approvals").iterdir())
    assert len(pending) == 1
    raw = pending[0].read_text()
    assert str(secret) not in raw
    assert secret.name not in raw
    assert "memo_key" not in raw


def test_posttooluse_rejects_policy_revision_change(tmp_path):
    secret = tmp_path / ".env"
    secret.write_text("DB_PASSWORD=hunter2hunter2")
    home = tmp_path / "home"
    custom = home / "policies.d" / "company.json"
    custom.parent.mkdir(parents=True)
    custom.write_text(json.dumps({"settings": {"level": "standard"}}))
    payload = {"tool_name": "Read", "tool_input": {"file_path": str(secret)},
               "cwd": str(tmp_path), "session_id": "revision-session",
               "event_id": "revision-event"}
    env = {"AGW_HOME": str(home)}
    assert _decision(_run(PRE, {**payload, "hook_event_name": "PreToolUse"}, env))[1] == "ask"
    custom.write_text(json.dumps({"settings": {"level": "standard", "marker": 2}}))
    _run(POST, {**payload, "hook_event_name": "PostToolUse"}, env)
    assert not (home / "sessions" / "revision-session.json").exists()
    assert not list((home / "pending-approvals").iterdir())


def test_posttooluse_rejects_degraded_policy_health(tmp_path):
    secret = tmp_path / ".env"
    secret.write_text("DB_PASSWORD=hunter2hunter2")
    home = tmp_path / "home"
    payload = {"tool_name": "Read", "tool_input": {"file_path": str(secret)},
               "cwd": str(tmp_path), "session_id": "health-session",
               "event_id": "health-event"}
    env = {"AGW_HOME": str(home)}
    assert _decision(_run(PRE, {**payload, "hook_event_name": "PreToolUse"}, env))[1] == "ask"
    custom = home / "policies.d" / "broken.yaml"
    custom.parent.mkdir(parents=True)
    custom.write_text("commands:\n  - pattern: [unclosed")
    _run(POST, {**payload, "hook_event_name": "PostToolUse"}, env)
    assert not (home / "sessions" / "health-session.json").exists()
    assert not list((home / "pending-approvals").iterdir())


def test_posttooluse_mismatch_consumes_without_approval(tmp_path):
    first = tmp_path / ".env"
    second = tmp_path / "credentials.json"
    first.write_text("DB_PASSWORD=hunter2hunter2")
    second.write_text('{"password":"another-secret"}')
    home = tmp_path / "home"
    payload = {"tool_name": "Read", "tool_input": {"file_path": str(first)},
               "cwd": str(tmp_path), "session_id": "mismatch-session",
               "event_id": "mismatch-event"}
    env = {"AGW_HOME": str(home)}
    assert _decision(_run(PRE, {**payload, "hook_event_name": "PreToolUse"}, env))[1] == "ask"
    mismatch = {**payload, "tool_input": {"file_path": str(second)},
                "hook_event_name": "PostToolUse"}
    _run(POST, mismatch, env)
    _run(POST, {**payload, "hook_event_name": "PostToolUse"}, env)
    assert not (home / "sessions" / "mismatch-session.json").exists()


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
    for verb in ("archive", "restore", "checkout", "publish"):
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


def test_sessionstart_uses_native_platform_launcher():
    context = _context(_run(START, {"hook_event_name": "SessionStart"}))
    assert "Use `agw`" in context
    assert "Use `agw.cmd`" not in context
    assert "bin/agw" not in context
