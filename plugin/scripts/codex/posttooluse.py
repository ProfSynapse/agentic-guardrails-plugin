#!/usr/bin/env python3
"""Codex PostToolUse adapter: audit-log completed tool calls and record session
approvals. PostToolUse only fires when a tool actually executed - i.e. it was
allowed or the user approved an ask - so it's the reliable signal that a
resource access was approved. Never blocks."""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = (os.environ.get("PLUGIN_ROOT") or os.environ.get("CLAUDE_PLUGIN_ROOT")
               or os.path.dirname(os.path.dirname(_HERE)))
sys.path.insert(0, os.path.dirname(_HERE))
sys.path.insert(0, _HERE)


def main():
    payload = json.load(sys.stdin)
    from core import auditlog
    from adapter_common import to_events
    tool = payload.get("tool_name", "")
    ti = payload.get("tool_input") or {}
    session = payload.get("session_id", "")

    events_list = to_events(payload)
    paths = [p for e in events_list for p in e.paths if p]
    # For Bash the command is the shell line; for apply_patch `command` is the
    # patch blob, so prefer a real EXEC command and otherwise leave it blank.
    command = ti.get("command", "") if tool == "Bash" else ""
    auditlog.log("posttooluse", {
        "tool": tool, "command": command, "paths": paths,
        "session": session, "platform": "codex",
        "ok": not payload.get("tool_error")})

    # If this call corresponded to an access-type ask, the fact that it ran
    # means it was approved - remember it so we don't re-prompt this session.
    if not payload.get("tool_error"):
        try:
            from core import engine, store
            policy = engine.load_policy(PLUGIN_ROOT)
            if engine.resolve_settings(policy).get("session_memory"):
                for ev in events_list:
                    decision = engine.evaluate(ev, policy, PLUGIN_ROOT)
                    if decision.memo_key:
                        store.session_approve(session, decision.memo_key)
        except Exception:
            pass


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
