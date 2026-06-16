#!/usr/bin/env python3
"""Claude PostToolUse adapter: audit-log completed tool calls and record
session approvals. PostToolUse only fires when a tool actually executed — i.e.
it was allowed or the user approved an ask — so it's the reliable signal that
a resource access was approved. Never blocks."""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = os.environ.get("CLAUDE_PLUGIN_ROOT") or os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, os.path.dirname(_HERE))
sys.path.insert(0, _HERE)


def main():
    payload = json.load(sys.stdin)
    from core import auditlog
    ti = payload.get("tool_input") or {}
    session = payload.get("session_id", "")
    auditlog.log("posttooluse", {
        "tool": payload.get("tool_name", ""),
        "command": ti.get("command", ""),
        "paths": [p for p in [ti.get("file_path", "")] if p],
        "session": session,
        "ok": not payload.get("tool_error"),
    })

    # If this call corresponded to an access-type ask, the fact that it ran
    # means it was approved — remember it so we don't re-prompt this session.
    if not payload.get("tool_error"):
        try:
            from adapter_common import to_event
            from core import engine, store
            policy = engine.load_policy(PLUGIN_ROOT)
            if engine.resolve_settings(policy).get("session_memory"):
                decision = engine.evaluate(to_event(payload), policy, PLUGIN_ROOT)
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
