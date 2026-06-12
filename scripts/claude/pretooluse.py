#!/usr/bin/env python3
"""Claude PreToolUse adapter: hook JSON on stdin → permissionDecision on stdout.

CRASH POLICY (the most important rule in this codebase): any internal failure
becomes ASK — never a silent allow (a nonzero exit would be non-blocking),
never an unconditional deny (which would brick the session on our own bugs).
"""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = os.environ.get("CLAUDE_PLUGIN_ROOT") or os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, os.path.dirname(_HERE))  # make `core` importable

FAIL_CLOSED = {
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "ask",
        "permissionDecisionReason":
            "agentic-guardrails hit an internal error evaluating this call "
            "(fail-closed). Review the operation manually.",
    }
}


def to_event(payload):
    from core import events
    tool = payload.get("tool_name", "")
    ti = payload.get("tool_input") or {}
    common = dict(cwd=payload.get("cwd", ""), session_id=payload.get("session_id", ""),
                  platform="claude", tool=tool)
    if tool == "Bash":
        return events.ToolEvent(kind=events.EXEC, command=ti.get("command", ""), **common)
    if tool == "Write":
        return events.ToolEvent(kind=events.WRITE, paths=[ti.get("file_path", "")],
                                content=ti.get("content", ""), **common)
    if tool in ("Edit", "NotebookEdit"):
        return events.ToolEvent(kind=events.EDIT, paths=[ti.get("file_path",
                                ti.get("notebook_path", ""))],
                                content=ti.get("new_string", ti.get("new_source", "")),
                                **common)
    if tool == "Read":
        return events.ToolEvent(kind=events.READ, paths=[ti.get("file_path", "")], **common)
    if tool.startswith("mcp__"):
        return events.ToolEvent(kind=events.MCP, extra={"input": ti}, **common)
    return events.ToolEvent(kind=events.OTHER, extra={"input": ti}, **common)


def main():
    payload = json.load(sys.stdin)
    from core import auditlog, engine, events, store

    event = to_event(payload)
    policy = engine.load_policy(PLUGIN_ROOT)
    decision = engine.evaluate(event, policy, PLUGIN_ROOT)

    # Write/Edit pre-image snapshot: nothing is ever destroyed, even by the
    # native tools. Hash-deduped, so repeat edits are nearly free.
    if event.kind in (events.WRITE, events.EDIT) and decision.action in (
            events.DEFER, events.ALLOW):
        for path in event.paths:
            try:
                if path and os.path.isfile(path):
                    store.archive_file(path, mode="copy", dedupe=True,
                                       reason=f"pre-image before {event.tool}",
                                       actor="guardrails-hook")
            except Exception:
                decision = decision.merge(engine.Decision(
                    events.ASK, "Could not snapshot the file before modification "
                                "(archive store unavailable?) — proceed only if a copy "
                                "exists elsewhere.", "builtin:snapshot-failed"))

    if decision.action != events.DEFER or decision.warnings:
        auditlog.log("pretooluse", {
            "tool": event.tool, "kind": event.kind, "decision": decision.action,
            "rule": decision.rule_id, "reason": decision.reason,
            "command": event.command, "paths": event.paths,
            "session": event.session_id})

    out = {}
    if decision.action in (events.ALLOW, events.ASK, events.DENY):
        reason = decision.reason
        if decision.warnings:
            reason = (reason + " | " if reason else "") + "; ".join(decision.warnings)
        out = {"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision.action,
            "permissionDecisionReason": reason or f"rule {decision.rule_id}"}}
    elif decision.warnings:
        out = {"systemMessage": "; ".join(decision.warnings)}
    if out:
        json.dump(out, sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        try:
            json.dump(FAIL_CLOSED, sys.stdout)
        except Exception:
            print(json.dumps(FAIL_CLOSED))
        sys.exit(0)
