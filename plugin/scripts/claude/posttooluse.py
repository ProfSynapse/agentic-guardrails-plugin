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
    try:
        auditlog.log("posttooluse", {
            "category": "tool-result", "tool": payload.get("tool_name", ""),
            "outcome": "error" if payload.get("tool_error") else "success",
            "reason_code": "tool-error" if payload.get("tool_error") else "tool-completed",
            "target_count": 1 if ti.get("file_path") else 0,
            "platform": "claude", "ok": not payload.get("tool_error"),
            "correlate": {"session": session, "operation": payload.get("event_id", "")},
        })
    except Exception:
        pass

    # If this call corresponded to an access-type ask, the fact that it ran
    # means it was approved — remember it so we don't re-prompt this session.
    try:
        from adapter_common import to_event
        from core import approvals, engine, events, policy_health, presentation, store
        # Consume first. Every terminal outcome, including tool failure and a
        # verification mismatch, permanently retires this one-use candidate.
        pending = approvals.consume_pending_approval(payload, session)
        if payload.get("tool_error") or not pending:
            return
        policy = engine.load_policy(PLUGIN_ROOT)
        if policy.health != policy_health.HEALTHY \
                or policy.revision != pending["policy_revision"]:
            return
        if not engine.resolve_settings(policy).get("session_memory"):
            return
        event = to_event(payload)
        decision = engine.evaluate(event, policy, PLUGIN_ROOT)
        if decision.action != events.ASK or not decision.memo_key \
                or decision.policy_revision != policy.revision:
            return
        fingerprint = presentation.operation_fingerprint(
            payload, [event], policy.revision
        )
        identity = approvals.approval_identity(decision.memo_key, policy.revision)
        if fingerprint != pending["operation_fingerprint"] \
                or identity != pending["approval_identity"]:
            return
        store.session_approve(session, decision.memo_key)
    except Exception:
        pass


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
