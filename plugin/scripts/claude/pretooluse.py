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
sys.path.insert(0, _HERE)                   # make `adapter_common` importable

FAIL_CLOSED = {
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "ask",
        "permissionDecisionReason":
            "agentic-guardrails hit an internal error evaluating this call "
            "(fail-closed). Review the operation manually.",
    }
}


from adapter_common import to_event  # noqa: E402


PRESNAP_MAX_BYTES = int(os.environ.get("AGW_PRESNAP_MAX_BYTES", 100 * 1024 * 1024))


def _snapshot(targets, event, store):
    """Pre-image snapshot of files about to be clobbered. Returns
    (any_error, [too_big_basenames]). Files over the cap are skipped (a huge
    legit write shouldn't be blocked or silently duplicate gigabytes) but
    reported, not turned into an ask."""
    failed, too_big = False, []
    for path in targets:
        try:
            if not (path and os.path.isfile(path)):
                continue
            if os.path.getsize(path) > PRESNAP_MAX_BYTES:
                too_big.append(os.path.basename(path))
                continue
            store.archive_file(path, mode="copy", dedupe=True,
                               reason=f"pre-image before {event.tool}",
                               actor="guardrails-hook")
        except Exception:
            failed = True
    return failed, too_big


def main():
    payload = json.load(sys.stdin)
    from core import auditlog, engine, events, store

    event = to_event(payload)
    policy = engine.load_policy(PLUGIN_ROOT)
    cfg = engine.resolve_settings(policy)
    decision = engine.evaluate(event, policy, PLUGIN_ROOT)
    observe = cfg.get("enforcement") == "observe"

    # Pre-image snapshot — nothing is destroyed, even by native tools or by a
    # shell `>`/mv/cp/tee that bypasses the Write tool entirely. We snapshot
    # whenever the operation will actually run (in observe mode everything runs,
    # so we still take the safety copy even while "not enforcing").
    will_run = observe or decision.action != events.DENY
    targets = []
    if event.kind in (events.WRITE, events.EDIT):
        targets = list(event.paths)
    elif event.kind == events.EXEC:
        targets = engine.clobber_targets(event.command, event.cwd)
    if targets and will_run:
        failed, too_big = _snapshot(targets, event, store)
        if failed:
            decision = decision.merge(engine.Decision(
                events.ASK, "Could not snapshot the file before modification "
                            "(archive store unavailable?) — proceed only if a copy "
                            "exists elsewhere.", "builtin:snapshot-failed"))
        if too_big:
            decision.warnings.append(
                f"note: {', '.join(too_big)} exceeds the {PRESNAP_MAX_BYTES // (1024*1024)}MB "
                "auto-snapshot cap and was NOT backed up before this change")

    # Session approval memory: a resource the user already okayed this session
    # doesn't prompt again. Convenience only — losing it just re-asks.
    memoed = False
    if decision.action == events.ASK and decision.memo_key and cfg.get("session_memory") \
            and store.session_approved(event.session_id, decision.memo_key):
        memoed = True

    # Audit the *real* engine decision (before observe/memory suppression), so
    # the trail shows what enforcement would have done.
    if decision.action != events.DEFER or decision.warnings:
        auditlog.log("pretooluse", {
            "tool": event.tool, "kind": event.kind, "decision": decision.action,
            "rule": decision.rule_id, "reason": decision.reason,
            "command": event.command, "paths": event.paths,
            "level": cfg.get("level"), "observe": observe,
            "suppressed": "memory" if memoed else ("observe" if observe and
                          decision.action in (events.ASK, events.DENY) else ""),
            "session": event.session_id})

    # Observe (shadow) mode: log, but never block. Memory: silently allow.
    if memoed:
        out = {"systemMessage": f"agentic-guardrails: already approved this session "
                                f"({decision.rule_id}); not re-asking."}
        json.dump(out, sys.stdout)
        return
    if observe and decision.action in (events.ASK, events.DENY):
        json.dump({"systemMessage": f"agentic-guardrails (observe mode): would have "
                                    f"{decision.action.upper()} — {decision.reason}"},
                  sys.stdout)
        return

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

    # Opportunistic retention: keep the store under a configured budget.
    try:
        budget = int(os.environ.get("AGW_ARCHIVE_MAX_BYTES",
                                    policy.settings.get("archive_max_bytes", 0)) or 0)
        if budget:
            store.enforce_budget(budget)
    except Exception:
        pass

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
