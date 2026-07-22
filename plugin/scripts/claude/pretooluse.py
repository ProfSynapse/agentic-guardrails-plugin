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


def main():
    payload = json.load(sys.stdin)
    from core import approvals, auditlog, enforcement, engine, events, mutations, preimages, \
        presentation, store
    from core.decisions import GuardrailDecision

    event = to_event(payload)
    policy = engine.load_policy(PLUGIN_ROOT)
    cfg = engine.resolve_settings(policy)
    decision = engine.evaluate(event, policy, PLUGIN_ROOT)
    observe = cfg.get("enforcement") == "observe"
    effective = enforcement.resolve(decision, observe)

    will_run = effective.action != events.DENY
    # Prestate failures are safety invariants. Unlike advisory policy choices,
    # they cannot be approved away or suppressed by observe mode.
    mutation_plan = mutations.plan([event], engine.clobber_targets)
    invariant_failure = ""
    if mutation_plan.mutating and will_run:
        if not mutation_plan.complete:
            invariant_failure = (
                "Guardrails blocked this change because it could not determine every file "
                f"that would be modified: {mutation_plan.reason}. Nothing was changed by "
                "this operation. Use a file-specific editing operation and try again."
            )
        else:
            archive_budget = int(os.environ.get(
                "AGW_ARCHIVE_MAX_BYTES", policy.settings.get("archive_max_bytes", 0)
            ) or 0)
            receipt = preimages.prepare(
                mutation_plan.targets, event.tool or "modification", PRESNAP_MAX_BYTES,
                archive_budget, policy_revision=policy.revision,
            )
            if not receipt.ok:
                invariant_failure = receipt.reason
    if invariant_failure:
        decision = engine.Decision(
            events.DENY, invariant_failure, "invariant:prestate-unavailable",
            policy_revision=policy.revision, policy_health=policy.health,
            enforcement_class=events.NON_WAIVABLE_INVARIANT,
        )
        effective = enforcement.resolve(decision, observe)

    def _audit(kind, data):
        try:
            auditlog.log(kind, data)
        except Exception:
            # Audit is evidence, not authority. Its availability must never
            # upgrade, downgrade, or replace an enforcement decision.
            pass

    # Session approval memory: a resource the user already okayed this session
    # doesn't prompt again. Convenience only — losing it just re-asks.
    memoed = False
    if effective.action == events.ASK and decision.memo_key and cfg.get("session_memory"):
        try:
            memoed = store.session_approved(event.session_id, decision.memo_key)
        except Exception:
            memoed = False

    # Audit the *real* engine decision (before observe/memory suppression), so
    # the trail shows what enforcement would have done.
    if decision.action != events.DEFER or decision.warnings:
        _audit("pretooluse", {
            "category": "decision", "tool": event.tool, "action": decision.action,
            "rule_code": decision.rule_id,
            "reason_code": "prestate-unavailable" if invariant_failure else "decision",
            "target_count": len(event.paths), "event_count": 1,
            "warning_count": len(decision.warnings),
            "level": cfg.get("level"), "observe": observe,
            "policy_health": decision.policy_health,
            "policy_revision": decision.policy_revision,
            "enforcement_class": decision.enforcement_class.value,
            "suppression": "memory" if memoed else effective.suppression or "none",
            "platform": "claude", "memoed": memoed,
            "correlate": {"session": event.session_id, "operation": event.event_id}})

    # Only explicit organization-policy findings shadow in observe mode.
    # Advisory findings never prompt/block; safety invariants retain their
    # ASK/DENY action at every enforcement level.
    if memoed:
        out = {"systemMessage": f"agentic-guardrails: already approved this session "
                                f"({decision.rule_id}); not re-asking."}
        json.dump(out, sys.stdout)
        return
    if effective.shadowed:
        label = "observe mode" if effective.suppression == "observe" else "advisory"
        json.dump({"systemMessage": f"agentic-guardrails ({label}): would have "
                                    f"{decision.action.upper()} — {decision.reason}"},
                  sys.stdout)
        return

    if effective.action == events.ASK and decision.memo_key and cfg.get("session_memory"):
        fingerprint = presentation.operation_fingerprint(
            payload, [event], decision.policy_revision
        )
        approvals.record_pending_approval(
            payload, event.session_id, decision.memo_key,
            decision.policy_revision, fingerprint,
        )

    out = {}
    if effective.action in (events.ALLOW, events.ASK, events.DENY):
        if effective.action == events.ASK:
            prompt_decision = GuardrailDecision.from_legacy(decision)
            request = presentation.build_prompt(prompt_decision, payload, [event])
            reason = request.action + "\n\n" + request.primary_text()
        elif effective.action == events.DENY:
            reason = presentation.build_denial_feedback(
                GuardrailDecision.from_legacy(decision)
            )
        else:
            reason = decision.reason
        if decision.warnings:
            reason = (reason + " | " if reason else "") + "; ".join(decision.warnings)
        out = {"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": effective.action,
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
