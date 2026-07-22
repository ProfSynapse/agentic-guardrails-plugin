#!/usr/bin/env python3
"""Codex PreToolUse adapter: hook JSON on stdin -> permissionDecision on stdout.

Codex's hook contract matches Claude's, so the output schema is identical. The
one structural difference: a single ``apply_patch`` call can touch several files
of different kinds, so the payload maps to a *list* of neutral events. We
evaluate each, then fold them into one decision (most severe wins) before
emitting a single permissionDecision.

CRASH POLICY: any internal failure becomes DENY. Codex does not safely enforce
a hook-level ASK, and a nonzero hook exit would also be non-blocking, so either
alternative could silently run an operation that guardrails failed to inspect.
"""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = (os.environ.get("PLUGIN_ROOT") or os.environ.get("CLAUDE_PLUGIN_ROOT")
               or os.path.dirname(os.path.dirname(_HERE)))
sys.path.insert(0, os.path.dirname(_HERE))  # make `core`/`codex` importable
sys.path.insert(0, _HERE)                   # make `adapter_common` importable

FAIL_CLOSED = {
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": (
            "Blocked: Guardrails hit an internal error while checking this operation.\n\n"
            "Result: The requested action did not run; no requested target was changed.\n\n"
            "Safe next step: Retry with one direct, file-specific operation. If the "
            "error continues, stop and report the Guardrails failure.\n\n"
            "User communication: Briefly explain the block in plain language and "
            "recommend a safe way to continue toward the user's goal. Do not quote "
            "the raw command or expose sensitive values."
        ),
    }
}

from adapter_common import to_events  # noqa: E402

PRESNAP_MAX_BYTES = int(os.environ.get("AGW_PRESNAP_MAX_BYTES", 100 * 1024 * 1024))
# Codex has no hook-driven approval prompt (permissionDecision "ask" is parsed
# but unsupported, so it silently proceeds). ASK is therefore resolved through
# an injected approval provider. Tests always use the deterministic headless
# provider; only core.approvals.NativeApprovalProvider may initialize UI.
ASK_MODAL_TIMEOUT = int(os.environ.get("AGW_ASK_MODAL_TIMEOUT", 100))


def main(approval_provider=None):
    payload = json.load(sys.stdin)
    from core import approvals, auditlog, enforcement, engine, events, mutations, preimages, \
        presentation, store
    from core.decisions import GuardrailDecision

    evlist = to_events(payload)
    policy = engine.load_policy(PLUGIN_ROOT)
    cfg = engine.resolve_settings(policy)
    observe = cfg.get("enforcement") == "observe"

    # Evaluate every sub-event, applying the apply_patch-specific semantics that
    # have no neutral-engine primitive, then fold to the most severe decision.
    decisions = []
    for ev in evlist:
        d = engine.evaluate(ev, policy, PLUGIN_ROOT)
        if ev.extra.get("delete"):
            # CRUA: deletion is disabled. Mirror the shell `rm` deny so an agent
            # cannot route around it through apply_patch.
            name = (ev.paths[0] if ev.paths else "the file")
            d = d.merge(engine.Decision(
                events.DENY,
                f"Deleting {name} via apply_patch is disabled. Use "
                f"`agw archive <path>` (reversible via `agw restore <path>`) "
                f"instead of removing it.",
                "builtin:patch-delete",
                enforcement_class=events.NON_WAIVABLE_INVARIANT))
        if ev.extra.get("opaque"):
            d = d.merge(engine.Decision(
                events.ASK,
                "apply_patch was invoked but its patch could not be parsed to "
                "determine which files it touches - review the change manually.",
                "builtin:patch-opaque",
                enforcement_class=events.NON_WAIVABLE_INVARIANT,
                presentation_context=events.DecisionContext.PATCH_UNKNOWN))
        decisions.append(d)
    decision = events.worst(decisions)
    effective = enforcement.resolve(decision, observe)

    will_run = effective.action != events.DENY
    label = payload.get("tool_name", "") or "modification"
    # Prestate failures are safety invariants. Unlike advisory policy choices,
    # they cannot be approved away or suppressed by observe mode.
    mutation_plan = mutations.plan(evlist, engine.clobber_targets)
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
                mutation_plan.targets, label, PRESNAP_MAX_BYTES, archive_budget,
                policy_revision=policy.revision,
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
    # doesn't prompt again. Convenience only - losing it just re-asks.
    memoed = False
    if effective.action == events.ASK and decision.memo_key and cfg.get("session_memory"):
        try:
            memoed = store.session_approved(
                payload.get("session_id", ""), decision.memo_key
            )
        except Exception:
            memoed = False

    # Audit the *real* engine decision (before observe/memory suppression).
    if decision.action != events.DEFER or decision.warnings:
        all_paths = [p for e in evlist for p in e.paths]
        _audit("pretooluse", {
            "category": "decision", "tool": payload.get("tool_name", ""),
            "action": decision.action, "rule_code": decision.rule_id,
            "reason_code": "prestate-unavailable" if invariant_failure else "decision",
            "target_count": len(all_paths), "event_count": len(evlist),
            "warning_count": len(decision.warnings),
            "level": cfg.get("level"), "observe": observe,
            "policy_health": decision.policy_health,
            "policy_revision": decision.policy_revision,
            "enforcement_class": decision.enforcement_class.value,
            "platform": "codex", "memoed": memoed,
            "suppression": "memory" if memoed else effective.suppression or "none",
            "correlate": {"session": payload.get("session_id", ""),
                          "operation": payload.get("event_id", "")}})

    # Only explicit organization-policy findings shadow in observe mode.
    # Advisory findings never prompt/block; safety invariants retain their
    # ASK/DENY action at every enforcement level.
    if memoed:
        json.dump({"systemMessage": f"agentic-guardrails: already approved this session "
                                    f"({decision.rule_id}); not re-asking."}, sys.stdout)
        return
    if effective.shadowed:
        label = "observe mode" if effective.suppression == "observe" else "advisory"
        json.dump({"systemMessage": f"agentic-guardrails ({label}): would have "
                                    f"{decision.action.upper()} - {decision.reason}"},
                  sys.stdout)
        return

    # Codex can't render a hook 'ask' prompt, so an emitted ASK would silently
    # proceed. Resolve it through an injected provider. Provider absence,
    # ineligibility, timeout, malformed response, or error always denies.
    action = effective.action
    approval_outcome = ""
    if action == events.ASK:
        sid = payload.get("session_id", "")
        prompt_decision = GuardrailDecision.from_legacy(decision)
        request = presentation.build_prompt(prompt_decision, payload, evlist)
        try:
            provider = approval_provider or approvals.default_provider(ASK_MODAL_TIMEOUT)
            response = approvals.request_approval(prompt_decision, request, provider)
        except Exception:
            response = approvals.ApprovalResponse(False, "provider-error")
        approved = response.authorizes()
        outcome = response.outcome
        approval_outcome = outcome
        _audit("pretooluse-approval", {
            "category": "approval", "outcome": outcome, "action": "ask",
            "rule_code": decision.rule_id,
            "reason_code": outcome if outcome in {
                "provider-unavailable", "provider-timeout", "provider-error",
                "headless-deny", "not-prompt-eligible", "policy-revision-unavailable"
            } else "approval",
            "policy_health": decision.policy_health,
            "policy_revision": decision.policy_revision,
            "enforcement_class": decision.enforcement_class.value,
            "platform": "codex", "correlate": {"session": sid,
                                                  "operation": payload.get("event_id", "")}})
        if approved:
            if decision.memo_key and cfg.get("session_memory"):
                try:
                    store.session_approve(sid, decision.memo_key)
                except Exception:
                    pass
            action = events.DEFER  # approved -> let the tool run
        else:
            action = events.DENY
            if outcome in {"provider-unavailable", "provider-timeout", "provider-error",
                           "headless-deny", "not-prompt-eligible",
                           "policy-revision-unavailable"}:
                decision.reason = ((decision.reason + " | ") if decision.reason else "") + \
                    ("Approval could not be safely obtained, so this action was blocked.")

    out = {}
    if action in (events.ALLOW, events.ASK, events.DENY):
        if action == events.DENY:
            reason = presentation.build_denial_feedback(
                GuardrailDecision.from_legacy(decision), approval_outcome
            )
        else:
            reason = decision.reason
        if decision.warnings:
            reason = (reason + " | " if reason else "") + "; ".join(decision.warnings)
        out = {"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": action,
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
