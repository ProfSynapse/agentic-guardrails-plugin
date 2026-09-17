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

from adapter_common import to_events, unrecognized_tool, \
    unrecognized_tool_reason  # noqa: E402

# Set once anything has reached stdout, so the fail-closed handler never
# appends a second object to a stream that already carries a decision.
_EMITTED = False


def _emit(out):
    """Write one decision object in a single, already-serialized write.

    `json.dump` streams chunks straight at stdout: a failure partway through
    leaves a truncated object, and the fail-closed handler then appends a whole
    second one. The host can parse neither, and a decision it cannot parse is
    no decision at all - which is an allow. Serializing first keeps stdout
    untouched unless the whole object is ready.
    """
    global _EMITTED
    text = json.dumps(out)
    _EMITTED = True
    sys.stdout.write(text)
    sys.stdout.flush()


PRESNAP_MAX_BYTES = int(os.environ.get("AGW_PRESNAP_MAX_BYTES", 100 * 1024 * 1024))
# Codex has no hook-driven approval prompt (permissionDecision "ask" is parsed
# but unsupported, so it silently proceeds). ASK is therefore resolved through
# an injected approval provider. Tests always use the deterministic headless
# provider; only core.approvals.NativeApprovalProvider may initialize UI.
ASK_MODAL_TIMEOUT = int(os.environ.get("AGW_ASK_MODAL_TIMEOUT", 100))


# The host's registry of tools that neither run a command nor touch a file.
# Bound at import time so the planner can be told which unmodeled tool names
# are inert without the platform-neutral core learning any of them.
from adapter_common import INERT_TOOLS  # noqa: E402


class _InertPlan:
    """The plan mutations.plan returns for an event that cannot mutate files."""
    mutating = False
    complete = True
    review_required = False
    reason = ""
    evidence = {}
    targets = []


def _plan_mutations(evlist, engine, events, mutations, **options):
    """Plan pre-images only for events that can mutate files.

    mutations.plan leaves a READ or MCP event inert by construction (a Read
    has no mutation primitive; a connected-service call has no local files to
    snapshot). Every other kind, including an unmodeled OTHER tool, goes to
    the planner. Skipping the call for the two inert kinds keeps the
    mutations/workflows/store import chain off the routine path entirely.
    """
    if all(ev.kind in (events.READ, events.MCP) for ev in evlist):
        return _InertPlan()
    return mutations.plan(evlist, engine.clobber_targets, plugin_root=PLUGIN_ROOT,
                          **options)


def _routine_read(payload):
    """The Read fast path: True means the engine would say nothing, so we say
    nothing without loading it. Anything else takes the full path below."""
    from core import readfast
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        return False
    path = tool_input.get("file_path") or tool_input.get("path") or ""
    return readfast.routine_read(path, PLUGIN_ROOT)


def main(approval_provider=None):
    payload = json.load(sys.stdin)
    if payload.get("tool_name") == "Read" and _routine_read(payload):
        return
    from core import auditlog, enforcement, engine, events, launcher, remediation
    from core.lazyimport import LazyModule
    # Deferred until a call site needs them: the store, workflows and the
    # prompt/approval machinery cost more to import than the whole routine
    # Read or MCP path. Each proxy imports inside this function, so a
    # broken module still lands in the fail-closed handler below.
    approvals = LazyModule("core.approvals")
    mutations = LazyModule("core.mutations")
    preimages = LazyModule("core.preimages")
    presentation = LazyModule("core.presentation")
    retention_policy = LazyModule("core.retention_policy")
    store = LazyModule("core.store")

    evaluation_payload = payload
    rewritten_command = None
    routed_workflow = ""
    if payload.get("tool_name") in {"Bash", "PowerShell"}:
        tool_input = payload.get("tool_input") or {}
        command = tool_input.get("command", "")
        rewritten_command = launcher.rewrite_shortcut(
            command, PLUGIN_ROOT,
            shell="powershell" if os.name == "nt" else "posix",
        )
        if not rewritten_command:
            dialect = "powershell" if payload.get("tool_name") == "PowerShell" else None
            matches = mutations.routable_trusted_workflows(
                command, payload.get("cwd", ""), dialect=dialect,
            )
            if len(matches) == 1:
                rewritten_command = launcher.rewrite_trusted_workflow(
                    command, matches[0], PLUGIN_ROOT,
                    shell="powershell" if os.name == "nt" else "posix",
                )
                routed_workflow = matches[0] if rewritten_command else ""
        if rewritten_command:
            evaluation_payload = dict(payload)
            evaluation_payload["tool_input"] = launcher.updated_tool_input(
                payload, rewritten_command
            )

    evlist = to_events(evaluation_payload)
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
        if ev.extra.get("unrecognized_tool"):
            # A tool identity this adapter cannot map to any guarded event.
            # events.OTHER alone DEFERs and emits nothing, which Codex reads as
            # allow. Ask instead — on Codex that routes through the approval
            # provider, whose absence or timeout denies — and log one stderr
            # line so the fall-through is diagnosable from the hook log.
            reason = unrecognized_tool_reason(
                unrecognized_tool(evaluation_payload)
            )
            sys.stderr.write("agentic-guardrails: %s\n" % reason)
            d = d.merge(engine.Decision(
                events.ASK, reason + ".", "builtin:unrecognized-tool",
                policy_revision=policy.revision, policy_health=policy.health,
                enforcement_class=events.NON_WAIVABLE_INVARIANT,
                presentation_context=events.DecisionContext.UNKNOWN))
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
    if decision.action == events.DENY \
            and decision.rule_id == "builtin:patch-delete":
        decision.safe_next = None
        decision.safe_next = remediation.for_events(decision, evlist)
    effective = enforcement.resolve(decision, observe)

    will_run = effective.action != events.DENY
    label = payload.get("tool_name", "") or "modification"
    # Prestate failures are safety invariants. Unlike advisory policy choices,
    # they cannot be approved away or suppressed by observe mode.
    mutation_plan = _plan_mutations(
        evlist, engine, events, mutations,
        regenerable=cfg.get("regenerable"), inert_tools=INERT_TOOLS,
    )
    invariant_failure = ""
    # Structured detail behind the refusal. Only the capacity failure has any,
    # and `render_safe_next` needs it to print the cap and the shortfall rather
    # than a sizeless "the cache is full".
    invariant_details = {}
    if mutation_plan.mutating and will_run:
        if not mutation_plan.complete:
            if mutation_plan.review_required:
                ambiguous_action = (
                    events.DENY if cfg.get("level") == "strict" else events.ASK
                )
                if mutation_plan.reason == mutations.UNRESOLVED_PATH_ASK:
                    # A recognized PowerShell write whose path only exists at
                    # run time (splatting, a variable, a here-string). Nothing
                    # about it says the operation is dangerous, only that the
                    # file cannot be named here, so it is a question for the
                    # user. The target is described by category so the prompt
                    # still carries enough for informed consent.
                    review_rule = "builtin:powershell-path-unresolved"
                    review_reason = (
                        "Guardrails recognized this as a file-writing PowerShell "
                        f"command, but its {mutations.UNRESOLVED_PATH_ASK}."
                    )
                    review_details = {
                        "operation": "write a file named at run time",
                        "targets": ["A file the command names at run time"],
                        "target_kind": "category",
                        "signal": "a file path supplied at run time",
                        "trigger": ("The command supplies its target path at run "
                                    "time, so Guardrails cannot read it statically."),
                    }
                else:
                    review_rule = "builtin:script-write-ambiguous"
                    review_reason = (
                        "Guardrails found ambiguous write-like source evidence but could "
                        "not confirm that this invocation writes files. Review this exact, "
                        f"hash-bound run before continuing: {mutation_plan.reason}"
                    )
                    review_details = {
                        "operation": "run script with ambiguous write evidence",
                        "targets": [mutation_plan.evidence.get("path", "")],
                        "target_kind": "file",
                        "signal": mutation_plan.evidence.get("primitive", "write-like source"),
                        "trigger": "Static source analysis found ambiguous write evidence.",
                    }
                decision = decision.merge(engine.Decision(
                    ambiguous_action, review_reason, review_rule,
                    policy_revision=policy.revision, policy_health=policy.health,
                    enforcement_class=events.POLICY_ENFORCEMENT,
                    presentation_context=events.DecisionContext.FILE_CHANGE,
                    presentation_details=review_details,
                ))
                if decision.action == events.DENY \
                        and decision.rule_id == review_rule:
                    decision.safe_next = None
                    decision.safe_next = remediation.for_events(decision, evlist)
                effective = enforcement.resolve(decision, observe)
            else:
                invariant_failure = (
                    "Guardrails blocked this change because it could not determine every file "
                    f"that would be modified: {mutation_plan.reason}. Nothing was changed by "
                    "this operation. Use a file-specific editing operation and try again."
                )
        else:
            try:
                retention_config = retention_policy.resolve_retention_policy(
                    policy.settings
                )
            except retention_policy.RetentionPolicyError as exc:
                invariant_failure = (
                    "Guardrails blocked this change because the recovery-cache "
                    f"policy is invalid ({exc.error_code}). Nothing was changed."
                )
            else:
                receipt = preimages.prepare(
                    mutation_plan.targets, label, PRESNAP_MAX_BYTES,
                    policy_revision=policy.revision,
                    retention_config=retention_config,
                )
                if not receipt.ok:
                    invariant_failure = receipt.reason
                    invariant_details = dict(receipt.details)
    if invariant_failure:
        decision = engine.Decision(
            events.DENY, invariant_failure, "invariant:prestate-unavailable",
            policy_revision=policy.revision, policy_health=policy.health,
            enforcement_class=events.NON_WAIVABLE_INVARIANT,
            presentation_details=invariant_details,
        )
        decision.safe_next = None
        decision.safe_next = remediation.for_events(decision, evlist)
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
        out = {"systemMessage": f"agentic-guardrails: already approved this session "
                                f"({decision.rule_id}); not re-asking."}
        _emit(launcher.attach_rewrite(
            out, payload, rewritten_command, may_run=True
        ))
        return
    if effective.shadowed:
        label = "observe mode" if effective.suppression == "observe" else "advisory"
        out = {"systemMessage": f"agentic-guardrails ({label}): would have "
                                f"{decision.action.upper()} - {decision.reason}"}
        _emit(launcher.attach_rewrite(
            out, payload, rewritten_command, may_run=True
        ))
        return

    # Codex can't render a hook 'ask' prompt, so an emitted ASK would silently
    # proceed. Resolve it through an injected provider. Provider absence,
    # ineligibility, timeout, malformed response, or error always denies.
    action = effective.action
    approval_outcome = ""
    if action == events.ASK:
        sid = payload.get("session_id", "")
        from core.decisions import GuardrailDecision
        prompt_decision = GuardrailDecision.from_legacy(decision)
        request = presentation.build_prompt(prompt_decision, evaluation_payload, evlist)
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
                "headless-deny", "not-prompt-eligible",
                "policy-revision-unavailable", "prompt-incomplete",
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
                           "policy-revision-unavailable", "prompt-incomplete"}:
                decision.reason = ((decision.reason + " | ") if decision.reason else "") + \
                    ("Approval could not be safely obtained, so this action was blocked.")

    out = {}
    refusal_metadata = None
    if action in (events.ALLOW, events.ASK, events.DENY):
        if action == events.DENY:
            from core.decisions import GuardrailDecision
            denial_decision = GuardrailDecision.from_legacy(decision)
            denial_decision.action = events.DENY
            reason = presentation.build_denial_feedback(
                denial_decision, approval_outcome, evlist
            )
            refusal_metadata = presentation.build_refusal_metadata(
                denial_decision, approval_outcome, evlist
            )
        else:
            reason = decision.reason
        if decision.warnings:
            reason = (reason + " | " if reason else "") + "; ".join(decision.warnings)
        out = {"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": action,
            "permissionDecisionReason": reason or f"rule {decision.rule_id}"}}
        if refusal_metadata is not None:
            out["hookSpecificOutput"]["agwRefusal"] = refusal_metadata
    elif decision.warnings:
        out = {"systemMessage": "; ".join(decision.warnings)}

    out = launcher.attach_rewrite(
        out, payload, rewritten_command, may_run=action != events.DENY
    )
    if routed_workflow and action != events.DENY and out.get("hookSpecificOutput"):
        out["hookSpecificOutput"]["permissionDecisionReason"] = (
            f"Routed this exact script and argument set through trusted workflow "
            f"{routed_workflow}."
        )

    if out:
        _emit(out)


def _fail_closed():
    """Last-resort decision for a failure the evaluation path did not catch.

    Only speaks if nothing already did. Appending a second object to a stream
    that already carries a decision makes both unparseable, and a decision the
    host cannot parse is no decision at all - which is an allow.
    """
    if _EMITTED:
        return
    try:
        _emit(FAIL_CLOSED)
    except Exception:
        pass


if __name__ == "__main__":
    try:
        main()
    except Exception:
        _fail_closed()
        sys.exit(0)
