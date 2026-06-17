#!/usr/bin/env python3
"""Codex PreToolUse adapter: hook JSON on stdin -> permissionDecision on stdout.

Codex's hook contract matches Claude's, so the output schema is identical. The
one structural difference: a single ``apply_patch`` call can touch several files
of different kinds, so the payload maps to a *list* of neutral events. We
evaluate each, then fold them into one decision (most severe wins) before
emitting a single permissionDecision.

CRASH POLICY (the most important rule in this codebase): any internal failure
becomes ASK - never a silent allow (a nonzero exit would be non-blocking),
never an unconditional deny (which would brick the session on our own bugs).
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
        "permissionDecision": "ask",
        "permissionDecisionReason":
            "agentic-guardrails hit an internal error evaluating this call "
            "(fail-closed). Review the operation manually.",
    }
}

from adapter_common import to_events  # noqa: E402

PRESNAP_MAX_BYTES = int(os.environ.get("AGW_PRESNAP_MAX_BYTES", 100 * 1024 * 1024))


def _abs(path, cwd):
    """Resolve a (possibly relative, possibly backslash) tool path to an absolute
    path against the event's cwd. apply_patch carries paths relative to the
    patch's working directory, so a bare os.path.isfile() would look in the hook
    PROCESS's cwd and silently miss the file - no pre-image taken."""
    if not path:
        return path
    p = os.path.expanduser(str(path).replace("\\", os.sep))
    if not os.path.isabs(p):
        p = os.path.join(cwd or os.getcwd(), p)
    return p


def _snapshot(targets, label, store):
    """Pre-image snapshot of files about to be clobbered. Returns
    (any_error, [too_big_basenames]). Files over the cap are skipped but
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
                               reason=f"pre-image before {label}",
                               actor="guardrails-hook")
        except Exception:
            failed = True
    return failed, too_big


def main():
    payload = json.load(sys.stdin)
    from core import auditlog, engine, events, store

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
                "builtin:patch-delete"))
        if ev.extra.get("opaque"):
            d = d.merge(engine.Decision(
                events.ASK,
                "apply_patch was invoked but its patch could not be parsed to "
                "determine which files it touches - review the change manually.",
                "builtin:patch-opaque"))
        decisions.append(d)
    decision = events.worst(decisions)

    # Pre-image snapshot of everything this call will mutate - writes, edits,
    # shell clobbers, and patch deletes. In observe mode everything runs, so we
    # still take the safety copy even while "not enforcing".
    will_run = observe or decision.action != events.DENY
    targets = []
    for ev in evlist:
        if ev.kind in (events.WRITE, events.EDIT):
            targets += [_abs(p, ev.cwd) for p in ev.paths]
        elif ev.kind == events.EXEC:
            targets += engine.clobber_targets(ev.command, ev.cwd)
        elif ev.extra.get("delete"):
            targets += [_abs(p, ev.cwd) for p in ev.paths]
    targets = [t for t in dict.fromkeys(targets) if t]  # de-dupe, keep order
    label = payload.get("tool_name", "") or "modification"
    if targets and will_run:
        failed, too_big = _snapshot(targets, label, store)
        if failed:
            decision = decision.merge(engine.Decision(
                events.ASK, "Could not snapshot the file before modification "
                            "(archive store unavailable?) - proceed only if a copy "
                            "exists elsewhere.", "builtin:snapshot-failed"))
        if too_big:
            decision.warnings.append(
                f"note: {', '.join(too_big)} exceeds the {PRESNAP_MAX_BYTES // (1024*1024)}MB "
                "auto-snapshot cap and was NOT backed up before this change")

    # Session approval memory: a resource the user already okayed this session
    # doesn't prompt again. Convenience only - losing it just re-asks.
    memoed = False
    if decision.action == events.ASK and decision.memo_key and cfg.get("session_memory") \
            and store.session_approved(payload.get("session_id", ""), decision.memo_key):
        memoed = True

    # Audit the *real* engine decision (before observe/memory suppression).
    if decision.action != events.DEFER or decision.warnings:
        first_exec = next((e for e in evlist if e.kind == events.EXEC), None)
        all_paths = [p for e in evlist for p in e.paths]
        auditlog.log("pretooluse", {
            "tool": payload.get("tool_name", ""), "kind": evlist[0].kind,
            "decision": decision.action, "rule": decision.rule_id,
            "reason": decision.reason,
            "command": first_exec.command if first_exec else "",
            "paths": all_paths, "level": cfg.get("level"), "observe": observe,
            "platform": "codex", "cwd": payload.get("cwd", ""),
            "suppressed": "memory" if memoed else ("observe" if observe and
                          decision.action in (events.ASK, events.DENY) else ""),
            "session": payload.get("session_id", "")})

    # Observe (shadow) mode: log, but never block. Memory: silently allow.
    if memoed:
        json.dump({"systemMessage": f"agentic-guardrails: already approved this session "
                                    f"({decision.rule_id}); not re-asking."}, sys.stdout)
        return
    if observe and decision.action in (events.ASK, events.DENY):
        json.dump({"systemMessage": f"agentic-guardrails (observe mode): would have "
                                    f"{decision.action.upper()} - {decision.reason}"},
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
