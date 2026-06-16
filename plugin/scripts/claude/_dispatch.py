#!/usr/bin/env python3
"""Hook dispatcher: run the event adapter that sits next to this file, with a
hard fail-closed guarantee.

The hooks.json bootstrap is a tiny self-locating shim (it has to be — it runs
before anything else can tell it where the plugin lives). Once it has found the
plugin's ``scripts/claude`` directory, it hands off to this dispatcher rather
than running the adapter directly, so that *all* of the error handling lives in
a normal, testable file instead of an inline ``python -c`` string.

Guarantee: any uncaught failure in an adapter degrades to an ASK decision (for
PreToolUse) and a clean ``exit 0`` — never a non-zero crash, which the host can
interpret as block-everything (or, depending on the runtime, fail *open*). The
adapters carry their own crash-to-ASK policy too; this is defense in depth for
the failures that happen before an adapter's own try/except is reachable (import
errors, missing files, interpreter-level problems).
"""
import json
import os
import runpy
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
EVENT = sys.argv[1] if len(sys.argv) > 1 else "pretooluse"


def _ask(reason):
    """Emit a PreToolUse ASK decision. No-op for events that cannot block."""
    if EVENT != "pretooluse":
        return
    sys.stderr.write("agentic-guardrails: %s\n" % reason)
    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": (
                    "agentic-guardrails %s; failing closed. "
                    "Review this operation manually." % reason
                ),
            }
        },
        sys.stdout,
    )


def main():
    target = os.path.join(_HERE, EVENT + ".py")
    if not os.path.isfile(target):
        _ask("could not find its adapter for %s" % EVENT)
        return
    try:
        sys.argv = [target]
        runpy.run_path(target, run_name="__main__")
    except SystemExit:
        # The adapter signalled its own exit code (e.g. printed a decision and
        # returned). Preserve it.
        raise
    except Exception as exc:  # noqa: BLE001 - last-resort fail-closed net
        _ask("hit an internal error (%s)" % type(exc).__name__)


if __name__ == "__main__":
    main()
