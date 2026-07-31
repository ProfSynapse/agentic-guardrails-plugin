#!/usr/bin/env python3
"""Codex hook dispatcher: run the event adapter that sits next to this file,
with a hard fail-closed guarantee.

Identical in spirit to the Claude dispatcher. The hooks.json bootstrap is a
self-locating shim that finds the plugin's ``scripts/codex`` directory and hands
off here, so all error handling lives in a normal, testable file rather than an
inline ``python -c`` string.

Guarantee: any uncaught failure degrades to an ASK decision (for PreToolUse) and
a clean ``exit 0`` - never a non-zero crash, which the host could read as
block-everything or, worse, fail open.
"""
import json
import os
import runpy
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
EVENT = sys.argv[1] if len(sys.argv) > 1 else "pretooluse"


def _configure_utf8_stdio():
    """Decode the host hook envelope as UTF-8 on every Windows code page.

    Hook payloads are UTF-8 JSON bytes.  A redirected Windows Python process
    can otherwise select a legacy locale encoding (for example CP1252), which
    silently turns an emoji in ``tool_input.command`` into mojibake before the
    trusted launcher has a chance to place the arguments in its ASCII envelope.
    """
    for stream, errors in ((sys.stdin, "strict"), (sys.stdout, "replace"),
                           (sys.stderr, "replace")):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors=errors)


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
        _configure_utf8_stdio()
        sys.argv = [target]
        runpy.run_path(target, run_name="__main__")
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - last-resort fail-closed net
        _ask("hit an internal error (%s)" % type(exc).__name__)


if __name__ == "__main__":
    main()
