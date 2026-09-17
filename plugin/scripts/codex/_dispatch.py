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


def _route_bytecode_cache():
    """Point bytecode at $AGW_HOME/pycache when the default cache is unusable.

    A plugin root that is read-only (Program Files, a locked-down install, an
    AV that blocks .pyc writes) or an interpreter told not to write bytecode
    makes every hook call recompile every module it imports, which costs more
    than the whole decision. SessionStart compiles the scripts into the same
    location this selects, so a call only ever reads. When the default
    __pycache__ next to the sources is writable, nothing changes.
    """
    try:
        core = os.path.join(os.path.dirname(_HERE), "core")
        default = os.path.join(core, "__pycache__")
        usable = os.access(default if os.path.isdir(default) else core, os.W_OK)
        if usable and not sys.dont_write_bytecode:
            return
        home = os.environ.get("AGW_HOME") or os.path.join(os.path.expanduser("~"), ".agw")
        sys.pycache_prefix = os.path.join(home, "pycache")
    except Exception:  # noqa: BLE001 - a cache decision must never break a hook
        pass


def _ask(reason):
    """Emit a PreToolUse ASK decision. No-op for events that cannot block."""
    if EVENT != "pretooluse":
        return
    sys.stderr.write("agentic-guardrails: %s\n" % reason)
    # Serialize first, then write once. `json.dump` streams chunks straight at
    # stdout, so a failure partway through would leave a truncated object for
    # the host to choke on - and a decision the host cannot parse is an allow.
    text = json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": (
                    "agentic-guardrails %s; failing closed. "
                    "Review this operation manually." % reason
                ),
            }
        }
    )
    sys.stdout.write(text)
    sys.stdout.flush()


def main():
    target = os.path.join(_HERE, EVENT + ".py")
    if not os.path.isfile(target):
        _ask("could not find its adapter for %s" % EVENT)
        return
    try:
        _configure_utf8_stdio()
        _route_bytecode_cache()
        sys.argv = [target]
        runpy.run_path(target, run_name="__main__")
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - last-resort fail-closed net
        _ask("hit an internal error (%s)" % type(exc).__name__)


if __name__ == "__main__":
    main()
