"""Trusted short-form launcher expansion for maintained host adapters.

The model emits ``agw`` (or ``agw.cmd`` on Windows).  A PreToolUse adapter
expands that leading token to the active package's launcher before the policy
engine evaluates it and before the host executes it.  This keeps the package
path out of model output without relying on PATH, aliases, or mutable shims.
"""
from __future__ import annotations

import ntpath
import os
import re
import shlex
from typing import Optional


_SHORTCUT = re.compile(r"^(?P<indent>\s*)(?P<name>agw(?:\.cmd)?)(?=$|\s)", re.IGNORECASE)


def rewrite_shortcut(command: str, plugin_root: str, *, platform: Optional[str] = None,
                     shell: str = "posix") -> str | None:
    """Return an exact-launcher command, or ``None`` when no shortcut matched.

    Only a literal leading command token is eligible.  Assignments, wrappers,
    quoted names, paths, and later pipeline/statement tokens are intentionally
    left alone for normal policy evaluation.
    """
    if not isinstance(command, str) or not plugin_root:
        return None
    platform = os.name if platform is None else platform
    match = _SHORTCUT.match(command)
    if not match:
        return None

    name = match.group("name")
    if platform != "nt" and name != "agw":
        return None

    if platform == "nt":
        target = ntpath.join(plugin_root, "bin", "agw.cmd")
        if shell == "powershell":
            replacement = "& '" + target.replace("'", "''") + "'"
        else:
            replacement = shlex.quote(target.replace("\\", "/"))
    else:
        target = os.path.join(plugin_root, "bin", "agw")
        replacement = shlex.quote(target)

    return match.group("indent") + replacement + command[match.end():]


def updated_tool_input(payload: dict, rewritten_command: str) -> dict:
    """Copy the complete tool input while replacing only its command."""
    tool_input = dict(payload.get("tool_input") or {})
    tool_input["command"] = rewritten_command
    return tool_input


def attach_rewrite(out: dict, payload: dict, rewritten_command: Optional[str],
                   *, may_run: bool) -> dict:
    """Attach a host-supported PreToolUse rewrite to an existing decision."""
    if not rewritten_command or not may_run:
        return out
    result = dict(out)
    specific = dict(result.get("hookSpecificOutput") or {})
    specific.setdefault("hookEventName", "PreToolUse")
    decision = specific.get("permissionDecision")
    if decision not in {"allow", "ask"}:
        specific["permissionDecision"] = "allow"
        specific.setdefault(
            "permissionDecisionReason",
            "Resolved the trusted Agentic Guardrails launcher.",
        )
    specific["updatedInput"] = updated_tool_input(payload, rewritten_command)
    result["hookSpecificOutput"] = specific
    return result
