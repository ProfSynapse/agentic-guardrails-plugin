"""Trusted short-form launcher expansion for maintained host adapters.

The model emits the platform-neutral ``agw``.  A PreToolUse adapter
expands that leading token to the active package's launcher before the policy
engine evaluates it and before the host executes it.  This keeps the package
path out of model output without relying on PATH, aliases, or mutable shims.
The ``agw.cmd`` spelling remains accepted for backward compatibility.
"""
from __future__ import annotations

import base64
import binascii
import json
import ntpath
import os
import re
import shlex
from typing import Optional

from .shellparse import DIALECT_POWERSHELL, ParseUncertain, extract_commands


_SHORTCUT = re.compile(r"^(?P<indent>\s*)(?P<name>agw(?:\.cmd)?)(?=$|\s)", re.IGNORECASE)
_INTERNAL_ARGV_FLAG = "--agw-argv-b64"
_MAX_INTERNAL_ARGV_BYTES = 64 * 1024
_MAX_INTERNAL_ARGC = 256


def encode_internal_argv(argv: list[str]) -> str:
    """Encode exact Unicode argv into an ASCII-only launcher envelope."""
    if not isinstance(argv, list) or len(argv) > _MAX_INTERNAL_ARGC or not all(
            isinstance(value, str) and "\0" not in value for value in argv):
        raise ValueError("argument vector is invalid or too large")
    raw = json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > _MAX_INTERNAL_ARGV_BYTES:
        raise ValueError("argument vector exceeds the internal launcher limit")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_internal_argv(argv: list[str]) -> list[str]:
    """Decode an internal launcher envelope, or return ordinary argv unchanged."""
    values = list(argv)
    if not values or values[0] != _INTERNAL_ARGV_FLAG:
        return values
    if len(values) != 2 or len(values[1]) > (_MAX_INTERNAL_ARGV_BYTES * 2):
        raise ValueError("malformed argument envelope")
    try:
        raw = base64.b64decode(values[1], altchars=b"-_", validate=True)
        decoded = json.loads(raw.decode("utf-8"))
    except (binascii.Error, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("malformed argument envelope") from exc
    if len(raw) > _MAX_INTERNAL_ARGV_BYTES or not isinstance(decoded, list) \
            or len(decoded) > _MAX_INTERNAL_ARGC or not all(
                isinstance(value, str) and "\0" not in value for value in decoded):
        raise ValueError("argument envelope contains an invalid vector")
    return decoded


def _has_powershell_control_syntax(command: str) -> bool:
    """Detect unquoted syntax that an argv envelope must not discard."""
    quote = ""
    index = 0
    while index < len(command):
        char = command[index]
        if quote:
            if char == "`" and quote == '"':
                index += 2
                continue
            if char == quote:
                if quote == "'" and index + 1 < len(command) and command[index + 1] == "'":
                    index += 2
                    continue
                quote = ""
        elif char in {"'", '"'}:
            quote = char
        elif char in ";|&<>()\r\n":
            return True
        index += 1
    return bool(quote)


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
            if any(ord(char) > 127 for char in command):
                if _has_powershell_control_syntax(command):
                    return None
                try:
                    parsed = extract_commands(command, dialect=DIALECT_POWERSHELL)
                except ParseUncertain:
                    return None
                if len(parsed.commands) != 1 or parsed.flags:
                    return None
                argv = parsed.commands[0].argv
                if not argv or argv[0].casefold() not in {"agw", "agw.cmd"}:
                    return None
                payload = encode_internal_argv(argv[1:])
                return (match.group("indent") + replacement + " "
                        + _INTERNAL_ARGV_FLAG + " '" + payload + "'")
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
