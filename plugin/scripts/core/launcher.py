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
_LATER_SHORTCUT = re.compile(r"agw(?:\.cmd)?(?=$|\s)", re.IGNORECASE)
_INTERNAL_ARGV_FLAG = "--agw-argv-b64"
_MAX_INTERNAL_ARGV_BYTES = 64 * 1024
_MAX_INTERNAL_ARGC = 256
_WORKFLOW_ID = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")


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


def _collapse_powershell_line_continuations(command: str) -> str:
    """Remove only PowerShell's exact backtick-newline continuation.

    A backtick must be the final character on the physical line. Backticks in
    single-quoted strings are literal, and any whitespace between a backtick
    and newline intentionally leaves the newline for fail-closed handling.
    """
    out = []
    in_single = False
    in_double = False
    index = 0
    while index < len(command):
        char = command[index]
        if char == "'" and not in_double:
            if in_single and index + 1 < len(command) and command[index + 1] == "'":
                out.extend((char, char))
                index += 2
                continue
            in_single = not in_single
            out.append(char)
            index += 1
            continue
        if char == '"' and not in_single:
            in_double = not in_double
            out.append(char)
            index += 1
            continue
        if char == "`" and not in_single and index + 1 < len(command):
            following = command[index + 1]
            if following == "\n":
                index += 2
                continue
            if following == "\r" and index + 2 < len(command) \
                    and command[index + 2] == "\n":
                index += 3
                continue
        out.append(char)
        index += 1
    return "".join(out)


def _powershell_segment_end(command: str, start: int) -> tuple[int, bool]:
    """Return the next top-level segment boundary and redirection ambiguity."""
    quote = ""
    depth = 0
    index = start
    while index < len(command):
        char = command[index]
        if quote:
            if quote == "'" and char == "'" and index + 1 < len(command) \
                    and command[index + 1] == "'":
                index += 2
                continue
            if quote == '"' and char == "`" and index + 1 < len(command):
                index += 2
                continue
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if char == "`" and index + 1 < len(command):
            index += 2
            continue
        if char == "#":
            return index, False
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                return index, False
            depth -= 1
        elif depth == 0 and char in "<>":
            return index, True
        elif depth == 0 and (char in "|;&" or char in "\r\n"):
            return index, False
        index += 1
    return len(command), bool(quote or depth)


def _skip_powershell_boundary_space(command: str, start: int) -> int:
    """Skip whitespace and exact backtick-newline continuations after a boundary."""
    index = start
    while index < len(command):
        if command[index].isspace():
            index += 1
            continue
        if command[index] == "`" and index + 1 < len(command):
            if command[index + 1] == "\n":
                index += 2
                continue
            if command[index + 1:index + 3] == "\r\n":
                index += 3
                continue
        break
    return index


def _powershell_later_shortcut_spans(command: str):
    """Yield literal later ``agw`` command spans outside data regions."""
    spans = []
    quote = ""
    here_quote = ""
    block_comment = False
    line_comment = False
    line_start = True
    depth = 0
    index = 0
    while index < len(command):
        char = command[index]
        if here_quote:
            if line_start:
                marker = index
                while marker < len(command) and command[marker] in " \t":
                    marker += 1
                if command.startswith(here_quote + "@", marker):
                    index = marker + 2
                    here_quote = ""
                    line_start = False
                    continue
            if char in "\r\n":
                line_start = True
            elif not char.isspace():
                line_start = False
            index += 1
            continue
        if block_comment:
            if command.startswith("#>", index):
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if line_comment:
            if char in "\r\n":
                line_comment = False
                line_start = True
            index += 1
            continue
        if quote:
            if quote == "'" and char == "'" and index + 1 < len(command) \
                    and command[index + 1] == "'":
                index += 2
                continue
            if quote == '"' and char == "`" and index + 1 < len(command):
                index += 2
                continue
            if char == quote:
                quote = ""
            index += 1
            continue
        if command.startswith("<#", index):
            block_comment = True
            index += 2
            continue
        if char == "#":
            line_comment = True
            index += 1
            continue
        if char == "@" and index + 1 < len(command) \
                and command[index + 1] in {"'", '"'}:
            line_end = command.find("\n", index + 2)
            tail_end = len(command) if line_end < 0 else line_end
            if not command[index + 2:tail_end].strip():
                here_quote = command[index + 1]
                index += 2
                line_start = False
                continue
        if char in {"'", '"'}:
            quote = char
            line_start = False
            index += 1
            continue
        if char == "`" and index + 1 < len(command):
            index += 3 if command[index + 1:index + 3] == "\r\n" else 2
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        boundary_end = None
        if char == "|" and depth == 0 \
                and command[index:index + 2] != "||" \
                and (index == 0 or command[index - 1] != "|"):
            boundary_end = index + 1
        elif char == ";" and depth == 0:
            boundary_end = index + 1
        elif char in "\r\n" and depth == 0:
            boundary_end = index + (2 if command[index:index + 2] == "\r\n" else 1)
        if boundary_end is not None:
            start = _skip_powershell_boundary_space(command, boundary_end)
            match = _LATER_SHORTCUT.match(command, start)
            if match:
                end, ambiguous = _powershell_segment_end(command, start)
                spans.append((start, match.end(), end, ambiguous))
                index = end
                continue
        if char in "\r\n":
            line_start = True
        elif not char.isspace():
            line_start = False
        index += 1
    return spans


def _rewrite_powershell_later_shortcuts(command: str, target: str) -> str | None:
    """Attest literal later launchers while preserving statement semantics."""
    spans = _powershell_later_shortcut_spans(command)
    if not spans:
        return None
    replacements = []
    replacement_head = "& '" + target.replace("'", "''") + "'"
    for start, token_end, segment_end, ambiguous in spans:
        if ambiguous:
            return None
        segment = _collapse_powershell_line_continuations(
            command[start:segment_end]
        ).strip()
        try:
            parsed = extract_commands(segment, dialect=DIALECT_POWERSHELL)
        except ParseUncertain:
            return None
        if len(parsed.commands) != 1 or parsed.flags:
            return None
        argv = parsed.commands[0].argv
        if not argv or argv[0].casefold() not in {"agw", "agw.cmd"}:
            return None
        if any(ord(char) > 127 for char in segment):
            if any(marker in segment for marker in ("$", "`")):
                return None
            payload = encode_internal_argv(argv[1:])
            replacement = (replacement_head + " " + _INTERNAL_ARGV_FLAG
                           + " '" + payload + "'")
            replacements.append((start, segment_end, replacement))
        else:
            replacements.append((start, token_end, replacement_head))
    rewritten = command
    for start, end, replacement in reversed(replacements):
        rewritten = rewritten[:start] + replacement + rewritten[end:]
    return rewritten


def rewrite_shortcut(command: str, plugin_root: str, *, platform: Optional[str] = None,
                     shell: str = "posix") -> str | None:
    """Return an exact-launcher command, or ``None`` when no shortcut matched.

    A literal leading command token is eligible. On Windows PowerShell, the
    same literal token is also eligible as a later top-level pipeline receiver
    or statement command so stdin and preceding value setup are retained.
    Wrappers, quoted names, paths, and ambiguous segments remain untrusted.
    """
    if not isinstance(command, str) or not plugin_root:
        return None
    platform = os.name if platform is None else platform
    match = _SHORTCUT.match(command)
    if not match:
        if platform == "nt" and shell == "powershell":
            target = ntpath.join(plugin_root, "bin", "agw.cmd")
            return _rewrite_powershell_later_shortcuts(command, target)
        return None

    name = match.group("name")
    if platform != "nt" and name != "agw":
        return None

    if platform == "nt":
        target = ntpath.join(plugin_root, "bin", "agw.cmd")
        if shell == "powershell":
            replacement = "& '" + target.replace("'", "''") + "'"
            if any(ord(char) > 127 for char in command):
                normalized = _collapse_powershell_line_continuations(command)
                if _has_powershell_control_syntax(normalized):
                    return None
                try:
                    parsed = extract_commands(normalized, dialect=DIALECT_POWERSHELL)
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


def rewrite_trusted_workflow(command: str, workflow_id: str, plugin_root: str, *,
                             platform: Optional[str] = None,
                             shell: str = "posix") -> str | None:
    """Wrap one literal command in an exact authenticated workflow invocation.

    The original argv is placed in the launcher's ASCII envelope, so no shell
    quoting or Unicode reconstruction is delegated to the model. Compound or
    dynamically parsed commands are never eligible for automatic routing.
    """
    if not isinstance(command, str) or not _WORKFLOW_ID.fullmatch(workflow_id or ""):
        return None
    dialect = DIALECT_POWERSHELL if shell == "powershell" else None
    try:
        parsed = extract_commands(command, dialect=dialect)
    except ParseUncertain:
        return None
    if len(parsed.commands) != 1 or parsed.flags:
        return None
    original_argv = parsed.commands[0].argv
    if not original_argv:
        return None
    payload = encode_internal_argv(
        ["run", "--workflow", workflow_id, "--", *original_argv]
    )
    platform = os.name if platform is None else platform
    if platform == "nt":
        target = ntpath.join(plugin_root, "bin", "agw.cmd")
        if shell == "powershell":
            return ("& '" + target.replace("'", "''") + "' "
                    + _INTERNAL_ARGV_FLAG + " '" + payload + "'")
        target = target.replace("\\", "/")
    else:
        target = os.path.join(plugin_root, "bin", "agw")
    return (shlex.quote(target) + " " + _INTERNAL_ARGV_FLAG + " "
            + shlex.quote(payload))


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
