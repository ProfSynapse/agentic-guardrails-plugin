"""Shared Codex-adapter helpers: map a Codex hook payload to neutral events.

Codex hooks deliver the same JSON envelope as Claude Code (``tool_name``,
``tool_input``, ``cwd``, ``session_id`` on stdin; ``permissionDecision`` JSON on
stdout), so most of this mirrors the Claude adapter. Two differences drive the
separate module:

* The shell tool is ``Bash`` (same as Claude) but ``tool_input.command`` is the
  patch string for ``apply_patch`` as well.
* There is no separate Write/Edit/NotebookEdit tool - *every* file mutation
  arrives as ``apply_patch``, whose patch can touch several files of different
  kinds at once. So the mapping returns a *list* of ToolEvents, one per file,
  and the adapter merges the per-file decisions.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.mcpshell import is_mcp_shell, mcp_command  # noqa: E402
from codex.applypatch import parse_patch  # noqa: E402

# Fields Codex may carry the patch under within an apply_patch tool_input. The
# documented key is ``command`` (same as Bash); the others are defensive.
_PATCH_FIELDS = ("command", "patch", "input", "content")


def _patch_text(ti: dict) -> str:
    for fld in _PATCH_FIELDS:
        val = ti.get(fld)
        if isinstance(val, str) and val.strip():
            return val
    return ""


def to_events(payload):
    """Map a Codex hook payload to one or more neutral ToolEvents.

    Always returns a non-empty list. apply_patch fans out to one event per
    touched file; an unparseable patch yields a single OTHER event flagged
    ``opaque`` so the adapter can fail closed.
    """
    from core import events
    tool = payload.get("tool_name", "")
    ti = payload.get("tool_input") or {}
    common = dict(cwd=payload.get("cwd", ""), session_id=payload.get("session_id", ""),
                  platform="codex", tool=tool)

    if tool == "Bash":
        return [events.ToolEvent(kind=events.EXEC, command=ti.get("command", ""), **common)]

    if tool == "apply_patch":
        return _patch_events(ti, common, events)

    if tool == "Read":
        path = ti.get("file_path") or ti.get("path") or ""
        return [events.ToolEvent(kind=events.READ, paths=[path], **common)]

    if tool.startswith("mcp__"):
        # A shell-type MCP tool is routed through the EXEC path so the full
        # command rule set applies; other MCP tools keep the name-matched path.
        if is_mcp_shell(tool):
            return [events.ToolEvent(kind=events.EXEC, command=mcp_command(ti),
                                     extra={"mcp_tool": tool, "input": ti}, **common)]
        return [events.ToolEvent(kind=events.MCP, extra={"input": ti}, **common)]

    return [events.ToolEvent(kind=events.OTHER, extra={"input": ti}, **common)]


def _patch_events(ti, common, events):
    patch = _patch_text(ti)
    files = parse_patch(patch)
    if not files:
        # We could not see which files this patch touches - never let an opaque
        # mutation through as a silent allow.
        return [events.ToolEvent(kind=events.OTHER,
                                 extra={"apply_patch": True, "opaque": True}, **common)]
    out = []
    for f in files:
        if f["op"] == "delete":
            # No neutral DELETE kind: deletion is platform-specific tool
            # semantics. Carry the path through as OTHER and let the adapter
            # apply the CRUA "never delete" rule.
            out.append(events.ToolEvent(kind=events.OTHER, paths=[f["path"]],
                                        extra={"apply_patch": True, "delete": True},
                                        **common))
        elif f["op"] == "add":
            out.append(events.ToolEvent(kind=events.WRITE, paths=[f["path"]],
                                        content=f.get("added", ""),
                                        extra={"apply_patch": True}, **common))
        else:  # update (optionally a rename via move_to)
            paths = [f["path"]] + ([f["move_to"]] if f.get("move_to") else [])
            out.append(events.ToolEvent(kind=events.EDIT, paths=paths,
                                        content=f.get("added", ""),
                                        extra={"apply_patch": True}, **common))
    return out
