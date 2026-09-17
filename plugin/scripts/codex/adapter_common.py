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

MONITOR_NORMALIZER_CONTRACT = (
    "Monitor is accepted only as a shell-execution envelope whose literal "
    "tool_input.command string is evaluated with the same rules as Bash."
)


def shell_command(tool, tool_input):
    """Normalize the documented shell envelope without guessing other fields."""
    if tool not in ("Bash", "PowerShell", "Monitor"):
        return ""
    command = tool_input.get("command", "")
    return command if isinstance(command, str) else ""

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

    if tool in ("Bash", "PowerShell", "Monitor"):
        # All maintained host shell surfaces carry their executable text in
        # tool_input.command and must traverse the same EXEC policy path.
        return [events.ToolEvent(kind=events.EXEC, command=shell_command(tool, ti), **common)]

    if tool == "apply_patch":
        return _patch_events(ti, common, events)

    if tool == "Read":
        path = ti.get("file_path") or ti.get("path") or ""
        return [events.ToolEvent(kind=events.READ, paths=[path], **common)]

    if tool in ("Glob", "Grep"):
        path = ti.get("path") or ti.get("directory") or payload.get("cwd", "")
        return [events.ToolEvent(
            kind=events.READ, paths=[path], extra={"input": ti}, **common
        )]

    if tool.startswith("mcp__"):
        # A shell-type MCP tool is routed through the EXEC path so the full
        # command rule set applies; other MCP tools keep the name-matched path.
        if is_mcp_shell(tool):
            return [events.ToolEvent(kind=events.EXEC, command=mcp_command(ti),
                                     extra={"mcp_tool": tool, "input": ti}, **common)]
        return [events.ToolEvent(kind=events.MCP, extra={"input": ti}, **common)]

    if unrecognized_tool(payload) is not None:
        # Not a tool this adapter can model. OTHER alone would DEFER, which the
        # host reads as allow; the flag lets pretooluse resolve it as an ASK.
        return [events.ToolEvent(kind=events.OTHER,
                                 extra={"input": ti, "unrecognized_tool": True},
                                 **common)]
    return [events.ToolEvent(kind=events.OTHER, extra={"input": ti}, **common)]


# Host tools this adapter is prepared to see, mirroring the Claude registry.
#   * modeled - to_events() maps it onto a guarded ToolEvent kind;
#   * inert   - it cannot read or modify a file and cannot run a command, so
#               letting the engine DEFER on it is correct.
# Anything else is not harmless by default: an unmodeled name means the host
# renamed a guarded tool or shipped a new one, and the guardrails cannot say
# what it does. PreToolUse resolves that through the approval provider rather
# than deferring silently. Codex's own exec surfaces (`shell`, `local_shell`,
# `exec_command`) are deliberately absent: they run commands and are not
# modeled, so they must prompt rather than pass.
MODELED_TOOLS = frozenset({
    "Bash", "PowerShell", "Monitor",      # shell execution -> EXEC
    "apply_patch",                        # every file mutation Codex makes
    "Read",                               # file read       -> READ
    "Glob", "Grep",                       # scoped search   -> READ
})
INERT_TOOLS = frozenset({
    # Codex-native, non-mutating
    "update_plan", "view_image", "web_search",
    # planning and bookkeeping
    "TodoWrite", "ExitPlanMode", "EnterPlanMode", "AskUserQuestion",
    # delegation; the delegate's own tool calls re-enter this hook
    "Task", "Agent", "TaskCreate", "TaskUpdate", "TaskList", "TaskGet",
    "TaskStop", "SlashCommand", "Skill", "SendMessage",
    # capability discovery (metadata only)
    "ToolSearch", "ListSkills", "SearchSkills", "ListPlugins", "SearchPlugins",
    # shell lifecycle; the command itself was guarded when Bash launched it
    "BashOutput", "KillShell", "KillBash",
    # directory listing and network reads
    "LS", "WebFetch", "WebSearch",
    # MCP plumbing (the mcp__* tools themselves are modeled above)
    "ListMcpResourcesTool", "ReadMcpResourceTool",
    # host-managed VCS plumbing; edits inside a worktree still arrive as a patch
    "EnterWorktree", "ExitWorktree",
    # published artifacts are not local files
    "Artifact", "ArtifactComments", "ArtifactData",
})
KNOWN_TOOLS = MODELED_TOOLS | INERT_TOOLS

# Label used when the payload carries no usable tool name at all.
MISSING_TOOL = "(no tool_name)"


def unrecognized_tool(payload):
    """Return a label for a tool this adapter cannot model, else ``None``.

    ``None`` means "recognized; evaluate normally". A missing, blank, or
    non-string ``tool_name`` is unrecognized too: a call we cannot identify is
    a call we cannot guard.
    """
    tool = payload.get("tool_name") if isinstance(payload, dict) else None
    if not isinstance(tool, str) or not tool.strip():
        return MISSING_TOOL
    tool = tool.strip()
    if tool in KNOWN_TOOLS or tool.startswith("mcp__"):
        return None
    return tool


def unrecognized_tool_reason(label):
    """User-facing reason text for an unrecognized-tool ASK."""
    if label == MISSING_TOOL:
        return ("agentic-guardrails received a tool call with no tool name; "
                "approve to proceed or update the plugin")
    return ("agentic-guardrails does not recognize tool %r; approve to proceed "
            "or update the plugin" % label)


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
