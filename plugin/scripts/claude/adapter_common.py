"""Shared Claude-adapter helpers: map a hook payload to a neutral ToolEvent.
Imported by both the PreToolUse and PostToolUse adapters."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# MCP shell/exec detection lives in core/ so every platform adapter shares one
# definition. Re-exported here for backward compatibility with anything that
# imported these names from the Claude adapter.
from core.mcpshell import is_mcp_shell, mcp_command  # noqa: E402,F401

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


def to_event(payload):
    from core import events
    tool = payload.get("tool_name", "")
    ti = payload.get("tool_input") or {}
    common = dict(cwd=payload.get("cwd", ""), session_id=payload.get("session_id", ""),
                  platform="claude", tool=tool)
    if tool in ("Bash", "PowerShell", "Monitor"):
        # Every host shell-exec tool must route through EXEC or it bypasses the
        # guardrails entirely (no audit, no deny) — a tool-name matcher is an
        # allowlist. `PowerShell` is the native Windows shell tool (rolls out
        # when Git Bash is present); a bare `Remove-Item ...` arrives here with
        # the same `command` field as Bash. `Monitor` runs background shell
        # scripts. The maintained contract accepts only a literal `command`
        # field and intentionally makes no claim of live-host validation.
        return events.ToolEvent(kind=events.EXEC, command=shell_command(tool, ti), **common)
    if tool == "Write":
        return events.ToolEvent(kind=events.WRITE, paths=[ti.get("file_path", "")],
                                content=ti.get("content", ""), **common)
    if tool in ("Edit", "NotebookEdit"):
        return events.ToolEvent(kind=events.EDIT, paths=[ti.get("file_path",
                                ti.get("notebook_path", ""))],
                                content=ti.get("new_string", ti.get("new_source", "")),
                                **common)
    if tool == "Read":
        return events.ToolEvent(kind=events.READ, paths=[ti.get("file_path", "")], **common)
    if tool in ("Glob", "Grep"):
        path = ti.get("path") or ti.get("directory") or payload.get("cwd", "")
        return events.ToolEvent(
            kind=events.READ, paths=[path], extra={"input": ti}, **common
        )
    if tool.startswith("mcp__"):
        # A shell-type MCP tool is routed through the EXEC path so the full
        # command rule set (rm, secret-exfil, curl|bash, snapshot-before-clobber)
        # applies. Non-shell MCP tools keep the name-matched MCP path.
        if is_mcp_shell(tool):
            return events.ToolEvent(kind=events.EXEC, command=mcp_command(ti),
                                    extra={"mcp_tool": tool, "input": ti}, **common)
        return events.ToolEvent(kind=events.MCP, extra={"input": ti}, **common)
    return events.ToolEvent(kind=events.OTHER, extra={"input": ti}, **common)


# Every host tool this adapter is prepared to see. Two kinds of entry:
#   * modeled - to_event() maps it onto a guarded ToolEvent kind;
#   * inert   - it cannot read or modify a file and cannot run a command, so
#               letting the engine DEFER on it is correct.
# A name outside this set is not harmless by default: it means the host renamed
# a tool we guard or shipped a new one, and the guardrails cannot say what it
# does. PreToolUse turns that into an ASK rather than a silent allow.
MODELED_TOOLS = frozenset({
    "Bash", "PowerShell", "Monitor",      # shell execution -> EXEC
    "Write",                              # file creation   -> WRITE
    "Edit", "NotebookEdit",               # file mutation   -> EDIT
    "Read",                               # file read       -> READ
    "Glob", "Grep",                       # scoped search   -> READ
})
# Tools that neither execute a command nor touch the filesystem themselves.
# Whatever they delegate to (a subagent's Bash, a slash command's Edit) arrives
# as its own hook call and is guarded there.
INERT_TOOLS = frozenset({
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
    # host-managed VCS plumbing; edits inside a worktree still arrive as Edit
    "EnterWorktree", "ExitWorktree",
    # published artifacts are not local files
    "Artifact", "ArtifactComments", "ArtifactData",
})
KNOWN_TOOLS = MODELED_TOOLS | INERT_TOOLS

# Label used when the payload carries no usable tool name at all.
MISSING_TOOL = "(no tool_name)"


def unrecognized_tool(payload):
    """Return a label for a tool this adapter cannot model, else ``None``.

    ``None`` means "recognized; evaluate normally". Any other return value is a
    display label for the ASK. A missing, blank, or non-string ``tool_name`` is
    unrecognized too: a call we cannot identify is a call we cannot guard.
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
