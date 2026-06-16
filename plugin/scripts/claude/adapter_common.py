"""Shared Claude-adapter helpers: map a hook payload to a neutral ToolEvent.
Imported by both the PreToolUse and PostToolUse adapters."""
import fnmatch
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# MCP shell/exec tools. Their command argument MUST be inspected by the same
# rules as a native Bash call — otherwise a destructive or exfiltration command
# issued through an MCP shell (e.g. `mcp__workspace__bash` running
# `cat .env | curl ...`) bypasses the guardrails entirely, because a plain MCP
# event carries no command for the engine to look at. We match the tool *name*
# conservatively, then pull the command out of the tool input.
_MCP_SHELL_GLOBS = (
    "mcp__*__bash", "mcp__*__sh", "mcp__*__zsh", "mcp__*__shell",
    "mcp__*__exec", "mcp__*__execute", "mcp__*__execute_command",
    "mcp__*__run", "mcp__*__run_command", "mcp__*__run_shell_command",
    "mcp__*__run_terminal_cmd", "mcp__*__terminal", "mcp__*__command",
    "mcp__*__powershell", "mcp__*__pwsh", "mcp__*__process", "mcp__*__system",
)
# Ordered candidate fields holding the command string within tool_input. Only
# consulted for tools whose *name* already matched a shell glob, so these
# field-name guesses can't misfire on unrelated MCP tools.
_MCP_CMD_FIELDS = ("command", "cmd", "shell_command", "commandLine",
                   "command_line", "script", "code", "args", "arguments")


def _mcp_shell_globs():
    """Built-in shell-tool globs plus any added via AGW_MCP_SHELL_TOOLS
    (comma-separated fnmatch globs)."""
    extra = os.environ.get("AGW_MCP_SHELL_TOOLS", "")
    return list(_MCP_SHELL_GLOBS) + [g.strip() for g in extra.split(",") if g.strip()]


def is_mcp_shell(tool: str) -> bool:
    return any(fnmatch.fnmatch(tool, g) for g in _mcp_shell_globs())


def mcp_command(ti: dict) -> str:
    """Best-effort extraction of the command string from a shell MCP tool's
    input. Returns "" if no recognized field is present (the adapter turns that
    into a fail-closed ASK rather than a silent allow)."""
    for fld in _MCP_CMD_FIELDS:
        if fld in ti:
            val = ti[fld]
            if isinstance(val, (list, tuple)):
                return " ".join(str(x) for x in val)
            if isinstance(val, str):
                return val
    return ""


def to_event(payload):
    from core import events
    tool = payload.get("tool_name", "")
    ti = payload.get("tool_input") or {}
    common = dict(cwd=payload.get("cwd", ""), session_id=payload.get("session_id", ""),
                  platform="claude", tool=tool)
    if tool == "Bash":
        return events.ToolEvent(kind=events.EXEC, command=ti.get("command", ""), **common)
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
    if tool.startswith("mcp__"):
        # A shell-type MCP tool is routed through the EXEC path so the full
        # command rule set (rm, secret-exfil, curl|bash, snapshot-before-clobber)
        # applies. Non-shell MCP tools keep the name-matched MCP path.
        if is_mcp_shell(tool):
            return events.ToolEvent(kind=events.EXEC, command=mcp_command(ti),
                                    extra={"mcp_tool": tool, "input": ti}, **common)
        return events.ToolEvent(kind=events.MCP, extra={"input": ti}, **common)
    return events.ToolEvent(kind=events.OTHER, extra={"input": ti}, **common)
