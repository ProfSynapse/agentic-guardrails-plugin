"""Shared Claude-adapter helpers: map a hook payload to a neutral ToolEvent.
Imported by both the PreToolUse and PostToolUse adapters."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# MCP shell/exec detection lives in core/ so every platform adapter shares one
# definition. Re-exported here for backward compatibility with anything that
# imported these names from the Claude adapter.
from core.mcpshell import is_mcp_shell, mcp_command  # noqa: E402,F401


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
