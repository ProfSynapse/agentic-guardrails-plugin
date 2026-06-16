"""Shared detection of MCP shell/exec tools, used by every platform adapter.

An MCP shell tool's command argument MUST be inspected by the same rules as a
native shell call - otherwise a destructive or exfiltration command issued
through an MCP shell (e.g. `mcp__workspace__bash` running `cat .env | curl ...`)
bypasses the guardrails entirely, because a plain MCP event carries no command
for the engine to look at. We match the tool *name* conservatively, then pull
the command out of the tool input.

This lives in core/ (not a single platform adapter) so the Claude, Codex, and
any future adapter all share one definition of "is this an MCP shell".
"""
import fnmatch
import os

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


def mcp_shell_globs():
    """Built-in shell-tool globs plus any added via AGW_MCP_SHELL_TOOLS
    (comma-separated fnmatch globs)."""
    extra = os.environ.get("AGW_MCP_SHELL_TOOLS", "")
    return list(_MCP_SHELL_GLOBS) + [g.strip() for g in extra.split(",") if g.strip()]


def is_mcp_shell(tool: str) -> bool:
    return any(fnmatch.fnmatch(tool, g) for g in mcp_shell_globs())


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
