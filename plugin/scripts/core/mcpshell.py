"""Shared detection of MCP shell/exec tools, used by every platform adapter.

An MCP shell tool's command argument MUST be inspected by the same rules as a
native shell call - otherwise a destructive or exfiltration command issued
through an MCP shell (e.g. `mcp__workspace__bash` running `cat .env | curl ...`)
bypasses the guardrails entirely, because a plain MCP event carries no command
for the engine to look at. We match the tool *name* conservatively, then pull
the command out of the tool input.

This lives in core/ (not a single platform adapter) so the Claude, Codex, and
any future adapter all share one definition of "is this an MCP shell".

The same file also owns `argv_command`, the one place a shell payload spelled as
an *argv list* rather than a command line is turned into the single string the
engine evaluates. MCP shell tools and Codex's native `shell`/`local_shell` tools
both hand over argv lists, and both must reach the engine through identical
normalization or the two surfaces disagree about the same command.
"""
import fnmatch
import os
import re
import shlex

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
                # An argv list is not a command line: joining it on spaces lets
                # `["rm", "-rf", "my documents"]` read as three arguments. Go
                # through the same normalizer the Codex argv surfaces use.
                return argv_command(val) or ""
            if isinstance(val, str):
                return val
    return ""


# Interpreters whose inline script body `shellparse` only unwraps behind a
# literal `-c`. An argv list may spell the same flag as `-lc`/`-ic`, which that
# scan does not recognize, so the body is lifted out here instead.
_POSIX_SHELL_HEADS = frozenset({"sh", "bash", "zsh", "ksh", "dash", "ash"})
# `-c`, and the combined short forms that still end in it (`-lc`, `-ic`, `-lic`).
_INLINE_SCRIPT_FLAG = re.compile(r"-[a-z]*c", re.IGNORECASE)
_ARGV0_EXT_RE = re.compile(r"\.(?:exe|cmd|bat)$")


def interpreter_head(token: str) -> str:
    """argv0 reduced to the bare interpreter name, as shellparse spells it."""
    head = str(token or "").strip().strip("'\"")
    head = head.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    return _ARGV0_EXT_RE.sub("", head)


def _inline_posix_script(argv):
    """The script body of `bash -lc <script>` and friends, else ``None``."""
    if interpreter_head(argv[0]) not in _POSIX_SHELL_HEADS:
        return None
    for index, token in enumerate(argv[1:], start=1):
        if _INLINE_SCRIPT_FLAG.fullmatch(token):
            if index + 1 >= len(argv):
                return None
            script = argv[index + 1]
            return script if script.strip() else None
        if not token.startswith("-"):
            # A script path or a positional argument: there is no inline body,
            # so the whole argv is handed on and parsed as written.
            return None
    return None


def argv_command(value):
    """Normalize a shell payload into the one command string the engine reads.

    Accepts either a command line already spelled as a string, or an argv list
    (Codex's `shell`/`local_shell` shape). Returns ``None`` for anything it
    cannot read - an empty command evaluates as harmless, so the caller must
    fail closed on ``None`` instead of passing "" to the engine.

    An argv list is normalized two ways:

    * `[<posix shell>, -lc|-c, <script>]` yields the script alone. `shellparse`
      recurses a literal `-c` but not the combined `-lc` spelling Codex uses,
      and an unrecursed wrapper hides everything inside it.
    * anything else is joined with shell quoting, so `["rm", "-rf", "x"]`
      evaluates as `rm -rf x` and a PowerShell or cmd wrapper
      (`["pwsh", "-Command", ...]`, `["cmd.exe", "/c", ...]`) reaches
      `shellparse` intact and picks up that interpreter's dialect through the
      wrapper recursion those tables already implement.
    """
    if isinstance(value, str):
        return value if value.strip() else None
    if not isinstance(value, (list, tuple)) or not value:
        return None
    argv = list(value)
    if not all(isinstance(token, str) for token in argv):
        return None
    inline = _inline_posix_script(argv)
    if inline is not None:
        return inline
    joined = shlex.join(argv)
    return joined if joined.strip() else None
