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
* Some Codex builds emit Claude-style tool names and some emit Codex's own exec
  surfaces - ``shell``/``local_shell`` (argv list in ``command``),
  ``exec_command`` (command line in ``cmd``) and ``write_stdin``. All of them
  are mapped here, because a build whose tool names this adapter does not know
  is a build running completely unguarded.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.mcpshell import argv_command, interpreter_head, is_mcp_shell, \
    mcp_command  # noqa: E402
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


# Codex's native exec surfaces. `shell` and `local_shell` carry an argv list in
# `command`; `exec_command` (the unified-exec build) carries one command line in
# `cmd` plus an optional interpreter in `shell`. Both may override the payload
# cwd with `workdir`.
CODEX_ARGV_SHELL_TOOLS = ("shell", "local_shell")


def exec_workdir(ti, cwd):
    """`workdir` when the call names one, else the session cwd."""
    workdir = ti.get("workdir")
    if isinstance(workdir, str) and workdir.strip():
        return workdir
    return cwd


def _exec_cwd(ti, common):
    resolved = exec_workdir(ti, common.get("cwd", ""))
    if resolved == common.get("cwd", ""):
        return common
    fields = dict(common)
    fields["cwd"] = resolved
    return fields


def exec_command_line(ti):
    """The command line an `exec_command` call runs, or ``None`` if unreadable.

    `shell` names the interpreter Codex hands the command to. A PowerShell or
    cmd interpreter changes how the same text parses, so the wrapper is put back
    in front of the command and `shellparse` picks the dialect through the
    recursion it already implements for `pwsh -Command` and `cmd /c`.
    """
    command = argv_command(ti.get("cmd"))
    if command is None:
        return None
    shell = ti.get("shell")
    head = interpreter_head(shell) if isinstance(shell, str) else ""
    if head in ("pwsh", "powershell"):
        return argv_command([shell, "-Command", command])
    if head == "cmd":
        return argv_command([shell, "/c", command])
    return command


def _exec_event(command, ti, common, events, uninspectable_label):
    """An EXEC event for a Codex-native exec call, or a fail-closed stand-in.

    `command is None` means the payload carried no command this adapter could
    read. An EXEC event with an empty command evaluates as harmless, so the
    event rides the same `unrecognized_tool` flag PreToolUse turns into a
    non-waivable ASK - it must never leave stdout empty, which Codex reads as
    allow.
    """
    fields = _exec_cwd(ti, common)
    if command is None:
        return events.ToolEvent(
            kind=events.EXEC, command="",
            extra={"input": ti, "unrecognized_tool": True,
                   "uninspectable": uninspectable_label},
            **fields)
    return events.ToolEvent(kind=events.EXEC, command=command,
                            extra={"input": ti}, **fields)


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

    if tool in CODEX_ARGV_SHELL_TOOLS:
        # Codex's own exec surface. The argv list is normalized to the single
        # command string the engine reads; an argv shape this adapter cannot
        # read fails closed rather than evaluating as an empty command.
        return [_exec_event(argv_command(ti.get("command")), ti, common, events,
                            UNREADABLE_SHELL)]

    if tool == "exec_command":
        return [_exec_event(exec_command_line(ti), ti, common, events,
                            UNREADABLE_SHELL)]

    if tool == "write_stdin":
        # Keystrokes for a session this hook never saw start. There is no
        # command text to evaluate, and the characters sent could complete any
        # command already waiting at that prompt, so this always asks.
        return [_exec_event(None, ti, common, events, UNINSPECTABLE_STDIN)]

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
# than deferring silently.
MODELED_TOOLS = frozenset({
    "Bash", "PowerShell", "Monitor",      # shell execution -> EXEC
    # Codex's own exec surfaces. A build that emits these instead of the
    # Claude-style names used to reach neither the matcher nor this registry,
    # which left every command it ran completely unguarded.
    "shell", "local_shell",               # argv list     -> EXEC
    "exec_command",                       # command line  -> EXEC
    "write_stdin",                        # uninspectable -> always ASK
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
# Labels for calls whose *tool* is recognized but whose payload cannot be read.
# The registry would clear these, so they carry their own label and their own
# reason text down the same non-waivable ASK path.
UNREADABLE_SHELL = "(unreadable shell command)"
UNINSPECTABLE_STDIN = "(write_stdin)"

_UNINSPECTABLE_REASONS = {
    UNREADABLE_SHELL: (
        "agentic-guardrails could not read a command out of this Codex shell "
        "call, so nothing about it was checked; approve to proceed or re-issue "
        "it with a literal command"),
    UNINSPECTABLE_STDIN: (
        "agentic-guardrails cannot check this call: stdin to a running process "
        "cannot be inspected, and the characters sent may complete any command "
        "already waiting at that prompt; approve to proceed or run the command "
        "as its own shell call"),
}


def uninspectable_call(payload):
    """Label for a *recognized* tool whose payload cannot be read, else ``None``.

    Tool identity is only half of "can we guard this". A `shell` call whose
    `command` is missing or malformed, and every `write_stdin` call, are known
    tools carrying nothing the engine can evaluate.
    """
    if not isinstance(payload, dict):
        return None
    tool = payload.get("tool_name")
    tool = tool.strip() if isinstance(tool, str) else ""
    ti = payload.get("tool_input")
    ti = ti if isinstance(ti, dict) else {}
    if tool == "write_stdin":
        return UNINSPECTABLE_STDIN
    if tool in CODEX_ARGV_SHELL_TOOLS and argv_command(ti.get("command")) is None:
        return UNREADABLE_SHELL
    if tool == "exec_command" and exec_command_line(ti) is None:
        return UNREADABLE_SHELL
    return None


def unrecognized_tool(payload):
    """Return a label for a call this adapter cannot guard, else ``None``.

    ``None`` means "recognized; evaluate normally". A missing, blank, or
    non-string ``tool_name`` is unrecognized too: a call we cannot identify is
    a call we cannot guard - and so is a call we can identify but whose payload
    carries no command to read.
    """
    tool = payload.get("tool_name") if isinstance(payload, dict) else None
    if not isinstance(tool, str) or not tool.strip():
        return MISSING_TOOL
    tool = tool.strip()
    uninspectable = uninspectable_call(payload)
    if uninspectable is not None:
        return uninspectable
    if tool in KNOWN_TOOLS or tool.startswith("mcp__"):
        return None
    return tool


def unrecognized_tool_reason(label):
    """User-facing reason text for an unrecognized-tool ASK."""
    if label == MISSING_TOOL:
        return ("agentic-guardrails received a tool call with no tool name; "
                "approve to proceed or update the plugin")
    if label in _UNINSPECTABLE_REASONS:
        return _UNINSPECTABLE_REASONS[label]
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
