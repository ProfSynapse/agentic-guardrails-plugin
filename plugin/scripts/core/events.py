"""Platform-neutral event and decision schemas.

This module is the boundary between platform adapters (scripts/claude/, future
scripts/codex/, scripts/cursor/) and the engine. Nothing in scripts/core/ may
import platform-specific shapes; adapters translate into these and back.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Event kinds
EXEC = "exec"      # shell command execution
READ = "read"      # file read
WRITE = "write"    # file creation / full overwrite
EDIT = "edit"      # partial file modification
MCP = "mcp"        # MCP / connector tool call
OTHER = "other"

# Decision actions, in increasing severity. DEFER means "no opinion — let the
# platform's default permission flow decide".
DEFER = "defer"
ALLOW = "allow"
ASK = "ask"
DENY = "deny"

_SEVERITY = {DEFER: 0, ALLOW: 1, ASK: 2, DENY: 3}


@dataclass
class ToolEvent:
    kind: str
    tool: str = ""                 # platform tool name (Bash, Write, mcp__x__y, ...)
    command: str = ""              # for EXEC: the raw command line
    paths: list = field(default_factory=list)   # absolute or as-given target paths
    content: str = ""              # for WRITE/EDIT: the new content (or new_string)
    cwd: str = ""
    session_id: str = ""
    platform: str = ""
    extra: dict = field(default_factory=dict)   # adapter passthrough (mcp input, etc.)


@dataclass
class Decision:
    action: str = DEFER
    reason: str = ""
    rule_id: str = ""
    warnings: list = field(default_factory=list)
    # Stable key identifying the *resource* this decision is about, for
    # session approval memory ("you already okayed reading this file").
    # Only set on access-type asks; None means "never remember, re-ask".
    memo_key: str = None

    def merge(self, other: "Decision") -> "Decision":
        """Combine two decisions: highest severity wins; warnings accumulate."""
        winner = self if _SEVERITY[self.action] >= _SEVERITY[other.action] else other
        merged = Decision(winner.action, winner.reason, winner.rule_id,
                          self.warnings + other.warnings, winner.memo_key)
        return merged


def worst(decisions) -> Decision:
    """Fold a list of decisions into the most severe one (DEFER if empty)."""
    result = Decision()
    for d in decisions:
        result = result.merge(d)
    return result
