"""Platform-neutral event and decision schemas.

This module is the boundary between platform adapters (scripts/claude/, future
scripts/codex/, scripts/cursor/) and the engine. Nothing in scripts/core/ may
import platform-specific shapes; adapters translate into these and back.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

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


class EnforcementClass(str, Enum):
    """Whether an engine finding may be shadowed by an enforcement level.

    This is explicit decision data.  Adapters must not reconstruct it from a
    rule id or another naming convention.
    """

    ADVISORY = "advisory"
    POLICY_ENFORCEMENT = "policy-enforcement"
    NON_WAIVABLE_INVARIANT = "non-waivable-invariant"


class DecisionContext(str, Enum):
    """Closed, privacy-safe context for approval presentation.

    Values describe categories, never commands, paths, filenames, exceptions,
    or free-form policy reasons. The audit schema does not include this field.
    """

    UNKNOWN = "unknown"
    AGW_ARCHIVE = "agw-archive"
    AGW_MUTATION = "agw-mutation"
    AGW_UNKNOWN = "agw-unknown"
    PATCH_UNKNOWN = "patch-unknown"
    RESTORE_FILES = "restore-files"
    SENSITIVE_READ = "sensitive-read"
    CREDENTIAL_SEARCH = "credential-search"
    FILE_CHANGE = "file-change"
    CONNECTED_SERVICE = "connected-service"


ADVISORY = EnforcementClass.ADVISORY
POLICY_ENFORCEMENT = EnforcementClass.POLICY_ENFORCEMENT
NON_WAIVABLE_INVARIANT = EnforcementClass.NON_WAIVABLE_INVARIANT

_ENFORCEMENT_STRENGTH = {
    ADVISORY: 0,
    POLICY_ENFORCEMENT: 1,
    NON_WAIVABLE_INVARIANT: 2,
}


def normalize_enforcement_class(value, action: str = DEFER) -> EnforcementClass:
    """Normalize legacy/untrusted class data with fail-closed deny semantics."""
    try:
        return value if isinstance(value, EnforcementClass) else EnforcementClass(value)
    except (TypeError, ValueError):
        # Missing/unknown ASK and DENY classifications are safety findings.
        # Routine ALLOW/DEFER decisions are inert and therefore advisory.
        return NON_WAIVABLE_INVARIANT if action in (ASK, DENY) else ADVISORY


def strongest_enforcement_class(*values) -> EnforcementClass:
    normalized = [normalize_enforcement_class(value) for value in values]
    return max(normalized, key=_ENFORCEMENT_STRENGTH.get, default=ADVISORY)


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
    # Optional host-provided identity. Adapters that do not receive one leave
    # this blank; approval de-duplication must never invent a broad substitute.
    event_id: str = ""
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
    policy_revision: str = ""
    policy_health: str = ""
    enforcement_class: EnforcementClass = None
    presentation_context: DecisionContext = DecisionContext.UNKNOWN
    # Closed, engine-generated labels for an approval prompt. Never place file
    # content or raw command text here; presentation sanitizes display strings.
    presentation_details: dict = field(default_factory=dict)
    # Inert structured remediation; never an authorization to execute.
    safe_next: object = None

    def __post_init__(self):
        self.enforcement_class = normalize_enforcement_class(
            self.enforcement_class, self.action
        )
        try:
            self.presentation_context = DecisionContext(self.presentation_context)
        except (TypeError, ValueError):
            self.presentation_context = DecisionContext.UNKNOWN

    def merge(self, other: "Decision") -> "Decision":
        """Combine two decisions: highest severity wins; warnings accumulate."""
        winner = self if _SEVERITY[self.action] >= _SEVERITY[other.action] else other
        merged = Decision(
            winner.action, winner.reason, winner.rule_id,
            self.warnings + other.warnings, winner.memo_key,
            winner.policy_revision or self.policy_revision or other.policy_revision,
            winner.policy_health or self.policy_health or other.policy_health,
            strongest_enforcement_class(
                self.enforcement_class, other.enforcement_class
            ),
            winner.presentation_context,
            dict(winner.presentation_details),
            winner.safe_next,
        )
        return merged


def worst(decisions) -> Decision:
    """Fold a list of decisions into the most severe one (DEFER if empty)."""
    result = Decision()
    for d in decisions:
        result = result.merge(d)
    return result
