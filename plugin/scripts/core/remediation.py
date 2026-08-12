"""Structured, host-neutral safe-next advice.

Advice is inert decision data. It never authorizes or executes an operation;
hosts must submit any ``recommended_argv`` as a new operation so normal policy
evaluation runs again.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from typing import Iterable, Optional

from . import events, mutations
from .shellparse import DIALECT_POWERSHELL, ParseUncertain, extract_commands


SCHEMA = "agw.safe-next/v1"
COMMAND_PARSED = "parsed-literal"
COMMAND_UNAVAILABLE = "unavailable"
CWD_EVENT = "event"
CWD_MISSING = "missing"

ASSUMPTION_EVENT_CURRENT = "event-is-current"
ASSUMPTION_CWD_BOUND = "cwd-bound"
ASSUMPTION_SINGLE_LITERAL = "single-literal-command"
ASSUMPTION_TARGETS_REVALIDATED = "targets-revalidated"
ASSUMPTION_AUTHENTICATED_WORKFLOW = "authenticated-workflow"
ASSUMPTION_WORKFLOW_REVALIDATED = "workflow-revalidated"
_ASSUMPTIONS = frozenset({
    ASSUMPTION_EVENT_CURRENT, ASSUMPTION_CWD_BOUND,
    ASSUMPTION_SINGLE_LITERAL, ASSUMPTION_TARGETS_REVALIDATED,
    ASSUMPTION_AUTHENTICATED_WORKFLOW, ASSUMPTION_WORKFLOW_REVALIDATED,
})
_COMPONENTS = frozenset({"engine", "workflow-diagnostics", "decision-fallback"})
_EVENT_KINDS = frozenset({
    "", events.EXEC, events.READ, events.WRITE, events.EDIT, events.MCP, events.OTHER,
})

REASON_ARCHIVE = "reversible-archive"
REASON_WORKFLOW = "authenticated-workflow"
REASON_DIRECT = "direct-explicit-operation"
REASON_INSPECT = "separate-inspection"
REASON_SECRET = "avoid-secret-transmission"
REASON_READ_ONLY = "read-only-query"
REASON_FILTERED_DELETE = "filtered-soft-delete"
REASON_MACHINE_SCOPE = "avoid-machine-wide-change"
REASON_REMOTE_REVIEW = "review-remote-state"
REASON_PRESERVE_WORK = "preserve-working-state"
REASON_AUTHORIZED_COPY = "authorized-workspace-copy"
REASON_CLOUD_DOCUMENT = "use-cloud-document-connector"
REASON_OFFLINE = "make-file-available-offline"
REASON_LAUNCHER = "use-packaged-launcher"
REASON_AGW_HELP = "use-documented-guardrails-operation"
REASON_POLICY_HEALTH = "repair-policy-package"
REASON_REMOVE_SECRET = "remove-secret-material"
REASON_NARROW = "narrow-reversible-operation"
REASON_DECLINED = "approval-declined"
REASON_PROVIDER = "approval-provider-unavailable"
_REASON_CODES = frozenset({
    REASON_ARCHIVE, REASON_WORKFLOW, REASON_DIRECT, REASON_INSPECT,
    REASON_SECRET, REASON_READ_ONLY, REASON_FILTERED_DELETE,
    REASON_MACHINE_SCOPE, REASON_REMOTE_REVIEW, REASON_PRESERVE_WORK,
    REASON_AUTHORIZED_COPY, REASON_CLOUD_DOCUMENT, REASON_OFFLINE,
    REASON_LAUNCHER, REASON_AGW_HELP, REASON_POLICY_HEALTH,
    REASON_REMOVE_SECRET, REASON_NARROW, REASON_DECLINED, REASON_PROVIDER,
})


@dataclass(frozen=True)
class RemediationSource:
    component: str
    rule_id: str = ""
    event_kind: str = ""
    command_parse: str = COMMAND_UNAVAILABLE
    cwd_source: str = CWD_MISSING

    def __post_init__(self):
        if self.component not in _COMPONENTS:
            object.__setattr__(self, "component", "decision-fallback")
        if self.event_kind not in _EVENT_KINDS:
            object.__setattr__(self, "event_kind", "")
        if self.command_parse not in {COMMAND_PARSED, COMMAND_UNAVAILABLE}:
            object.__setattr__(self, "command_parse", COMMAND_UNAVAILABLE)
        if self.cwd_source not in {CWD_EVENT, CWD_MISSING}:
            object.__setattr__(self, "cwd_source", CWD_MISSING)

    def as_dict(self) -> dict:
        return {
            "component": self.component,
            "rule_id": self.rule_id,
            "event_kind": self.event_kind,
            "command_parse": self.command_parse,
            "cwd_source": self.cwd_source,
        }


@dataclass(frozen=True)
class SafeNext:
    reason_code: str
    recommended_argv: tuple[str, ...] = ()
    safe_to_retry: bool = False
    requires_user_choice: bool = False
    assumptions: tuple[str, ...] = ()
    source: RemediationSource = field(
        default_factory=lambda: RemediationSource("decision-fallback")
    )
    missing_fields: tuple[str, ...] = ("recommended_argv",)

    def __post_init__(self):
        source = self.source if isinstance(self.source, RemediationSource) \
            else RemediationSource("decision-fallback")
        reason_code = self.reason_code if self.reason_code in _REASON_CODES \
            else REASON_NARROW
        argv_input = self.recommended_argv
        argv = tuple(argv_input or ()) if isinstance(argv_input, (list, tuple)) else ()
        supplied_assumptions = tuple(dict.fromkeys(self.assumptions or ()))
        assumptions = tuple(value for value in supplied_assumptions if value in _ASSUMPTIONS)
        missing = list(dict.fromkeys(self.missing_fields or ()))
        if assumptions != supplied_assumptions and "assumptions" not in missing:
            missing.append("assumptions")
        complete_source = (
            source.event_kind == events.EXEC
            and source.command_parse == COMMAND_PARSED
            and source.cwd_source == CWD_EVENT
        )
        valid = (
            bool(argv) and all(
                isinstance(value, str) and value
                and not any(ord(char) < 32 or ord(char) == 127 for char in value)
                for value in argv
            )
            and complete_source and not missing
        )
        if self.safe_to_retry and not valid:
            argv = ()
            if not complete_source:
                for name, present in (
                    ("event_kind", source.event_kind == events.EXEC),
                    ("command_parse", source.command_parse == COMMAND_PARSED),
                    ("cwd", source.cwd_source == CWD_EVENT),
                ):
                    if not present and name not in missing:
                        missing.append(name)
            if "recommended_argv" not in missing:
                missing.append("recommended_argv")
        if not self.safe_to_retry:
            argv = ()
            if "recommended_argv" not in missing:
                missing.append("recommended_argv")
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "reason_code", reason_code)
        object.__setattr__(self, "recommended_argv", argv)
        object.__setattr__(self, "assumptions", assumptions)
        object.__setattr__(self, "missing_fields", tuple(missing))
        object.__setattr__(self, "safe_to_retry", bool(self.safe_to_retry and valid))
        object.__setattr__(self, "requires_user_choice", bool(self.requires_user_choice))

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "reason_code": self.reason_code,
            "recommended_argv": list(self.recommended_argv),
            "safe_to_retry": self.safe_to_retry,
            "requires_user_choice": self.requires_user_choice,
            "assumptions": list(self.assumptions),
            "source": self.source.as_dict(),
            "missing_fields": list(self.missing_fields),
        }


_ARCHIVE_RULES = {
    "builtin:rm", "builtin:find-delete", "builtin:move-null",
    "builtin:pwsh-delete", "builtin:interpreter-delete",
    "builtin:patch-delete", "builtin:git-clean", "builtin:mcp-delete",
    "core.yaml:mcp[0]", "core.yaml:mcp[1]",
}
_DIRECT_RULES = {
    "builtin:monitor-opaque", "builtin:mcp-shell-opaque",
    "builtin:unparseable-mutation", "builtin:indirect-mutation",
    "builtin:patch-targets-unknown", "builtin:patch-opaque",
    "invariant:prestate-unavailable", "builtin:script-write-ambiguous",
}
_WORKFLOW_ELIGIBLE_RULES = {
    "invariant:prestate-unavailable", "builtin:script-write-ambiguous",
}
_MACHINE_RULES = {"builtin:dd", "builtin:disk", "builtin:sudo", "builtin:chmod"}


def reason_for_rule(rule_id: str) -> tuple[str, bool]:
    """Return a closed reason code and whether choosing a path needs the user."""
    if rule_id in _ARCHIVE_RULES:
        return REASON_ARCHIVE, False
    if rule_id in _DIRECT_RULES:
        return REASON_DIRECT, False
    if rule_id in {"builtin:decode-pipe", "builtin:download-pipe"}:
        return REASON_INSPECT, False
    if rule_id == "builtin:secret-exfil":
        return REASON_SECRET, False
    if rule_id == "builtin:sql-drop":
        return REASON_READ_ONLY, True
    if rule_id == "builtin:sql-delete":
        return REASON_FILTERED_DELETE, True
    if rule_id in _MACHINE_RULES:
        return REASON_MACHINE_SCOPE, True
    if rule_id == "builtin:git-force":
        return REASON_REMOTE_REVIEW, True
    if rule_id == "builtin:git-reset-hard":
        return REASON_PRESERVE_WORK, True
    if rule_id in {"builtin:protected-path", "policy:zone"}:
        return REASON_AUTHORIZED_COPY, True
    if rule_id == "builtin:gdoc-stub":
        return REASON_CLOUD_DOCUMENT, False
    if rule_id in {"builtin:placeholder", "builtin:placeholder-read"}:
        return REASON_OFFLINE, False
    if rule_id == "builtin:agw-impostor":
        return REASON_LAUNCHER, False
    if rule_id in {
            "builtin:agw-empty", "builtin:agw-search-empty",
            "builtin:agw-unknown", "builtin:agw-workflow-unknown"}:
        return REASON_AGW_HELP, False
    if rule_id.startswith("policy:health-"):
        return REASON_POLICY_HEALTH, False
    if ":snippets[" in rule_id:
        return REASON_REMOVE_SECRET, False
    return REASON_NARROW, True


def incomplete(rule_id: str, event=None, *, component: str = "decision-fallback",
               extra_missing: Iterable[str] = ()) -> SafeNext:
    reason_code, needs_choice = reason_for_rule(rule_id)
    kind = getattr(event, "kind", "") if event is not None else ""
    cwd = getattr(event, "cwd", "") if event is not None else ""
    missing = ["recommended_argv", *extra_missing]
    if kind != events.EXEC:
        missing.append("event_kind")
    missing.append("command_parse")
    if not cwd:
        missing.append("cwd")
    return SafeNext(
        reason_code=reason_code,
        requires_user_choice=needs_choice,
        source=RemediationSource(
            component, rule_id, kind, COMMAND_UNAVAILABLE,
            CWD_EVENT if cwd else CWD_MISSING,
        ),
        missing_fields=tuple(dict.fromkeys(missing)),
    )


def _literal_event(event):
    if event is None or event.kind != events.EXEC or not event.command or not event.cwd:
        return None
    dialect = DIALECT_POWERSHELL \
        if str(event.tool).lower() in {"powershell", "pwsh"} else None
    try:
        parsed = extract_commands(event.command, dialect=dialect)
    except (ParseUncertain, TypeError, ValueError):
        return None
    if len(parsed.commands) != 1 or parsed.flags or not parsed.commands[0].argv:
        return None
    if not all(isinstance(value, str) and value for value in parsed.commands[0].argv):
        return None
    return parsed.commands[0], dialect


def _archive_argv(command, cwd: str) -> tuple[str, ...]:
    """Build advice only for a narrow one-target literal deletion form."""
    if command.name not in {
        "rm", "unlink", "shred", "rmdir", "del", "erase", "rd", "ri",
        "remove-item",
    }:
        return ()
    operands = []
    for value in command.argv[1:]:
        lowered = value.lower()
        if value.startswith("-") or (value.startswith("/") and command.name in {
                "del", "erase", "rd"}):
            continue
        if lowered in {"$null", "nul", "nul:", "/dev/null"}:
            return ()
        operands.append(value)
    if len(operands) != 1:
        return ()
    target = operands[0]
    if any(char in target for char in "$`*?[]{}()") or "\x00" in target:
        return ()
    resolved = os.path.normpath(os.path.abspath(
        target if os.path.isabs(target) else os.path.join(cwd, target)
    ))
    if os.path.normcase(resolved) != os.path.normcase(os.path.normpath(
            os.path.abspath(resolved))):
        return ()
    return "agw", "archive", resolved


def for_event(decision, event) -> Optional[SafeNext]:
    """Derive inert advice from one evaluated event; incomplete data fails closed."""
    if getattr(decision, "action", "") != events.DENY:
        return None
    rule_id = str(getattr(decision, "rule_id", "") or "")
    parsed = _literal_event(event)
    if parsed is None:
        return incomplete(rule_id, event)
    command, dialect = parsed
    source = RemediationSource(
        "engine", rule_id, events.EXEC, COMMAND_PARSED, CWD_EVENT,
    )
    argv = mutations.workflow_recommended_argv(
        event.command, event.cwd, dialect=dialect,
    ) if rule_id in _WORKFLOW_ELIGIBLE_RULES else []
    if argv:
        return SafeNext(
            REASON_WORKFLOW, tuple(argv), True, False,
            (ASSUMPTION_EVENT_CURRENT, ASSUMPTION_CWD_BOUND,
             ASSUMPTION_SINGLE_LITERAL, ASSUMPTION_AUTHENTICATED_WORKFLOW,
             ASSUMPTION_WORKFLOW_REVALIDATED),
            RemediationSource(
                "workflow-diagnostics", rule_id, events.EXEC,
                COMMAND_PARSED, CWD_EVENT,
            ), (),
        )
    if rule_id in _ARCHIVE_RULES:
        argv = _archive_argv(command, event.cwd)
        if argv:
            return SafeNext(
                REASON_ARCHIVE, argv, True, False,
                (ASSUMPTION_EVENT_CURRENT, ASSUMPTION_CWD_BOUND,
                 ASSUMPTION_SINGLE_LITERAL, ASSUMPTION_TARGETS_REVALIDATED),
                source, (),
            )
    return incomplete(rule_id, event, component="engine",
                      extra_missing=("revalidated_recommendation",))


def for_events(decision, evlist) -> Optional[SafeNext]:
    """Public adapter seam; multiple events never have their argv combined."""
    events_list = list(evlist or ())
    if len(events_list) != 1:
        return incomplete(
            str(getattr(decision, "rule_id", "") or ""),
            component="decision-fallback", extra_missing=("single_event",),
        ) if getattr(decision, "action", "") == events.DENY else None
    return for_event(decision, events_list[0])


def approval_outcome(advice: Optional[SafeNext], outcome: str) -> SafeNext:
    source = advice.source if advice else RemediationSource("decision-fallback")
    if outcome in {"cancelled", "denied"}:
        return SafeNext(REASON_DECLINED, source=source,
                        missing_fields=("recommended_argv",))
    return SafeNext(REASON_PROVIDER, source=source,
                    missing_fields=("recommended_argv",))
