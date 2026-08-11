"""Canonical top-level Guardrails command contract.

The CLI and policy engine both consume this module so a documented command
cannot be executable in one boundary and "unknown" in the other.  The contract
contains reviewed operation metadata only; it never contains model-authored
descriptions or raw command arguments.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re


class OperationEffect(str, Enum):
    READ_ONLY = "read-only"
    RECOVERABLE_MUTATION = "recoverable-mutation"
    HUMAN_APPROVAL = "human-approval"


@dataclass(frozen=True)
class OperationSpec:
    name: str
    effect: OperationEffect
    canonical_name: str = ""
    help_route: str = ""

    def __post_init__(self):
        if not self.canonical_name:
            object.__setattr__(self, "canonical_name", self.name)
        if not self.help_route:
            object.__setattr__(self, "help_route", f"agw {self.name} --help")


def _spec(name: str, effect: OperationEffect, *, canonical_name: str = ""):
    return OperationSpec(name, effect, canonical_name=canonical_name)


_OPERATIONS = {
    name: _spec(name, OperationEffect.READ_ONLY)
    for name in {
        "scan", "list", "search", "diff", "status", "log", "doctor", "schema",
    }
}
_OPERATIONS.update({
    name: _spec(name, OperationEffect.RECOVERABLE_MUTATION)
    for name in {
        "init", "checkout", "convert", "archive", "move", "snapshot",
        "restore", "undo", "publish", "publish-file", "unlink-link",
        "file", "run", "office", "workflow",
    }
})
_OPERATIONS["rename"] = _spec(
    "rename", OperationEffect.RECOVERABLE_MUTATION, canonical_name="move"
)
_OPERATIONS["prune"] = _spec("prune", OperationEffect.HUMAN_APPROVAL)

OPERATIONS = dict(sorted(_OPERATIONS.items()))


def operation(name: str) -> OperationSpec | None:
    return OPERATIONS.get(str(name or "").casefold())


def operation_names() -> frozenset[str]:
    return frozenset(OPERATIONS)


def registration_problem(names) -> str:
    """Return a compact CLI/contract mismatch, or an empty string."""
    registered = {str(value).casefold() for value in names}
    expected = set(OPERATIONS)
    missing = sorted(expected - registered)
    extra = sorted(registered - expected)
    parts = []
    if missing:
        parts.append("missing=" + ",".join(missing))
    if extra:
        parts.append("extra=" + ",".join(extra))
    return "; ".join(parts)


_DISPLAYABLE_VERB = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def display_unknown_verb(value: str) -> str:
    """Return a bounded inert label for an unsupported top-level token."""
    candidate = str(value or "")
    return candidate if _DISPLAYABLE_VERB.fullmatch(candidate) else "unsupported-token"


__all__ = [
    "OPERATIONS", "OperationEffect", "OperationSpec", "display_unknown_verb",
    "operation", "operation_names", "registration_problem",
]
