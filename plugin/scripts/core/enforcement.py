"""Shared, host-neutral enforcement resolution.

Observe mode is permitted to shadow only decisions explicitly marked as
organization policy.  Safety invariants retain their action in every level;
advisories never prompt or block.
"""
from __future__ import annotations

from dataclasses import dataclass

from .events import ADVISORY, ASK, DEFER, DENY, POLICY_ENFORCEMENT, \
    normalize_enforcement_class


@dataclass(frozen=True)
class EffectiveEnforcement:
    action: str
    suppression: str = ""

    @property
    def shadowed(self) -> bool:
        return bool(self.suppression)


def resolve(decision, observe: bool = False) -> EffectiveEnforcement:
    """Return the action a host must enforce for this decision.

    Missing or unknown classifications on ASK/DENY normalize to a non-waivable
    invariant.  Thus corrupted or legacy decision data cannot turn observe mode
    into a bypass.
    """
    action = getattr(decision, "action", DEFER)
    classification = normalize_enforcement_class(
        getattr(decision, "enforcement_class", None), action
    )
    if action in (ASK, DENY) and classification == ADVISORY:
        return EffectiveEnforcement(DEFER, "advisory")
    if observe and action in (ASK, DENY) and classification == POLICY_ENFORCEMENT:
        return EffectiveEnforcement(DEFER, "observe")
    return EffectiveEnforcement(action)
