"""Structured, host-neutral decision and approval request contracts.

The policy engine still returns :class:`core.events.Decision`.  Adapters use
``GuardrailDecision.from_legacy`` while the richer contract is introduced
incrementally, avoiding a flag-day engine change.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .events import DecisionContext, EnforcementClass, normalize_enforcement_class

LOW = "low"
MEDIUM = "medium"
HIGH = "high"


@dataclass
class GuardrailDecision:
    action: str
    reason: str = ""
    rule_id: str = ""
    warnings: list = field(default_factory=list)
    memo_key: Optional[str] = None
    confidence: str = HIGH
    prompt_eligible: bool = True
    category: str = "review"
    policy_revision: str = ""
    policy_health: str = ""
    enforcement_class: EnforcementClass = None
    presentation_context: DecisionContext = DecisionContext.UNKNOWN

    def __post_init__(self):
        self.enforcement_class = normalize_enforcement_class(
            self.enforcement_class, self.action
        )
        try:
            self.presentation_context = DecisionContext(self.presentation_context)
        except (TypeError, ValueError):
            self.presentation_context = DecisionContext.UNKNOWN

    @classmethod
    def from_legacy(cls, decision) -> "GuardrailDecision":
        confidence = getattr(decision, "confidence", HIGH)
        eligible = getattr(decision, "prompt_eligible", True)
        # Low-confidence findings are exposed for later policy tuning, but they
        # must not create user-facing approval noise.
        if confidence == LOW:
            eligible = False
        return cls(
            action=decision.action,
            reason=decision.reason,
            rule_id=decision.rule_id,
            warnings=list(decision.warnings),
            memo_key=decision.memo_key,
            confidence=confidence,
            prompt_eligible=eligible,
            category=getattr(decision, "category", "review"),
            policy_revision=getattr(decision, "policy_revision", ""),
            policy_health=getattr(decision, "policy_health", ""),
            enforcement_class=normalize_enforcement_class(
                getattr(decision, "enforcement_class", None), decision.action
            ),
            presentation_context=getattr(
                decision, "presentation_context", DecisionContext.UNKNOWN
            ),
        )


@dataclass(frozen=True)
class PromptRequest:
    title: str
    action: str
    targets: tuple[str, ...]
    reason: str
    consequence: str
    safeguard: str
    event_id: str
    operation_fingerprint: str
    policy_revision: str = ""
    allow_label: str = "Allow once"
    cancel_label: str = "Cancel (recommended)"
    default_choice: str = "cancel"
    technical_details: str = ""

    def primary_text(self) -> str:
        sections = [
            "Target: " + (", ".join(self.targets) if self.targets else
                          "The exact files could not be identified"),
            "Why we're asking: " + self.reason,
            "What could happen: " + self.consequence,
            "Safety measure: " + self.safeguard,
        ]
        return "\n\n".join(sections)
