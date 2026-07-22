"""Privacy-safe policy health and revision metadata."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib


HEALTHY = "HEALTHY"
DEGRADED = "DEGRADED"
UNAVAILABLE = "UNAVAILABLE"
BASELINE_SEED = b"agentic-guardrails-immutable-baseline-v1"


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def combine_revision(baseline_digest: str, source_tokens) -> str:
    digest = hashlib.sha256(BASELINE_SEED)
    digest.update(str(baseline_digest or "unavailable").encode("ascii", "replace"))
    for token in sorted(str(item) for item in source_tokens):
        digest.update(b"\0")
        digest.update(token.encode("utf-8", "replace"))
    return digest.hexdigest()


@dataclass(frozen=True)
class Health:
    status: str
    baseline_revision: str
    revision: str
    issue_codes: tuple[str, ...] = ()

    def audit_metadata(self) -> dict:
        # Revisions are one-way hashes; issue codes never include paths or data.
        return {"policy_health": self.status, "policy_revision": self.revision}
