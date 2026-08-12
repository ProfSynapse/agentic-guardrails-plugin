"""Shared policy-pack retention resolution for direct AGW operations."""
from __future__ import annotations

import os
import time

from core import engine, retention_policy


_HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = os.environ.get("CLAUDE_PLUGIN_ROOT") or \
    os.path.dirname(os.path.dirname(_HERE))
DAY_NS = 24 * 60 * 60 * 1_000_000_000


def load(plugin_root: str = "") -> retention_policy.RetentionPolicy:
    """Load the effective policy pack and resolve its retention contract."""
    loaded = engine.load_policy(plugin_root or PLUGIN_ROOT)
    return retention_policy.resolve_retention_policy(loaded.settings)


def protected_until_ns(policy: retention_policy.RetentionPolicy,
                       now_ns: int | None = None) -> int:
    return int(time.time_ns() if now_ns is None else now_ns) \
        + policy.min_protected_age_days * DAY_NS


__all__ = ["DAY_NS", "PLUGIN_ROOT", "load", "protected_until_ns"]
