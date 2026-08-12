"""Typed retention configuration and archive-size state assessment.

This module is intentionally independent of the archive store.  Hosts and CLI
surfaces can resolve one policy contract, then pass measured archive bytes to
``classify_retention_state`` without performing deletion or other I/O here.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import os
from typing import Mapping


GIB = 1024 ** 3

DEFAULT_MAX_BYTES = 4 * GIB
DEFAULT_HIGH_WATER_PERCENT = 90
DEFAULT_LOW_WATER_PERCENT = 80
DEFAULT_MIN_PROTECTED_AGE_DAYS = 7
DEFAULT_INACTIVE_COLLAPSE_AGE_DAYS = 30
DEFAULT_MAX_CANDIDATES = 256
DEFAULT_MAX_RECLAIM_BYTES = GIB


class RetentionPolicyError(ValueError):
    """Stable, machine-readable retention configuration failure."""

    def __init__(self, message: str, *, error_code: str, details: dict):
        super().__init__(message)
        self.error_code = error_code
        self.details = dict(details)


class RetentionClassification(str, Enum):
    UNLIMITED = "unlimited"
    BELOW_LOW_WATER = "below_low_water"
    BETWEEN_WATERMARKS = "between_watermarks"
    HIGH_WATER = "high_water"
    OVER_CAPACITY = "over_capacity"


@dataclass(frozen=True)
class RetentionPolicy:
    max_bytes: int
    high_water_bytes: int
    low_water_bytes: int
    min_protected_age_days: int
    inactive_collapse_age_days: int
    max_candidates: int
    max_reclaim_bytes: int
    sources: tuple[tuple[str, str], ...] = ()

    @property
    def unlimited(self) -> bool:
        return self.max_bytes == 0

    def as_dict(self) -> dict:
        return {
            "schema": "agw.retention-policy/v1",
            "max_bytes": self.max_bytes,
            "high_water_bytes": self.high_water_bytes,
            "low_water_bytes": self.low_water_bytes,
            "min_protected_age_days": self.min_protected_age_days,
            "inactive_collapse_age_days": self.inactive_collapse_age_days,
            "max_candidates": self.max_candidates,
            "max_reclaim_bytes": self.max_reclaim_bytes,
            "unlimited": self.unlimited,
            "sources": dict(self.sources),
        }


@dataclass(frozen=True)
class RetentionState:
    classification: RetentionClassification
    current_bytes: int
    max_bytes: int
    high_water_bytes: int
    low_water_bytes: int
    bytes_until_high_water: int | None
    bytes_until_capacity: int | None
    over_capacity_bytes: int
    reclaim_target_bytes: int
    prune_recommended: bool

    @property
    def capacity_exceeded(self) -> bool:
        return self.classification == RetentionClassification.OVER_CAPACITY

    def as_dict(self) -> dict:
        return {
            "schema": "agw.retention-state/v1",
            "classification": self.classification.value,
            "current_bytes": self.current_bytes,
            "max_bytes": self.max_bytes,
            "high_water_bytes": self.high_water_bytes,
            "low_water_bytes": self.low_water_bytes,
            "bytes_until_high_water": self.bytes_until_high_water,
            "bytes_until_capacity": self.bytes_until_capacity,
            "over_capacity_bytes": self.over_capacity_bytes,
            "reclaim_target_bytes": self.reclaim_target_bytes,
            "prune_recommended": self.prune_recommended,
            "capacity_exceeded": self.capacity_exceeded,
        }


_FIELDS = {
    "high_water_bytes": ("archive_high_water_bytes", "AGW_ARCHIVE_HIGH_WATER_BYTES"),
    "low_water_bytes": ("archive_low_water_bytes", "AGW_ARCHIVE_LOW_WATER_BYTES"),
    "min_protected_age_days": (
        "archive_min_protected_age_days", "AGW_ARCHIVE_MIN_PROTECTED_AGE_DAYS",
    ),
    "inactive_collapse_age_days": (
        "archive_inactive_collapse_age_days",
        "AGW_ARCHIVE_INACTIVE_COLLAPSE_AGE_DAYS",
    ),
    "max_candidates": ("archive_max_candidates", "AGW_ARCHIVE_MAX_CANDIDATES"),
    "max_reclaim_bytes": (
        "archive_max_reclaim_bytes", "AGW_ARCHIVE_MAX_RECLAIM_BYTES",
    ),
}


def _detail_value(value):
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return f"<{type(value).__name__}>"


def _invalid_integer(field: str, source: str, value) -> RetentionPolicyError:
    return RetentionPolicyError(
        f"Retention setting {field} must be a non-negative integer.",
        error_code="retention_value_not_integer",
        details={"field": field, "source": source,
                 "value": _detail_value(value)},
    )


def _parse_nonnegative(value, field: str, source: str) -> int:
    if isinstance(value, bool):
        raise _invalid_integer(field, source, value)
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and value.strip().lstrip("-").isdigit():
        parsed = int(value.strip(), 10)
    else:
        raise _invalid_integer(field, source, value)
    if parsed < 0:
        raise RetentionPolicyError(
            f"Retention setting {field} must not be negative.",
            error_code="retention_value_negative",
            details={"field": field, "source": source,
                     "value": _detail_value(value)},
        )
    return parsed


def _pick(settings: Mapping[str, object], environ: Mapping[str, str],
          policy_key: str, env_key: str, default: int) -> tuple[int, str, bool]:
    if env_key in environ:
        return _parse_nonnegative(environ[env_key], policy_key, f"env:{env_key}"), \
            f"env:{env_key}", True
    if policy_key in settings:
        return _parse_nonnegative(settings[policy_key], policy_key,
                                  f"policy:{policy_key}"), \
            f"policy:{policy_key}", True
    return default, "default", False


def _resolve_max(settings: Mapping[str, object],
                 environ: Mapping[str, str]) -> tuple[int, str]:
    canonical, source, present = _pick(
        settings, environ, "archive_max_bytes", "AGW_ARCHIVE_MAX_BYTES",
        DEFAULT_MAX_BYTES,
    )
    if present:
        return canonical, source
    legacy_key = "archive_max_warn_gb"
    if legacy_key in settings:
        legacy = _parse_nonnegative(
            settings[legacy_key], legacy_key, f"policy:{legacy_key}"
        )
        return legacy * GIB, f"legacy-policy:{legacy_key}"
    return canonical, source


def _threshold_default(max_bytes: int, percent: int) -> int:
    return 0 if max_bytes == 0 else max_bytes * percent // 100


def resolve_retention_policy(
    settings: Mapping[str, object] | None = None,
    environ: Mapping[str, str] | None = None,
) -> RetentionPolicy:
    """Resolve canonical env/policy settings into a validated frozen contract.

    Precedence is canonical environment, canonical policy, legacy policy, then
    built-in defaults.  Canonical values suppress legacy parsing entirely.
    """
    settings = settings or {}
    environ = os.environ if environ is None else environ
    max_bytes, max_source = _resolve_max(settings, environ)
    sources = {"max_bytes": max_source}

    defaults = {
        "high_water_bytes": _threshold_default(
            max_bytes, DEFAULT_HIGH_WATER_PERCENT
        ),
        "low_water_bytes": _threshold_default(
            max_bytes, DEFAULT_LOW_WATER_PERCENT
        ),
        "min_protected_age_days": DEFAULT_MIN_PROTECTED_AGE_DAYS,
        "inactive_collapse_age_days": DEFAULT_INACTIVE_COLLAPSE_AGE_DAYS,
        "max_candidates": DEFAULT_MAX_CANDIDATES,
        "max_reclaim_bytes": DEFAULT_MAX_RECLAIM_BYTES,
    }
    values = {}
    explicit = {}
    for field, (policy_key, env_key) in _FIELDS.items():
        value, source, was_explicit = _pick(
            settings, environ, policy_key, env_key, defaults[field]
        )
        values[field] = value
        sources[field] = source
        explicit[field] = was_explicit

    high = values["high_water_bytes"]
    low = values["low_water_bytes"]
    if max_bytes == 0:
        if (explicit["high_water_bytes"] and high != 0) or \
                (explicit["low_water_bytes"] and low != 0):
            raise RetentionPolicyError(
                "Unlimited retention requires zero or omitted watermarks.",
                error_code="retention_threshold_invalid",
                details={
                    "max_bytes": max_bytes,
                    "high_water_bytes": high,
                    "low_water_bytes": low,
                },
            )
        high = low = 0
    elif not (0 <= low <= high <= max_bytes):
        raise RetentionPolicyError(
            "Retention watermarks must satisfy 0 <= low <= high <= maximum.",
            error_code="retention_threshold_invalid",
            details={
                "max_bytes": max_bytes,
                "high_water_bytes": high,
                "low_water_bytes": low,
            },
        )

    if values["inactive_collapse_age_days"] < values["min_protected_age_days"]:
        raise RetentionPolicyError(
            "Inactive-collapse age must not precede the protected age.",
            error_code="retention_age_order_invalid",
            details={
                "min_protected_age_days": values["min_protected_age_days"],
                "inactive_collapse_age_days": values["inactive_collapse_age_days"],
            },
        )
    safety_limits = {
        "max_candidates": DEFAULT_MAX_CANDIDATES,
        "max_reclaim_bytes": DEFAULT_MAX_RECLAIM_BYTES,
    }
    for field, maximum in safety_limits.items():
        if not 0 < values[field] <= maximum:
            raise RetentionPolicyError(
                f"Retention setting {field} must be between 1 and {maximum}.",
                error_code="retention_limit_invalid",
                details={"field": field, "value": values[field],
                         "maximum": maximum},
            )

    return RetentionPolicy(
        max_bytes=max_bytes,
        high_water_bytes=high,
        low_water_bytes=low,
        min_protected_age_days=values["min_protected_age_days"],
        inactive_collapse_age_days=values["inactive_collapse_age_days"],
        max_candidates=values["max_candidates"],
        max_reclaim_bytes=values["max_reclaim_bytes"],
        sources=tuple(sorted(sources.items())),
    )


def classify_retention_state(policy: RetentionPolicy,
                             current_bytes: int) -> RetentionState:
    """Classify measured archive bytes and calculate a bounded reclaim pass."""
    current = _parse_nonnegative(current_bytes, "current_bytes", "runtime")
    if policy.unlimited:
        classification = RetentionClassification.UNLIMITED
        until_high = until_capacity = None
        over = reclaim = 0
        prune = False
    else:
        until_high = max(0, policy.high_water_bytes - current)
        until_capacity = max(0, policy.max_bytes - current)
        over = max(0, current - policy.max_bytes)
        if current > policy.max_bytes:
            classification = RetentionClassification.OVER_CAPACITY
        elif current >= policy.high_water_bytes:
            classification = RetentionClassification.HIGH_WATER
        elif current >= policy.low_water_bytes:
            classification = RetentionClassification.BETWEEN_WATERMARKS
        else:
            classification = RetentionClassification.BELOW_LOW_WATER
        prune = current >= policy.high_water_bytes
        reclaim = min(
            policy.max_reclaim_bytes,
            max(0, current - policy.low_water_bytes),
        ) if prune else 0
    return RetentionState(
        classification=classification,
        current_bytes=current,
        max_bytes=policy.max_bytes,
        high_water_bytes=policy.high_water_bytes,
        low_water_bytes=policy.low_water_bytes,
        bytes_until_high_water=until_high,
        bytes_until_capacity=until_capacity,
        over_capacity_bytes=over,
        reclaim_target_bytes=reclaim,
        prune_recommended=prune,
    )


__all__ = [
    "DEFAULT_HIGH_WATER_PERCENT", "DEFAULT_INACTIVE_COLLAPSE_AGE_DAYS",
    "DEFAULT_LOW_WATER_PERCENT", "DEFAULT_MAX_BYTES", "DEFAULT_MAX_CANDIDATES",
    "DEFAULT_MAX_RECLAIM_BYTES", "DEFAULT_MIN_PROTECTED_AGE_DAYS", "GIB",
    "RetentionClassification", "RetentionPolicy", "RetentionPolicyError",
    "RetentionState", "classify_retention_state", "resolve_retention_policy",
]
