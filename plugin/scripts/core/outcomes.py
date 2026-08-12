"""Independent operation outcomes and their deterministic presentation mapping.

Recovery durability is deliberately not used to infer whether a process ran or
whether its declared output contract was satisfied.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Mapping


class _StringEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class ProcessOutcome(_StringEnum):
    NOT_STARTED = "not_started"
    NOT_APPLICABLE = "not_applicable"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    UNKNOWN = "unknown"


class ContractOutcome(_StringEnum):
    NOT_EVALUATED = "not_evaluated"
    SATISFIED = "satisfied"
    OUTPUT_MISMATCH = "output_mismatch"
    EXTRA_OUTPUTS = "extra_outputs"
    INDETERMINATE = "indeterminate"


class PreconditionOutcome(_StringEnum):
    SATISFIED = "satisfied"
    STALE = "stale"


class PolicyOutcome(_StringEnum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"


class EnvironmentOutcome(_StringEnum):
    READY = "ready"
    FAILED = "failed"


class PublicationOutcome(_StringEnum):
    NOT_APPLICABLE = "not_applicable"
    NOT_ATTEMPTED = "not_attempted"
    VALIDATED = "validated"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"
    NEEDS_ATTENTION = "needs_attention"


class CompositeOutcome(_StringEnum):
    POLICY_BLOCKED = "policy_blocked"
    STALE_PRECONDITION = "stale_precondition"
    ENVIRONMENT_FAILURE = "environment_failure"
    PROCESS_FAILED = "process_failed"
    SUCCESS_EXTRA_OUTPUTS = "success_extra_outputs"
    SUCCESS_OUTPUT_MISMATCH = "success_output_mismatch"
    SUCCESS = "success"


def _value(value: Any) -> str:
    return value.value if isinstance(value, Enum) else str(value)


def _axis_value(enum_type, value: Any, fallback: _StringEnum) -> str:
    try:
        return enum_type(_value(value)).value
    except (TypeError, ValueError):
        return fallback.value


def composite_outcome(
    *,
    policy_outcome: PolicyOutcome | str = PolicyOutcome.ALLOWED,
    precondition_outcome: PreconditionOutcome | str = PreconditionOutcome.SATISFIED,
    environment_outcome: EnvironmentOutcome | str = EnvironmentOutcome.READY,
    process_outcome: ProcessOutcome | str = ProcessOutcome.UNKNOWN,
    contract_outcome: ContractOutcome | str = ContractOutcome.NOT_EVALUATED,
) -> CompositeOutcome:
    """Map independent axes using the public, stable precedence order."""
    policy = PolicyOutcome(_value(policy_outcome))
    precondition = PreconditionOutcome(_value(precondition_outcome))
    environment = EnvironmentOutcome(_value(environment_outcome))
    process = ProcessOutcome(_value(process_outcome))
    contract = ContractOutcome(_value(contract_outcome))
    if policy is PolicyOutcome.BLOCKED:
        return CompositeOutcome.POLICY_BLOCKED
    if precondition is PreconditionOutcome.STALE:
        return CompositeOutcome.STALE_PRECONDITION
    if environment is EnvironmentOutcome.FAILED:
        return CompositeOutcome.ENVIRONMENT_FAILURE
    if process is ProcessOutcome.NOT_APPLICABLE:
        raise ValueError(
            "process_outcome=not_applicable requires an explicit operation_outcome"
        )
    if process is not ProcessOutcome.SUCCEEDED:
        return CompositeOutcome.PROCESS_FAILED
    if contract is ContractOutcome.EXTRA_OUTPUTS:
        return CompositeOutcome.SUCCESS_EXTRA_OUTPUTS
    if contract in {ContractOutcome.OUTPUT_MISMATCH, ContractOutcome.INDETERMINATE}:
        return CompositeOutcome.SUCCESS_OUTPUT_MISMATCH
    return CompositeOutcome.SUCCESS


def completed_record(
    record: Mapping[str, Any],
    *,
    operation_outcome: CompositeOutcome | str | None = None,
) -> dict:
    """Attach a known composite outcome to a completed live evaluation."""
    projected = _normalized_record(record)
    explicit = operation_outcome
    if explicit is None:
        explicit = record.get("operation_outcome", record.get("outcome"))
    if projected["process_outcome"] == ProcessOutcome.NOT_APPLICABLE.value:
        if explicit is None:
            raise ValueError(
                "a non-process operation requires an explicit operation_outcome"
            )
        operation = CompositeOutcome(_value(explicit))
    else:
        operation = composite_outcome(
            policy_outcome=projected["policy_outcome"],
            precondition_outcome=projected["precondition_outcome"],
            environment_outcome=projected["environment_outcome"],
            process_outcome=projected["process_outcome"],
            contract_outcome=projected["contract_outcome"],
        )
    projected["operation_outcome"] = operation.value
    projected["outcome"] = operation.value
    projected["outcome_known"] = True
    projected["outcome_source"] = "live_evaluation"
    projected.pop("outcome_reason", None)
    return projected


def _normalized_record(record: Mapping[str, Any]) -> dict:
    projected = dict(record)
    projected.setdefault("recovery_state", str(record.get("recovery_state") or
                                               record.get("state") or "UNKNOWN"))
    projected["process_outcome"] = _axis_value(
        ProcessOutcome, record.get("process_outcome"), ProcessOutcome.UNKNOWN)
    projected["contract_outcome"] = _axis_value(
        ContractOutcome, record.get("contract_outcome"), ContractOutcome.NOT_EVALUATED)
    projected["precondition_outcome"] = _axis_value(
        PreconditionOutcome, record.get("precondition_outcome"),
        PreconditionOutcome.SATISFIED)
    projected["policy_outcome"] = _axis_value(
        PolicyOutcome, record.get("policy_outcome"), PolicyOutcome.ALLOWED)
    projected["environment_outcome"] = _axis_value(
        EnvironmentOutcome, record.get("environment_outcome"),
        EnvironmentOutcome.READY)
    projected["publication_outcome"] = _axis_value(
        PublicationOutcome, record.get("publication_outcome"),
        PublicationOutcome.NOT_APPLICABLE)
    return projected


def _explicit_bool(record: Mapping[str, Any], *names: str) -> bool | None:
    values = [record[name] for name in names
              if name in record and isinstance(record[name], bool)]
    if not values or any(value != values[0] for value in values[1:]):
        return None
    return values[0]


def _exit_code(record: Mapping[str, Any]) -> tuple[int | None, bool]:
    values = []
    for name in ("exit_code", "exit"):
        value = record.get(name)
        if isinstance(value, int) and not isinstance(value, bool):
            values.append(value)
    return (None, True) if len(set(values)) > 1 else (values[0], False) if values else (None, False)


def _legacy_outcome(record: Mapping[str, Any], projected: Mapping[str, Any]
                    ) -> tuple[CompositeOutcome | None, str]:
    """Infer an outcome only from affirmative, mutually consistent evidence."""
    process = projected["process_outcome"]
    contract = projected["contract_outcome"]
    executed = _explicit_bool(record, "executed", "execution_started")
    timed_out = _explicit_bool(record, "timed_out")
    exit_code, exit_conflict = _exit_code(record)
    extra_outputs = _explicit_bool(record, "extra_outputs_detected", "has_extra_outputs")
    mismatch = _explicit_bool(record, "required_output_mismatch", "output_mismatch")
    evaluated = _explicit_bool(record, "contract_evaluated")

    conflict = exit_conflict
    conflict = conflict or (executed is False and (
        process in {ProcessOutcome.SUCCEEDED.value, ProcessOutcome.FAILED.value,
                    ProcessOutcome.TIMED_OUT.value} or exit_code is not None
        or timed_out is True))
    conflict = conflict or (process == ProcessOutcome.SUCCEEDED.value and (
        timed_out is True or (exit_code is not None and exit_code != 0)))
    conflict = conflict or (process == ProcessOutcome.TIMED_OUT.value and timed_out is False)
    conflict = conflict or (contract == ContractOutcome.SATISFIED.value and (
        extra_outputs is True or mismatch is True))
    if conflict:
        return None, "conflicting_historical_evidence"

    if projected["policy_outcome"] == PolicyOutcome.BLOCKED.value:
        return CompositeOutcome.POLICY_BLOCKED, "explicit_policy_block"
    if projected["precondition_outcome"] == PreconditionOutcome.STALE.value:
        return CompositeOutcome.STALE_PRECONDITION, "explicit_stale_precondition"
    if (projected["environment_outcome"] == EnvironmentOutcome.FAILED.value
            and (executed is False or process == ProcessOutcome.NOT_STARTED.value)):
        return CompositeOutcome.ENVIRONMENT_FAILURE, "explicit_environment_failure"
    if timed_out is True or process == ProcessOutcome.TIMED_OUT.value:
        return CompositeOutcome.PROCESS_FAILED, "explicit_process_timeout"
    if executed is True and exit_code is not None and exit_code != 0:
        return CompositeOutcome.PROCESS_FAILED, "explicit_nonzero_exit"
    if executed is True and exit_code == 0:
        if contract == ContractOutcome.EXTRA_OUTPUTS.value or extra_outputs is True:
            return CompositeOutcome.SUCCESS_EXTRA_OUTPUTS, "explicit_extra_outputs"
        if contract == ContractOutcome.OUTPUT_MISMATCH.value or mismatch is True:
            return CompositeOutcome.SUCCESS_OUTPUT_MISMATCH, "explicit_output_mismatch"
        if (contract == ContractOutcome.SATISFIED.value
                and (evaluated is True or "contract_outcome" in record)):
            return CompositeOutcome.SUCCESS, "explicit_satisfied_contract"
    return None, "insufficient_historical_evidence"


def project_record(record: Mapping[str, Any]) -> dict:
    """Return a compatible record with explicit, conservatively projected axes.

    Legacy ``state=COMMITTED`` only establishes recovery durability. Existing
    aliases are retained verbatim. Insufficient or conflicting
    historical evidence produces an explicitly unknown (null) outcome.
    """
    if record.get("outcome_source") == "live_evaluation" \
            and record.get("outcome_known") is True:
        return completed_record(record)
    projected = _normalized_record(record)
    outcome, reason = _legacy_outcome(record, projected)
    projected["outcome"] = outcome.value if outcome is not None else None
    projected["operation_outcome"] = projected["outcome"]
    projected["outcome_known"] = outcome is not None
    projected["outcome_source"] = "legacy_record"
    projected["outcome_reason"] = reason
    return projected
