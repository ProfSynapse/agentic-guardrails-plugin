from core import outcomes
from core import recovery_contracts
import pytest


def test_composite_outcome_precedence_is_deterministic():
    assert outcomes.composite_outcome(
        policy_outcome="blocked", precondition_outcome="stale",
        environment_outcome="failed", process_outcome="succeeded",
        contract_outcome="extra_outputs",
    ) == outcomes.CompositeOutcome.POLICY_BLOCKED
    assert outcomes.composite_outcome(
        precondition_outcome="stale", environment_outcome="failed",
        process_outcome="succeeded", contract_outcome="extra_outputs",
    ) == outcomes.CompositeOutcome.STALE_PRECONDITION
    assert outcomes.composite_outcome(
        environment_outcome="failed", process_outcome="succeeded",
        contract_outcome="extra_outputs",
    ) == outcomes.CompositeOutcome.ENVIRONMENT_FAILURE
    assert outcomes.composite_outcome(
        process_outcome="failed", contract_outcome="extra_outputs",
    ) == outcomes.CompositeOutcome.PROCESS_FAILED


def test_success_contract_variants():
    assert outcomes.composite_outcome(
        process_outcome="succeeded", contract_outcome="extra_outputs",
    ).value == "success_extra_outputs"
    assert outcomes.composite_outcome(
        process_outcome="succeeded", contract_outcome="output_mismatch",
    ).value == "success_output_mismatch"
    assert outcomes.composite_outcome(
        process_outcome="succeeded", contract_outcome="satisfied",
    ).value == "success"


def test_legacy_committed_record_never_infers_process_success():
    projected = recovery_contracts.outcome_fields({
        "state": "COMMITTED", "ok": True, "exit": 0,
    })
    assert projected["state"] == projected["recovery_state"] == "COMMITTED"
    assert projected["ok"] is True and projected["exit"] == 0
    assert projected["process_outcome"] == "unknown"
    assert projected["contract_outcome"] == "not_evaluated"
    assert projected["outcome"] is None
    assert projected["operation_outcome"] is None
    assert projected["outcome_known"] is False
    assert projected["outcome_source"] == "legacy_record"
    assert projected["outcome_reason"] == "insufficient_historical_evidence"


def test_explicit_axes_are_persisted_without_alias_rewrites():
    projected = outcomes.project_record({
        "state": "COMMITTED", "ok": False, "exit": 7,
        "executed": True, "contract_outcome": "extra_outputs",
    })
    assert projected["ok"] is False and projected["exit"] == 7
    assert projected["outcome"] == "process_failed"


def test_unknown_legacy_axis_values_project_conservatively():
    projected = outcomes.project_record({
        "process_outcome": "future-value", "contract_outcome": "future-value",
    })
    assert projected["process_outcome"] == "unknown"
    assert projected["contract_outcome"] == "not_evaluated"
    assert projected["outcome"] is None
    assert projected["outcome_known"] is False


def test_legacy_projection_requires_affirmative_success_evidence():
    incomplete = outcomes.project_record({
        "executed": True, "exit": 0, "contract_outcome": "not_evaluated",
    })
    assert incomplete["outcome"] is None
    satisfied = outcomes.project_record({
        "executed": True, "exit": 0, "contract_evaluated": True,
        "contract_outcome": "satisfied",
    })
    assert satisfied["outcome"] == "success"
    assert satisfied["outcome_known"] is True


def test_legacy_projection_uses_only_explicit_failure_and_contract_evidence():
    cases = [
        ({"policy_outcome": "blocked"}, "policy_blocked"),
        ({"precondition_outcome": "stale"}, "stale_precondition"),
        ({"environment_outcome": "failed", "executed": False},
         "environment_failure"),
        ({"timed_out": True}, "process_failed"),
        ({"executed": True, "exit": 9}, "process_failed"),
        ({"executed": True, "exit": 0, "contract_outcome": "extra_outputs"},
         "success_extra_outputs"),
        ({"executed": True, "exit": 0,
          "contract_outcome": "output_mismatch"}, "success_output_mismatch"),
    ]
    for record, expected in cases:
        projected = outcomes.project_record(record)
        assert projected["outcome"] == expected
        assert projected["outcome_known"] is True


def test_conflicting_legacy_evidence_remains_unknown():
    projected = outcomes.project_record({
        "executed": True, "exit": 3, "process_outcome": "succeeded",
        "contract_outcome": "satisfied",
    })
    assert projected["outcome"] is None
    assert projected["outcome_known"] is False
    assert projected["outcome_reason"] == "conflicting_historical_evidence"


def test_completed_live_evaluation_always_has_composite_outcome():
    projected = outcomes.completed_record({
        "process_outcome": "succeeded", "contract_outcome": "extra_outputs",
    })
    assert projected["outcome"] == "success_extra_outputs"
    assert projected["operation_outcome"] == projected["outcome"]
    assert projected["outcome_known"] is True
    assert projected["outcome_source"] == "live_evaluation"


@pytest.mark.parametrize("publication", [
    "not_applicable", "not_attempted", "validated", "committed",
    "rolled_back", "needs_attention",
])
def test_non_process_operations_require_explicit_outcome(publication):
    projected = outcomes.completed_record({
        "process_outcome": "not_applicable",
        "publication_outcome": publication,
    }, operation_outcome="success")
    assert projected["process_outcome"] == "not_applicable"
    assert projected["publication_outcome"] == publication
    assert projected["operation_outcome"] == "success"
    assert projected["outcome"] == projected["operation_outcome"]


def test_not_applicable_never_falls_through_to_process_failed():
    with pytest.raises(ValueError, match="explicit operation_outcome"):
        outcomes.composite_outcome(process_outcome="not_applicable")
    with pytest.raises(ValueError, match="explicit operation_outcome"):
        outcomes.completed_record({"process_outcome": "not_applicable"})


def test_live_operation_outcome_is_restricted_to_the_seven_values():
    with pytest.raises(ValueError):
        outcomes.completed_record(
            {"process_outcome": "not_applicable"},
            operation_outcome="publication_committed",
        )


def test_legacy_null_projection_preserves_authoritative_alias():
    projected = outcomes.project_record({"state": "COMMITTED"})
    assert projected["operation_outcome"] is None
    assert projected["outcome"] is None
    assert projected["publication_outcome"] == "not_applicable"
