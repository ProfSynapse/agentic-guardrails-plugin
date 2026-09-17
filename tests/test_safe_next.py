import json
import os
import sys

from core import mutations, remediation, store, workflows
from core.decisions import GuardrailDecision
from core.events import DENY, EXEC, Decision, ToolEvent


def _event(command="rm -rf notes", cwd=None):
    return ToolEvent(
        kind=EXEC, tool="Bash", command=command,
        cwd=cwd or os.getcwd(),
    )


def test_complete_archive_advice_is_literal_cwd_bound_and_inert():
    event = _event()
    advice = remediation.for_event(
        Decision(DENY, rule_id="builtin:rm"), event,
    )

    assert advice.safe_to_retry is True
    assert advice.recommended_argv == (
        "agw", "archive", os.path.join(event.cwd, "notes"),
    )
    assert advice.source.as_dict() == {
        "component": "engine",
        "rule_id": "builtin:rm",
        "event_kind": "exec",
        "command_parse": "parsed-literal",
        "cwd_source": "event",
    }
    assert advice.missing_fields == ()
    assert "rm -rf notes" not in str(advice.as_dict())


def test_incomplete_provenance_fails_closed_and_never_echoes_command():
    canary = "RAW-SECRET-COMMAND"
    advice = remediation.for_event(
        Decision(DENY, rule_id="builtin:rm"),
        ToolEvent(kind=EXEC, command=f"rm {canary}", cwd=""),
    )

    assert advice.safe_to_retry is False
    assert advice.recommended_argv == ()
    assert {"cwd", "command_parse", "recommended_argv"}.issubset(advice.missing_fields)
    assert canary not in str(advice.as_dict())


def test_unsafe_claim_is_downgraded_and_unknown_assumptions_are_closed():
    advice = remediation.SafeNext(
        remediation.REASON_ARCHIVE,
        ("agw", "archive", "x"),
        True,
        assumptions=("invented-assumption",),
        source=remediation.RemediationSource("unknown-component"),
        missing_fields=(),
    )

    assert advice.safe_to_retry is False
    assert advice.recommended_argv == ()
    assert advice.assumptions == ()
    assert advice.source.component == "decision-fallback"
    assert "assumptions" in advice.missing_fields


def test_non_retryable_contract_cannot_carry_argv():
    advice = remediation.SafeNext(
        remediation.REASON_NARROW,
        ("denied-original", "--force"),
        False,
        source=remediation.RemediationSource(
            "engine", "builtin:test", EXEC, "parsed-literal", "event",
        ),
        missing_fields=(),
    )
    assert advice.recommended_argv == ()
    assert advice.safe_to_retry is False
    assert "recommended_argv" in advice.missing_fields


def test_decision_merge_keeps_only_winning_advice():
    lower = Decision(
        action="ask", rule_id="lower",
        safe_next=remediation.incomplete("lower"),
    )
    winner_advice = remediation.for_event(
        Decision(DENY, rule_id="builtin:rm"), _event(),
    )
    higher = Decision(
        action=DENY, rule_id="builtin:rm", safe_next=winner_advice,
    )

    merged = lower.merge(higher)
    assert merged.safe_next is winner_advice
    assert merged.safe_next.recommended_argv == winner_advice.recommended_argv


def test_guardrail_conversion_preserves_structured_advice():
    legacy = Decision(DENY, rule_id="builtin:rm")
    legacy.safe_next = remediation.for_event(legacy, _event())
    converted = GuardrailDecision.from_legacy(legacy)
    assert converted.safe_next is legacy.safe_next


def test_workflow_diagnostic_consumes_only_top_level_revalidated_argv(monkeypatch):
    recommendation = [
        "agw", "run", "--workflow", "example.writer", "--",
        "python", "writer.py",
    ]

    monkeypatch.setattr(
        mutations.workflows, "diagnose_matching_workflows",
        lambda argv, cwd: {
            "schema": mutations.workflows.DIAGNOSTIC_SCHEMA,
            "ok": True,
            "recommended_argv": recommendation,
            "suggested_argv": {
                "deprecated": True,
                "replacement": "recommended_argv",
                "value_included": False,
            },
            "candidates": [{"rank": 1, "recommended_argv": ["evil"]}],
        },
    )
    assert mutations.workflow_recommended_argv(
        "python writer.py", os.getcwd(),
    ) == recommendation

    monkeypatch.setattr(
        mutations, "workflow_recommended_argv",
        lambda command, cwd, dialect=None: recommendation,
    )
    advice = remediation.for_event(
        Decision(DENY, rule_id="invariant:prestate-unavailable"),
        _event("python writer.py"),
    )
    assert advice.safe_to_retry is True
    assert advice.recommended_argv == tuple(recommendation)
    assert advice.source.component == "workflow-diagnostics"
    assert remediation.ASSUMPTION_WORKFLOW_REVALIDATED in advice.assumptions


def test_workflow_diagnostic_rejects_ranked_candidate_without_top_level_value(monkeypatch):
    monkeypatch.setattr(
        mutations.workflows, "diagnose_matching_workflows",
        lambda argv, cwd: {
            "schema": mutations.workflows.DIAGNOSTIC_SCHEMA,
            "ok": True,
            "recommended_argv": [],
            "suggested_argv": {
                "deprecated": True,
                "replacement": "recommended_argv",
                "value_included": False,
            },
            "candidates": [{
                "rank": 1,
                "recommended_argv": ["agw", "run", "--workflow", "evil", "--", "x"],
            }],
        },
    )
    assert mutations.workflow_recommended_argv(
        "python writer.py", os.getcwd(),
    ) == []


def test_workflow_diagnostic_malformed_migration_metadata_fails_closed(monkeypatch):
    recommendation = [
        "agw", "run", "--workflow", "example.writer", "--",
        "python", "writer.py",
    ]
    for malformed in (
        recommendation,
        {"deprecated": False, "replacement": "recommended_argv",
         "value_included": False},
        {"deprecated": True, "replacement": "suggested_argv",
         "value_included": False},
        {"deprecated": True, "replacement": "recommended_argv",
         "value_included": True},
    ):
        monkeypatch.setattr(
            mutations.workflows, "diagnose_matching_workflows",
            lambda argv, cwd, value=malformed: {
                "schema": mutations.workflows.DIAGNOSTIC_SCHEMA,
                "ok": True,
                "recommended_argv": recommendation,
                "suggested_argv": value,
            },
        )
        assert mutations.workflow_recommended_argv(
            "python writer.py", os.getcwd(),
        ) == []


def test_missing_migration_metadata_keeps_revalidated_recommendation(monkeypatch):
    recommendation = [
        "agw", "run", "--workflow", "example.writer", "--",
        "python", "writer.py",
    ]
    monkeypatch.setattr(
        mutations.workflows, "diagnose_matching_workflows",
        lambda argv, cwd: {
            "schema": mutations.workflows.DIAGNOSTIC_SCHEMA,
            "ok": True,
            "recommended_argv": recommendation,
        },
    )
    assert mutations.workflow_recommended_argv(
        "python writer.py", os.getcwd(),
    ) == recommendation


def test_real_authenticated_diagnostic_recommendation_survives_once(tmp_path):
    script = tmp_path / "writer.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    private_arg = "private-safe-next-value"
    manifest = {
        "schema": workflows.MANIFEST_SCHEMA,
        "id": "example.safe-next",
        "description": "safe-next integration fixture",
        "command": {
            "runtime": "python",
            "script": script.name,
            "script_sha256": store.file_sha256(str(script)),
            "args": [private_arg],
        },
        "allowed_roots": ["{cwd}"],
        "outputs": [{"path": "{cwd}/out.txt", "expected": "absent"}],
        "observed_roots": [],
    }
    manifest_path = tmp_path / "workflow.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    workflows.trust_manifest(
        str(manifest_path), store.file_sha256(str(manifest_path)),
    )
    command = f'"{sys.executable}" "{script}" "{private_arg}"'

    diagnostic = workflows.diagnose_matching_workflows(
        [sys.executable, str(script), private_arg], str(tmp_path),
    )
    recommendation = mutations.workflow_recommended_argv(command, str(tmp_path))

    assert recommendation == diagnostic["recommended_argv"]
    assert recommendation[:4] == [
        "agw", "run", "--workflow", "example.safe-next",
    ]
    assert diagnostic["suggested_argv"] == {
        "deprecated": True,
        "replacement": "recommended_argv",
        "value_included": False,
    }
    assert private_arg in recommendation
    assert json.dumps(diagnostic).count(private_arg) == 1
    assert private_arg not in json.dumps(diagnostic["suggested_argv"])


def test_workflow_advice_cannot_replace_an_unrelated_semantic_denial(monkeypatch):
    monkeypatch.setattr(
        mutations, "workflow_recommended_argv",
        lambda command, cwd, dialect=None: [
            "agw", "run", "--workflow", "example.writer", "--",
            "python", "writer.py",
        ],
    )
    advice = remediation.for_event(
        Decision(DENY, rule_id="builtin:secret-exfil"),
        _event("python writer.py"),
    )
    assert advice.safe_to_retry is False
    assert advice.recommended_argv == ()
    assert advice.reason_code == remediation.REASON_SECRET


def test_multiple_events_never_combine_recommendations():
    advice = remediation.for_events(
        Decision(DENY, rule_id="builtin:rm"), [_event("rm a"), _event("rm b")],
    )
    assert advice.safe_to_retry is False
    assert advice.recommended_argv == ()
    assert "single_event" in advice.missing_fields


def test_capacity_instruction_names_prune_and_the_cap_override():
    text = remediation.capacity_instruction({
        "maximum_bytes": 20 * 1024 * 1024, "required_free_bytes": 4096,
    })
    assert "agw prune" in text
    assert "--yes-i-am-a-human" in text
    assert "agw status" in text
    assert "AGW_ARCHIVE_MAX_BYTES" in text
    assert "archive_max_bytes" in text
    assert "20,971,520" in text and "4,096" in text
    assert "Retry with one direct" not in text
    # Robust to missing or malformed details.
    assert "agw prune" in remediation.capacity_instruction(None)
    assert "agw prune" in remediation.capacity_instruction({"maximum_bytes": "x"})


def test_capacity_denial_gets_reclaim_advice_not_direct_retry():
    reason = (
        "Guardrails blocked this change because it could not create and verify "
        "a recovery point for a.txt. " + remediation.capacity_instruction({})
        + f" (error code {remediation.CAPACITY_ERROR_CODE})"
    )
    decision = Decision(DENY, reason, "invariant:prestate-unavailable")
    from core.events import EDIT, ToolEvent
    event = ToolEvent(kind=EDIT, tool="Edit", paths=["a.txt"], cwd=os.getcwd())

    advice = remediation.for_event(decision, event)
    assert advice.reason_code == remediation.REASON_CAPACITY
    assert advice.requires_user_choice is True
    assert advice.safe_to_retry is False
    assert advice.recommended_argv == ()
    assert advice.source.rule_id == "invariant:prestate-unavailable"
    assert remediation.for_events(decision, [event]).reason_code \
        == remediation.REASON_CAPACITY
    assert remediation.for_events(decision, [event, event]).reason_code \
        == remediation.REASON_CAPACITY

    # An ordinary prestate refusal keeps the direct-operation advice.
    plain = Decision(DENY, "could not identify the target", "invariant:prestate-unavailable")
    assert remediation.for_event(plain, event).reason_code == remediation.REASON_DIRECT


def test_a_capacity_denial_renders_the_reclaim_instruction_not_the_fallback():
    """The generic sentence cannot be acted on when the cache is full.

    Every remaining rollback point is protected, so "propose something
    narrower" can never succeed; the safe-next text has to name the prune.
    """
    from core import presentation

    advice = remediation.SafeNext(
        remediation.REASON_CAPACITY, requires_user_choice=True,
        missing_fields=("recommended_argv",),
    )
    text = presentation.render_safe_next(
        advice, {"maximum_bytes": 20 * 1024 * 1024, "required_free_bytes": 4096},
    )
    assert "agw prune" in text
    assert "--yes-i-am-a-human" in text
    assert "20,971,520" in text
    assert "Propose a narrower, reversible operation" not in text
    # Robust without details, which is how the hook reaches it today.
    assert "agw prune" in presentation.render_safe_next(advice)

    decision = GuardrailDecision(
        DENY, reason="the recovery cache is full",
        rule_id="invariant:prestate-unavailable", safe_next=advice,
    )
    feedback = presentation.build_denial_feedback(decision, "", [_event()])
    assert "agw prune" in feedback
    assert "Propose a narrower, reversible operation" not in feedback
