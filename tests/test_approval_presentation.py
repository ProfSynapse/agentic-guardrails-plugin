"""Focused tests for UI-free approval contracts and plain-language copy."""
import os
import sys
from dataclasses import replace

REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugin")
sys.path.insert(0, os.path.join(REPO, "scripts"))

from core import approvals, events, presentation  # noqa: E402
from core.approvals import ApprovalProvider, ApprovalResponse  # noqa: E402
from core.decisions import GuardrailDecision, LOW  # noqa: E402


def _request(event_id="event-1"):
    decision = GuardrailDecision(
        events.ASK, rule_id="builtin:review", policy_revision="revision-a"
    )
    ev = events.ToolEvent(kind=events.OTHER, tool="apply_patch",
                          command="PowerShell -Command Remove-Item x",
                          extra={"opaque": True})
    payload = {"event_id": event_id, "tool_name": "apply_patch",
               "tool_input": {"command": "PowerShell -Command Remove-Item x"}}
    return decision, presentation.build_prompt(decision, payload, [ev])


def test_headless_provider_never_calls_messagebox(monkeypatch):
    def native_ui_was_called(*_args, **_kwargs):
        raise AssertionError("native UI was called")

    monkeypatch.setattr(approvals.NativeApprovalProvider, "_task_dialog",
                        native_ui_was_called)
    decision, request = _request()
    response = approvals.request_approval(
        decision, request, approvals.HeadlessApprovalProvider())
    assert response == ApprovalResponse(False, "headless-deny")


def test_low_confidence_content_never_invokes_provider():
    class MustNotRun(ApprovalProvider):
        def request(self, request):
            raise AssertionError("provider must not run for low-confidence content")

    decision, request = _request()
    decision.confidence = LOW
    decision.prompt_eligible = False
    response = approvals.request_approval(decision, request, MustNotRun())
    assert response.approved is False
    assert response.outcome == "not-prompt-eligible"


def test_prompt_copy_contains_no_shell_jargon():
    _decision, request = _request()
    primary = request.primary_text().lower()
    for jargon in ("bash", "powershell", "apply_patch", "remove-item", "shell"):
        assert jargon not in primary
    assert request.title == "Agent safety check"
    assert request.allow_label == "Allow once"
    assert request.cancel_label == "Cancel (recommended)"
    assert request.default_choice == "cancel"
    assert "Why we're asking:" in request.primary_text()
    assert "What could happen:" in request.primary_text()
    assert "Safety measure:" in request.primary_text()
    assert "Cancel to make no changes" in request.primary_text()
    assert request.action not in request.primary_text()


def test_closed_prompt_copy_uses_safe_categories_not_raw_inputs():
    canary = "PRIVATE-CANARY-client-secret-command"
    cases = (
        ("builtin:agw-ask", events.DecisionContext.AGW_ARCHIVE,
         "Stored Guardrails recovery copies", "changes retained data"),
        ("builtin:agw-unknown", events.DecisionContext.AGW_UNKNOWN,
         "exact files could not be identified", "unrecognized Guardrails operation"),
        ("builtin:patch-opaque", events.DecisionContext.PATCH_UNKNOWN,
         "exact files could not be identified", "proposed change"),
        ("builtin:secret-file", events.DecisionContext.SENSITIVE_READ,
         "potentially sensitive file", "account or access information"),
        ("builtin:credential-hunt", events.DecisionContext.CREDENTIAL_SEARCH,
         "requested search scope", "search broadly"),
        ("builtin:git-restore", events.DecisionContext.RESTORE_FILES,
         "selected working file", "restore working files"),
        ("builtin:mcp-mutation", events.DecisionContext.CONNECTED_SERVICE,
         "connected service", "change information"),
    )
    for rule_id, context, target_text, action_text in cases:
        decision = GuardrailDecision(
            events.ASK, reason=canary, rule_id=rule_id,
            policy_revision="revision-a", presentation_context=context,
        )
        ev = events.ToolEvent(
            kind=events.EXEC, tool="PowerShell", command=canary,
            paths=[f"C:/private/{canary}.env"],
        )
        request = presentation.build_prompt(
            decision,
            {"event_id": "safe-copy", "tool_input": {"command": canary}},
            [ev],
        )
        rendered = (request.action + "\n" + request.primary_text()).lower()
        assert target_text.lower() in rendered
        assert action_text.lower() in rendered
        assert canary.lower() not in rendered
        assert "powershell" not in rendered
        assert "remove-item" not in rendered


def test_unknown_target_is_honest_and_cancel_is_recommended():
    decision = GuardrailDecision(
        events.ASK, rule_id="builtin:agw-unknown",
        policy_revision="revision-a",
        presentation_context=events.DecisionContext.AGW_UNKNOWN,
    )
    event = events.ToolEvent(kind=events.EXEC, command="private raw text")
    request = presentation.build_prompt(decision, {"event_id": "unknown"}, [event])
    assert "The exact files could not be identified" in request.primary_text()
    assert request.allow_label == "Allow once"
    assert request.cancel_label == "Cancel (recommended)"
    assert request.default_choice == "cancel"


def test_known_reversible_guardrails_change_recommends_allow():
    decision = GuardrailDecision(
        events.ASK, rule_id="builtin:agw-ask",
        policy_revision="revision-a",
        presentation_context=events.DecisionContext.RESTORE_FILES,
    )
    event = events.ToolEvent(kind=events.EXEC, command="private raw text")
    request = presentation.build_prompt(decision, {"event_id": "restore"}, [event])
    assert request.allow_label == "Allow once (recommended)"
    assert request.cancel_label == "Cancel"
    assert request.default_choice == "allow"
    assert approvals._default_button_id(request, 100, 101) == 100


def test_cancel_recommendation_is_native_dialog_default():
    _decision, request = _request()
    assert request.default_choice == "cancel"
    assert approvals._default_button_id(request, 100, 101) == 101


def test_hard_denial_feedback_is_actionable_and_tells_agent_to_explain():
    decision = GuardrailDecision(
        events.DENY,
        reason="Deletion is disabled by Guardrails.",
        rule_id="builtin:rm",
        policy_revision="revision-a",
    )
    feedback = presentation.build_denial_feedback(decision)
    assert feedback.startswith("Blocked: Deletion is disabled")
    assert "Result: The requested action did not run" in feedback
    assert "Safe next step:" in feedback
    assert "reversible archive" in feedback
    assert "User communication:" in feedback
    assert "plain language" in feedback
    assert "toward the user's goal" in feedback
    assert "Do not quote the raw command" in feedback


def test_declined_approval_tells_agent_not_to_nag():
    decision = GuardrailDecision(
        events.ASK, reason="Sensitive read", rule_id="builtin:secret-file",
        policy_revision="revision-a",
    )
    feedback = presentation.build_denial_feedback(decision, "cancelled")
    assert "was not approved" in feedback
    assert "Do not retry the same operation" in feedback
    assert "safer alternative" in feedback
    assert "Sensitive read" not in feedback


def test_unknown_denial_gets_safe_generic_recovery_without_raw_input():
    canary = "RAW-COMMAND-AND-SECRET-CANARY"
    decision = GuardrailDecision(
        events.DENY, reason="", rule_id="company:unknown",
        policy_revision="revision-a",
    )
    feedback = presentation.build_denial_feedback(decision)
    assert "narrower, reversible operation with explicit targets" in feedback
    assert canary not in feedback


def test_custom_connector_deny_does_not_inherit_bundled_delete_advice():
    decision = GuardrailDecision(
        events.DENY, reason="Company connector policy",
        rule_id="company.json:mcp[0]", policy_revision="revision-a",
    )
    feedback = presentation.build_denial_feedback(decision)
    assert "narrower, reversible operation with explicit targets" in feedback
    assert "soft-delete" not in feedback


def test_duplicate_host_event_coalesces_prompt():
    class CountingProvider(ApprovalProvider):
        def __init__(self):
            self.calls = 0

        def request(self, request):
            self.calls += 1
            return ApprovalResponse(False, "denied")

    approvals._CACHE.clear()
    decision, request = _request("same-host-event")
    provider = CountingProvider()
    first = approvals.request_approval(decision, request, provider)
    second = approvals.request_approval(decision, request, provider)
    assert first == second
    assert provider.calls == 1


def test_provider_failure_denies():
    class BrokenProvider(ApprovalProvider):
        def request(self, request):
            raise RuntimeError("provider unavailable")

    approvals._CACHE.clear()
    decision, request = _request("provider-failure")
    response = approvals.request_approval(decision, request, BrokenProvider())
    assert response.approved is False
    assert response.outcome == "provider-error"


def test_malformed_approval_response_denies():
    class MalformedProvider(ApprovalProvider):
        def request(self, request):
            return ApprovalResponse("invalid", "unexpected")

    approvals._CACHE.clear()
    decision, request = _request("malformed-response")
    response = approvals.request_approval(decision, request, MalformedProvider())
    assert response.authorizes() is False
    assert response.approved is False
    assert response.outcome == "invalid-response"


def test_truthy_and_conflicting_approval_values_deny():
    malformed = (
        ApprovalResponse(1, "approved"),
        ApprovalResponse("yes", "approved"),
        ApprovalResponse(True, "denied"),
        ApprovalResponse(False, "approved"),
    )
    assert all(response.authorizes() is False for response in malformed)


def test_expired_dedupe_prompts_again(monkeypatch):
    class CountingProvider(ApprovalProvider):
        def __init__(self):
            self.calls = 0

        def request(self, request):
            self.calls += 1
            return ApprovalResponse(False, "denied")

    moments = iter((10.0, 10.0 + approvals.DEDUPE_SECONDS + 1.0))
    monkeypatch.setattr(approvals.time, "monotonic", lambda: next(moments))
    approvals._CACHE.clear()
    decision, request = _request("expiring-event")
    provider = CountingProvider()
    approvals.request_approval(decision, request, provider)
    approvals.request_approval(decision, request, provider)
    assert provider.calls == 2


def test_different_event_id_or_fingerprint_misses_cache():
    class CountingProvider(ApprovalProvider):
        def __init__(self):
            self.calls = 0

        def request(self, request):
            self.calls += 1
            return ApprovalResponse(False, "denied")

    approvals._CACHE.clear()
    decision, request = _request("event-a")
    provider = CountingProvider()
    approvals.request_approval(decision, request, provider)
    approvals.request_approval(decision, replace(request, event_id="event-b"), provider)
    approvals.request_approval(
        decision, replace(request, operation_fingerprint="different"), provider)
    assert provider.calls == 3


def test_policy_revision_change_misses_cache():
    class CountingProvider(ApprovalProvider):
        def __init__(self):
            self.calls = 0

        def request(self, request):
            self.calls += 1
            return ApprovalResponse(False, "denied")

    approvals._CACHE.clear()
    decision, request = _request("revision-event")
    provider = CountingProvider()
    approvals.request_approval(decision, request, provider)
    changed = replace(decision, policy_revision="revision-b")
    changed_request = replace(request, policy_revision="revision-b")
    approvals.request_approval(changed, changed_request, provider)
    assert provider.calls == 2


def test_missing_policy_revision_denies_without_provider():
    class MustNotRun(ApprovalProvider):
        def request(self, request):
            raise AssertionError("provider must not run without a policy revision")

    decision, request = _request("missing-revision")
    decision.policy_revision = ""
    request = replace(request, policy_revision="")
    response = approvals.request_approval(decision, request, MustNotRun())
    assert response == ApprovalResponse(False, "policy-revision-unavailable")


def test_pending_approval_is_private_single_use_and_revision_bound(tmp_path, monkeypatch):
    monkeypatch.setenv("AGW_HOME", str(tmp_path / "home"))
    payload = {
        "event_id": "host-event-secret",
        "tool_name": "Read",
        "tool_input": {"file_path": "C:/private/customer-record.txt"},
    }
    private_memo = "policy:rev:secret-file:C:/private/customer-record.txt"
    assert approvals.record_pending_approval(
        payload, "session-secret", private_memo, "rev", "fingerprint"
    )
    pending = list((tmp_path / "home" / "pending-approvals").iterdir())
    assert len(pending) == 1
    raw = pending[0].read_text()
    assert "customer-record" not in raw
    assert "host-event-secret" not in raw
    assert "session-secret" not in raw
    assert private_memo not in raw
    assert "memo_key" not in raw
    record = approvals.consume_pending_approval(payload, "session-secret")
    assert record["policy_revision"] == "rev"
    assert record["approval_identity"] == approvals.approval_identity(private_memo, "rev")
    assert approvals.consume_pending_approval(payload, "session-secret") is None


def test_stale_pending_approval_is_consumed_and_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("AGW_HOME", str(tmp_path / "home"))
    payload = {"event_id": "stale-event"}
    moments = iter((10.0, 10.0 + approvals.PENDING_SECONDS + 1))
    monkeypatch.setattr(approvals.time, "time", lambda: next(moments))
    assert approvals.record_pending_approval(
        payload, "session", "private-resource", "rev", "fingerprint"
    )
    assert approvals.consume_pending_approval(payload, "session") is None
    assert approvals.consume_pending_approval(payload, "session") is None


def test_native_ui_tripwire_is_not_masked():
    class ForbiddenNativeProvider(ApprovalProvider):
        def request(self, request):
            raise approvals.NativeUIInTestError("native UI forbidden")

    approvals._CACHE.clear()
    decision, request = _request("native-tripwire")
    try:
        approvals.request_approval(decision, request, ForbiddenNativeProvider())
    except approvals.NativeUIInTestError:
        pass
    else:
        raise AssertionError("native UI tripwire was masked")


def test_cancel_and_non_allow_results_deny():
    for response in (
        ApprovalResponse(False, "cancelled"),
        ApprovalResponse(False, "denied"),
        ApprovalResponse(False, "provider-unavailable"),
        ApprovalResponse(True, "unexpected"),
    ):
        assert response.authorizes() is False


def test_technical_details_are_safely_omitted():
    _decision, request = _request("safe-details")
    assert request.technical_details == ""
    primary = request.primary_text()
    assert "PowerShell -Command Remove-Item x" not in primary


def test_native_provider_initialization_fails_in_test_mode(monkeypatch):
    monkeypatch.setenv("AGW_TEST_MODE", "1")
    try:
        approvals.NativeApprovalProvider()
    except approvals.NativeUIInTestError as exc:
        assert "during a test" in str(exc)
    else:
        raise AssertionError("native provider initialized during a test")
