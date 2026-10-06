"""Action contract tests: no real connector or external action is executed."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "plugin" / "scripts"))
from core import action_contracts, approvals, engine, enforcement, presentation
from core.decisions import GuardrailDecision, PromptRequest
from core.events import ASK, DEFER, DENY, MCP, READ, Decision, ToolEvent

TOOL = "mcp__fixture__operate"


def config(effect="send"):
    return {"version": 1, "unmatched": "deny", "tools": {
        TOOL: {"effect": effect, "required": ["to", "body"],
               "arguments": ["to", "body"]}}}


def event(data=None, tool=TOOL):
    return ToolEvent(MCP, tool=tool, extra={"input": (
        {"to": "person@example.invalid", "body": "fixture"} if data is None else data)})


def evaluate(cfg=None, ev=None):
    return action_contracts.evaluate(
        ev or event(), {"action_contracts": config() if cfg is None else cfg})


@pytest.mark.parametrize("effect", ["send", "share", "publish", "admin"])
def test_consequential_actions_need_fresh_review_even_in_observe(effect):
    result = evaluate(config(effect))
    assert result.action == ASK
    assert result.fresh_approval and result.memo_key is None
    assert enforcement.resolve(result, observe=True).action == ASK


@pytest.mark.parametrize("effect", ["read", "draft", "edit"])
def test_routine_contract_does_not_grant_or_override_permission(effect):
    result = evaluate(config(effect))
    assert result.action == DEFER
    assert result.merge(Decision(DENY, "existing safeguard")).action == DENY


def test_unmatched_is_exact_and_denied():
    assert evaluate(ev=event(tool=TOOL.upper())).action == DENY
    assert evaluate(ev=event(tool=TOOL + "_other")).action == DENY
    c = config()
    c["unmatched"] = "defer"
    assert evaluate(c, event(tool="mcp__other__read")).action == DEFER


def test_blocked_contract():
    assert evaluate(config("blocked")).action == DENY


@pytest.mark.parametrize("data", [
    {}, {"to": "x"}, {"to": "x", "body": "y", "approved": True},
    {"to": "x", "body": "y", "effect": "read"}, [], "approved"])
def test_argument_envelope_rejects_missing_extra_and_self_authorization(data):
    assert evaluate(ev=event(data)).action == DENY


@pytest.mark.parametrize("cfg", [
    None, {}, [], {"version": True, "unmatched": "deny", "tools": {}},
    {"version": 2, "unmatched": "deny", "tools": {}},
    {"version": 1, "unmatched": "allow", "tools": {}},
    {"version": 1, "unmatched": "deny", "tools": [], "typo": True},
])
def test_invalid_contracts_fail_closed(cfg):
    assert action_contracts.evaluate(event(), {"action_contracts": cfg}).action == DENY


def test_wildcards_unknown_effect_and_unknown_rule_keys_rejected():
    for change in ("wildcard", "effect", "field", "required"):
        c = config()
        if change == "wildcard":
            c["tools"]["mcp__*"] = c["tools"].pop(TOOL)
        elif change == "effect":
            c["tools"][TOOL]["effect"] = "approve"
        elif change == "field":
            c["tools"][TOOL]["attention"] = "optional"
        else:
            c["tools"][TOOL]["required"] = ["missing"]
        assert evaluate(c).action == DENY


def test_opt_in_and_native_reads_unchanged():
    assert action_contracts.evaluate(event(), {}).action == DEFER
    assert evaluate(ev=ToolEvent(READ, tool="Read")).action == DEFER


def test_review_cannot_inherit_memo_key_regardless_of_merge_order():
    review = evaluate()
    remembered = Decision(ASK, "resource review", memo_key="resource")
    for result in (review.merge(remembered), remembered.merge(review)):
        assert result.fresh_approval
        assert result.memo_key is None
        assert GuardrailDecision.from_legacy(result).fresh_approval


def test_fresh_review_does_not_reuse_even_same_event_id():
    decision = GuardrailDecision.from_legacy(evaluate())
    decision.policy_revision = "fixture-revision"
    request = PromptRequest("Review", "Send fixture", ("fixture",), "Consequential",
                            "External effect", "", "same-event", "exact-hash",
                            policy_revision="fixture-revision")
    class Provider:
        calls = 0
        def request(self, request):
            self.calls += 1
            return approvals.ApprovalResponse(self.calls == 1,
                                             "approved" if self.calls == 1 else "cancelled")
    provider = Provider()
    assert approvals.request_approval(decision, request, provider).authorizes()
    assert not approvals.request_approval(decision, request, provider).authorizes()
    assert provider.calls == 2


def test_exact_fingerprint_changes_for_recipient_body_and_policy():
    payload = {"tool_name": TOOL, "tool_input": event().extra["input"]}
    first = presentation.operation_fingerprint(payload, [event()], "revision")
    for key in ("to", "body"):
        changed = copy.deepcopy(payload)
        changed["tool_input"][key] = "changed"
        assert presentation.operation_fingerprint(changed, [event()], "revision") != first
    assert presentation.operation_fingerprint(payload, [event()], "new-revision") != first


def install_fixture_policy(tmp_path, monkeypatch, cfg):
    home = tmp_path / "agw"
    packs = home / "policies.d"
    packs.mkdir(parents=True)
    (packs / "actions.json").write_text(json.dumps({"settings": {"action_contracts": cfg}}))
    monkeypatch.setenv("AGW_HOME", str(home))
    return home


def test_loader_cache_and_engine_preserve_contract(tmp_path, monkeypatch):
    install_fixture_policy(tmp_path, monkeypatch, config())
    for _ in range(2):
        policy = engine.load_policy(str(ROOT / "plugin"))
        result = engine.evaluate(event(), policy)
        assert result.action == ASK and result.fresh_approval
        assert result.policy_revision
        assert engine.evaluate(event(tool="mcp__fixture__unknown"), policy).action == DENY


def test_contract_cannot_approve_connector_deletion(tmp_path, monkeypatch):
    c = config("read")
    c["tools"]["mcp__fixture__delete_file"] = c["tools"].pop(TOOL)
    install_fixture_policy(tmp_path, monkeypatch, c)
    result = engine.evaluate(event(tool="mcp__fixture__delete_file"),
                             engine.load_policy(str(ROOT / "plugin")))
    assert result.action == DENY
    assert result.rule_id in {"builtin:mcp-delete", "core.yaml:mcp[0]"}


def test_malformed_pack_degrades_instead_of_disappearing(tmp_path, monkeypatch):
    install_fixture_policy(tmp_path, monkeypatch, {"version": 1})
    result = engine.evaluate(event(), engine.load_policy(str(ROOT / "plugin")))
    assert result.action == DENY
    assert result.rule_id == "policy:health-degraded"


@pytest.mark.parametrize("case", ["review", "unknown", "malformed"])
def test_real_codex_adapter_denies_without_human_channel(tmp_path, monkeypatch, case):
    home = install_fixture_policy(tmp_path, monkeypatch,
                                  {"version": 1} if case == "malformed" else config())
    payload = {"hook_event_name": "PreToolUse", "tool_name":
               "mcp__fixture__unknown" if case == "unknown" else TOOL,
               "tool_input": event().extra["input"],
               "session_id": "action-contract-fixture", "cwd": str(tmp_path)}
    env = dict(os.environ, AGW_HOME=str(home), AGW_APPROVAL_PROVIDER="headless",
               PLUGIN_ROOT=str(ROOT / "plugin"), AGW_TEST_MODE="1",
               PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(
        [sys.executable, str(ROOT / "plugin/scripts/codex/pretooluse.py")],
        input=json.dumps(payload), text=True, capture_output=True, env=env, timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
