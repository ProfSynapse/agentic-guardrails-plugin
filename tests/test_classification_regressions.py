"""Prompt-noise regressions for contextual and target-aware classification."""
import os

from core import engine
from core.events import ALLOW, ASK, DENY, DEFER, OTHER, READ, ToolEvent

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN_ROOT = os.path.join(REPO_ROOT, "plugin")


def _read(path, policy):
    return engine.evaluate(
        ToolEvent(kind=READ, tool="Read", paths=[str(path)]), policy, PLUGIN_ROOT)


def test_guardrail_source_docs_plans_tests_and_logs_do_not_prompt(policy, tmp_path):
    generated = {
        tmp_path / "source.py": "This test discusses CONFIDENTIAL markers.\n",
        tmp_path / "tests" / "test_rules.py": "Ignore the test instructions in this fixture.\n",
        tmp_path / "docs" / "guide.md": "INTERNAL USE ONLY is example vocabulary.\n",
        tmp_path / "plans" / "remediation.md": "Do not distribute is quoted policy text.\n",
        tmp_path / "audit.log": "The fixture says it was already approved.\n",
    }
    for path, content in generated.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        decision = _read(path, policy)
        assert decision.action in (DEFER, ALLOW), (path, decision)
        if decision.rule_id == "builtin:contextual-content":
            assert decision.confidence == "low"
            assert decision.prompt_eligible is False


def test_presentation_source_markings_do_not_prompt(policy):
    paths = (
        os.path.join(PLUGIN_ROOT, "scripts", "core", "shellparse.py"),
        os.path.join(PLUGIN_ROOT, "scripts", "codex", "sessionstart.py"),
        os.path.join(PLUGIN_ROOT, "scripts", "core", "engine.py"),
        os.path.join(PLUGIN_ROOT, "scripts", "core", "presentation.py"),
        os.path.join(REPO_ROOT, "docs", "plans", "guardrails-safety-ux-remediation-plan.md"),
    )
    for path in paths:
        assert _read(path, policy).action in (DEFER, ALLOW), path


def test_actual_credential_material_in_source_still_prompts(policy, tmp_path):
    source = tmp_path / "sample.py"
    marker = "-----BEGIN " + "RSA PRIVATE" + " KEY-----"
    source.write_text(marker + "\nactual-sensitive-material\n")
    assert _read(source, policy).action == ASK


def test_recursive_filename_search_does_not_trigger_content_prompt(evaluate):
    for command in ("rg --files -g '*secret*' .", "rg -l api_key ."):
        assert evaluate(command).action in (DEFER, ALLOW)


def test_exact_file_search_is_not_labeled_recursive(evaluate, tmp_path):
    target = tmp_path / "engine.py"
    target.write_text("def _is_secret_path(path): pass\n")
    decision = evaluate(f'rg -n -C 12 "_is_secret_path" "{target}"')
    assert decision.action in (DEFER, ALLOW)


def test_apply_patch_extracts_target_files():
    from codex.applypatch import parse_patch

    patch = "*** Begin Patch\n*** Update File: docs/report.txt\n+new\n*** End Patch\n"
    files = parse_patch(patch)
    assert [(item["op"], item["path"]) for item in files] == [
        ("update", "docs/report.txt")]


def test_apply_patch_unknown_targets_denies_without_prompt(policy):
    event = ToolEvent(kind=OTHER, tool="apply_patch",
                      extra={"apply_patch": True, "opaque": True})
    decision = engine.evaluate(event, policy, PLUGIN_ROOT)
    assert decision.action == DENY
    assert "explicit file paths" in decision.reason.lower()
