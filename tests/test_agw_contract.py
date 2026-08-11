"""The packaged CLI and policy engine must share one operation vocabulary."""
import os
import subprocess
import sys

from core import agw_contract


REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugin")
AGW = os.path.join(REPO, "scripts", "agw", "agw.py")


def test_every_contracted_top_level_operation_has_cli_help():
    assert "apply" not in agw_contract.operation_names()
    assert "hydrate" not in agw_contract.operation_names()
    for operation in sorted(agw_contract.operation_names()):
        result = subprocess.run(
            [sys.executable, AGW, operation, "--help"],
            capture_output=True, text=True, timeout=20,
        )
        assert result.returncode == 0, (operation, result.stderr)


def test_contract_has_only_reviewed_effects_and_help_routes():
    assert agw_contract.operation("rename").canonical_name == "move"
    assert agw_contract.operation("prune").effect == \
        agw_contract.OperationEffect.HUMAN_APPROVAL
    for name, spec in agw_contract.OPERATIONS.items():
        assert spec.name == name
        assert spec.help_route == f"agw {name} --help"
        assert isinstance(spec.effect, agw_contract.OperationEffect)


def test_unknown_verb_display_is_bounded_and_inert():
    assert agw_contract.display_unknown_verb("future-operation") == "future-operation"
    assert agw_contract.display_unknown_verb("secret value") == "unsupported-token"
    assert agw_contract.display_unknown_verb("x" * 65) == "unsupported-token"
