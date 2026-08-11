"""Manual QA gate for the real Windows native approval dialog.

This script never performs the described operation; it only renders the prompt.
"""
import argparse
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "plugin" / "scripts"))

from core import events, presentation  # noqa: E402
from core.approvals import NativeApprovalProvider  # noqa: E402
from core.decisions import GuardrailDecision  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="Open one test-only approval dialog.")
    parser.add_argument("--i-understand-this-opens-a-dialog", action="store_true")
    parser.add_argument(
        "--scenario", choices=("sensitive", "prune"), default="sensitive",
    )
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this manual smoke is Windows-only")
    if not args.i_understand_this_opens_a_dialog:
        parser.error("confirmation flag is required")

    print("QA checklist: confirm native styling, three required headings, an optional "
          "factual Recovery heading, Allow once, Cancel as default, and no duplicated "
          "action or Cancel instruction. This test performs no described operation.")
    os.environ.pop("AGW_TEST_MODE", None)
    os.environ.pop("PYTEST_CURRENT_TEST", None)
    if args.scenario == "sensitive":
        decision = GuardrailDecision(
            events.ASK, rule_id="builtin:secret-file",
            presentation_context=events.DecisionContext.SENSITIVE_READ,
            presentation_details={
                "operation": "read",
                "targets": ["C:/example/example.env"],
                "target_kind": "file",
                "signal": "account or access information",
                "trigger": "The selected filename identifies a credential-type file.",
            },
        )
        event = events.ToolEvent(kind=events.READ, paths=["C:/example/example.env"])
        request = presentation.build_prompt(
            decision, {"event_id": "manual-sensitive-smoke"}, [event],
        )
    else:
        decision = GuardrailDecision(
            events.ASK, rule_id="builtin:agw-ask",
            presentation_context=events.DecisionContext.AGW_ARCHIVE,
            presentation_details={
                "operation": "permanently prune stored recovery copies",
                "targets": ["Stored Guardrails recovery copies"],
                "target_kind": "category",
                "trigger": "This operation permanently removes retained recovery data.",
            },
        )
        event = events.ToolEvent(kind=events.EXEC)
        request = presentation.build_prompt(
            decision, {"event_id": "manual-prune-smoke"}, [event],
        )
    response = NativeApprovalProvider().request(request)
    print(json.dumps({"approved": response.approved, "outcome": response.outcome,
                      "diagnostic": response.diagnostic}, sort_keys=True))
    return 0 if response.outcome in {"approved", "cancelled"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
