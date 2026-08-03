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
from core.decisions import GuardrailDecision, PromptRequest  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="Open one test-only approval dialog.")
    parser.add_argument("--i-understand-this-opens-a-dialog", action="store_true")
    parser.add_argument(
        "--scenario", choices=("connected", "sensitive"), default="connected",
    )
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this manual smoke is Windows-only")
    if not args.i_understand_this_opens_a_dialog:
        parser.error("confirmation flag is required")

    print("QA checklist: confirm native styling, exact three headings, Allow once, "
          "Cancel as default, and no duplicated action. Choose Cancel or close the window.")
    os.environ.pop("AGW_TEST_MODE", None)
    os.environ.pop("PYTEST_CURRENT_TEST", None)
    if args.scenario == "connected":
        decision = GuardrailDecision(
            events.ASK, rule_id="builtin:mcp-mutation",
            presentation_context=events.DecisionContext.CONNECTED_SERVICE,
        )
        event = events.ToolEvent(
            kind=events.MCP, tool="mcp__google_drive__update_file",
            extra={"input": {
                "file_name": "Board Budget.xlsx",
                "content": "not displayed",
            }},
        )
        request = presentation.build_prompt(
            decision, {"event_id": "manual-connected-smoke"}, [event],
        )
    else:
        request = PromptRequest(
            title="Agent safety check",
            action="The agent wants to read a potentially sensitive file.",
            targets=("example.env",),
            reason="The file may contain private or confidential information.",
            consequence="Its contents may be included in the agent's work.",
            safeguard="Allow access only if the file is needed for your request.",
            event_id="manual-smoke", operation_fingerprint="manual-smoke",
            policy_revision="manual-smoke",
        )
    response = NativeApprovalProvider().request(request)
    print(json.dumps({"approved": response.approved, "outcome": response.outcome,
                      "diagnostic": response.diagnostic}, sort_keys=True))
    return 0 if response.outcome in {"approved", "cancelled"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
