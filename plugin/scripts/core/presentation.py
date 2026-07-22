"""Plain-language presentation for guardrail approval requests."""
from __future__ import annotations

import hashlib
import json

from . import events
from .decisions import GuardrailDecision, PromptRequest


def operation_fingerprint(payload: dict, evlist, policy_revision: str = "") -> str:
    """Bind an approval to the exact operation without displaying raw input."""
    material = {
        "tool": payload.get("tool_name", ""),
        "cwd": payload.get("cwd", ""),
        "input": payload.get("tool_input") or {},
        "events": [
            {"kind": ev.kind, "paths": list(ev.paths), "command": ev.command}
            for ev in evlist
        ],
        "policy_revision": str(policy_revision or ""),
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


_COPY_BY_RULE = {
    "builtin:agw-ask": (
        "The agent wants Guardrails to change managed files or stored copies.",
        "This Guardrails operation changes retained data or working files.",
        "Files or retained recovery copies may be moved, replaced, or removed.",
    ),
    "builtin:agw-unknown": (
        "The agent wants to run an unrecognized Guardrails operation.",
        "Guardrails cannot verify the effects of this operation name.",
        "The operation could change files or retained recovery copies.",
    ),
    "builtin:agw-empty": (
        "The agent wants to run Guardrails without a documented operation.",
        "No safe, read-only operation could be identified.",
        "The effect cannot be determined from the structured request.",
    ),
    "builtin:patch-opaque": (
        "The agent wants to apply a file change whose targets are unclear.",
        "Guardrails could not identify every file in the proposed change.",
        "Files could be changed without a verified recovery copy.",
    ),
    "builtin:credential-hunt": (
        "The agent wants to search broadly for credential-related information.",
        "The search scope is not limited to verified project diagnostics.",
        "Private matches could be included in the agent's work.",
    ),
    "builtin:secret-file": (
        "The agent wants to read a potentially sensitive file.",
        "The selected file may hold account or access information.",
        "Its contents could be included in the agent's work.",
    ),
    "builtin:content-prescan": (
        "The agent wants to read potentially confidential content.",
        "Guardrails detected a high-confidence sensitive-content marker.",
        "The content could be included in the agent's work.",
    ),
    "builtin:placeholder-read": (
        "The agent wants to read a cloud-only file.",
        "The local copy may be incomplete or may trigger a download.",
        "The result may be incomplete or may retrieve cloud content.",
    ),
    "builtin:mcp-remove": (
        "The agent wants to remove an item from a connected service.",
        "Removing or unlinking a connected item needs confirmation.",
        "Information in the connected service may no longer be available here.",
    ),
    "builtin:mcp-mutation": (
        "The agent wants to change information in a connected service.",
        "This external change needs your approval before it continues.",
        "The service may create or update an item.",
    ),
    "builtin:git-checkout": (
        "The agent wants to replace uncommitted working-file changes.",
        "This source-control operation can discard local edits.",
        "Uncommitted work may be replaced.",
    ),
    "builtin:git-restore": (
        "The agent wants to restore working files from source control.",
        "Restoring files can discard local edits.",
        "Uncommitted work may be replaced.",
    ),
    "invariant:prestate-unavailable": (
        "The agent wants to change files without a verified recovery copy.",
        "Guardrails could not verify the required pre-change protection.",
        "A failed change might not be safely reversible.",
    ),
}


_ARCHIVE_DENIALS = {
    "builtin:rm", "builtin:find-delete", "builtin:move-null",
    "builtin:pwsh-delete", "builtin:interpreter-delete",
    "builtin:patch-delete", "builtin:git-clean", "builtin:mcp-delete",
}
_DIRECT_DENIALS = {
    "builtin:monitor-opaque", "builtin:mcp-shell-opaque",
    "builtin:unparseable-mutation", "builtin:indirect-mutation",
    "builtin:patch-targets-unknown", "builtin:patch-opaque",
}
_MACHINE_DENIALS = {
    "builtin:dd", "builtin:disk", "builtin:sudo", "builtin:chmod",
}


def _safe_next_step(rule_id: str) -> str:
    """Return closed, actionable recovery copy for a denied operation.

    The instruction is selected only from the trusted rule identifier. Raw
    commands, paths, content, and exception strings never enter this field.
    """
    if rule_id in _ARCHIVE_DENIALS or rule_id in {
            "core.yaml:mcp[0]", "core.yaml:mcp[1]"}:
        return (
            "Use a reversible archive, move, or soft-delete operation for each "
            "explicit target. If the service has no reversible option, leave the "
            "item in place."
        )
    if rule_id in _DIRECT_DENIALS or rule_id == "invariant:prestate-unavailable":
        return (
            "Retry with one direct, file-specific operation that names every target "
            "so Guardrails can verify and protect it."
        )
    if rule_id in {"builtin:decode-pipe", "builtin:download-pipe"}:
        return (
            "Separate retrieval, inspection, and execution into distinct steps; "
            "inspect the content before proposing any execution."
        )
    if rule_id == "builtin:secret-exfil":
        return (
            "Continue without transmitting credential content. Use a destination's "
            "supported credential reference or secret-store integration instead."
        )
    if rule_id == "builtin:sql-drop":
        return "Use a read-only query or a reversible migration plan that preserves existing data."
    if rule_id == "builtin:sql-delete":
        return (
            "Identify the exact records first, then use an archive or soft-delete "
            "workflow with an explicit filter."
        )
    if rule_id in _MACHINE_DENIALS:
        return "Revise the task to avoid privileged, recursive, or machine-wide changes."
    if rule_id == "builtin:git-force":
        return "Review the remote state and use force-with-lease only if replacement is still required."
    if rule_id == "builtin:git-reset-hard":
        return "Preserve the work with a Guardrails snapshot or Git stash before proposing a reset."
    if rule_id in {"builtin:protected-path", "policy:zone"}:
        return (
            "Work on an authorized workspace copy, or ask the user to revise the "
            "access policy before trying again."
        )
    if rule_id == "builtin:gdoc-stub":
        return "Use the Google Drive connector to edit or export the actual cloud document."
    if rule_id == "builtin:placeholder":
        return "Make the file available offline, verify the local copy, and then retry."
    if rule_id == "builtin:agw-impostor":
        return "Use the packaged Guardrails launcher reported at session start."
    if rule_id.startswith("policy:health-"):
        return "Repair or reinstall the Guardrails policy package, verify its health, and retry."
    if ":snippets[" in rule_id:
        return (
            "Remove credential or private-key material and use a secret-store or "
            "environment reference instead."
        )
    return (
        "Propose a narrower, reversible operation with explicit targets that "
        "satisfies the active safety policy."
    )


def build_denial_feedback(decision: GuardrailDecision,
                          approval_outcome: str = "") -> str:
    """Render a denial as useful feedback instead of a dead end.

    A declined approval is deliberately non-retriable so an agent cannot nag by
    immediately presenting the same operation again.
    """
    if approval_outcome in {"cancelled", "denied"}:
        blocked = "The requested operation was not approved."
        next_step = (
            "Do not retry the same operation. Continue without it or propose a "
            "safer alternative that still serves the user's request."
        )
    elif approval_outcome:
        blocked = "Guardrails could not safely obtain approval for the requested operation."
        next_step = (
            "Continue without the operation, or retry later when an approval "
            "provider is available."
        )
    else:
        blocked = decision.reason or "The requested operation did not meet the active safety policy."
        next_step = _safe_next_step(decision.rule_id)
    return (
        f"Blocked: {blocked}\n\n"
        "Result: The requested action did not run; no requested target was changed.\n\n"
        f"Safe next step: {next_step}\n\n"
        "User communication: Briefly explain in plain language why Guardrails "
        "blocked the action and recommend the safest way to continue toward the "
        "user's goal. Do not quote the raw command or expose sensitive values. "
        "Ask the user only when choosing among safe alternatives requires their decision."
    )


def _target_count(evlist) -> int:
    return len({str(path) for ev in evlist for path in ev.paths if path})


def _friendly_targets(decision: GuardrailDecision, evlist) -> tuple[str, ...]:
    """Return only closed category/count labels, never path-derived text."""
    context = decision.presentation_context
    count = _target_count(evlist)
    if context == events.DecisionContext.AGW_ARCHIVE:
        return ("Stored Guardrails recovery copies",)
    if context == events.DecisionContext.AGW_MUTATION:
        return ("Files managed by Guardrails",)
    if context == events.DecisionContext.AGW_UNKNOWN:
        return ("The exact files could not be identified",)
    if context == events.DecisionContext.PATCH_UNKNOWN:
        return ("The exact files could not be identified",)
    if context == events.DecisionContext.RESTORE_FILES:
        return ((f"{count} selected working file" + ("" if count == 1 else "s"),)
                if count else ("Working files selected for restoration",))
    if context == events.DecisionContext.SENSITIVE_READ:
        return ((f"{count} potentially sensitive file" + ("" if count == 1 else "s"),)
                if count else ("Potentially sensitive content",))
    if context == events.DecisionContext.CREDENTIAL_SEARCH:
        return ("Files in the requested search scope",)
    if context == events.DecisionContext.FILE_CHANGE:
        return ((f"{count} selected working file" + ("" if count == 1 else "s"),)
                if count else ("The exact files could not be identified",))
    if context == events.DecisionContext.CONNECTED_SERVICE:
        return ("An item in a connected service",)
    kinds = {ev.kind for ev in evlist}
    if kinds == {events.READ}:
        return ((f"{count} selected file" + ("" if count == 1 else "s"),)
                if count else ("Potentially sensitive content",))
    if kinds & {events.WRITE, events.EDIT}:
        return ((f"{count} selected working file" + ("" if count == 1 else "s"),)
                if count else ("The exact files could not be identified",))
    if kinds == {events.MCP}:
        return ("An item in a connected service",)
    return ("The exact files could not be identified",)


def _copy(decision: GuardrailDecision, evlist) -> tuple[str, str, str, str]:
    mapped = _COPY_BY_RULE.get(decision.rule_id)
    if mapped:
        return (*mapped, "Choose Cancel to make no changes.")
    kinds = {ev.kind for ev in evlist}
    opaque = any(ev.extra.get("opaque") for ev in evlist)
    if opaque:
        return (
            "The agent wants to change files, but Guardrails could not identify which files.",
            "Guardrails could not determine every file this action may affect.",
            "Files may be changed in ways that cannot be shown here.",
            "Choose Cancel to make no changes.",
        )
    if kinds == {events.READ}:
        return (
            "The agent wants to read a potentially sensitive file.",
            "The file may contain private or confidential information.",
            "Its contents may be included in the agent's work.",
            "Choose Cancel to make no changes.",
        )
    if kinds & {events.WRITE, events.EDIT}:
        return (
            "The agent wants to change one or more files.",
            "This change needs your approval before it continues.",
            "Existing file contents may be replaced or updated.",
            "Choose Cancel to make no changes.",
        )
    if kinds == {events.MCP}:
        return (
            "The agent wants to use a connected service.",
            "This service action needs your approval.",
            "Information in the connected service may be read or changed.",
            "Choose Cancel to make no changes.",
        )
    return (
        "The agent wants to perform an operation that needs review.",
        "Guardrails could not confirm that this operation is routine.",
        "Files, applications, or settings may change.",
        "Choose Cancel to make no changes.",
    )


def build_prompt(decision: GuardrailDecision, payload: dict, evlist) -> PromptRequest:
    action, reason, consequence, safeguard = _copy(decision, evlist)
    event_id = str(payload.get("event_id") or payload.get("invocation_id") or
                   payload.get("tool_use_id") or "")
    recommended_allow = (
        decision.rule_id == "builtin:agw-ask"
        and decision.presentation_context in {
            events.DecisionContext.AGW_MUTATION,
            events.DecisionContext.RESTORE_FILES,
        }
    )
    return PromptRequest(
        title="Agent safety check",
        action=action,
        targets=_friendly_targets(decision, evlist),
        reason=reason,
        consequence=consequence,
        safeguard=safeguard,
        event_id=event_id,
        operation_fingerprint=operation_fingerprint(
            payload, evlist, decision.policy_revision
        ),
        policy_revision=decision.policy_revision,
        allow_label=("Allow once (recommended)" if recommended_allow else "Allow once"),
        cancel_label=("Cancel" if recommended_allow else "Cancel (recommended)"),
        default_choice=("allow" if recommended_allow else "cancel"),
    )
