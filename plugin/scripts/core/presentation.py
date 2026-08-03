"""Plain-language presentation for guardrail approval requests."""
from __future__ import annotations

import hashlib
import json
import os
import re

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

_CONNECTOR_ACTION_VERBS = {
    "add", "approve", "assign", "close", "convert", "copy", "create",
    "disable", "edit", "enable", "forward", "grant", "invite", "lock",
    "mark", "merge", "move", "publish", "react", "rename", "reopen",
    "replace", "reply", "resolve", "revoke", "schedule", "send", "set",
    "share", "submit", "unassign", "unlock", "unresolve", "update",
    "upload", "write", "remove", "unlink", "discard", "detach",
}
_CONNECTOR_REMOVE_VERBS = {"remove", "unlink", "discard", "detach"}
_CONNECTOR_NAME_FIELDS = (
    "file_name", "filename", "document_name", "folder_name", "item_name",
    "record_name", "event_name", "channel_name", "target_name", "name",
    "title", "subject", "file_path", "path",
)
_CONNECTOR_ID_FIELDS = (
    "file_id", "document_id", "folder_id", "item_id", "record_id",
    "event_id", "channel_id", "thread_id", "message_id", "id",
)
_SERVICE_LABELS = {
    "github": "GitHub", "gmail": "Gmail", "google_drive": "Google Drive",
    "google_calendar": "Google Calendar", "onedrive": "OneDrive",
    "sharepoint": "SharePoint", "slack": "Slack", "outlook": "Outlook",
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


def _safe_display(value, *, file_name: bool = False) -> str:
    """Render an untrusted path label without exposing raw command/content text."""
    text = str(value or "")
    if file_name:
        text = os.path.basename(text.replace("\\", "/"))
    elif os.path.isabs(text):
        text = os.path.basename(text.rstrip("/\\")) or text
    text = re.sub(r"[\x00-\x1f\x7f]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return "unnamed target"
    return text if len(text) <= 96 else text[:93] + "..."


def _identifier_words(value) -> list[str]:
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(value or ""))
    return [part.lower() for part in re.split(r"[^A-Za-z0-9]+", text) if part]


def _human_identifier(value) -> str:
    words = _identifier_words(value)
    return " ".join(words).title() if words else "Connected Service"


def _connector_labels(tool_input: dict) -> tuple[str, ...]:
    """Select display-safe target identity fields, never payload content."""
    if not isinstance(tool_input, dict):
        return ()
    normalized = {
        "_".join(_identifier_words(key)): value
        for key, value in tool_input.items()
    }
    for key in _CONNECTOR_NAME_FIELDS:
        value = normalized.get(key)
        if not isinstance(value, (str, int, float)) or isinstance(value, bool):
            continue
        label = _safe_display(
            value,
            file_name=key in {"file_name", "filename", "file_path", "path"},
        )
        if label != "unnamed target":
            return (label,)
    for key in _CONNECTOR_ID_FIELDS:
        value = normalized.get(key)
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            continue
        label = _safe_display(value)
        if label == "unnamed target":
            continue
        kind = " ".join(key.split("_")[:-1]).title()
        return ((f"{kind} ID: {label}" if kind else f"ID: {label}"),)
    return ()


def _connector_summary(evlist) -> dict:
    event = next((ev for ev in evlist if ev.kind == events.MCP), None)
    if event is None:
        return {}
    segments = [part for part in str(event.tool or "").split("__") if part]
    service_key = segments[-2].lower() if len(segments) >= 3 else ""
    service = _safe_display(
        _SERVICE_LABELS.get(service_key, _human_identifier(service_key))
    )
    short = segments[-1] if segments else ""
    words = _identifier_words(short)
    action_index = next(
        (index for index, word in enumerate(words) if word in _CONNECTOR_ACTION_VERBS),
        None,
    )
    verb = words[action_index] if action_index is not None else "change"
    object_words = words[action_index + 1:] if action_index is not None else []
    object_words = [word for word in object_words if not re.fullmatch(r"v?\d+", word)]
    object_name = _safe_display(" ".join(object_words) or "item")
    article = "an" if object_name[:1] in "aeiou" else "a"
    tool_input = event.extra.get("input") if isinstance(event.extra, dict) else {}
    return {
        "service": service,
        "verb": verb,
        "object": object_name,
        "operation": f"{verb} {article} {object_name}",
        "labels": _connector_labels(tool_input),
    }


def _detail_labels(decision: GuardrailDecision) -> tuple[str, ...]:
    details = decision.presentation_details or {}
    values = details.get("targets") or []
    file_name = details.get("target_kind") == "file"
    labels = tuple(_safe_display(value, file_name=file_name) for value in values[:4])
    if len(values) > 4:
        labels += (f"and {len(values) - 4} more",)
    return labels


def _natural_list(values: tuple[str, ...]) -> str:
    if not values:
        return "the requested target"
    if len(values) == 1:
        return values[0]
    return ", ".join(values[:-1]) + " and " + values[-1]


def _friendly_targets(decision: GuardrailDecision, evlist) -> tuple[str, ...]:
    """Return sanitized filenames/scopes when the engine supplied exact labels."""
    context = decision.presentation_context
    count = _target_count(evlist)
    labels = _detail_labels(decision)
    target_kind = (decision.presentation_details or {}).get("target_kind")
    if labels and target_kind == "file":
        return tuple(f"File: {label}" for label in labels)
    if labels and target_kind == "search_scope":
        return ("Search scope: " + _natural_list(labels),)
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
        summary = _connector_summary(evlist)
        if summary:
            base = f"{summary['service']} {summary['object']}"
            if summary["labels"]:
                return (base + ": " + _natural_list(summary["labels"]),)
            return (base,)
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
    details = decision.presentation_details or {}
    labels = _detail_labels(decision)
    target_text = _natural_list(labels)
    signal = str(details.get("signal") or "potentially sensitive information")
    trigger = str(details.get("trigger") or "This operation needs confirmation.")
    if details and decision.rule_id == "builtin:credential-hunt":
        return (
            f"The agent wants to search {target_text} for {signal}.",
            trigger,
            "Private matches could be included in the agent's work.",
            "Choose Cancel to keep search results out of the agent's work.",
        )
    if details and decision.rule_id in {
            "builtin:secret-file", "builtin:content-prescan",
            "builtin:placeholder-read"}:
        return (
            f"The agent wants to read {target_text}, which may contain {signal}.",
            trigger,
            "The file's contents could be included in the agent's work.",
            "Choose Cancel to keep the content out of the agent's work.",
        )
    if decision.rule_id in {"builtin:mcp-mutation", "builtin:mcp-remove"}:
        summary = _connector_summary(evlist)
        if summary:
            consequence = (
                f"{summary['service']} may remove or unlink the specified "
                f"{summary['object']}."
                if summary["verb"] in _CONNECTOR_REMOVE_VERBS else
                f"{summary['service']} may create or change the specified "
                f"{summary['object']}."
            )
            return (
                f"The agent wants to {summary['operation']} in {summary['service']}.",
                f"This {summary['service']} operation needs your approval before it continues.",
                consequence,
                "Choose Cancel to leave the connected service unchanged.",
            )
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
            "Choose Cancel to keep the content out of the agent's work.",
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
