"""Opt-in action contracts for structured connector calls.

Inspired by OpenAPPA's explicit contracts and per-action attention requirements.
Independent implementation: no APPA runtime or copied upstream source. These
checks supplement the engine; a contract never authorizes an existing denial.
"""
from __future__ import annotations

from .events import ASK, DENY, MCP, Decision, DecisionContext

_EFFECTS = {"read", "draft", "edit", "send", "share", "publish", "admin", "blocked"}
_REVIEW = {"send", "share", "publish", "admin"}


def _names(value):
    return (isinstance(value, list)
            and all(isinstance(v, str) and v and v.isprintable() for v in value)
            and len(value) == len(set(value)))


def validate(config):
    """Reject typos/unsupported fields instead of silently widening authority."""
    if not isinstance(config, dict) or set(config) != {"version", "unmatched", "tools"}:
        raise ValueError("action_contracts requires version, unmatched and tools")
    if type(config["version"]) is not int or config["version"] != 1:
        raise ValueError("unsupported action contract version")
    if config["unmatched"] not in ("deny", "defer"):
        raise ValueError("invalid unmatched action")
    if not isinstance(config["tools"], dict):
        raise ValueError("action contract tools must be a mapping")
    for tool, rule in config["tools"].items():
        if (not isinstance(tool, str) or not tool.startswith("mcp__")
                or not tool.isprintable() or any(c in tool for c in "*?[]")):
            raise ValueError("action contracts require exact MCP tool names")
        if not isinstance(rule, dict) or set(rule) != {"effect", "required", "arguments"}:
            raise ValueError("contract requires effect, required and arguments")
        if not isinstance(rule["effect"], str) or rule["effect"] not in _EFFECTS:
            raise ValueError("invalid action effect")
        if not _names(rule["required"]) or not _names(rule["arguments"]):
            raise ValueError("argument names must be unique strings")
        if not set(rule["required"]) <= set(rule["arguments"]):
            raise ValueError("required arguments must be declared")


def evaluate(event, settings):
    """Inspect config, never accept action/approval declarations from tool input.

    Arguments are an exact top-level envelope, not semantic validation of values.
    A broker must still validate values, display them and mediate actual effects.
    """
    if event.kind != MCP or "action_contracts" not in settings:
        return Decision()
    config = settings["action_contracts"]
    try:
        validate(config)
    except (TypeError, ValueError):
        return Decision(DENY, "Action contracts could not be validated.",
                        "action-contract:invalid")
    rule = config["tools"].get(event.tool)
    if rule is None:
        if config["unmatched"] == "deny":
            return Decision(DENY, "No reviewed contract exists for this connector tool.",
                            "action-contract:unmatched")
        return Decision()
    data = event.extra.get("input") if isinstance(event.extra, dict) else None
    if (not isinstance(data, dict) or not set(rule["required"]) <= set(data)
            or not set(data) <= set(rule["arguments"])):
        return Decision(DENY, "Tool arguments do not match the reviewed contract.",
                        "action-contract:arguments")
    if rule["effect"] == "blocked":
        return Decision(DENY, "This action is forbidden by its contract.",
                        "action-contract:blocked")
    if rule["effect"] in _REVIEW:
        return Decision(
            ASK, "This action requires fresh human review of the exact operation.",
            "action-contract:review", fresh_approval=True,
            presentation_context=DecisionContext.CONNECTED_SERVICE,
        )
    # No permission grant: preserve existing recovery, deletion and access rules.
    return Decision()
