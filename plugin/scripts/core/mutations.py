"""Plan the complete local target set for operations that may change files."""
from __future__ import annotations

from dataclasses import dataclass, field
import os
import re

from . import events


_LOCAL_MUTATION = re.compile(
    r"(?i)(?:^|[;&|]\s*)(?:rm|del|erase|rmdir|remove-item|mkdir|touch|new-item|"
    r"sed\s+-i|perl\s+-p?i|git\s+(?:clean|reset|checkout|restore)|"
    r"set-content|out-file|copy-item|move-item|copy|move|ren|rename|"
    r"cp|mv|install|tee|dd|truncate)\b"
)
_OVERWRITE_REDIRECT = re.compile(r"(?<!>)>(?!>)")
_MUTATION_WORDS = {
    "add", "copy", "create", "delete", "edit", "move", "remove", "rename",
    "replace", "truncate", "update", "upload", "write",
}


@dataclass
class MutationPlan:
    targets: list[str] = field(default_factory=list)
    mutating: bool = False
    complete: bool = True
    reason: str = ""


def _canonical(path: str, cwd: str) -> str:
    raw = str(path or "").strip()
    if not raw or "\x00" in raw:
        raise ValueError("a target path is missing or invalid")
    raw = os.path.expanduser(raw.replace("\\", os.sep))
    if any(ch in raw for ch in "*?["):
        raise ValueError("a target path contains a wildcard")
    if not os.path.isabs(raw):
        if not cwd:
            raise ValueError("a relative target has no working folder")
        raw = os.path.join(cwd, raw)
    return os.path.normcase(os.path.realpath(os.path.abspath(raw)))


def _tool_words(name: str) -> set[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(name or ""))
    return set(re.findall(r"[a-z]+", spaced.lower()))


def plan(evlist, clobber_resolver) -> MutationPlan:
    """Return exact canonical targets, or an explicit incomplete plan."""
    result = MutationPlan()
    seen = set()

    def add_paths(paths, cwd):
        for path in paths:
            canonical = _canonical(path, cwd)
            if canonical not in seen:
                seen.add(canonical)
                result.targets.append(canonical)

    try:
        for ev in evlist:
            if ev.kind in (events.WRITE, events.EDIT):
                result.mutating = True
                if not ev.paths:
                    raise ValueError("the editing operation did not identify a file")
                add_paths(ev.paths, ev.cwd)
                continue
            if ev.extra.get("apply_patch") and ev.extra.get("opaque"):
                result.mutating = True
                raise ValueError("the patch could not be read well enough to identify every file")
            if ev.extra.get("delete"):
                result.mutating = True
                if not ev.paths:
                    raise ValueError("the deletion did not identify a file")
                add_paths(ev.paths, ev.cwd)
                continue
            if ev.kind == events.EXEC:
                dialect = "powershell" if ev.tool.lower() in {"powershell", "pwsh"} else None
                targets = clobber_resolver(
                    ev.command, ev.cwd, include_absent=True, dialect=dialect
                )
                looks_mutating = bool(targets) or bool(_OVERWRITE_REDIRECT.search(ev.command or "")) \
                    or bool(_LOCAL_MUTATION.search(ev.command or ""))
                if not getattr(targets, "complete", True):
                    result.mutating = True
                    raise ValueError(getattr(targets, "reason", "") or
                                     "PowerShell target binding was incomplete")
                if looks_mutating:
                    result.mutating = True
                if targets:
                    add_paths(targets, ev.cwd)
                elif looks_mutating:
                    raise ValueError(
                        "the command may change local files, but every target could not be identified"
                    )
                continue
            if ev.kind == events.MCP and (_tool_words(ev.tool) & _MUTATION_WORDS):
                result.mutating = True
                raise ValueError(
                    "this connected-service operation changes data outside the local recovery store"
                )
            if ev.kind == events.OTHER and (_tool_words(ev.tool) & _MUTATION_WORDS):
                result.mutating = True
                raise ValueError(
                    "this operation may change files, but its targets are not available to guardrails"
                )
    except (OSError, TypeError, ValueError) as exc:
        result.complete = False
        result.reason = str(exc) or "every mutation target could not be identified"

    if result.mutating and result.complete and not result.targets:
        result.complete = False
        result.reason = "the operation may change data, but no exact recovery target was available"
    return result
