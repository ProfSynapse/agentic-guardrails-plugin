"""Plan the complete local target set for operations that may change files."""
from __future__ import annotations

from dataclasses import dataclass, field
import os
import re

from . import events, workflows
from .shellparse import ParseUncertain, extract_commands


_LOCAL_MUTATION = re.compile(
    r"(?i)(?:^|[;&|]\s*)(?:rm|del|erase|rmdir|remove-item|mkdir|touch|new-item|"
    r"sed\s+-i|perl\s+-p?i|git\s+(?:clean|reset|checkout|restore)|"
    r"set-content|out-file|copy-item|move-item|copy|move|ren|rename|"
    r"cp|mv|install|tee|dd|truncate)\b"
)
_OVERWRITE_REDIRECT = re.compile(r"(?<!>)>(?!>)")
_NULL_REDIRECT = re.compile(
    r"(?i)(?:\d*|&)?>\|?\s*(?:\$null|nul:?|/dev/null)(?=$|[\s;&|])"
)
_MUTATION_WORDS = {
    "add", "copy", "create", "delete", "edit", "move", "remove", "rename",
    "replace", "truncate", "update", "upload", "write",
}
_LOCAL_MUTATION_NAMES = {
    "rm", "del", "erase", "rmdir", "remove-item", "mkdir", "md", "ni",
    "touch", "new-item", "set-content", "out-file", "copy-item", "move-item",
    "copy", "move", "ren", "rename", "cp", "mv", "install", "tee", "dd",
    "truncate",
}
_SCRIPT_INTERPRETERS = {
    "python", "python3", "pythonw", "py", "node", "nodejs", "ruby", "perl", "php",
    "powershell", "pwsh", "bash", "sh", "zsh", "ksh", "dash", "ash",
}
_VERSIONED_SCRIPT_INTERPRETER = re.compile(
    r"^(?:pythonw?|node(?:js)?|ruby|perl|php|powershell|pwsh|bash|zsh|ksh)"
    r"\d+(?:\.\d+)*$"
)
_SCRIPT_SUFFIXES = {
    ".py", ".js", ".mjs", ".cjs", ".rb", ".pl", ".php",
    ".ps1", ".psm1", ".sh", ".bash",
}
_SCRIPT_WRITE_EVIDENCE = re.compile(
    r"(?ix)(?:"
    r"writeFile(?:Sync)?\s*\(|appendFile(?:Sync)?\s*\(|createWriteStream\s*\(|"
    r"\.write_(?:text|bytes)\s*\(|\.to_excel\s*\(|"
    r"\bFile\.write\s*\(|"
    r"\bFile\.open\s*\([^\n]{0,300},\s*['\"](?:w|a|x|r\+|w\+|a\+)|"
    r"\bfile_put_contents\s*\(|"
    r"\bopen\s*\([^\n]{0,300},\s*['\"](?:w|a|x|r\+|w\+|a\+)"
    r"|\.save\s*\("
    r"|\b(?:os\.replace|os\.rename|shutil\.(?:copy|copy2|move))\s*\("
    r"|\.xlsx\.write(?:File|Buffer)?\s*\(|@oai/artifact-tool"
    r"|\b(?:Set-Content|Add-Content|Out-File|New-Item|Copy-Item|Move-Item|"
    r"Remove-Item)\b"
    r"|\[(?:System\.)?IO\.(?:File|Directory)\]::(?:Write|Create|Copy|Move|Delete)"
    r"|(?:^|[;\n])\s*(?:cp|mv|touch|mkdir|rm|install|tee|truncate)\b"
    r"|(?<!>)>(?!>)\s*[^\s&|;]+"
    r")"
)


def _unquoted_surface(command: str) -> str:
    """Preserve executable syntax while blanking quoted data arguments."""
    out = []
    quote = ""
    escaped = False
    for char in str(command or ""):
        if quote:
            if escaped:
                escaped = False
            elif char in {"\\", "`"} and quote == '"':
                escaped = True
            elif char == quote:
                quote = ""
            out.append(" ")
        elif char in {"'", '"'}:
            quote = char
            out.append(" ")
        else:
            out.append(char)
    return "".join(out)


def _looks_locally_mutating(command: str, dialect: str = None) -> bool:
    """Detect mutation command heads without treating quoted search data as code."""
    try:
        parsed = extract_commands(command, dialect=dialect)
    except ParseUncertain:
        return bool(_LOCAL_MUTATION.search(_unquoted_surface(command)))
    for cmd in parsed.commands:
        name = cmd.name
        if name in _LOCAL_MUTATION_NAMES:
            return True
        if name == "git" and len(cmd.argv) > 1 \
                and cmd.argv[1].lower() in {"clean", "reset", "checkout", "restore"}:
            return True
        if name == "sed" and any(arg == "-i" or arg.startswith("-i") for arg in cmd.argv[1:]):
            return True
        if name == "perl" and any(arg.startswith("-") and "i" in arg[1:]
                                  for arg in cmd.argv[1:]):
            return True
    return False


def _is_script_interpreter(name: str) -> bool:
    return name in _SCRIPT_INTERPRETERS or bool(
        _VERSIONED_SCRIPT_INTERPRETER.fullmatch(name)
    )


def _write_capable_script(command: str, cwd: str, dialect: str = None) -> str:
    """Return a bounded local script path when static text shows file writes."""
    try:
        parsed = extract_commands(command, dialect=dialect)
    except ParseUncertain:
        return ""
    for cmd in parsed.commands:
        if not _is_script_interpreter(cmd.name):
            continue
        script = ""
        for token in cmd.argv[1:]:
            lowered = token.lower()
            if lowered in {"-c", "-e", "--eval", "--check", "-m"}:
                break
            if token.startswith("-"):
                continue
            if os.path.splitext(lowered)[1] in _SCRIPT_SUFFIXES:
                script = token
                break
        if not script or any(char in script for char in "$`*?[]{}()"):
            continue
        path = os.path.abspath(os.path.join(cwd or os.getcwd(), script)) \
            if not os.path.isabs(script) else os.path.abspath(script)
        try:
            if os.path.getsize(path) > 1024 * 1024:
                continue
            with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
                source = handle.read(1024 * 1024 + 1)
        except OSError:
            continue
        if _SCRIPT_WRITE_EVIDENCE.search(source):
            return path
    return ""


def _trusted_agw_help(
    command: str,
    cwd: str,
    plugin_root: str,
    dialect: str = None,
) -> bool:
    """Recognize only the active package's read-only Python help entrypoint."""
    if not plugin_root:
        return False
    try:
        parsed = extract_commands(command, dialect=dialect)
    except ParseUncertain:
        return False
    if len(parsed.commands) != 1 or parsed.flags:
        return False
    cmd = parsed.commands[0]
    if cmd.name != "py" and not re.fullmatch(
            r"pythonw?(?:\d+(?:\.\d+)*)?", cmd.name):
        return False
    script_index = -1
    for index, token in enumerate(cmd.argv[1:], 1):
        lowered = token.lower()
        if lowered in {"-c", "-e", "--eval", "-m"}:
            return False
        if token.startswith("-"):
            continue
        if os.path.splitext(lowered)[1] == ".py":
            script_index = index
            break
    if script_index < 0:
        return False
    raw_script = cmd.argv[script_index]
    if any(char in raw_script for char in "$`*?[]{}()"):
        return False
    script = os.path.realpath(
        raw_script if os.path.isabs(raw_script)
        else os.path.join(cwd or os.getcwd(), raw_script)
    )
    root = os.path.realpath(plugin_root)
    expected = os.path.realpath(os.path.join(root, "scripts", "agw", "agw.py"))
    try:
        trusted = os.path.commonpath([script, root]) == root \
            and os.path.normcase(script) == os.path.normcase(expected)
    except ValueError:
        trusted = False
    if not trusted:
        return False
    args = cmd.argv[script_index + 1:]
    return (
        any(value in {"-h", "--help"} for value in args)
        and "--agw-argv-b64" not in args
    )


def _matching_trusted_workflow(command: str, cwd: str, dialect: str = None) -> str:
    """Find a valid integration only to produce a compact remediation hint."""
    try:
        parsed = extract_commands(command, dialect=dialect)
    except ParseUncertain:
        return ""
    for cmd in parsed.commands:
        if not _is_script_interpreter(cmd.name):
            continue
        try:
            workflow_id = workflows.matching_workflow(cmd.argv, cwd or os.getcwd())
        except (OSError, workflows.WorkflowError):
            continue
        if workflow_id:
            return workflow_id
    return ""


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


def plan(evlist, clobber_resolver, plugin_root: str = "") -> MutationPlan:
    """Return exact canonical targets, or an explicit incomplete plan."""
    result = MutationPlan()
    seen = set()
    covered_without_target = False

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
                trusted_help = _trusted_agw_help(
                    ev.command, ev.cwd, plugin_root, dialect=dialect
                )
                opaque_script = "" if trusted_help else _write_capable_script(
                    ev.command, ev.cwd, dialect=dialect
                )
                if opaque_script:
                    result.mutating = True
                    workflow_id = _matching_trusted_workflow(
                        ev.command, ev.cwd, dialect=dialect
                    )
                    if workflow_id:
                        raise ValueError(
                            "the script has a trusted output contract but direct "
                            "interpreter execution cannot apply it; use "
                            f"`agw run --workflow {workflow_id} -- <command>`"
                        )
                    raise ValueError(
                        "the script may write files but has no pre-execution output "
                        "contract; use `agw run --output <path> --expected-hash <hash> "
                        "-- <command>`, or install a reviewed reusable contract with "
                        "`agw workflow trust --help`"
                    )
                surface = _NULL_REDIRECT.sub("", _unquoted_surface(ev.command))
                looks_mutating = bool(targets) or bool(_OVERWRITE_REDIRECT.search(surface)) \
                    or _looks_locally_mutating(ev.command, dialect=dialect)
                if not getattr(targets, "complete", True):
                    result.mutating = True
                    raise ValueError(getattr(targets, "reason", "") or
                                     "PowerShell target binding was incomplete")
                if looks_mutating:
                    result.mutating = True
                if targets:
                    add_paths(targets, ev.cwd)
                elif looks_mutating and getattr(targets, "covered", False):
                    covered_without_target = True
                elif looks_mutating:
                    raise ValueError(
                        "the command may change local files, but every target could not be identified"
                    )
                continue
            if ev.kind == events.MCP:
                # This planner protects local filesystem targets by taking
                # pre-change recovery copies. Connected-service actions do not
                # have local files to snapshot; the engine applies their own
                # consent/CRUA policy instead. MCP shell tools are routed to
                # EXEC before reaching this planner, so local mutations issued
                # through a connector still receive normal preimage coverage.
                continue
            if ev.kind == events.OTHER and (_tool_words(ev.tool) & _MUTATION_WORDS):
                result.mutating = True
                raise ValueError(
                    "this operation may change files, but its targets are not available to guardrails"
                )
    except (OSError, TypeError, ValueError) as exc:
        result.complete = False
        result.reason = str(exc) or "every mutation target could not be identified"

    if result.mutating and result.complete and not result.targets \
            and not covered_without_target:
        result.complete = False
        result.reason = "the operation may change data, but no exact recovery target was available"
    return result
