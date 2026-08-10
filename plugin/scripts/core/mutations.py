"""Plan the complete local target set for operations that may change files."""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
import hashlib
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

_HIGH_CONFIDENCE_PYTHON_CALLS = {
    "path.write_text", "path.write_bytes", "path.touch",
    "os.replace", "os.rename", "shutil.copy", "shutil.copy2", "shutil.move",
}
_HIGH_CONFIDENCE_PYTHON_METHODS = {
    "write_text", "write_bytes", "to_excel", "touch",
}


@dataclass(frozen=True)
class ScriptWriteEvidence:
    """Bounded, display-safe evidence that a local script may write files."""

    path: str
    primitive: str
    line: int
    confidence: str
    sha256: str

    def details(self) -> dict:
        return {
            "path": self.path,
            "primitive": self.primitive,
            "line": self.line,
            "confidence": self.confidence,
            "sha256": self.sha256,
        }


def _python_call_name(node) -> str:
    parts = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts)).lower()


def _literal_string(node) -> str:
    return node.value if isinstance(node, ast.Constant) \
        and isinstance(node.value, str) else ""


def _python_write_evidence(source: str, path: str, digest: str):
    """Return syntax-aware Python evidence, ignoring comments and inert strings."""
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return None
    imported_openpyxl = any(
        isinstance(node, (ast.Import, ast.ImportFrom))
        and any(
            (alias.name if isinstance(node, ast.Import) else node.module or "")
            .lower().startswith("openpyxl")
            for alias in node.names
        )
        for node in ast.walk(tree)
    )
    for node in sorted(
            (item for item in ast.walk(tree) if isinstance(item, ast.Call)),
            key=lambda item: (getattr(item, "lineno", 0), getattr(item, "col_offset", 0))):
        name = _python_call_name(node.func)
        method = name.rsplit(".", 1)[-1]
        if name in {"exec", "eval"} and node.args:
            dynamic_source = _literal_string(node.args[0])
            dynamic_match = _SCRIPT_WRITE_EVIDENCE.search(dynamic_source)
            if dynamic_match:
                primitive = " ".join(dynamic_match.group(0).strip().split())[:120]
                return ScriptWriteEvidence(
                    path, f"{name}({primitive})", node.lineno, "high", digest,
                )
        builtin_open = isinstance(node.func, ast.Name) and node.func.id == "open"
        method_open = isinstance(node.func, ast.Attribute) and node.func.attr == "open"
        if builtin_open or method_open:
            mode_node = None
            if builtin_open and len(node.args) > 1:
                mode_node = node.args[1]
            elif method_open and node.args:
                mode_node = node.args[0]
            mode_node = next(
                (item.value for item in node.keywords if item.arg == "mode"),
                mode_node,
            )
            mode = _literal_string(mode_node)
            if mode and any(char in mode for char in "wax+"):
                return ScriptWriteEvidence(
                    path, f"{name}(mode={mode!r})", node.lineno, "high", digest,
                )
        if name in _HIGH_CONFIDENCE_PYTHON_CALLS \
                or method in _HIGH_CONFIDENCE_PYTHON_METHODS:
            return ScriptWriteEvidence(
                path, name or method, node.lineno, "high", digest,
            )
        if method == "save":
            confidence = "high" if imported_openpyxl else "low"
            return ScriptWriteEvidence(
                path, name or ".save", node.lineno, confidence, digest,
            )
    return None


def _mask_shell_heredocs(source: str) -> str:
    """Blank literal shell heredoc bodies without changing source offsets."""
    lines = source.splitlines(keepends=True)
    delimiter = ""
    strip_tabs = False
    literal = False
    result = []
    heredoc = re.compile(
        r"<<(?P<tabs>-?)\s*(?P<quote>['\"]?)(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
        r"(?P=quote)"
    )
    for line in lines:
        if delimiter:
            candidate = line.rstrip("\r\n")
            compared = candidate.lstrip("\t") if strip_tabs else candidate
            masked_line = [char if char in "\r\n" else " " for char in line]
            if not literal:
                index = 0
                while index < len(line):
                    if line.startswith("$(", index):
                        depth = 1
                        end = index + 2
                        while end < len(line) and depth:
                            if line.startswith("$(", end):
                                depth += 1
                                end += 2
                                continue
                            if line[end] == ")":
                                depth -= 1
                            end += 1
                        for position in range(index, min(end, len(line))):
                            masked_line[position] = line[position]
                        index = end
                        continue
                    if line[index] == "`":
                        end = line.find("`", index + 1)
                        if end >= 0:
                            for position in range(index, end + 1):
                                masked_line[position] = line[position]
                            index = end + 1
                            continue
                    index += 1
            result.append("".join(masked_line))
            if compared == delimiter:
                delimiter = ""
                strip_tabs = False
                literal = False
            continue
        result.append(line)
        match = heredoc.search(line)
        if match:
            delimiter = match.group("name")
            strip_tabs = bool(match.group("tabs"))
            literal = bool(match.group("quote"))
    return "".join(result)


def _mask_noncode(source: str, suffix: str) -> str:
    """Blank comments and quoted data while preserving offsets and newlines."""
    slash_comments = suffix in {".js", ".mjs", ".cjs", ".php"}
    hash_comments = suffix in {
        ".rb", ".pl", ".php", ".ps1", ".psm1", ".sh", ".bash",
    }
    block_start, block_end = (
        ("<#", "#>") if suffix in {".ps1", ".psm1"}
        else (("=begin", "=end") if suffix == ".rb"
              else (("/*", "*/") if slash_comments else ("", "")))
    )
    quote_chars = {"'", '"'} | ({"`"} if suffix in {".js", ".mjs", ".cjs"} else set())
    mask_source = _mask_shell_heredocs(source) \
        if suffix in {".sh", ".bash"} else source
    chars = list(mask_source)
    output = list(mask_source)
    quote = ""
    line_comment = False
    block_comment = False
    index = 0

    def blank(position: int):
        if chars[position] not in "\r\n":
            output[position] = " "

    while index < len(chars):
        if line_comment:
            if chars[index] in "\r\n":
                line_comment = False
            else:
                blank(index)
            index += 1
            continue
        if block_comment:
            if block_end and mask_source.startswith(block_end, index):
                for offset in range(len(block_end)):
                    blank(index + offset)
                index += len(block_end)
                block_comment = False
            else:
                blank(index)
                index += 1
            continue
        if quote:
            char = chars[index]
            interpolation = ""
            closing = ""
            if quote == '"' and suffix in {".ps1", ".psm1", ".sh", ".bash"} \
                    and mask_source.startswith("$(", index):
                interpolation, closing = "$(", ")"
            elif quote == '"' and suffix == ".rb" \
                    and mask_source.startswith("#{", index):
                interpolation, closing = "#{", "}"
            elif quote == "`" and suffix in {".js", ".mjs", ".cjs"} \
                    and mask_source.startswith("${", index):
                interpolation, closing = "${", "}"
            if interpolation:
                depth = 1
                end = index + len(interpolation)
                while end < len(chars) and depth:
                    if mask_source.startswith(interpolation, end):
                        depth += 1
                        end += len(interpolation)
                        continue
                    if chars[end] == closing:
                        depth -= 1
                    end += 1
                index = end
                continue
            blank(index)
            if suffix in {".ps1", ".psm1"} and quote == "'" \
                    and char == "'" and index + 1 < len(chars) \
                    and chars[index + 1] == "'":
                blank(index + 1)
                index += 2
                continue
            escape = "`" if suffix in {".ps1", ".psm1"} else "\\"
            if char == escape and index + 1 < len(chars):
                blank(index + 1)
                index += 2
                continue
            if char == quote:
                quote = ""
            index += 1
            continue
        if block_start and mask_source.startswith(block_start, index):
            for offset in range(len(block_start)):
                blank(index + offset)
            index += len(block_start)
            block_comment = True
            continue
        if slash_comments and mask_source.startswith("//", index):
            blank(index)
            blank(index + 1)
            index += 2
            line_comment = True
            continue
        if hash_comments and chars[index] == "#":
            blank(index)
            index += 1
            line_comment = True
            continue
        if chars[index] in quote_chars:
            quote = chars[index]
            blank(index)
        index += 1
    return "".join(output)


def _dynamic_noncode_execution(masked: str, suffix: str) -> bool:
    markers = {
        ".js": r"\b(?:eval|Function)\s*\(",
        ".mjs": r"\b(?:eval|Function)\s*\(",
        ".cjs": r"\b(?:eval|Function)\s*\(",
        ".rb": r"\beval\b",
        ".pl": r"\beval\b",
        ".php": r"\beval\s*\(",
        ".ps1": r"(?i)\bInvoke-Expression\b",
        ".psm1": r"(?i)\bInvoke-Expression\b",
        ".sh": r"\beval\b",
        ".bash": r"\beval\b",
    }
    marker = markers.get(suffix, "")
    return bool(marker and re.search(marker, masked))


def _dynamic_shell_evidence(source: str, path: str, digest: str):
    match = re.search(
        r"(?i)\b(?:cp|mv|touch|mkdir|rm|install|tee|truncate)\b", source,
    )
    if not match:
        return None
    return ScriptWriteEvidence(
        path, match.group(0), source.count("\n", 0, match.start()) + 1,
        "high", digest,
    )


def _regex_write_evidence(source: str, path: str, digest: str,
                          scan_source: str = ""):
    scanned = scan_source if scan_source else source
    match = _SCRIPT_WRITE_EVIDENCE.search(scanned)
    if not match:
        return None
    matched_source = source[match.start():match.end()]
    primitive = " ".join(matched_source.strip().split())[:120]
    confidence = "low" if re.search(r"(?i)\.save\s*\(", matched_source) else "high"
    return ScriptWriteEvidence(
        path, primitive, source.count("\n", 0, match.start()) + 1,
        confidence, digest,
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


def _write_capable_script(command: str, cwd: str,
                          dialect: str = None) -> ScriptWriteEvidence | None:
    """Return bounded source evidence when a local script may write files."""
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
            with open(path, "rb") as handle:
                raw = handle.read(1024 * 1024 + 1)
        except OSError:
            continue
        source = raw.decode("utf-8-sig", "replace")
        digest = hashlib.sha256(raw).hexdigest()
        if os.path.splitext(path)[1].lower() == ".py":
            evidence = _python_write_evidence(source, path, digest)
            if evidence:
                return evidence
            # Invalid or dynamically generated Python remains reviewable rather
            # than silently bypassing lexical evidence.
            try:
                ast.parse(source, filename=path)
            except SyntaxError:
                evidence = _regex_write_evidence(source, path, digest)
                if evidence:
                    return ScriptWriteEvidence(
                        evidence.path, evidence.primitive, evidence.line,
                        "low", evidence.sha256,
                    )
            continue
        suffix = os.path.splitext(path)[1].lower()
        masked = _mask_noncode(source, suffix)
        evidence = _regex_write_evidence(
            source, path, digest, scan_source=masked,
        )
        if not evidence and _dynamic_noncode_execution(masked, suffix):
            dynamic = _regex_write_evidence(source, path, digest)
            if dynamic:
                evidence = ScriptWriteEvidence(
                    dynamic.path, dynamic.primitive, dynamic.line,
                    "high", dynamic.sha256,
                )
        if not evidence and suffix in {".sh", ".bash"} \
                and ("$(" in masked or "`" in masked):
            evidence = _dynamic_shell_evidence(masked, path, digest)
        if evidence:
            return evidence
    return None


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


def matching_trusted_workflows(command: str, cwd: str,
                               dialect: str = None) -> list[str]:
    """Find exact authenticated integrations for one literal script command."""
    try:
        parsed = extract_commands(command, dialect=dialect)
    except ParseUncertain:
        return []
    if len(parsed.commands) != 1 or parsed.flags:
        return []
    cmd = parsed.commands[0]
    if not _is_script_interpreter(cmd.name):
        return []
    try:
        return workflows.matching_workflows(cmd.argv, cwd or os.getcwd())
    except (OSError, workflows.WorkflowError):
        return []


def routable_trusted_workflows(command: str, cwd: str,
                               dialect: str = None) -> list[str]:
    """Return exact workflows only when the direct script has write evidence."""
    if not _write_capable_script(command, cwd, dialect=dialect):
        return []
    return matching_trusted_workflows(command, cwd, dialect=dialect)


@dataclass
class MutationPlan:
    targets: list[str] = field(default_factory=list)
    mutating: bool = False
    complete: bool = True
    reason: str = ""
    review_required: bool = False
    evidence: dict = field(default_factory=dict)


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
                opaque_script = None if trusted_help else _write_capable_script(
                    ev.command, ev.cwd, dialect=dialect
                )
                if opaque_script:
                    result.mutating = True
                    result.evidence = opaque_script.details()
                    workflow_ids = matching_trusted_workflows(
                        ev.command, ev.cwd, dialect=dialect
                    )
                    evidence_label = (
                        f"{opaque_script.primitive} at {opaque_script.path}:"
                        f"{opaque_script.line} (source SHA-256 {opaque_script.sha256})"
                    )
                    if len(workflow_ids) == 1:
                        raise ValueError(
                            "the script has a trusted output contract but direct "
                            "interpreter execution cannot apply it; use "
                            f"`agw run --workflow {workflow_ids[0]} -- <command>`; "
                            f"write evidence: {evidence_label}"
                        )
                    if len(workflow_ids) > 1:
                        raise ValueError(
                            "multiple trusted output contracts match this script; "
                            "choose one with `agw workflow match -- <command>`; "
                            f"candidates: {', '.join(workflow_ids)}; write evidence: "
                            f"{evidence_label}"
                        )
                    if opaque_script.confidence == "low":
                        result.review_required = True
                        raise ValueError(
                            "ambiguous write-like source evidence needs one-run "
                            f"review: {evidence_label}. If the invocation writes, use "
                            "`agw run --output <path> --expected-hash <hash> -- "
                            "<command>` or a reviewed workflow"
                        )
                    raise ValueError(
                        f"the script may write files ({evidence_label}) but has no "
                        "pre-execution output "
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
