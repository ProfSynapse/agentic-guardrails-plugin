"""Shell-aware command extraction.

Parses a Bash command line into the list of simple commands it would execute,
recursing into command substitution, `bash -c` strings, xargs, and
find -exec. Anything we cannot confidently parse raises ParseUncertain and
the engine fails closed to ASK.

This is accident-prevention, not a security boundary (the OS sandbox is the
boundary). The goal is that no destructive command reaches `allow` by hiding
inside shell plumbing.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

MAX_DEPTH = 6

# Wrappers that pass through to the real command. Mirrors Claude Code's own
# strip list; env-runners (npx, docker) are deliberately NOT stripped — rules
# must name them.
_TRANSPARENT = {"nohup", "nice", "stdbuf", "time", "command", "builtin", "env", "setsid"}
_SHELLS = {"bash", "sh", "zsh", "ksh", "dash", "ash"}


class ParseUncertain(Exception):
    """Raised when the command can't be confidently decomposed."""


@dataclass
class SimpleCommand:
    argv: list
    raw: str = ""

    @property
    def name(self) -> str:
        """Basename of argv[0], lowered — '/bin/RM' -> 'rm'."""
        if not self.argv:
            return ""
        head = self.argv[0]
        return head.rsplit("/", 1)[-1].lower()

    def joined(self) -> str:
        return " ".join(self.argv)


@dataclass
class ParseResult:
    commands: list = field(default_factory=list)   # list[SimpleCommand]
    flags: set = field(default_factory=set)        # see FLAG_* below

FLAG_EVAL = "eval"                    # eval / source of dynamic strings
FLAG_INDIRECT = "indirect-command"    # command name comes from a variable/substitution
FLAG_DECODE_PIPE = "decode-pipe"      # base64/xxd/openssl output piped into a shell
FLAG_DOWNLOAD_PIPE = "download-pipe"  # curl/wget piped into a shell
FLAG_SUBSTITUTION = "substitution"    # contained $(...) or backticks (also recursed)

_DECODERS = {"base64", "base32", "xxd", "openssl"}
_DOWNLOADERS = {"curl", "wget"}

_SUBST_RE = re.compile(r"\$\(((?:[^()]|\([^()]*\))*)\)|`([^`]*)`")
_HEREDOC_RE = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?\n(.*?)\n\1", re.DOTALL)

# Truncating redirects (`>`, `>|`, fd-prefixed `1>`/`&>`) and their target.
# Deliberately NOT `>>` (append: no data loss). Best-effort, for snapshotting
# only — a false positive just snapshots a file that wasn't clobbered (cheap,
# deduped); a miss is the cost we avoid by biasing toward matching.
_REDIR_TARGET_RE = re.compile(
    r"""(?:^|[^>\d&])(?:\d*|&)>\|?\s*("[^"]+"|'[^']+'|[^\s;|&<>()]+)""")


def redirect_targets(command: str) -> list:
    """Files a command would truncate via `>`/`>|` redirection (not `>>`)."""
    s = _HEREDOC_RE.sub(" ", command)
    s = _SUBST_RE.sub(" ", s)
    s = re.sub(r">>", "  ", s)  # drop appends before scanning for truncates
    out = []
    for m in _REDIR_TARGET_RE.finditer(s):
        tok = m.group(1).strip("\"'")
        if tok and not tok.startswith("/dev/") and tok != "SUBST_OUT":
            out.append(tok)
    return out


def extract_commands(command: str, depth: int = 0) -> ParseResult:
    if depth > MAX_DEPTH:
        raise ParseUncertain("substitution nesting too deep")
    result = ParseResult()

    # Pull out heredoc bodies so shlex doesn't choke; bodies are inspected by
    # the engine's content rules via extract_payloads().
    work = _HEREDOC_RE.sub(lambda m: f"<<{m.group(1)} HEREDOC_BODY", command)

    # Recurse into $(...) / `...` and replace with a plain placeholder.
    def _sub(match):
        inner = match.group(1) if match.group(1) is not None else match.group(2)
        if inner.strip():
            result.flags.add(FLAG_SUBSTITUTION)
            sub_result = extract_commands(inner, depth + 1)
            result.commands.extend(sub_result.commands)
            result.flags.update(sub_result.flags)
        return "SUBST_OUT"

    work = _SUBST_RE.sub(_sub, work)
    if "$(" in work or "`" in work:
        raise ParseUncertain("unbalanced command substitution")

    try:
        lex = shlex.shlex(work, posix=True, punctuation_chars=";|&()<>")
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError as exc:
        raise ParseUncertain(f"tokenization failed: {exc}") from exc

    # Split into pipeline segments / command groups on shell operators.
    segments, current = [], []
    for tok in tokens:
        if tok and all(c in ";|&()<>" for c in tok):
            if current:
                segments.append(current)
                current = []
            # detect "decoder | shell" and "downloader | shell" at split time
        else:
            current.append(tok)
    if current:
        segments.append(current)

    prev_name = ""
    for seg in segments:
        cmds = _analyze_segment(seg, result, depth)
        for cmd in cmds:
            cmd.raw = command
            result.commands.append(cmd)
            if cmd.name in _SHELLS and prev_name in _DECODERS:
                result.flags.add(FLAG_DECODE_PIPE)
            if cmd.name in _SHELLS and prev_name in _DOWNLOADERS:
                result.flags.add(FLAG_DOWNLOAD_PIPE)
            prev_name = cmd.name
    return result


def _analyze_segment(tokens, result: ParseResult, depth: int):
    """Turn one pipeline segment into SimpleCommand(s), recursing wrappers."""
    toks = list(tokens)

    # strip leading VAR=value assignments and transparent wrappers
    while toks:
        head = toks[0]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", head):
            toks.pop(0)
            continue
        base = head.rsplit("/", 1)[-1].lower()
        if base in _TRANSPARENT:
            toks.pop(0)
            # skip option-style args of wrappers (env -i, nice -n 10 ...)
            while toks and toks[0].startswith("-"):
                flag = toks.pop(0)
                if flag in ("-n", "-u", "-S") and toks and not toks[0].startswith("-"):
                    toks.pop(0)  # the flag's value
            continue
        if base == "timeout":
            toks.pop(0)
            while toks and (toks[0].startswith("-") or re.fullmatch(r"\d+[smhd]?", toks[0])):
                toks.pop(0)
            continue
        break

    if not toks:
        return []

    head_base = toks[0].rsplit("/", 1)[-1].lower()

    # command name supplied by variable or substitution output => indirection
    if toks[0].startswith("$") or toks[0] == "SUBST_OUT":
        result.flags.add(FLAG_INDIRECT)
        return [SimpleCommand(argv=toks)]

    if head_base == "eval" or (head_base == "source" and len(toks) > 1):
        result.flags.add(FLAG_EVAL)
        return [SimpleCommand(argv=toks)]

    # bash -c "string" → recurse into the string
    if head_base in _SHELLS:
        for i, tok in enumerate(toks[1:], start=1):
            if tok == "-c" and i + 1 < len(toks):
                inner = extract_commands(toks[i + 1], depth + 1)
                result.flags.update(inner.flags)
                return [SimpleCommand(argv=toks)] + inner.commands
        return [SimpleCommand(argv=toks)]

    # xargs [flags] CMD ... → the real command is what xargs runs
    if head_base == "xargs":
        rest = toks[1:]
        while rest and rest[0].startswith("-"):
            flag = rest.pop(0)
            if flag in ("-I", "-n", "-P", "-d", "-a", "-E", "-s") and rest:
                rest.pop(0)
        if rest:
            inner = _analyze_segment(rest, result, depth)
            return [SimpleCommand(argv=toks)] + inner
        raise ParseUncertain("bare xargs with unknown command")

    # find ... -exec CMD ... ; → extract the -exec command
    if head_base == "find":
        cmds = [SimpleCommand(argv=toks)]
        i = 0
        while i < len(toks):
            if toks[i] in ("-exec", "-execdir", "-ok", "-okdir"):
                sub = []
                i += 1
                while i < len(toks) and toks[i] not in (";", "+"):
                    sub.append(toks[i])
                    i += 1
                if sub:
                    cmds.extend(_analyze_segment(sub, result, depth))
            i += 1
        return cmds

    return [SimpleCommand(argv=toks)]


def extract_payloads(command: str) -> list:
    """Heredoc bodies and echo/printf arguments — content the command would
    write. Fed to snippet (content) rules by the engine."""
    payloads = [m.group(2) for m in _HEREDOC_RE.finditer(command)]
    try:
        parsed = extract_commands(command)
        for cmd in parsed.commands:
            if cmd.name in ("echo", "printf", "tee") and len(cmd.argv) > 1:
                payloads.append(" ".join(cmd.argv[1:]))
    except ParseUncertain:
        payloads.append(command)  # let content rules see the raw string
    return payloads
