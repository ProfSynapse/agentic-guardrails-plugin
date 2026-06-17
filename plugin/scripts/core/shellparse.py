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

import base64
import binascii
import re
import shlex
from dataclasses import dataclass, field

MAX_DEPTH = 6

# Wrappers that pass through to the real command. Mirrors Claude Code's own
# strip list; env-runners (npx, docker) are deliberately NOT stripped — rules
# must name them.
_TRANSPARENT = {"nohup", "nice", "stdbuf", "time", "command", "builtin", "env", "setsid"}
_SHELLS = {"bash", "sh", "zsh", "ksh", "dash", "ash"}
# Windows interpreters. Codex (and Cowork) on Windows route shell calls through
# these, so a destructive command can hide inside `-Command`/`/c` like it hides
# inside `bash -c`. We recurse their inner command line the same way.
_PWSH = {"powershell", "pwsh"}
_WIN_CMD = {"cmd"}

# PowerShell parameter prefixes (it accepts any unambiguous abbreviation). We
# only need the exec-surface ones: -Command, -EncodedCommand, -File, plus the
# value-taking setup flags so we can skip them and their argument.
_PWSH_COMMAND_RE = re.compile(r"c(o(m(m(a(n(d)?)?)?)?)?)?$", re.IGNORECASE)
_PWSH_ENCODED_RE = re.compile(r"e(n(c(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?)?)?)?)?)?)?)?$",
                              re.IGNORECASE)
_PWSH_FILE_RE = re.compile(r"f(i(l(e)?)?)?$", re.IGNORECASE)
_PWSH_VALUE_FLAG_RE = re.compile(
    r"(ex(e(c(u(t(i(o(n(p(o(l(i(c(y)?)?)?)?)?)?)?)?)?)?)?)?)?"
    r"|version|inputformat|if|outputformat|of"
    r"|windowstyle|configurationname|workingdirectory|cwd)$", re.IGNORECASE)


def _decode_pwsh_encoded(token: str):
    """Decode a PowerShell -EncodedCommand argument (base64 of UTF-16LE).
    Returns the script text, or None if it does not decode."""
    try:
        raw = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return None
    for enc in ("utf-16-le", "utf-8"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


class ParseUncertain(Exception):
    """Raised when the command can't be confidently decomposed."""


@dataclass
class SimpleCommand:
    argv: list
    raw: str = ""

    @property
    def name(self) -> str:
        """Basename of argv[0], lowered, with a Windows `.exe` suffix dropped:
        '/bin/RM' -> 'rm', r'C:\\bin\\curl.exe' -> 'curl'. Stripping the suffix
        and splitting on both separators means the POSIX-named command tables
        match what a Windows host actually runs (curl.exe, python.exe)."""
        if not self.argv:
            return ""
        head = self.argv[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        if head.endswith(".exe"):
            head = head[:-4]
        return head

    def joined(self) -> str:
        return " ".join(self.argv)


@dataclass
class ParseResult:
    commands: list = field(default_factory=list)   # list[SimpleCommand]
    flags: set = field(default_factory=set)        # see FLAG_* below
    # Inner command-line text recovered from wrappers we recursed (PowerShell
    # -Command / -EncodedCommand, cmd /c). The engine scans these for
    # PowerShell/.NET deletion and for secret content that argv parsing misses.
    payloads: list = field(default_factory=list)

FLAG_EVAL = "eval"                    # eval / source of dynamic strings
FLAG_INDIRECT = "indirect-command"    # command name comes from a variable/substitution
FLAG_DECODE_PIPE = "decode-pipe"      # base64/xxd/openssl output piped into a shell
FLAG_DOWNLOAD_PIPE = "download-pipe"  # curl/wget piped into a shell
FLAG_SUBSTITUTION = "substitution"    # contained $(...) or backticks (also recursed)

_DECODERS = {"base64", "base32", "xxd", "openssl"}
_DOWNLOADERS = {"curl", "wget"}

_SUBST_RE = re.compile(r"\$\(((?:[^()]|\([^()]*\))*)\)|`([^`]*)`")
_HEREDOC_RE = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?\n(.*?)\n\1", re.DOTALL)

# A backslash that precedes a path-like character. shlex(posix=True) treats `\`
# as an escape, so an unquoted Windows path like `secrets\.env` tokenizes to
# `secrets.env` — separator and leading-dot basename vanish, defeating
# secret/placeholder/content detection. Codex and Cowork on Windows emit exactly
# these (PowerShell `Get-Content secrets\.env`). Such a backslash is a Windows
# separator, not a POSIX metachar-escape, so we double it: shlex then yields one
# literal backslash and detection sees the real path. POSIX escapes of shell
# metacharacters (`\ `, `\"`, `\;`, `\*`) are untouched, as are single-quoted
# spans (no escaping happens there, so doubling would inject a real backslash).
_WIN_PATH_CHAR = re.compile(r"[A-Za-z0-9._~-]")


def _double_winpath_backslashes(s: str) -> str:
    out, in_single, in_double = [], False, False
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "'" and not in_double:
            in_single = not in_single
        elif c == '"' and not in_single:
            in_double = not in_double
        elif c == "\\" and not in_single and i + 1 < n:
            nxt = s[i + 1]
            if nxt == "\\":            # an explicit escaped backslash: pass through
                out.append("\\\\")
                i += 2
                continue
            if _WIN_PATH_CHAR.match(nxt):  # Windows separator: double so shlex keeps it
                out.append("\\\\")
                i += 1
                continue
        out.append(c)
        i += 1
    return "".join(out)

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

    # Preserve Windows path separators so shlex doesn't strip them as escapes.
    work = _double_winpath_backslashes(work)

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

    # command name supplied by variable or substitution output => indirection.
    # $_ / $PSItem are the pipeline current-object (e.g. `| % { $_.Name }`), not
    # a command name from a variable, so property access on them is not
    # indirection — a destructive `$_.Delete()` is caught by the content scan.
    if toks[0].startswith("$") or toks[0] == "SUBST_OUT":
        if not re.match(r"\$(_|psitem)\b", toks[0], re.IGNORECASE):
            result.flags.add(FLAG_INDIRECT)
        return [SimpleCommand(argv=toks)]

    if head_base == "eval" or (head_base == "source" and len(toks) > 1):
        result.flags.add(FLAG_EVAL)
        return [SimpleCommand(argv=toks)]

    # PowerShell dynamic-eval / scriptblock invokers (iex, Invoke-Expression,
    # icm, Invoke-Command): the real command hides in a string/scriptblock we
    # can't tokenize, so treat like `eval` — reviewed, not silently run.
    if head_base in ("iex", "invoke-expression", "icm", "invoke-command"):
        result.flags.add(FLAG_EVAL)
        return [SimpleCommand(argv=toks)]

    # PowerShell block / pipeline invokers: the real command sits after a
    # dot-source / ForEach / Where invoker (`. cmd`, `% cmd`, `foreach cmd`).
    # argv0 would be the invoker, so the verb hides in argv[1] — drop it and
    # recurse so a deletion buried behind it is still evaluated.
    if head_base in (".", "%", "foreach", "foreach-object", "?", "where",
                     "where-object") and len(toks) > 1:
        return _analyze_segment(toks[1:], result, depth)

    # PowerShell scriptblock `{ ... }` (e.g. after `&`, `%`, or a dot-source).
    # shlex makes `{` the argv0, hiding the verb inside the braces — strip the
    # braces and recurse the body.
    if toks[0].startswith("{"):
        inner = list(toks)
        inner[0] = inner[0].lstrip("{")
        inner[-1] = inner[-1].rstrip("}")
        inner = [t for t in inner if t]
        if inner and inner != toks:
            return _analyze_segment(inner, result, depth)

    # bash -c "string" → recurse into the string
    if head_base in _SHELLS:
        for i, tok in enumerate(toks[1:], start=1):
            if tok == "-c" and i + 1 < len(toks):
                inner = extract_commands(toks[i + 1], depth + 1)
                result.flags.update(inner.flags)
                return [SimpleCommand(argv=toks)] + inner.commands
        return [SimpleCommand(argv=toks)]

    # Windows interpreters. Strip a trailing .exe so 'cmd.exe'/'powershell.exe'
    # match. A destructive command can hide in their inner command line exactly
    # as it does in `bash -c`, so we recurse it and record the inner text.
    wname = head_base[:-4] if head_base.endswith(".exe") else head_base

    def _recurse_inner(inner_text: str):
        if not inner_text.strip():
            return [SimpleCommand(argv=toks)]
        inner = extract_commands(inner_text, depth + 1)
        result.flags.update(inner.flags)
        result.payloads.append(inner_text)
        result.payloads.extend(inner.payloads)
        return [SimpleCommand(argv=toks)] + inner.commands

    # cmd /c <command> / cmd /k <command> → the real command follows the switch
    if wname in _WIN_CMD:
        rest = toks[1:]
        for i, tok in enumerate(rest):
            if tok.lower() in ("/c", "/k", "/r"):
                return _recurse_inner(" ".join(rest[i + 1:]))
        return [SimpleCommand(argv=toks)]

    # powershell / pwsh -Command "..." / -EncodedCommand <b64> / positional
    if wname in _PWSH:
        rest = toks[1:]
        i = 0
        while i < len(rest):
            tok = rest[i]
            stripped = tok[1:] if tok.startswith("-") else ""
            if stripped and _PWSH_ENCODED_RE.fullmatch(stripped):
                # -EncodedCommand: base64 of UTF-16LE. Undecodable => fail closed.
                if i + 1 < len(rest):
                    decoded = _decode_pwsh_encoded(rest[i + 1])
                    if decoded is None:
                        raise ParseUncertain("undecodable PowerShell -EncodedCommand")
                    return _recurse_inner(decoded)
                break
            if stripped and _PWSH_COMMAND_RE.fullmatch(stripped):
                # -Command consumes the remainder of the line as the script.
                return _recurse_inner(" ".join(rest[i + 1:]))
            if stripped and _PWSH_FILE_RE.fullmatch(stripped):
                break  # -File <script>: a path we cannot inspect
            if stripped and _PWSH_VALUE_FLAG_RE.fullmatch(stripped):
                i += 2  # skip the flag and its value
                continue
            if not tok.startswith("-"):
                # first positional arg is the implicit -Command body
                return _recurse_inner(" ".join(rest[i:]))
            i += 1  # an unrecognized boolean switch (-NoProfile, ...)
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
