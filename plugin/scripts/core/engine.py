"""Policy engine: ToolEvent in, Decision out.

Layers, in order of authority:
  1. Built-in semantic checks (hardcoded — survive even total policy-pack
     failure; these are the non-negotiable accident guards).
  2. Policy packs: YAML rules from <plugin>/policies/ (core, sync-safety,
     content-rules.d/*) and ~/.agw/policies.d/*. deny > ask > allow.
  3. Folder-profile modifiers (sync-safety guards activate on sync profiles;
     they also run for unknown profiles — fail toward caution).

Crash policy: this module raises freely; the ADAPTER catches everything and
converts to ASK (never silent allow, never a bricked session).
"""
from __future__ import annotations

import fnmatch
import os
import re
import shutil

from . import policy_health, powershell_bind, profiles as prof
from .events import ALLOW, ASK, DENY, DEFER, EDIT, EXEC, MCP, OTHER, READ, WRITE, \
    NON_WAIVABLE_INVARIANT, POLICY_ENFORCEMENT, Decision, DecisionContext, \
    ToolEvent, worst
from .shellparse import DIALECT_POWERSHELL, FLAG_DECODE_PIPE, FLAG_DOWNLOAD_PIPE, \
    FLAG_EVAL, FLAG_INDIRECT, FLAG_INNER_UNCERTAIN, ParseUncertain, SimpleCommand, \
    _HEREDOC_RE, extract_commands, extract_payloads, redirect_targets

ARCHIVE_REDIRECT = ("Deletion is disabled by agentic-guardrails. Use `agw archive <path>` "
                    "instead — it moves files to the archive store and is fully reversible "
                    "with `agw restore`.")

# Documented agw verbs are built to be reversible or non-destructive. Trust the
# packaged safety vocabulary rather than adding a second Guardrails prompt; a
# host sandbox may still request its normal outside-workspace approval for
# ~/.agw. Permanent/special verbs remain in AGW_ASK_VERBS below.
AGW_READ_ONLY_VERBS = {"scan", "diff", "status", "log", "doctor"}
AGW_SAFE_MUTATING_VERBS = {
    "init", "checkout", "convert", "archive", "move", "rename", "snapshot",
    "restore", "undo", "publish", "publish-file", "unlink-link",
    "file", "run", "office",
}
AGW_ASK_VERBS = {"prune": "prune permanently destroys archived versions (human decision)",
                 "apply": "bulk apply executes a stored plan — review the manifest",
                 "hydrate": "hydration downloads cloud-only content"}

# --- secret/confidential detection: ask, don't block --------------------------
# Reading a credential-type file is often legitimate (dev setup), so it asks.
# The only hard deny is the exfiltration shape: credential file + network tool
# in the same command.

_SECRET_BASENAME_RE = re.compile(
    r"^(?:\.env(?:\..+)?|\.netrc|\.pgpass|\.git-credentials"
    r"|id_(?:rsa|dsa|ecdsa|ed25519)|.*\.(?:pem|key|p12|pfx|jks|keystore|ppk))$",
    re.IGNORECASE)
_SECRET_NAMES = {"credentials", "credentials.json", "service_account.json",
                 "service-account.json", "secrets.json", "secrets.yaml", "secrets.yml"}
_SECRET_DIRS = {".ssh", ".aws", ".azure", ".kube", "gcloud"}
_NOT_SECRET_SUFFIX = re.compile(r"\.(?:example|sample|template|dist|pub)$", re.IGNORECASE)

# These commands may mention a credential-named path while creating or updating
# it, but do not read that file into the agent conversation. Nested reads are
# parsed as their own commands and still prompt. Credential + network remains a
# hard deny regardless of the command in this set.
_NON_CONVERSATIONAL_FILE_COMMANDS = {
    "new-item", "ni", "mkdir", "md",
    "set-content", "sc", "out-file", "add-content", "ac",
    "copy-item", "copy", "cpi", "cp",
    "move-item", "move", "mi", "mv",
    "remove-item", "del", "erase", "rd", "ri", "rm", "rmdir",
    "touch",
}

# Network tools. The PowerShell web cmdlets/aliases are included because a
# Windows host (Codex/Cowork on PowerShell) reaches the net through them, not
# curl; `curl.exe`/`wget.exe` normalize to curl/wget via the .exe strip in
# SimpleCommand.name. Without these the credential-exfil shape goes undetected.
_NETWORK_CMDS = {"curl", "wget", "nc", "ncat", "netcat", "scp", "sftp", "rsync",
                 "ssh", "ftp", "telnet", "socat",
                 "invoke-webrequest", "iwr", "invoke-restmethod", "irm",
                 "start-bitstransfer", "bitsadmin"}
# Plain file readers. PowerShell's Get-Content and its aliases (gc, type) read
# file contents exactly like cat, so the content-prescan must recognize them or
# a Windows host reads secrets/confidential files with no prompt.
_READER_CMDS = {"cat", "head", "tail", "less", "more", "bat", "strings",
                "get-content", "gc", "type"}

_HUNT_RE = re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|token|credential)")

_PRESCAN_BYTES = 64 * 1024
_PRESCAN_MARKERS = (
    ("a private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), True),
    ("an AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), True),
    ("an API token", re.compile(
        r"\bgh[pos]_[A-Za-z0-9]{20,}|\bsk-[A-Za-z0-9_-]{20,}"
        r"|\bxox[bpoars]-[A-Za-z0-9-]{10,}"), True),
    ("a hardcoded password", re.compile(
        r"(?i)\b(?:password|passwd|pwd)\s*[=:]\s*[\"'][^\"']{6,}[\"']"), True),
    ("a credential assignment", re.compile(
        r"(?mi)^[A-Za-z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_?KEY)[A-Za-z0-9_]*"
        r"\s*=\s*(?:[\"'][^\"']{6,}[\"']|[A-Za-z0-9_./+=:-]{6,})\s*$"), True),
    ("a confidentiality marking", re.compile(
        r"(?i)\b(?:confidential|do not distribute|internal use only|trade secret)\b"), False),
    ("embedded prompt-injection instructions", re.compile(
        r"\b(?:ignore|disregard|forget)\b[^.\n]{0,40}"
        r"\b(?:instructions|prompt|rules|guidance|directives)\b"
        r"|\b(?:say|claim|pretend|tell them)\b[^.\n]{0,30}"
        r"\b(?:already\s+)?approved\b", re.IGNORECASE), False),
)

_DEV_SOURCE_SUFFIXES = {
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".sh", ".ps1", ".psm1",
    ".rb", ".go", ".rs", ".java", ".c", ".cc", ".cpp", ".h", ".hpp",
}
_DEV_DOC_BASENAMES = {
    "readme.md", "research.md", "plan.md", "testing.md", "releasing.md",
    "contributing.md", "codex.md", "deployment.md", "agents.md",
}


def _is_low_confidence_context(path: str) -> bool:
    normalized = os.path.abspath(path).replace("\\", "/").lower()
    parts = [part for part in normalized.split("/") if part]
    base = parts[-1] if parts else ""
    suffix = os.path.splitext(base)[1]
    return (suffix in _DEV_SOURCE_SUFFIXES or suffix in {".log", ".jsonl"}
            or base in _DEV_DOC_BASENAMES
            or any(part in {"test", "tests", "docs", "plans"} for part in parts))


def _is_secret_path(path: str) -> bool:
    if "://" in path:
        return False  # URL, not a filesystem path
    p = os.path.expanduser(path).replace("\\", "/")
    base = os.path.basename(p)
    if _NOT_SECRET_SUFFIX.search(base):
        return False
    if _SECRET_BASENAME_RE.match(base) or base.lower() in _SECRET_NAMES:
        return True
    return any(d in p.split("/")[:-1] for d in _SECRET_DIRS)


def _prescan_file(path: str):
    """Return a human label for the first secret/confidential marker found in
    the file head, or None. Cheap (one bounded read), binary-safe."""
    if _NOT_SECRET_SUFFIX.search(os.path.basename(path)):
        return None  # .example/.sample/.template files hold placeholders
    try:
        if not os.path.isfile(path) or os.path.getsize(path) == 0:
            return None
        with open(path, "rb") as f:
            head = f.read(_PRESCAN_BYTES)
    except OSError:
        return None
    if b"\0" in head:
        return None  # binary container; plaintext markers won't be meaningful
    text = head.decode("utf-8", "replace")
    for label, rx, high_confidence in _PRESCAN_MARKERS:
        if rx.search(text):
            contextual_low = not high_confidence and _is_low_confidence_context(path)
            return label, contextual_low
    return None

_INTERPRETER_DESTRUCTIVE = re.compile(
    r"os\.(remove|unlink|rmdir|removedirs)|shutil\.rmtree|\.unlink\(|send2trash"
    r"|\b(rmSync|rmdirSync|unlinkSync|rm_rf|rm_r)\b|\.rm\s*\(|FileUtils\.(rm|remove)"
    r"|unlink\s", re.IGNORECASE)

# PowerShell/.NET deletion and truncation forms that do not tokenize to a clean
# argv0 verb (so the verb table can't see them): the [IO.File]::Delete() family
# and the Clear-* content-wiping cmdlets. Verb-first forms (Remove-Item, del,
# rd, ...) are intentionally NOT here — the verb table handles those, with the
# regenerable-dir allowance this scan would clobber. Scanned over the raw
# command and over any decoded -EncodedCommand / inner -Command payloads.
_PWSH_DESTRUCTIVE = re.compile(
    # static [IO.File]::Delete(...) family
    r"\[\s*(?:system\.)?io\.(?:file|directory|fileinfo|directoryinfo)\s*\]\s*::\s*delete"
    # instance .Delete(...) on any receiver: (Get-Item x).Delete(), $_.Delete(), $f.Delete()
    r"|[)\]\w$]\s*\.\s*delete\s*\("
    # parens-less method invocation: `... | % Delete`, `ForEach-Object Delete`
    r"|(?:%|foreach(?:-object)?)\s+delete\b"
    # .MoveTo(NUL)/$null — relocating a file into a null sink destroys it
    r"|\.\s*moveto\s*\(\s*['\"]?(?:nul|\$null)"
    # content-wiping cmdlets
    r"|(?:^|[\s;|&({@.'\"])(?:clear-content|clear-item|clear-recyclebin)\b",
    re.IGNORECASE)

# .NET in-place file writers — overwrite an existing file with no `>` token, so
# redirect_targets misses them. Append* is excluded (no data loss). Used by
# clobber_targets to pre-image the target, not to block.
_WRITEALLTEXT_RE = re.compile(
    r"\[\s*(?:system\.)?io\.file\s*\]\s*::\s*"
    r"writeall(?:text|lines|bytes)\s*\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE)

_SQL_DENY = re.compile(r"\b(DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE?)\b", re.IGNORECASE)
_SQL_DELETE = re.compile(r"\bDELETE\s+FROM\b(?![\s\S]*\bWHERE\b)", re.IGNORECASE)

# The SQL / PowerShell content scans must fire on *executed* code, not on the
# same text appearing as a search pattern or as echoed data. Scanning the raw
# command string denied `grep "DROP TABLE" schema.sql` and
# `rg "Clear-Content" scripts/` — the destructive text there is the thing being
# searched for, never run. So we scan a "code view": the raw command with the
# operands of pure data tools blanked out — search-tool patterns always, and
# data-producer (echo/printf) output when nothing in the command line would run
# it (no shell, interpreter, or SQL client to consume the pipe/heredoc). The
# raw structure is otherwise preserved, so PowerShell's `.NET` method syntax
# (`(Get-Item x).Delete()`) and wrapper payloads still match.
#
# Blanking operands can only remove matches, never add them, so this introduces
# no new false positives — only removes the data-context ones. The class it
# still can't disambiguate (`git commit -m "add DROP TABLE migration"`) stays as
# before; that would need per-flag span typing.
_SEARCH_TOOLS = {
    "grep", "egrep", "fgrep", "rg", "ripgrep", "ag", "ack", "select-string",
}
_DATA_PRODUCERS = {"echo", "printf"}
_SQL_CLIENTS = {"psql", "mysql", "mariadb", "sqlite3", "sqlite", "mongo", "mongosh",
                "cockroach", "clickhouse-client", "sqlplus", "sqlcmd", "cqlsh"}
# Anything that consumes piped/heredoc text and executes it: shells, script
# interpreters, and SQL clients. When one of these is present, echoed data and
# heredoc bodies become executable code (e.g. `echo 'DROP TABLE x' | psql`).
_CODE_CONSUMERS = _SQL_CLIENTS | {
    "python", "python3", "perl", "ruby", "node", "php",
    "bash", "sh", "zsh", "ksh", "dash", "ash",
    "powershell", "pwsh", "cmd"}


def _code_view(command: str, parsed) -> str:
    """The command with pure-data-tool operands blanked, so the SQL / PowerShell
    content scans see executed code, not search patterns or un-consumed echoed
    data. See the note above _SEARCH_TOOLS for the rationale. Payloads (decoded
    -EncodedCommand / inner wrapper text) are appended so smuggled deletions
    still match."""
    consumers = {c.name for c in parsed.commands} & _CODE_CONSUMERS
    view = command
    for cmd in parsed.commands:
        drop = cmd.name in _SEARCH_TOOLS or (cmd.name in _DATA_PRODUCERS and not consumers)
        if not drop:
            continue
        for tok in cmd.argv[1:]:
            if len(tok) >= 2 and not tok.startswith("-"):
                view = view.replace(tok, " " * len(tok), 1)  # blank first occurrence
    return "\n".join([view] + parsed.payloads)

_MUTATOR_CMDS = {"mv", "cp", "tee", "sed", "touch", "ln", "install", "rsync", "truncate"}

# File/dir deletion verbs across shells. `name` is the lowered argv0 basename,
# so PowerShell `Remove-Item` arrives as "remove-item" and its aliases/cmd
# builtins (del, erase, rd, ri) as themselves. Without these a Windows host
# (Cowork/Codex on PowerShell) could delete files via `Remove-Item -Recurse
# -Force` and the engine would never see a destructive verb.
_DELETE_VERBS = {"rm", "rmdir", "unlink",          # POSIX
                 "remove-item", "ri", "del", "erase", "rd"}  # PowerShell / cmd
_SECURE_WIPE_VERBS = {"shred"}  # secure-wipe: always deny, even on regenerables
# Removers that honour the regenerable-dir allowance: the general file/dir
# removers plus the recursive dir removers (`rd /s` / `rmdir` is the Windows
# equivalent of `rm -rf node_modules`). `unlink` (single named file) and
# `shred` (secure-wipe) never get it — they always deny.
_REGEN_OK_VERBS = {"rm", "remove-item", "ri", "del", "erase", "rd", "rmdir"}
# cmd verbs whose operands can carry `/s /q`-style switches. Only these get the
# cmd-switch filtering below — applying it to POSIX `rm` would wrongly drop a
# real root path like `/e` from the operand list (and silently allow its
# deletion when paired with a regenerable name).
_CMD_SWITCH_VERBS = {"del", "erase", "rd", "rmdir"}
# cmd-style switch (`/s`, `/q`, `/a:h`) — a flag, not a path operand.
_CMD_SWITCH_RE = re.compile(r"/[A-Za-z](?::.*)?$")

# Move/rename verbs (PowerShell + cmd). Relocating a file into a null sink
# destroys it, so that specific shape is a hard deny.
_MOVE_VERBS = {"move-item", "mi", "rename-item", "rni", "ren", "move"}
_NULL_SINKS = {"nul", "nul:", "$null", "/dev/null"}

# Regenerable build/dependency dirs: deleting them is routine dev work and
# archiving them would copy gigabytes of reproducible junk. rm of these is
# allowed (item: don't make the backup plan absurd). Company-extensible.
_REGENERABLE = {"node_modules", "bower_components", ".venv", "venv", "__pycache__",
                ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", "build", "dist",
                "target", "out", ".next", ".nuxt", ".svelte-kit", ".turbo", ".parcel-cache",
                ".cache", "coverage", ".gradle", ".terraform"}

# Access-type asks (about *reading* a sensitive resource, not destroying one):
# eligible for session approval memory and for relaxed-level downgrade.
_ACCESS_ASK_RULES = {"builtin:secret-file", "builtin:content-prescan",
                     "builtin:credential-hunt", "builtin:placeholder-read"}

# Subset of the above that `deny_secret_read` (strict level) upgrades ASK->DENY:
# the credential-type reads. Placeholder reads are excluded (that guard is
# about cloud-synced stub files, not secret exposure).
_SECRET_READ_RULES = {"builtin:secret-file", "builtin:content-prescan",
                      "builtin:credential-hunt"}

# Named enforcement levels. Each expands to defaults for the individual knobs;
# explicit settings/env knobs override. `standard` is the safe default.
_LEVELS = {
    "strict":   {"enforcement": "enforce", "session_memory": False,
                 "regenerable_rm": False, "relaxed_access": False,
                 "deny_secret_read": True},
    "standard": {"enforcement": "enforce", "session_memory": True,
                 "regenerable_rm": True,  "relaxed_access": False,
                 "deny_secret_read": False},
    "relaxed":  {"enforcement": "enforce", "session_memory": True,
                 "regenerable_rm": True,  "relaxed_access": True,
                 "deny_secret_read": False},
    "observe":  {"enforcement": "observe", "session_memory": True,
                 "regenerable_rm": True,  "relaxed_access": False,
                 "deny_secret_read": False},
}
_DEFAULT_LEVEL = "standard"
_BOOL_KNOBS = {"session_memory", "regenerable_rm", "relaxed_access",
               "deny_secret_read"}


def _as_bool(val):
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in ("1", "true", "yes", "on")


def resolve_settings(policy: "Policy") -> dict:
    """Effective config: built-in default <- level bundle <- explicit knobs
    (policy `settings:` block) <- AGW_* environment overrides. The company
    sets `level` once; power users override individual knobs."""
    s = dict(policy.settings or {})
    level = os.environ.get("AGW_LEVEL") or s.get("level") or _DEFAULT_LEVEL
    level = level if level in _LEVELS else _DEFAULT_LEVEL
    cfg = dict(_LEVELS[level])
    cfg["level"] = level
    for knob in _BOOL_KNOBS:
        if knob in s:
            cfg[knob] = _as_bool(s[knob])
    if "enforcement" in s:
        cfg["enforcement"] = str(s["enforcement"]).lower()
    # env overrides win last
    env_map = {"AGW_ENFORCEMENT": "enforcement", "AGW_SESSION_MEMORY": "session_memory",
               "AGW_REGENERABLE_RM": "regenerable_rm", "AGW_RELAXED_ACCESS": "relaxed_access",
               "AGW_DENY_SECRET_READ": "deny_secret_read"}
    for env, knob in env_map.items():
        if env in os.environ:
            cfg[knob] = (os.environ[env].lower() if knob == "enforcement"
                         else _as_bool(os.environ[env]))
    # company-extended regenerable list (additive); empty when the knob is off,
    # so the rm handler simply sees no regenerable set and denies as normal.
    extra = s.get("regenerable_globs") or []
    cfg["regenerable"] = ((_REGENERABLE | {str(x) for x in extra})
                          if cfg.get("regenerable_rm") else set())
    return cfg


def _is_regenerable(path: str, regen: set) -> bool:
    parts = [p for p in os.path.normpath(path).replace("\\", "/").split("/") if p]
    return any(p in regen for p in parts)


class Policy:
    def __init__(self):
        self.command_rules = []   # {pattern, action, reason, id}
        self.snippet_rules = []   # {pattern(re), action, applies_to, reason, id}
        self.path_rules = []      # {glob, zone, id}
        self.mcp_rules = []       # {matcher, action, reason, id}
        self.protected_globs = []
        self.degraded = []        # names of packs that failed to load
        self.settings = {}
        self.health = policy_health.UNAVAILABLE
        self.baseline_revision = ""
        self.revision = policy_health.combine_revision("", ())
        self.health_record = policy_health.Health(
            self.health, self.baseline_revision, self.revision,
            ("baseline-unavailable",),
        )


def _expand(glob: str) -> str:
    return os.path.expanduser(glob)


def _policy_files(directory: str, suffixes=(".yaml", ".yml", ".json")):
    if not os.path.isdir(directory):
        return [], False
    try:
        return [os.path.join(directory, name) for name in sorted(os.listdir(directory))
                if name.lower().endswith(suffixes)], False
    except OSError:
        return [], True


def load_policy(plugin_root: str = "") -> Policy:
    policy = Policy()
    home = os.path.expanduser("~")
    agw_home = os.environ.get("AGW_HOME") or os.path.join(home, ".agw")
    policy.protected_globs = [
        os.path.join(agw_home, "**"), agw_home,
        os.path.join(home, ".ssh", "**"), os.path.join(home, ".aws", "**"),
        os.path.join(home, ".gnupg", "**"),
        "**/.tmp.driveupload/**", "**/.tmp.drivedownload/**", "**/.dropbox.cache/**",
    ]
    if plugin_root:
        policy.protected_globs += [os.path.join(plugin_root, "**"), plugin_root]

    baseline_path = os.path.join(plugin_root, "policies", "core.yaml") if plugin_root else ""
    source_tokens = []
    baseline_ok = False
    if baseline_path:
        try:
            baseline_raw = _read_policy_bytes(baseline_path)
            baseline_digest = policy_health.digest_bytes(baseline_raw)
            data = _load_policy_document(baseline_path, baseline_raw)
            _validate_pack(data, "baseline")
            _merge_pack(policy, data, "core.yaml", NON_WAIVABLE_INVARIANT)
            policy.baseline_revision = policy_health.combine_revision(baseline_digest, ())
            baseline_ok = True
        except Exception:
            policy.baseline_revision = policy_health.combine_revision("unavailable", ())
            policy.degraded.append("core.yaml")

    pack_files = []
    discovery_failed = False
    if plugin_root:
        sub = os.path.join(plugin_root, "policies", "content-rules.d")
        files, failed = _policy_files(sub)
        pack_files.extend(files)
        discovery_failed = discovery_failed or failed
    local = os.path.join(agw_home, "policies.d")
    files, failed = _policy_files(local)
    pack_files.extend(files)
    discovery_failed = discovery_failed or failed

    for path in pack_files:
        try:
            raw = _read_policy_bytes(path)
            source_tokens.append(policy_health.digest_bytes(raw))
            data = _load_policy_document(path, raw)
            _validate_pack(data, "custom")
            if baseline_ok:
                _merge_pack(policy, data, os.path.basename(path), POLICY_ENFORCEMENT)
        except Exception:
            policy.degraded.append(os.path.basename(path))
            try:
                source_tokens.append("invalid:" + policy_health.digest_bytes(
                    _read_policy_bytes(path)))
            except Exception:
                source_tokens.append("invalid-unreadable")
    if discovery_failed:
        policy.degraded.append("policy-directory-unavailable")
        source_tokens.append("directory-unavailable")

    if not baseline_ok:
        policy.health = policy_health.UNAVAILABLE
        issues = ("baseline-unavailable",)
    elif policy.degraded:
        policy.health = policy_health.DEGRADED
        issues = tuple("custom-policy-invalid" for _ in policy.degraded)
    else:
        policy.health = policy_health.HEALTHY
        issues = ()
    policy.revision = policy_health.combine_revision(
        policy.baseline_revision, source_tokens + [policy.health]
    )
    policy.health_record = policy_health.Health(
        policy.health, policy.baseline_revision, policy.revision, issues
    )
    return policy


def _read_policy_bytes(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def _load_policy_document(path: str, raw: bytes):
    text = raw.decode("utf-8")
    if path.lower().endswith(".json"):
        import json
        return json.loads(text)
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except ImportError:
        from . import miniyaml
        return miniyaml.loads(text)


def _load_yaml(path: str):
    return _load_policy_document(path, _read_policy_bytes(path))


def _validate_pack(data, source_kind: str):
    if not isinstance(data, dict):
        raise TypeError(f"{source_kind} policy root must be a mapping")
    for section in ("commands", "snippets", "paths", "mcp_tools"):
        rules = data.get(section, [])
        if rules is None:
            rules = []
        if not isinstance(rules, list):
            raise TypeError(f"policy section {section} must be a list")
        for rule in rules:
            if not isinstance(rule, dict):
                raise TypeError(f"policy section {section} contains a non-mapping rule")
    settings = data.get("settings", {})
    if settings is not None and not isinstance(settings, dict):
        raise TypeError("policy settings must be a mapping")
    for rule in data.get("commands") or []:
        if not isinstance(rule.get("pattern"), str) or not rule["pattern"]:
            raise TypeError("command pattern must be a non-empty string")
        if rule.get("action", "ask") not in {"allow", "ask", "deny"}:
            raise ValueError("command action is invalid")
    for rule in data.get("snippets") or []:
        if not isinstance(rule.get("pattern"), str):
            raise TypeError("snippet pattern must be a string")
        re.compile(rule["pattern"])
        applies = rule.get("applies_to", ["*"])
        if not isinstance(applies, list) or not all(isinstance(item, str) for item in applies):
            raise TypeError("snippet applies_to must be a list of strings")
        if rule.get("action", "ask") not in {"allow", "ask", "deny"}:
            raise ValueError("snippet action is invalid")
    for rule in data.get("paths") or []:
        glob = rule.get("glob")
        if not isinstance(glob, str) or not glob or "\x00" in glob:
            raise TypeError("path glob must be a non-empty valid string")
        if rule.get("zone", "open") not in {"open", "no-access", "read-only", "workspace"}:
            raise ValueError("path zone is invalid")
    for rule in data.get("mcp_tools") or []:
        if not isinstance(rule.get("matcher"), str) or not rule["matcher"]:
            raise TypeError("MCP matcher must be a non-empty string")
        if rule.get("action", "ask") not in {"allow", "ask", "deny"}:
            raise ValueError("MCP action is invalid")


def _merge_pack(policy: Policy, data, pack: str,
                enforcement_class=NON_WAIVABLE_INVARIANT):
    if not isinstance(data, dict):
        return
    for i, rule in enumerate(data.get("commands") or []):
        policy.command_rules.append({
            "pattern": rule.get("pattern", ""), "action": rule.get("action", "ask"),
            "reason": rule.get("reason", ""), "id": f"{pack}:commands[{i}]",
            "enforcement_class": enforcement_class})
    for i, rule in enumerate(data.get("snippets") or []):
        policy.snippet_rules.append({
            "pattern": re.compile(rule.get("pattern", "$^")),
            "action": rule.get("action", "ask"),
            "applies_to": rule.get("applies_to") or ["*"],
            "reason": rule.get("reason", ""), "id": f"{pack}:snippets[{i}]",
            "enforcement_class": enforcement_class})
    for i, rule in enumerate(data.get("paths") or []):
        policy.path_rules.append({
            "glob": _expand(rule.get("glob", "")), "zone": rule.get("zone", "open"),
            "id": f"{pack}:paths[{i}]", "enforcement_class": enforcement_class})
    for i, rule in enumerate(data.get("mcp_tools") or []):
        policy.mcp_rules.append({
            "matcher": rule.get("matcher", ""), "action": rule.get("action", "ask"),
            "reason": rule.get("reason", ""), "id": f"{pack}:mcp[{i}]",
            "enforcement_class": enforcement_class})
    policy.settings.update(data.get("settings") or {})


# --- evaluation ---------------------------------------------------------------

def evaluate(event: ToolEvent, policy: Policy, plugin_root: str = "") -> Decision:
    cfg = resolve_settings(policy)
    if event.kind == EXEC:
        decision = _eval_exec(event, policy, plugin_root, cfg)
    elif event.kind in (WRITE, EDIT):
        decision = _eval_write(event, policy)
    elif event.kind == READ:
        decision = _eval_read(event, policy)
    elif event.kind == MCP:
        decision = _eval_mcp(event, policy)
    elif event.kind == OTHER and event.extra.get("apply_patch") \
            and event.extra.get("opaque"):
        decision = Decision(
            DENY,
            "Guardrails could not identify which files this change would affect. "
            "Ask the agent to provide a valid patch with explicit file paths.",
            "builtin:patch-targets-unknown")
    else:
        decision = Decision()
    if policy.health == policy_health.UNAVAILABLE:
        decision = Decision(
            DENY,
            "Guardrails blocked this operation because the required baseline policy "
            "could not be validated. Repair or reinstall the policy package and try again.",
            "policy:health-unavailable",
        )
        decision.prompt_eligible = False
    elif policy.health == policy_health.DEGRADED:
        routine_read = event.kind == READ and decision.action in (DEFER, ALLOW)
        if not routine_read:
            decision = Decision(
                DENY,
                "Guardrails blocked this operation because custom policy could not be "
                "validated. Only routine file reads are available until policy health is restored.",
                "policy:health-degraded",
            )
            decision.prompt_eligible = False
    if decision.rule_id in {"builtin:contextual-content", "builtin:indirect-no-effect",
                            "builtin:unparseable-no-effect"}:
        decision.confidence = "low"
        decision.prompt_eligible = False
    # strict level: reading a credential-type file is a hard deny, not an ask.
    # Symmetric to the relaxed downgrade below; applied first so deny wins if
    # both knobs are somehow set. Scoped to the credential rules (not cloud
    # placeholder reads, which are a different concern).
    if cfg.get("deny_secret_read") and decision.action == ASK \
            and decision.rule_id in _SECRET_READ_RULES:
        decision = Decision(DENY, f"{decision.reason} [strict: secret reads are "
                            f"blocked]", decision.rule_id, memo_key=decision.memo_key)
    # relaxed level: access-type asks (reading a sensitive resource) become
    # silent-with-audit. The hard denies (exfil, destruction) are untouched.
    if cfg.get("relaxed_access") and decision.action == ASK \
            and decision.rule_id in _ACCESS_ASK_RULES:
        decision = Decision(DEFER, "", decision.rule_id,
                            warnings=[f"relaxed mode: allowed without prompt "
                                      f"({decision.rule_id}) — {decision.reason}"],
                            memo_key=decision.memo_key)
    if policy.health == policy_health.DEGRADED and decision.action in (DEFER, ALLOW):
        decision.warnings.append(
            "guardrails policy health is DEGRADED; only baseline routine reads are available")
    decision.policy_revision = policy.revision
    decision.policy_health = policy.health
    if decision.memo_key:
        decision.memo_key = f"policy:{policy.revision}:{decision.memo_key}"
    return decision


def _named_arg(argv: list, flags: tuple) -> str:
    """Value of the first `-Flag value` whose flag (lowered) is in `flags`."""
    for i, a in enumerate(argv):
        if a.lower() in flags and i + 1 < len(argv):
            return argv[i + 1]
    return ""


class TargetList(list):
    """List-compatible clobber result carrying conservative completeness."""

    def __init__(self, values=(), complete=True, reason="", covered=False):
        super().__init__(values)
        self.complete = complete
        self.reason = reason
        # True when a recognized mutator was fully analyzed but legitimately
        # needs no pre-image (for example mkdir -p on an existing directory).
        self.covered = covered


def _static_shell_path(token: str) -> bool:
    """Whether a shell path can be resolved without runtime expansion."""
    return bool(token) and not any(char in token for char in "$`*?[]{}()")


def _absent_creation_root(path: str) -> str:
    """Highest absent ancestor created as part of a new literal path."""
    root = os.path.normpath(path)
    parent = os.path.dirname(root)
    while parent and parent != root and not os.path.exists(parent):
        root = parent
        parent = os.path.dirname(root)
    return root


def _covered_by_absent_root(path: str, roots: set[str]) -> bool:
    """Whether removing a planned absent ancestor also removes this path."""
    for root in roots:
        try:
            if os.path.commonpath((path, root)) == root:
                return True
        except ValueError:
            continue
    return False


def _posix_mkdir_paths(argv: list[str]) -> tuple[list[str], str]:
    """Bind the portable mkdir options needed for literal creation planning."""
    paths = []
    options = True
    i = 0
    while i < len(argv):
        token = argv[i]
        if options and token == "--":
            options = False
            i += 1
            continue
        if options and token in {
                "-p", "--parents", "-v", "--verbose", "-Z", "--context"}:
            i += 1
            continue
        if options and token.startswith("-") and len(token) > 2 \
                and not token.startswith("--") \
                and set(token[1:]).issubset({"p", "v", "Z"}):
            i += 1
            continue
        if options and token in {"-m", "--mode"}:
            if i + 1 >= len(argv):
                return [], f"mkdir option {token!r} is missing its value"
            i += 2
            continue
        if options and (token.startswith("--mode=")
                        or token.startswith("--context=")
                        or token.startswith("-m") and len(token) > 2):
            i += 1
            continue
        if options and token.startswith("-"):
            return [], f"mkdir option {token!r} is unsupported for static planning"
        if not _static_shell_path(token):
            return [], "mkdir target uses runtime expansion or a wildcard"
        paths.append(token)
        i += 1
    if not paths:
        return [], "mkdir did not identify a literal target directory"
    return paths, ""


def _powershell_directory_creation(argv: list[str]) -> bool:
    name = argv[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    if name in {"mkdir", "md"}:
        return True
    lowered = [value.lower() for value in argv]
    for index, value in enumerate(lowered[:-1]):
        if value.lstrip("-") in {"itemtype", "type"}:
            return lowered[index + 1] in {"directory", "dir"}
    return False


def clobber_targets(command: str, cwd: str = "", include_absent: bool = False,
                    dialect: str = None) -> list:
    """Existing files a shell command would overwrite/truncate: `>` redirects,
    POSIX mv/cp/tee/dd/truncate/install destinations, and the PowerShell/cmd
    write forms (Set-Content/Out-File, Copy-Item/copy /y, Move-Item/move,
    [IO.File]::WriteAllText) that carry no `>` token. Used by the adapter to
    pre-image-snapshot them before the command runs — the Bash equivalent of
    the Write/Edit pre-image. Best-effort: never raises. Over-inclusion is
    cheap (a redundant snapshot is deduped); a miss is silent data loss."""
    def _abs(tok):
        tok = tok.strip("'\"")
        p = os.path.expanduser(tok)
        if not os.path.isabs(p):
            p = os.path.join(cwd or os.getcwd(), p)
        return os.path.normpath(p)

    targets = set()
    planned_dirs = set()
    absent_dir_roots = set()
    complete = True
    incomplete_reason = ""
    covered = False
    try:
        for t in redirect_targets(command):
            targets.add(_abs(t))
    except Exception:
        pass
    try:
        parsed = extract_commands(command, dialect=dialect)
    except Exception:
        parsed = None
    if parsed:
        if FLAG_INNER_UNCERTAIN in parsed.flags and any(
                _has_mutation_evidence(payload) for payload in parsed.payloads):
            complete = False
            incomplete_reason = (
                "a recovered PowerShell payload could not be parsed well enough "
                "to identify every mutation target"
            )
        for cmd in parsed.commands:
            ops = [a for a in cmd.argv[1:] if not a.startswith("-")]
            name = cmd.name
            argv_low = [a.lower() for a in cmd.argv]
            binding = powershell_bind.bind(cmd.argv, cmd.dialect)
            if binding.recognized:
                if not binding.complete:
                    complete = False
                    incomplete_reason = incomplete_reason or binding.reason
                    continue
                covered = True
                if binding.append:
                    continue
                creates_directory = _powershell_directory_creation(cmd.argv)
                for target in binding.targets:
                    target_abs = _abs(target)
                    if name in ("copy-item", "copy", "cp", "cpi",
                                "move-item", "move", "mv", "mi") \
                            and (os.path.isdir(target_abs)
                                 or target_abs in planned_dirs):
                        for source in binding.sources:
                            destination = os.path.join(
                                target_abs, os.path.basename(source)
                            )
                            if not _covered_by_absent_root(
                                    destination, absent_dir_roots):
                                targets.add(destination)
                    elif creates_directory:
                        planned_dirs.add(target_abs)
                        if not os.path.isdir(target_abs):
                            creation_root = _absent_creation_root(target_abs)
                            absent_dir_roots.add(creation_root)
                            targets.add(creation_root)
                    else:
                        targets.add(target_abs)
                if name in ("move-item", "move", "mv", "mi"):
                    targets.update(_abs(source) for source in binding.sources)
                continue
            if name == "mkdir":
                mkdir_paths, reason = _posix_mkdir_paths(cmd.argv[1:])
                if reason:
                    complete = False
                    incomplete_reason = incomplete_reason or reason
                    continue
                covered = True
                for target in mkdir_paths:
                    target_abs = _abs(target)
                    planned_dirs.add(target_abs)
                    if not os.path.isdir(target_abs):
                        creation_root = _absent_creation_root(target_abs)
                        absent_dir_roots.add(creation_root)
                        targets.add(creation_root)
                continue
            if name == "touch":
                touch_args = list(cmd.argv[1:])
                if any(value.startswith("-") and value != "--"
                       for value in touch_args):
                    complete = False
                    incomplete_reason = incomplete_reason or \
                        "touch options are unsupported for static planning"
                    continue
                touch_paths = [value for value in touch_args if value != "--"]
                if not touch_paths or any(
                        not _static_shell_path(value) for value in touch_paths):
                    complete = False
                    incomplete_reason = incomplete_reason or \
                        "touch did not identify only literal target files"
                    continue
                covered = True
                targets.update(_abs(value) for value in touch_paths)
                continue
            if name in ("mv", "cp", "install") and len(ops) >= 2:
                dest = ops[-1]
                sources = ops[:-1]
                if not _static_shell_path(dest) or any(
                        not _static_shell_path(source) for source in sources):
                    complete = False
                    incomplete_reason = incomplete_reason or \
                        f"{name} source or destination uses runtime expansion or a wildcard"
                    continue
                dest_abs = _abs(dest)
                if os.path.isdir(dest_abs) or dest_abs in planned_dirs \
                        or dest.endswith(("/", "\\")):
                    for src in sources:
                        destination = os.path.join(
                            dest_abs, os.path.basename(src)
                        )
                        if not _covered_by_absent_root(
                                destination, absent_dir_roots):
                            targets.add(destination)
                else:
                    targets.add(dest_abs)
                if name == "mv":
                    targets.update(_abs(source) for source in sources)
            elif name == "tee" and "-a" not in cmd.argv and "--append" not in cmd.argv:
                targets.update(_abs(o) for o in ops)
            elif name == "dd":
                for a in cmd.argv[1:]:
                    if a.startswith("of=") and not a.startswith("of=/dev/"):
                        targets.add(_abs(a[3:]))
            elif name == "truncate":
                targets.update(_abs(o) for o in ops)
            elif name in ("copy", "move", "ren", "rename"):
                pos = [a for a in cmd.argv[1:]
                       if not a.startswith("-") and not _CMD_SWITCH_RE.fullmatch(a)]
                if len(pos) >= 2:
                    targets.add(_abs(pos[-1]))
    # [IO.File]::WriteAllText("path", ...) in the raw line or a wrapper payload.
    for text in [command] + (parsed.payloads if parsed else []):
        for m in _WRITEALLTEXT_RE.finditer(text):
            targets.add(_abs(m.group(1)))
    values = list(targets) if include_absent else [p for p in targets if os.path.isfile(p)]
    return TargetList(values, complete, incomplete_reason, covered=covered)


def _zone_rule_for(path: str, policy: Policy):
    p = _match_path(path)
    match = {"zone": "open", "enforcement_class": NON_WAIVABLE_INVARIANT}
    for rule in policy.path_rules:
        if fnmatch.fnmatchcase(p, _match_pattern(rule["glob"])):
            match = rule
    return match


def _zone_for(path: str, policy: Policy) -> str:
    return _zone_rule_for(path, policy)["zone"]


def _match_path(path: str) -> str:
    value = os.path.expanduser(str(path))
    value = os.path.normcase(os.path.abspath(value))
    return value.replace("\\", "/")


def _match_pattern(pattern: str) -> str:
    """Normalize path globs without turning relative anywhere-globs absolute."""
    value = os.path.expanduser(str(pattern))
    if os.path.isabs(value) or re.match(r"^[A-Za-z]:[\\/]", value):
        value = os.path.abspath(value)
    return os.path.normcase(value).replace("\\", "/")


def _is_protected(path: str, policy: Policy) -> bool:
    p = _match_path(path)
    try:
        real = _match_path(os.path.realpath(os.path.expanduser(path)))
    except OSError:
        real = p
    for glob in policy.protected_globs:
        pattern = _match_pattern(glob)
        if fnmatch.fnmatchcase(p, pattern) or fnmatch.fnmatchcase(real, pattern):
            return True
    return False


# --- exec ---------------------------------------------------------------------

_MUTATION_EVIDENCE_RE = re.compile(
    r"(?i)(?:^|[\s;|&({])(?:rm|rmdir|unlink|shred|remove-item|ri|del|erase|rd|"
    r"clear-content|clear-item|truncate|move-item|copy-item|set-content|out-file)\b"
    r"|(?:^|[;\n])\s*[A-Za-z_]\w*\s*=\s*(?:rm|rmdir|unlink|remove-item|del|rd)\b"
    r"|(?:-recurse\b[\s\S]{0,80}-force\b|--force\b)")


def _has_mutation_evidence(command: str) -> bool:
    return bool(_MUTATION_EVIDENCE_RE.search(command)
                or _PWSH_DESTRUCTIVE.search(command)
                or redirect_targets(command))


_SEARCH_VALUE_FLAGS = {
    "-A", "-B", "-C", "--after-context", "--before-context", "--context",
    "-g", "--glob", "-t", "--type", "-T", "--type-not", "-e", "--regexp",
    "-f", "--file", "--iglob", "--include", "--exclude",
}
_SEARCH_FILENAME_FLAGS = {"--files", "--files-with-matches", "--files-without-match"}
_SEARCH_PATTERN_FLAGS = {"-e", "--regexp", "-pattern"}
_SEARCH_SCOPE_FLAGS = {"-path", "-literalpath"}
_PROJECT_DIAGNOSTIC_DIRS = {
    ".github", "doc", "docs", "log", "logs", "plans", "plugin", "scripts",
    "source", "src", "test", "tests",
}
_CLOUD_SCOPE_PARTS = {"dropbox", "google drive", "google drivefs", "onedrive",
                      "sharepoint"}


def _search_shape(cmd: SimpleCommand, event: ToolEvent):
    """Return (content pattern, recursive scope, filename-only output, scopes)."""
    explicit_patterns, positionals, explicit_scopes = [], [], []
    filename_only = False
    explicit_recursive = False
    args = cmd.argv[1:]
    i = 0
    while i < len(args):
        arg = args[i]
        lowered = arg.lower()
        if lowered in _SEARCH_FILENAME_FLAGS or lowered == "-list":
            filename_only = True
            i += 1
            continue
        if lowered in _SEARCH_SCOPE_FLAGS:
            if i + 1 < len(args):
                explicit_scopes.append(args[i + 1])
                i += 2
                continue
            i += 1
            continue
        if lowered in {flag.lower() for flag in _SEARCH_VALUE_FLAGS} \
                or lowered in _SEARCH_PATTERN_FLAGS:
            if i + 1 < len(args):
                if lowered in _SEARCH_PATTERN_FLAGS:
                    explicit_patterns.append(args[i + 1])
                i += 2
                continue
            i += 1
            continue
        if any(arg.startswith(flag + "=") for flag in _SEARCH_VALUE_FLAGS
               if flag.startswith("--")):
            flag, value = arg.split("=", 1)
            if flag == "--regexp":
                explicit_patterns.append(value)
            i += 1
            continue
        if lowered in {"-r", "--recursive", "-recurse"}:
            explicit_recursive = True
            i += 1
            continue
        if arg.startswith("-"):
            short = arg[1:] if not arg.startswith("--") else ""
            if "l" in short or "L" in short:
                filename_only = True
            if "r" in short or "R" in short:
                explicit_recursive = True
            i += 1
            continue
        positionals.append(arg)
        i += 1

    pattern = explicit_patterns[0] if explicit_patterns else \
        (positionals.pop(0) if positionals else "")
    scopes = explicit_scopes + positionals
    recursive = explicit_recursive
    if cmd.name in {"rg", "ag"} and not recursive:
        if not scopes:
            recursive = True
        else:
            for scope in scopes:
                path = os.path.expanduser(scope.replace("\\", os.sep))
                if not os.path.isabs(path):
                    path = os.path.join(event.cwd or os.getcwd(), path)
                if scope in {".", "..", "/", "~"} or os.path.isdir(path):
                    recursive = True
                    break
    return pattern, recursive, filename_only, scopes


def _within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([os.path.realpath(path), root]) == root
    except ValueError:
        return False


def _project_search_is_routine(cmd: SimpleCommand, event: ToolEvent,
                               plugin_root: str) -> bool:
    """True only for a static, read-only diagnostic inside the project."""
    _pattern, recursive, filename_only, scopes = _search_shape(cmd, event)
    if not recursive or filename_only or not plugin_root:
        return False
    if redirect_targets(event.command) or _has_mutation_evidence(event.command):
        return False
    root = os.path.realpath(os.path.dirname(os.path.realpath(plugin_root)))
    cwd = os.path.realpath(event.cwd or os.getcwd())
    if not _within(cwd, root):
        return False
    candidates = scopes or [cwd]
    for raw_scope in candidates:
        scope = str(raw_scope).strip("'\"")
        if not scope or any(marker in scope for marker in ("$", "%", "SUBST_OUT")):
            return False
        if _is_secret_path(scope):
            return False
        static_prefix = re.split(r"[\*\?\[]", scope, maxsplit=1)[0] or "."
        resolved = os.path.realpath(os.path.expanduser(
            static_prefix.replace("\\", os.sep)
            if os.path.isabs(static_prefix)
            else os.path.join(cwd, static_prefix.replace("\\", os.sep))
        ))
        if not _within(resolved, root) or not os.path.exists(resolved):
            return False
        parts = {part.lower() for part in resolved.replace("\\", "/").split("/")}
        if parts & _CLOUD_SCOPE_PARTS:
            return False
        relative = os.path.relpath(resolved, root).replace("\\", "/")
        first = relative.split("/", 1)[0].lower()
        base = os.path.basename(resolved).lower()
        suffix = os.path.splitext(base)[1]
        if resolved != root and first not in _PROJECT_DIAGNOSTIC_DIRS \
                and suffix not in _DEV_SOURCE_SUFFIXES \
                and suffix not in {".md", ".txt", ".log", ".jsonl"} \
                and base not in _DEV_DOC_BASENAMES:
            return False
    return True

def _eval_exec(event: ToolEvent, policy: Policy, plugin_root: str, cfg: dict) -> Decision:
    if event.tool == "Monitor" and not event.command.strip():
        return Decision(
            DENY,
            "Guardrails could not inspect this Monitor operation because it did not "
            "contain the documented command text.",
            "builtin:monitor-opaque",
            enforcement_class=NON_WAIVABLE_INVARIANT,
        )
    # A recognized MCP shell tool whose command we couldn't read from the tool
    # input must fail closed — never let an opaque shell call through as a
    # silent allow (that was the MCP-shell bypass).
    if event.tool.startswith("mcp__") and not event.command.strip():
        return Decision(DENY, "Guardrails could not inspect this connected-service "
                              "operation. Ask the agent to use a direct, inspectable "
                              "action.", "builtin:mcp-shell-opaque")
    try:
        dialect = DIALECT_POWERSHELL if event.tool.lower() in {"powershell", "pwsh"} else None
        parsed = extract_commands(event.command, dialect=dialect)
    except ParseUncertain as exc:
        if str(exc).startswith("undecodable PowerShell") or \
                _has_mutation_evidence(event.command):
            return Decision(DENY, "Guardrails could not fully inspect a potentially "
                                  "file-changing operation. Ask the agent to use a direct, "
                                  "inspectable form.", "builtin:unparseable-mutation")
        return Decision(ALLOW, f"Uncertain syntax was treated as non-mutating ({exc}).",
                        "builtin:unparseable-no-effect")

    decisions = []

    if FLAG_INNER_UNCERTAIN in parsed.flags and any(
            _has_mutation_evidence(payload) for payload in parsed.payloads):
        decisions.append(Decision(
            DENY,
            "Guardrails recovered a file-changing PowerShell command from a wrapper, "
            "but could not parse it well enough to identify every target. Use a "
            "literal file path and try again.",
            "builtin:unparseable-mutation",
            enforcement_class=NON_WAIVABLE_INVARIANT,
        ))

    if FLAG_DECODE_PIPE in parsed.flags:
        decisions.append(Decision(DENY, "Decoding data and piping it into a shell is "
                                        "blocked (obfuscated-command pattern).",
                                  "builtin:decode-pipe"))
    if FLAG_DOWNLOAD_PIPE in parsed.flags:
        decisions.append(Decision(DENY, "Piping downloaded content into a shell "
                                        "(curl|bash) is blocked.", "builtin:download-pipe"))
    if FLAG_EVAL in parsed.flags:
        decisions.append(Decision(ASK, "eval/source of dynamic content — review carefully.",
                                  "builtin:eval"))
    if FLAG_INDIRECT in parsed.flags:
        if _has_mutation_evidence(event.command):
            decisions.append(Decision(
                DENY, "Guardrails could not identify a potentially file-changing action. "
                      "Ask the agent to use the direct command name so it can be checked.",
                "builtin:indirect-mutation"))
        else:
            decisions.append(Decision(
                ALLOW, "Unresolved command indirection had no file-changing evidence.",
                "builtin:indirect-no-effect"))

    # Scan executed code only — not search patterns (`grep "DROP TABLE" x.sql`)
    # or echoed data — so those don't false-deny. See _code_view.
    code_view = _code_view(event.command, parsed)
    if _SQL_DENY.search(code_view):
        decisions.append(Decision(DENY, "DROP/TRUNCATE statements are blocked.",
                                  "builtin:sql-drop"))
    if _SQL_DELETE.search(code_view):
        decisions.append(Decision(DENY, "DELETE without WHERE is blocked.",
                                  "builtin:sql-delete"))

    # PowerShell/.NET deletion that argv parsing can't reach (.NET methods,
    # Clear-* cmdlets). code_view already folds in decoded/inner wrapper payloads.
    if _PWSH_DESTRUCTIVE.search(code_view):
        decisions.append(Decision(DENY, "PowerShell/.NET file deletion or content "
                                        "wiping is blocked. " + ARCHIVE_REDIRECT,
                                  "builtin:pwsh-delete"))

    # credential files anywhere in the command: ask; with a network tool in the
    # same command line, that's the exfiltration shape: deny. Tokens directly
    # after -i are identity-file *usage* (ssh -i key host), not access.
    secret_hits, secret_read_hits, prev = [], [], ""
    for cmd in parsed.commands:
        prev = ""
        for tok in cmd.argv[1:]:
            t = tok.lstrip("@")  # curl -d @.env
            if t and not t.startswith("-") and prev != "-i" and _is_secret_path(t):
                name = os.path.basename(t)
                secret_hits.append(name)
                if cmd.name not in _NON_CONVERSATIONAL_FILE_COMMANDS:
                    secret_read_hits.append(name)
            prev = tok
    if secret_hits:
        names = ", ".join(sorted(set(secret_hits)))
        net = sorted({c.name for c in parsed.commands if c.name in _NETWORK_CMDS})
        if net:
            decisions.append(Decision(
                DENY, f"This command combines credential file(s) ({names}) with a "
                      f"network tool ({', '.join(net)}) — that is the shape of "
                      "credential exfiltration, so it is blocked.",
                "builtin:secret-exfil"))
        elif secret_read_hits:
            names = ", ".join(sorted(set(secret_read_hits)))
            decisions.append(Decision(
                ASK, f"Heads up: this reads credential-type file(s) ({names}), and "
                     "their contents would enter the conversation. Confirm this is "
                     "needed for the task.", "builtin:secret-file",
                memo_key=f"secret-file:{'|'.join(sorted(set(secret_read_hits)))}",
                presentation_context=DecisionContext.SENSITIVE_READ))

    for cmd in parsed.commands:
        decisions.append(_eval_simple_command(cmd, policy, plugin_root, event, cfg))

    # content rules also see payloads the command would write (heredocs, echo)
    # and the inner text of any wrapper we recursed (so secrets smuggled through
    # a -EncodedCommand / cmd /c string are scanned, not just the argv).
    for payload in extract_payloads(event.command):
        decisions.append(_snippet_check(payload, "", policy))
    for payload in parsed.payloads:
        decisions.append(_snippet_check(payload, "", policy))

    return worst(decisions)


def _eval_simple_command(cmd: SimpleCommand, policy: Policy, plugin_root: str,
                         event: ToolEvent, cfg: dict = None) -> Decision:
    name = cmd.name
    cfg = cfg or {}

    # Trusted agw verbs. Bare names must resolve to the exact active package;
    # maintained adapters normally expand the short form before evaluation.
    if name in {"agw", "agw.py", "agw.cmd"}:
        head = cmd.argv[0]
        root = os.path.realpath(plugin_root) if plugin_root else ""
        expected_rel = {
            "agw": os.path.join("bin", "agw"),
            "agw.cmd": os.path.join("bin", "agw.cmd"),
            "agw.py": os.path.join("scripts", "agw", "agw.py"),
        }[name]
        expected = os.path.realpath(os.path.join(root, expected_rel)) if root else ""
        if "/" in head or "\\" in head or os.path.isabs(head):
            real = os.path.realpath(head if os.path.isabs(head)
                                    else os.path.join(event.cwd or ".", head))
        else:
            resolved = shutil.which(head)
            real = os.path.realpath(resolved) if resolved else ""
        try:
            trusted = bool(real and expected and root) and \
                os.path.commonpath([real, root]) == root and \
                os.path.normcase(real) == os.path.normcase(expected)
        except ValueError:
            trusted = False
        if not trusted:
            return Decision(
                DENY,
                "This launcher could not be verified as the active packaged "
                "Guardrails launcher.",
                "builtin:agw-impostor",
                enforcement_class=NON_WAIVABLE_INVARIANT,
                presentation_context=DecisionContext.AGW_UNKNOWN,
            )
        args = cmd.argv[1:]
        verb = next((a for a in args if not a.startswith("-")), "")
        if not verb and any(a in {"-h", "--help", "-V", "--version"} for a in args):
            return Decision(ALLOW, "", "builtin:agw-info")
        if not verb:
            return Decision(
                ASK, "No documented Guardrails operation was supplied.",
                "builtin:agw-empty",
                enforcement_class=NON_WAIVABLE_INVARIANT,
                presentation_context=DecisionContext.AGW_UNKNOWN,
            )
        if verb in AGW_ASK_VERBS:
            context = (DecisionContext.AGW_ARCHIVE if verb == "prune"
                       else DecisionContext.AGW_MUTATION)
            return Decision(
                ASK, f"Guardrails {verb} needs confirmation.", "builtin:agw-ask",
                enforcement_class=NON_WAIVABLE_INVARIANT,
                presentation_context=context,
            )
        if verb in AGW_READ_ONLY_VERBS or verb in AGW_SAFE_MUTATING_VERBS:
            return Decision(ALLOW, "", "builtin:agw")
        return Decision(
            ASK, "This Guardrails operation is not recognized.",
            "builtin:agw-unknown",
            enforcement_class=NON_WAIVABLE_INVARIANT,
            presentation_context=DecisionContext.AGW_UNKNOWN,
        )

    # ---- built-in semantic deny table ----
    if name in _DELETE_VERBS or name in _SECURE_WIPE_VERBS:
        # Regenerable build/dependency dirs are routine to delete and pointless
        # (and huge) to archive — allow deletion when every path operand is
        # regenerable. Only the general removers get this; dir-only verbs
        # (rmdir/rd/unlink) and shred (secure-wipe, not cleanup) always deny.
        regen = cfg.get("regenerable")
        if name in _REGEN_OK_VERBS and regen:
            ops = [a for a in cmd.argv[1:]
                   if not a.startswith("-")
                   and not (name in _CMD_SWITCH_VERBS and _CMD_SWITCH_RE.fullmatch(a))]
            if ops and all(_is_regenerable(o, regen) for o in ops):
                return Decision(ALLOW, "", "builtin:rm-regenerable")
        return Decision(DENY, ARCHIVE_REDIRECT, "builtin:rm")
    if name in _MOVE_VERBS and any(
            a.lower().strip("'\"") in _NULL_SINKS for a in cmd.argv[1:]):
        return Decision(DENY, "Moving or renaming a file into a null sink (NUL/$null) "
                              "destroys it. " + ARCHIVE_REDIRECT, "builtin:move-null")
    if name == "find" and ("-delete" in cmd.argv):
        return Decision(DENY, ARCHIVE_REDIRECT, "builtin:find-delete")
    if name == "dd" and any(a.startswith("of=/dev/") for a in cmd.argv):
        return Decision(DENY, "Writing to raw devices is blocked.", "builtin:dd")
    if name.startswith("mkfs") or name in ("fdisk", "parted", "diskpart"):
        return Decision(DENY, "Disk/partition tools are blocked.", "builtin:disk")
    if name in ("sudo", "doas", "pkexec"):
        return Decision(DENY, "Privilege escalation is blocked in agent sessions.",
                        "builtin:sudo")
    if name in ("chmod", "chown") and any(a in ("-R", "-r") or
                                          (a.startswith("-") and "R" in a) for a in cmd.argv):
        if name == "chown" or "777" in cmd.argv:
            return Decision(DENY, "Recursive ownership/permission changes are blocked.",
                            "builtin:chmod")
        return Decision(ASK, "Recursive permission change — review scope.", "builtin:chmod-r")
    if name == "git":
        return _eval_git(cmd)
    if name in ("python", "python3", "perl", "ruby", "node", "php"):
        flag = "-c" if name.startswith("py") or name == "php" else "-e"
        if flag in cmd.argv or "-e" in cmd.argv or "-c" in cmd.argv:
            code = " ".join(cmd.argv)
            if _INTERPRETER_DESTRUCTIVE.search(code):
                return Decision(DENY, "Inline interpreter code performing file deletion is "
                                      "blocked. " + ARCHIVE_REDIRECT,
                                "builtin:interpreter-delete")
    if name == "trash" or name == "gio" and "trash" in cmd.argv:
        return Decision(ALLOW, "", "builtin:trash-ok")

    # recursive keyword sweeps for credentials: ask, with the why
    if name in ("grep", "egrep", "fgrep", "rg", "ripgrep", "ag", "ack",
                "select-string"):
        pattern, recursive, filename_only, _scopes = _search_shape(cmd, event)
        if recursive and not filename_only and _HUNT_RE.search(pattern):
            if _project_search_is_routine(cmd, event, plugin_root):
                return Decision(
                    ALLOW,
                    "A read-only diagnostic search stayed inside verified project files.",
                    "builtin:project-diagnostic-search",
                )
            return Decision(ASK, "This recursively searches for credential-related "
                                 "keywords (password/secret/key...). Fine for "
                                 "debugging, but confirm it's intended — the matches "
                                 "would land in the conversation.",
                            "builtin:credential-hunt", memo_key=f"credential-hunt:{pattern}",
                            enforcement_class=NON_WAIVABLE_INVARIANT,
                            presentation_context=DecisionContext.CREDENTIAL_SEARCH)

    # content prescan for plain readers: "hey, this might contain a password"
    if name in _READER_CMDS:
        checked = 0
        for tok in cmd.argv[1:]:
            if tok.startswith("-") or checked >= 2:
                continue
            p = os.path.expanduser(tok.replace("\\", os.sep))
            if not os.path.isabs(p):
                p = os.path.join(event.cwd or os.getcwd(), p)
            if os.path.isfile(p):
                checked += 1
                finding = _prescan_file(p)
                if finding:
                    marker, contextual_low = finding
                    if contextual_low:
                        return Decision(ALLOW, "Context-only safety vocabulary in a "
                                             "development or documentation file did not "
                                             "require approval.",
                                        "builtin:contextual-content")
                    return Decision(ASK, f"Heads up: {os.path.basename(tok)} looks "
                                         f"like it contains {marker}. Reading it "
                                         "pulls that into the conversation — confirm "
                                         "this is needed.", "builtin:content-prescan",
                                    memo_key=f"content-prescan:{p}",
                                    presentation_context=DecisionContext.SENSITIVE_READ)

    # protected-path mutation via shell
    if name in _MUTATOR_CMDS or name in ("rm",):
        for token in cmd.argv[1:]:
            if not token.startswith("-") and _is_protected(token, policy):
                return Decision(DENY, f"'{token}' is a guardrails-protected path.",
                                "builtin:protected-path")

    # ---- policy pack command rules ----
    joined = cmd.joined()
    base_joined = " ".join([name] + cmd.argv[1:])  # normalized argv0
    verdicts = []
    for rule in policy.command_rules:
        pat = rule["pattern"]
        if fnmatch.fnmatch(joined, pat) or fnmatch.fnmatch(base_joined, pat) \
                or joined == pat or base_joined == pat:
            verdicts.append(Decision(rule["action"], rule["reason"] or
                                     f"matched policy rule {rule['id']}", rule["id"],
                                     enforcement_class=rule["enforcement_class"]))
    return worst(verdicts) if verdicts else Decision()


def _eval_git(cmd: SimpleCommand) -> Decision:
    args = cmd.argv[1:]
    sub = next((a for a in args if not a.startswith("-")), "")
    argset = set(args)
    if sub == "push" and ({"--force", "-f"} & argset) and "--force-with-lease" not in argset:
        return Decision(DENY, "git push --force is blocked (history destruction). Use "
                              "--force-with-lease after review.", "builtin:git-force")
    if sub == "reset" and "--hard" in argset:
        return Decision(DENY, "git reset --hard discards work. Use `agw snapshot .` first, "
                              "or `git stash`.", "builtin:git-reset-hard")
    if sub == "clean" and any(a.startswith("-") and "f" in a for a in args):
        return Decision(DENY, "git clean -f deletes untracked files. Use `agw archive` for "
                              "specific files.", "builtin:git-clean")
    if sub == "checkout" and "--" in args:
        return Decision(ASK, "git checkout -- discards uncommitted changes to these files.",
                        "builtin:git-checkout")
    if sub == "restore" and "--staged" not in argset:
        return Decision(ASK, "git restore discards uncommitted changes.",
                        "builtin:git-restore")
    if sub == "stash" and ({"drop", "clear"} & argset):
        return Decision(ASK, "Dropping stashes loses work permanently.", "builtin:git-stash")
    if sub == "branch" and "-D" in args:
        return Decision(ASK, "Force-deleting a branch can lose unmerged commits.",
                        "builtin:git-branch")
    return Decision()


# --- write / edit -------------------------------------------------------------

SHRINK_GUARD_MIN = 64 * 1024     # only guard files larger than this
SHRINK_GUARD_RATIO = 0.2         # new content < 20% of old size → ask


def _eval_write(event: ToolEvent, policy: Policy) -> Decision:
    decisions = []
    for path in event.paths:
        p = os.path.abspath(os.path.expanduser(path))
        if _is_protected(p, policy):
            decisions.append(Decision(DENY, f"'{p}' is a guardrails-protected path "
                                            "(plugin, policies, archive store, or "
                                            "credentials).", "builtin:protected-path"))
            continue
        zone_rule = _zone_rule_for(p, policy)
        zone = zone_rule["zone"]
        if zone == "no-access":
            decisions.append(Decision(
                DENY, f"'{p}' is in a no-access zone.", "policy:zone",
                enforcement_class=zone_rule["enforcement_class"]))
            continue
        if zone == "read-only":
            decisions.append(Decision(
                DENY, f"'{p}' is in a read-only zone.", "policy:zone",
                enforcement_class=zone_rule["enforcement_class"]))
            continue

        if prof.is_gdoc_stub(p):
            decisions.append(Decision(DENY, "This is a Google Docs pointer stub — it has no "
                                            "document content and editing it corrupts the "
                                            "link. Use the Drive connector to export the "
                                            "doc through a Google connector/export workflow.",
                                      "builtin:gdoc-stub"))
            continue
        if prof.is_placeholder(p):
            decisions.append(Decision(DENY, "This file is a cloud-only placeholder — its "
                                            "local content is not fully present, and "
                                            "editing it can corrupt the cloud copy. "
                                            "Hydrate it first (mark 'Always keep on this "
                                            "device' / 'Available offline').",
                                      "builtin:placeholder"))
            continue
        if prof.is_sync_artifact(p):
            decisions.append(Decision(ASK, "This looks like a sync conflict/lock artifact — "
                                           "modifying it can break sync reconciliation.",
                                      "builtin:sync-artifact"))

        # shrink guard (full-overwrite events only)
        if event.kind == WRITE and event.content:
            try:
                old = os.path.getsize(p)
            except OSError:
                old = 0
            if old > SHRINK_GUARD_MIN and len(event.content.encode("utf-8", "replace")) \
                    < old * SHRINK_GUARD_RATIO:
                decisions.append(Decision(ASK, f"This write shrinks {os.path.basename(p)} "
                                               f"from {old} bytes to a fraction of its size "
                                               "— signature of a truncated-read corruption. "
                                               "Verify the full content was read.",
                                          "builtin:shrink-guard"))

        ws_profile = prof.detect(p)
        ext = os.path.splitext(p)[1].lower()
        if zone == "workspace" and ext in prof.PROPRIETARY_EXTS \
                and "_workspace" not in p:
            decisions.append(Decision(ASK, "Direct writes to Office files in a workspace "
                                           "zone bypass CRUA. Use `agw checkout` / "
                                           "`agw publish` instead.", "builtin:crua"))
        decisions.append(_snippet_check(event.content, p, policy))
        if ws_profile.sync_provider:
            decisions.append(Decision(DEFER, "",
                                      warnings=[f"note: '{os.path.basename(p)}' is in a "
                                                f"{ws_profile.name} synced folder"]))
    return worst(decisions)


def _snippet_check(content: str, path: str, policy: Policy) -> Decision:
    if not content:
        return Decision()
    verdicts = []
    base = os.path.basename(path) if path else ""
    for rule in policy.snippet_rules:
        applies = any(fnmatch.fnmatch(base or "*", g) for g in rule["applies_to"])
        if applies and rule["pattern"].search(content):
            verdicts.append(Decision(rule["action"],
                                     rule["reason"] or f"content matched {rule['id']}",
                                     rule["id"],
                                     enforcement_class=rule["enforcement_class"]))
    return worst(verdicts) if verdicts else Decision()


# --- read ---------------------------------------------------------------------

def _eval_read(event: ToolEvent, policy: Policy) -> Decision:
    decisions = []
    for path in event.paths:
        p = os.path.abspath(os.path.expanduser(path))
        zone_rule = _zone_rule_for(p, policy)
        zone = zone_rule["zone"]
        if zone == "no-access":
            decisions.append(Decision(
                DENY, f"'{p}' is in a no-access zone.", "policy:zone",
                enforcement_class=zone_rule["enforcement_class"]))
            continue
        if prof.is_placeholder(p):
            decisions.append(Decision(ASK, "This file is a cloud-only placeholder; reading "
                                           "it here may return truncated content (or "
                                           "trigger a download). Hydrate it first for "
                                           "reliable results.", "builtin:placeholder-read",
                                      memo_key=f"placeholder-read:{p}",
                                      presentation_context=DecisionContext.SENSITIVE_READ))
            continue
        if _is_secret_path(p):
            decisions.append(Decision(ASK, f"'{os.path.basename(p)}' is a credential-type "
                                           "file (keys/secrets/tokens). Its contents would "
                                           "enter the conversation — confirm this is "
                                           "needed for the task.", "builtin:secret-file",
                                      memo_key=f"secret-file:{p}",
                                      presentation_context=DecisionContext.SENSITIVE_READ))
            continue
        finding = _prescan_file(p)
        if finding:
            marker, contextual_low = finding
            if contextual_low:
                decisions.append(Decision(
                    ALLOW, "Context-only safety vocabulary in a development or "
                           "documentation file did not require approval.",
                    "builtin:contextual-content"))
                continue
            decisions.append(Decision(ASK, f"Heads up: this file looks like it contains "
                                           f"{marker}. Reading it pulls that into the "
                                           "conversation — confirm this is needed.",
                                      "builtin:content-prescan", memo_key=f"content-prescan:{p}",
                                      presentation_context=DecisionContext.SENSITIVE_READ))
    return worst(decisions)


# --- mcp ----------------------------------------------------------------------

# Destructive / removal verbs that may appear ANYWHERE in a connector tool's
# name. `allow_cowork_file_delete` and `bulk_purge_v2` must be caught as
# readily as `delete_file`, so we tokenize the name rather than prefix-match it
# (a prefix check let `allow_cowork_file_delete` through because it starts with
# "allow", not "delete").
_MCP_DESTROY_VERBS = {"delete", "destroy", "purge", "trash", "erase", "wipe",
                      "shred", "rm", "rmdir", "truncate", "drop"}
_MCP_REMOVE_VERBS = {"remove", "unlink", "discard", "detach"}
_MCP_MUTATION_VERBS = {
    "add", "approve", "assign", "close", "convert", "copy", "create",
    "disable", "edit", "enable", "forward", "grant", "invite", "lock",
    "mark", "merge", "move", "publish", "react", "rename", "reopen",
    "replace", "reply", "revoke", "schedule", "send", "set", "share",
    "submit", "truncate", "unassign", "unlock", "unresolve", "update",
    "upload", "write",
}
_MCP_MUTATION_TOKEN_GROUPS = (
    # `resolve_shortlink` is a read-only lookup, while resolving a review
    # thread changes remote state. Require the complete side-effect shape.
    {"resolve", "review", "thread"},
)
# Safe verbs that neutralize a destructive-sounding token, so read-only or
# recovery tools aren't blocked: restore_from_trash, list_deleted_files,
# undelete_item, get_trash.
_MCP_RECOVERY_VERBS = {"restore", "undelete", "undo", "recover"}
_MCP_READ_VERBS = {"list", "get", "search", "find", "read", "view", "fetch",
                   "describe", "count"}


def _mcp_name_tokens(tool: str) -> set:
    """Lowercase word tokens of a connector tool's short name, splitting on
    both snake_case and camelCase: `allow_cowork_file_delete` -> {allow,
    cowork, file, delete}; `deleteFileForever` -> {delete, file, forever}."""
    short = tool.split("__")[-1]
    short = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", short)
    return {t for t in re.split(r"[^A-Za-z0-9]+", short.lower()) if t}


def _eval_mcp(event: ToolEvent, policy: Policy) -> Decision:
    tool = event.tool
    verdicts = []
    for rule in policy.mcp_rules:
        if fnmatch.fnmatch(tool, rule["matcher"]):
            verdicts.append(Decision(rule["action"], rule["reason"] or
                                     f"matched {rule['id']}", rule["id"],
                                     enforcement_class=rule["enforcement_class"]))
    if not verdicts:
        tokens = _mcp_name_tokens(tool)
        destructive = tokens & _MCP_DESTROY_VERBS
        recovery = bool(tokens & _MCP_RECOVERY_VERBS)
        recovery_trash = recovery and destructive == {"trash"}
        read_trash = destructive == {"trash"} and bool(tokens & _MCP_READ_VERBS)
        if destructive and not recovery_trash and not read_trash:
            verdicts.append(Decision(DENY, "This connector tool performs or enables a "
                                           "delete/destroy operation, which is blocked "
                                           "(CRUA: archive instead of deleting).",
                                     "builtin:mcp-delete"))
        elif tokens & _MCP_REMOVE_VERBS:
            verdicts.append(Decision(
                ASK,
                "This connector tool performs a remove/unlink operation — confirm intent.",
                "builtin:mcp-remove",
                presentation_context=DecisionContext.CONNECTED_SERVICE,
            ))
        elif (tokens & _MCP_MUTATION_VERBS) or any(
                group <= tokens for group in _MCP_MUTATION_TOKEN_GROUPS):
            verdicts.append(Decision(
                ASK,
                "This action creates or changes information in a connected service. "
                "Confirm that the external change is intended.",
                "builtin:mcp-mutation",
                presentation_context=DecisionContext.CONNECTED_SERVICE,
            ))
    return worst(verdicts) if verdicts else Decision()
