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

from . import profiles as prof
from .events import ALLOW, ASK, DENY, DEFER, EDIT, EXEC, MCP, READ, WRITE, \
    Decision, ToolEvent, worst
from .shellparse import FLAG_DECODE_PIPE, FLAG_DOWNLOAD_PIPE, FLAG_EVAL, \
    FLAG_INDIRECT, ParseUncertain, SimpleCommand, extract_commands, extract_payloads, \
    redirect_targets

ARCHIVE_REDIRECT = ("Deletion is disabled by agentic-guardrails. Use `agw archive <path>` "
                    "instead — it moves files to the archive store and is fully reversible "
                    "with `agw restore`. (User: to delete permanently anyway, run the "
                    "command yourself in a terminal.)")

# agw verbs the agent may run without prompts; everything else asks.
AGW_ALLOWED_VERBS = {"scan", "checkout", "convert", "diff", "archive", "move", "rename",
                     "snapshot", "restore", "undo", "status", "log", "doctor", "init",
                     "publish", "office"}
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

_NETWORK_CMDS = {"curl", "wget", "nc", "ncat", "netcat", "scp", "sftp", "rsync",
                 "ssh", "ftp", "telnet", "socat"}
_READER_CMDS = {"cat", "head", "tail", "less", "more", "bat", "strings"}

_HUNT_RE = re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|token|credential)")

_PRESCAN_BYTES = 64 * 1024
_PRESCAN_MARKERS = (
    ("a private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("an AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("an API token", re.compile(
        r"\bgh[pos]_[A-Za-z0-9]{20,}|\bsk-[A-Za-z0-9_-]{20,}"
        r"|\bxox[bpoars]-[A-Za-z0-9-]{10,}")),
    ("a hardcoded password", re.compile(
        r"(?i)\b(?:password|passwd|pwd)\s*[=:]\s*[\"'][^\"']{6,}[\"']")),
    ("a credential assignment", re.compile(
        r"(?m)^[A-Za-z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_?KEY)[A-Za-z0-9_]*\s*=\s*\S{6,}")),
    ("a confidentiality marking", re.compile(
        r"(?i)\b(?:confidential|do not distribute|internal use only|trade secret)\b")),
)


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
    for label, rx in _PRESCAN_MARKERS:
        if rx.search(text):
            return label
    return None

_INTERPRETER_DESTRUCTIVE = re.compile(
    r"os\.(remove|unlink|rmdir|removedirs)|shutil\.rmtree|\.unlink\(|send2trash"
    r"|\b(rmSync|rmdirSync|unlinkSync|rm_rf|rm_r)\b|\.rm\s*\(|FileUtils\.(rm|remove)"
    r"|unlink\s", re.IGNORECASE)

_SQL_DENY = re.compile(r"\b(DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE?)\b", re.IGNORECASE)
_SQL_DELETE = re.compile(r"\bDELETE\s+FROM\b(?![\s\S]*\bWHERE\b)", re.IGNORECASE)

_MUTATOR_CMDS = {"mv", "cp", "tee", "sed", "touch", "ln", "install", "rsync", "truncate"}

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

# Named enforcement levels. Each expands to defaults for the individual knobs;
# explicit settings/env knobs override. `standard` is the safe default.
_LEVELS = {
    "strict":   {"enforcement": "enforce", "session_memory": False,
                 "regenerable_rm": False, "relaxed_access": False},
    "standard": {"enforcement": "enforce", "session_memory": True,
                 "regenerable_rm": True,  "relaxed_access": False},
    "relaxed":  {"enforcement": "enforce", "session_memory": True,
                 "regenerable_rm": True,  "relaxed_access": True},
    "observe":  {"enforcement": "observe", "session_memory": True,
                 "regenerable_rm": True,  "relaxed_access": False},
}
_DEFAULT_LEVEL = "standard"
_BOOL_KNOBS = {"session_memory", "regenerable_rm", "relaxed_access"}


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
               "AGW_REGENERABLE_RM": "regenerable_rm", "AGW_RELAXED_ACCESS": "relaxed_access"}
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


def _expand(glob: str) -> str:
    return os.path.expanduser(glob)


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

    pack_files = []
    if plugin_root:
        pol_dir = os.path.join(plugin_root, "policies")
        if os.path.isdir(pol_dir):
            for name in sorted(os.listdir(pol_dir)):
                if name.endswith((".yaml", ".yml")):
                    pack_files.append(os.path.join(pol_dir, name))
            sub = os.path.join(pol_dir, "content-rules.d")
            if os.path.isdir(sub):
                pack_files += [os.path.join(sub, n) for n in sorted(os.listdir(sub))
                               if n.endswith((".yaml", ".yml"))]
    local = os.path.join(agw_home, "policies.d")
    if os.path.isdir(local):
        pack_files += [os.path.join(local, n) for n in sorted(os.listdir(local))
                       if n.endswith((".yaml", ".yml"))]

    for path in pack_files:
        try:
            _merge_pack(policy, _load_yaml(path), os.path.basename(path))
        except Exception:
            policy.degraded.append(os.path.basename(path))
    return policy


def _load_yaml(path: str):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except ImportError:
        from . import miniyaml
        return miniyaml.loads(text)


def _merge_pack(policy: Policy, data, pack: str):
    if not isinstance(data, dict):
        return
    for i, rule in enumerate(data.get("commands") or []):
        policy.command_rules.append({
            "pattern": rule.get("pattern", ""), "action": rule.get("action", "ask"),
            "reason": rule.get("reason", ""), "id": f"{pack}:commands[{i}]"})
    for i, rule in enumerate(data.get("snippets") or []):
        policy.snippet_rules.append({
            "pattern": re.compile(rule.get("pattern", "$^")),
            "action": rule.get("action", "ask"),
            "applies_to": rule.get("applies_to") or ["*"],
            "reason": rule.get("reason", ""), "id": f"{pack}:snippets[{i}]"})
    for i, rule in enumerate(data.get("paths") or []):
        policy.path_rules.append({
            "glob": _expand(rule.get("glob", "")), "zone": rule.get("zone", "open"),
            "id": f"{pack}:paths[{i}]"})
    for i, rule in enumerate(data.get("mcp_tools") or []):
        policy.mcp_rules.append({
            "matcher": rule.get("matcher", ""), "action": rule.get("action", "ask"),
            "reason": rule.get("reason", ""), "id": f"{pack}:mcp[{i}]"})
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
    else:
        decision = Decision()
    # relaxed level: access-type asks (reading a sensitive resource) become
    # silent-with-audit. The hard denies (exfil, destruction) are untouched.
    if cfg.get("relaxed_access") and decision.action == ASK \
            and decision.rule_id in _ACCESS_ASK_RULES:
        decision = Decision(DEFER, "", decision.rule_id,
                            warnings=[f"relaxed mode: allowed without prompt "
                                      f"({decision.rule_id}) — {decision.reason}"],
                            memo_key=decision.memo_key)
    if policy.degraded and decision.action in (DEFER, ALLOW):
        decision.warnings.append(
            f"guardrails: policy pack(s) failed to load: {', '.join(policy.degraded)}")
    return decision


def clobber_targets(command: str, cwd: str = "") -> list:
    """Existing files a shell command would overwrite/truncate: `>` redirects
    plus mv/cp/tee/dd/truncate/install destinations. Used by the adapter to
    pre-image-snapshot them before the command runs — the Bash equivalent of
    the Write/Edit pre-image. Best-effort: never raises."""
    def _abs(tok):
        p = os.path.expanduser(tok)
        if not os.path.isabs(p):
            p = os.path.join(cwd or os.getcwd(), p)
        return os.path.normpath(p)

    targets = set()
    try:
        for t in redirect_targets(command):
            targets.add(_abs(t))
    except Exception:
        pass
    try:
        parsed = extract_commands(command)
    except Exception:
        parsed = None
    if parsed:
        for cmd in parsed.commands:
            ops = [a for a in cmd.argv[1:] if not a.startswith("-")]
            name = cmd.name
            if name in ("mv", "cp", "install") and len(ops) >= 2:
                dest = ops[-1]
                dest_abs = _abs(dest)
                if os.path.isdir(dest_abs):
                    for src in ops[:-1]:
                        targets.add(os.path.join(dest_abs, os.path.basename(src)))
                else:
                    targets.add(dest_abs)
            elif name == "tee" and "-a" not in cmd.argv and "--append" not in cmd.argv:
                targets.update(_abs(o) for o in ops)
            elif name == "dd":
                for a in cmd.argv[1:]:
                    if a.startswith("of=") and not a.startswith("of=/dev/"):
                        targets.add(_abs(a[3:]))
            elif name == "truncate":
                targets.update(_abs(o) for o in ops)
    return [p for p in targets if os.path.isfile(p)]


def _zone_for(path: str, policy: Policy) -> str:
    p = os.path.abspath(os.path.expanduser(path))
    zone = "open"
    for rule in policy.path_rules:
        if fnmatch.fnmatch(p, rule["glob"]):
            zone = rule["zone"]
    return zone


def _is_protected(path: str, policy: Policy) -> bool:
    p = os.path.abspath(os.path.expanduser(path))
    try:
        real = os.path.realpath(p)
    except OSError:
        real = p
    for glob in policy.protected_globs:
        if fnmatch.fnmatch(p, glob) or fnmatch.fnmatch(real, glob):
            return True
    return False


# --- exec ---------------------------------------------------------------------

def _eval_exec(event: ToolEvent, policy: Policy, plugin_root: str, cfg: dict) -> Decision:
    try:
        parsed = extract_commands(event.command)
    except ParseUncertain as exc:
        return Decision(ASK, f"guardrails could not confidently parse this command "
                             f"({exc}); approve only if you understand what it does.",
                        "builtin:unparseable")

    decisions = []

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
        decisions.append(Decision(ASK, "Command name comes from a variable or substitution "
                                       "(indirection) — review carefully.",
                                  "builtin:indirect"))

    raw = event.command
    if _SQL_DENY.search(raw):
        decisions.append(Decision(DENY, "DROP/TRUNCATE statements are blocked.",
                                  "builtin:sql-drop"))
    if _SQL_DELETE.search(raw):
        decisions.append(Decision(DENY, "DELETE without WHERE is blocked.",
                                  "builtin:sql-delete"))

    # credential files anywhere in the command: ask; with a network tool in the
    # same command line, that's the exfiltration shape: deny. Tokens directly
    # after -i are identity-file *usage* (ssh -i key host), not access.
    secret_hits, prev = [], ""
    for cmd in parsed.commands:
        prev = ""
        for tok in cmd.argv[1:]:
            t = tok.lstrip("@")  # curl -d @.env
            if t and not t.startswith("-") and prev != "-i" and _is_secret_path(t):
                secret_hits.append(os.path.basename(t))
            prev = tok
    if secret_hits:
        names = ", ".join(sorted(set(secret_hits)))
        net = sorted({c.name for c in parsed.commands if c.name in _NETWORK_CMDS})
        if net:
            decisions.append(Decision(
                DENY, f"This command combines credential file(s) ({names}) with a "
                      f"network tool ({', '.join(net)}) — that is the shape of "
                      "credential exfiltration, so it is blocked. If this is "
                      "legitimate, the user can run it themselves.",
                "builtin:secret-exfil"))
        else:
            decisions.append(Decision(
                ASK, f"Heads up: this reads credential-type file(s) ({names}), and "
                     "their contents would enter the conversation. Confirm this is "
                     "needed for the task.", "builtin:secret-file",
                memo_key=f"secret-file:{'|'.join(sorted(set(secret_hits)))}"))

    for cmd in parsed.commands:
        decisions.append(_eval_simple_command(cmd, policy, plugin_root, event, cfg))

    # content rules also see payloads the command would write (heredocs, echo)
    for payload in extract_payloads(event.command):
        decisions.append(_snippet_check(payload, "", policy))

    return worst(decisions)


def _eval_simple_command(cmd: SimpleCommand, policy: Policy, plugin_root: str,
                         event: ToolEvent, cfg: dict = None) -> Decision:
    name = cmd.name
    cfg = cfg or {}

    # trusted agw verbs
    if name == "agw" or name == "agw.py":
        head = cmd.argv[0]
        if "/" in head or "\\" in head:
            real = os.path.realpath(head if os.path.isabs(head)
                                    else os.path.join(event.cwd or ".", head))
            if plugin_root and not real.startswith(os.path.realpath(plugin_root)):
                return Decision(DENY, "An `agw` outside the guardrails plugin is not "
                                      "trusted.", "builtin:agw-impostor")
        verb = next((a for a in cmd.argv[1:] if not a.startswith("-")), "")
        if verb in AGW_ASK_VERBS:
            return Decision(ASK, f"agw {verb}: {AGW_ASK_VERBS[verb]}", "builtin:agw-ask")
        if verb in AGW_ALLOWED_VERBS:
            return Decision(ALLOW, "", "builtin:agw")
        return Decision(ASK, f"unknown agw verb '{verb}'", "builtin:agw-unknown")

    # ---- built-in semantic deny table ----
    if name in ("rm", "rmdir", "shred", "unlink"):
        # Regenerable build/dependency dirs are routine to delete and pointless
        # (and huge) to archive — allow rm of them when every path operand is
        # regenerable. shred still denies (it's about secure-wipe, not cleanup).
        regen = cfg.get("regenerable")
        if name == "rm" and regen:
            ops = [a for a in cmd.argv[1:] if not a.startswith("-")]
            if ops and all(_is_regenerable(o, regen) for o in ops):
                return Decision(ALLOW, "", "builtin:rm-regenerable")
        return Decision(DENY, ARCHIVE_REDIRECT, "builtin:rm")
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
    if name in ("grep", "egrep", "rg", "ag", "ack"):
        recursive = name in ("rg", "ag") or any(
            a in ("-r", "-R", "--recursive") or
            (a.startswith("-") and not a.startswith("--") and
             any(ch in "rR" for ch in a[1:]))
            for a in cmd.argv[1:])
        pattern = next((a for a in cmd.argv[1:] if not a.startswith("-")), "")
        if recursive and _HUNT_RE.search(pattern):
            return Decision(ASK, "This recursively searches for credential-related "
                                 "keywords (password/secret/key...). Fine for "
                                 "debugging, but confirm it's intended — the matches "
                                 "would land in the conversation.",
                            "builtin:credential-hunt", memo_key=f"credential-hunt:{pattern}")

    # content prescan for plain readers: "hey, this might contain a password"
    if name in _READER_CMDS:
        checked = 0
        for tok in cmd.argv[1:]:
            if tok.startswith("-") or checked >= 2:
                continue
            p = os.path.expanduser(tok)
            if not os.path.isabs(p):
                p = os.path.join(event.cwd or os.getcwd(), p)
            if os.path.isfile(p):
                checked += 1
                marker = _prescan_file(p)
                if marker:
                    return Decision(ASK, f"Heads up: {os.path.basename(tok)} looks "
                                         f"like it contains {marker}. Reading it "
                                         "pulls that into the conversation — confirm "
                                         "this is needed.", "builtin:content-prescan",
                                    memo_key=f"content-prescan:{p}")

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
                                     f"matched policy rule {rule['id']}", rule["id"]))
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
        zone = _zone_for(p, policy)
        if zone == "no-access":
            decisions.append(Decision(DENY, f"'{p}' is in a no-access zone.", "policy:zone"))
            continue
        if zone == "read-only":
            decisions.append(Decision(DENY, f"'{p}' is in a read-only zone.", "policy:zone"))
            continue

        if prof.is_gdoc_stub(p):
            decisions.append(Decision(DENY, "This is a Google Docs pointer stub — it has no "
                                            "document content and editing it corrupts the "
                                            "link. Use the Drive connector to export the "
                                            "doc (see the gdocs-bridge skill).",
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
                                     rule["id"]))
    return worst(verdicts) if verdicts else Decision()


# --- read ---------------------------------------------------------------------

def _eval_read(event: ToolEvent, policy: Policy) -> Decision:
    decisions = []
    for path in event.paths:
        p = os.path.abspath(os.path.expanduser(path))
        zone = _zone_for(p, policy)
        if zone == "no-access":
            decisions.append(Decision(DENY, f"'{p}' is in a no-access zone.", "policy:zone"))
            continue
        if prof.is_placeholder(p):
            decisions.append(Decision(ASK, "This file is a cloud-only placeholder; reading "
                                           "it here may return truncated content (or "
                                           "trigger a download). Hydrate it first for "
                                           "reliable results.", "builtin:placeholder-read",
                                      memo_key=f"placeholder-read:{p}"))
            continue
        if _is_secret_path(p):
            decisions.append(Decision(ASK, f"'{os.path.basename(p)}' is a credential-type "
                                           "file (keys/secrets/tokens). Its contents would "
                                           "enter the conversation — confirm this is "
                                           "needed for the task.", "builtin:secret-file",
                                      memo_key=f"secret-file:{p}"))
            continue
        marker = _prescan_file(p)
        if marker:
            decisions.append(Decision(ASK, f"Heads up: this file looks like it contains "
                                           f"{marker}. Reading it pulls that into the "
                                           "conversation — confirm this is needed.",
                                      "builtin:content-prescan", memo_key=f"content-prescan:{p}"))
    return worst(decisions)


# --- mcp ----------------------------------------------------------------------

def _eval_mcp(event: ToolEvent, policy: Policy) -> Decision:
    tool = event.tool
    verdicts = []
    for rule in policy.mcp_rules:
        if fnmatch.fnmatch(tool, rule["matcher"]):
            verdicts.append(Decision(rule["action"], rule["reason"] or
                                     f"matched {rule['id']}", rule["id"]))
    if not verdicts:
        short = tool.split("__")[-1].lower()
        if short.startswith(("delete", "trash", "destroy", "purge")):
            verdicts.append(Decision(DENY, "Connector delete/trash operations are blocked "
                                           "(CRUA: archive instead).", "builtin:mcp-delete"))
        elif short.startswith("remove"):
            verdicts.append(Decision(ASK, "Connector remove operation — confirm intent.",
                                     "builtin:mcp-remove"))
    return worst(verdicts) if verdicts else Decision()
