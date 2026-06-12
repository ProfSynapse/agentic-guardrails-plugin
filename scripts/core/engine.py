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
    FLAG_INDIRECT, ParseUncertain, SimpleCommand, extract_commands, extract_payloads

ARCHIVE_REDIRECT = ("Deletion is disabled by agentic-guardrails. Use `agw archive <path>` "
                    "instead — it moves files to the archive store and is fully reversible "
                    "with `agw restore`. (User: to delete permanently anyway, run the "
                    "command yourself in a terminal.)")

# agw verbs the agent may run without prompts; everything else asks.
AGW_ALLOWED_VERBS = {"scan", "checkout", "convert", "diff", "archive", "move", "rename",
                     "snapshot", "restore", "undo", "status", "log", "doctor", "init",
                     "publish"}
AGW_ASK_VERBS = {"prune": "prune permanently destroys archived versions (human decision)",
                 "apply": "bulk apply executes a stored plan — review the manifest",
                 "hydrate": "hydration downloads cloud-only content"}

_INTERPRETER_DESTRUCTIVE = re.compile(
    r"os\.(remove|unlink|rmdir|removedirs)|shutil\.rmtree|\.unlink\(|send2trash"
    r"|\b(rmSync|rmdirSync|unlinkSync|rm_rf|rm_r)\b|\.rm\s*\(|FileUtils\.(rm|remove)"
    r"|unlink\s", re.IGNORECASE)

_SQL_DENY = re.compile(r"\b(DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE?)\b", re.IGNORECASE)
_SQL_DELETE = re.compile(r"\bDELETE\s+FROM\b(?![\s\S]*\bWHERE\b)", re.IGNORECASE)

_MUTATOR_CMDS = {"mv", "cp", "tee", "sed", "touch", "ln", "install", "rsync", "truncate"}


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
    if event.kind == EXEC:
        decision = _eval_exec(event, policy, plugin_root)
    elif event.kind in (WRITE, EDIT):
        decision = _eval_write(event, policy)
    elif event.kind == READ:
        decision = _eval_read(event, policy)
    elif event.kind == MCP:
        decision = _eval_mcp(event, policy)
    else:
        decision = Decision()
    if policy.degraded and decision.action in (DEFER, ALLOW):
        decision.warnings.append(
            f"guardrails: policy pack(s) failed to load: {', '.join(policy.degraded)}")
    return decision


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

def _eval_exec(event: ToolEvent, policy: Policy, plugin_root: str) -> Decision:
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

    for cmd in parsed.commands:
        decisions.append(_eval_simple_command(cmd, policy, plugin_root, event))

    # content rules also see payloads the command would write (heredocs, echo)
    for payload in extract_payloads(event.command):
        decisions.append(_snippet_check(payload, "", policy))

    return worst(decisions)


def _eval_simple_command(cmd: SimpleCommand, policy: Policy, plugin_root: str,
                         event: ToolEvent) -> Decision:
    name = cmd.name

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
                                           "reliable results.", "builtin:placeholder-read"))
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
