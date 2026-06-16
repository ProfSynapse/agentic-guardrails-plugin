# agentic-guardrails

Make agentic tools (Claude Code, Cowork) safe on a real computer, including
the OneDrive/SharePoint/Google Drive/Dropbox folders synced to it, with one
plugin install.

**The core promise: nothing is ever destroyed.**

- `rm` and every destructive equivalent is blocked and redirected to
  `agw archive`: a reversible, versioned move into an archive store.
- Every file the agent Writes or Edits is snapshotted *first*, automatically.
  So is every file a raw shell `>`, `mv`, `cp`, or `tee` would clobber, so the
  promise holds even when the agent bypasses the Write tool.
- Office documents are edited via **CRUA** (Create, Read, Update, **Archive**):
  the agent works on a markdown/csv copy in `_workspace/`, and `agw publish`
  archives the old version before replacing the original, with conflict
  detection if a human edited it in the meantime.
- Cloud-only placeholder files and `.gdoc` pointer stubs (the classic synced-
  folder data-loss traps) are detected and protected.
- Anything archived comes back with `agw restore` or `agw undo`.

## Install

```
/plugin marketplace add https://github.com/ProfSynapse/agentic-guardrails-plugin.git
/plugin install agentic-guardrails@synaptic-guardrails
```

If Claude's marketplace UI rejects `ProfSynapse/agentic-guardrails-plugin`, use
the full GitHub URL above instead of the owner/repo shorthand.

Requires Python 3.9+ as `python3`. Optional: `pandoc` (docx↔markdown) and
`openpyxl` (xlsx→csv) for high-fidelity document checkout; without them files
are checked out in plain-copy mode. Fleet rollout: see
[enterprise/DEPLOYMENT.md](enterprise/DEPLOYMENT.md).

### Installing in Claude Cowork

Cowork has no `/plugin` command — installs are UI-driven:
**Customize → Plugins → Create plugin → Add marketplace**, then enter the repo
(`ProfSynapse/agentic-guardrails-plugin`, or the full GitHub URL if the
shorthand is rejected) and install **Agentic Guardrails** from the catalog.

## Troubleshooting

**Cowork still shows an old version after I pushed an update.** Cowork caches
the marketplace catalog in its **backend, keyed to your account** — not in a
local file. So the stale version follows you to other computers, and clearing
local folders or re-pushing the repo won't move it. Two things are required:

1. The repo's default branch must carry a **new `version`** (in both
   `.claude-plugin/marketplace.json` and the plugin manifest). If the version
   string doesn't change, clients keep the cached copy.
2. **Remove the marketplace entry itself, then re-add it** — uninstalling the
   *plugin* is not enough; the catalog stays pinned at the old version. The
   remove control is buried:
   **Customize → Plugins → Browse plugins → Personal tab → the plugin's tab →
   the three-dots menu *on the tab itself* → Remove.** Then re-add the
   marketplace (see above). The re-add re-fetches `marketplace.json` from the
   default branch.

If it still shows the old version after a full marketplace remove + re-add,
that's a sticky server-side cache TTL on Cowork's side — wait it out or use the
UI's refresh/update action; nothing in the repo or your local folders will
change it.

## What's inside

| Piece | Purpose |
|---|---|
| `hooks/` | PreToolUse/PostToolUse/SessionStart wiring, the enforcement surface (works in Claude Code and Cowork) |
| `scripts/claude/` | Thin Claude adapter: tool call → neutral `ToolEvent`, decision → hook JSON. Fails **closed** (any internal error → "ask", never silent allow) |
| `scripts/core/` | Platform-neutral policy engine: shell parser (substitutions, `bash -c`, xargs, wrappers, decode-pipes), folder profiles, archive store, audit log with secret redaction |
| `scripts/agw/` + `bin/agw` | The `agw` CLI ("agent workspace"): `scan`, `checkout`, `diff`, `publish`, `archive`, `restore`, `undo`, `move`, `snapshot`, `status`, `log`, `doctor`, plus `office` for targeted in-place docx/xlsx/pptx edits (replace-text, set-cell, append-rows) with automatic pre-image snapshots |
| `policies/` | Editable YAML rules: command rules, content/snippet rules (regex → deny/ask), path zones. Per-machine drop-ins in `~/.agw/policies.d/` |
| `skills/` | Teach the agent the workflows: agent-workspace, synced-folders, gdocs-bridge, restore |
| `commands/` | `/agw-status`, `/agw-publish`, `/agw-restore`, `/guardrails-report` |
| `enterprise/` | Managed-settings template + deployment guide |

## The agent's vocabulary

Denied primitives always come with a safe replacement in the denial message,
so the agent self-corrects instead of fighting the rails:

| Instead of | The agent uses |
|---|---|
| `rm file` | `agw archive file` (reversible) |
| editing `report.docx` in place | `agw checkout` → edit markdown → `agw publish` |
| `python -c` openpyxl one-liners | `agw office set-cell` / `replace-text` / `append-rows` |
| `mv` (untracked) | `agw move` (logged, undoable) |
| bulk folder surgery | `agw snapshot` first, then work |

Exception: `rm` of purely regenerable build/dependency dirs (`node_modules`,
`dist`, `.venv`, `__pycache__`...) is allowed at `standard` and above (pointless
and huge to archive). `strict` archives even those. The list is extensible via
`settings.regenerable_globs`.

Escalations (`ask`): `git checkout -- <file>`, shrink-suspicious writes
(replacing a large file with tiny content), reading cloud-only placeholders,
publish conflicts, `agw prune`/`apply`/`hydrate`, reading credential-type
files (.env, keys, `~/.aws`...), files whose content prescan finds secrets or
"CONFIDENTIAL" markings ("this might contain a password, confirm"), and
recursive credential-keyword searches. Combining a credential file with a
network tool in one command (`curl -d @.env ...`) is denied as exfiltration. Hard denies: `rm`/`shred`/
`find -delete`, `git push --force` / `reset --hard` / `clean -f`, `dd` to
devices, `mkfs`, `sudo`, decode-to-shell and download-to-shell pipes,
destructive SQL/interpreter one-liners, writes to `.gdoc` stubs, placeholders,
protected zones, the plugin itself, and the archive store.

## Customizing

- **Block arbitrary code/content patterns:** drop a YAML file in
  `policies/content-rules.d/` with `pattern` (regex), `action` (`deny`/`ask`),
  `message`. Built-in examples block AWS keys and private-key material.
- **Zone a folder:** mark globs `no-access`, `read-only`, or `workspace` in
  `~/.agw/policies.d/*.yaml`.
- **Archive location:** defaults to `~/.agw` (deliberately outside synced
  trees); override with `AGW_HOME`. In Cowork, set it to a persistent volume;
  the hook VM's home is wiped per session.
- **Enforcement level:** `AGW_LEVEL` (or `settings.level`) picks a bundle:
  `strict`, `standard` (default), `relaxed`, or `observe` (shadow mode: logs
  what it would do, blocks nothing). Safe by default; the company sets one knob.
  See [enterprise/DEPLOYMENT.md](enterprise/DEPLOYMENT.md) for the full table.
- **Disk budget:** `AGW_ARCHIVE_MAX_BYTES` caps the store (0 = unlimited);
  oldest redundant pre-image copies are evicted first, never the sole copy of an
  archived file.

## Testing

```
python3 -m pytest tests/   # 185 tests, no third-party deps beyond pytest
```

Includes a ~50-entry bypass corpus (nested `bash -c`, command substitution,
xargs, wrapper commands, encode/decode pipes, interpreter one-liners) that
must always resolve to deny/ask, golden subprocess tests of the actual hook
(including the crash-fails-closed contract), and store concurrency tests. See
[TESTING.md](TESTING.md) for the full plan including manual Cowork validation.

## Roadmap

Plan→apply transactions for bulk reorganization, `hydrate` verb, Codex and
Cursor adapters on the same core engine, instruction compiler. Design notes in
[PLAN.md](PLAN.md), research trail in [RESEARCH.md](RESEARCH.md).
