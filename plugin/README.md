# agentic-guardrails

Make agentic coding tools safe on a real computer, including the
OneDrive/SharePoint/Google Drive/Dropbox folders synced to it, with one plugin
install.

**Supported hosts:** Claude Code (terminal and desktop app) and OpenAI Codex —
the safety engine and the `agw` CLI are identical across both; only a thin
adapter differs. Cowork support is planned but **not working yet**: its hooks
don't fire there. Tracking:
[../docs/plans/0001-cowork-hook-enablement.md](../docs/plans/0001-cowork-hook-enablement.md).

> **Release status:** `0.3.0` is the Windows-first stable release.
> It has extensive automated and hands-on validation on Windows, which is the
> current client deployment target. macOS and Linux support remains in preview:
> the shared code is designed to be cross-platform, but this release has not
> yet received equivalent real-machine validation on those operating systems.
> Use it there only for development testing and report platform-specific
> issues before relying on it for production work.

**The core promise: preserve user work through CRUA instead of permanent deletion.**

- Permanent deletion of user files is blocked and redirected to
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

### Claude Code (terminal and desktop app)

```
/plugin marketplace add https://github.com/ProfSynapse/agentic-guardrails-plugin.git
/plugin install agentic-guardrails@synaptic-guardrails
```

If Claude's marketplace UI rejects `ProfSynapse/agentic-guardrails-plugin`, use
the full GitHub URL above instead of the owner/repo shorthand.

### OpenAI Codex

```bash
codex plugin marketplace add https://github.com/ProfSynapse/agentic-guardrails-plugin --ref main
```

Then run `/plugins` inside Codex, install **Agentic Guardrails**, and trust its
hooks with `/hooks`. The full walkthrough — including the `apply_patch` deletion
guard and a smoke test to confirm interception on your build — is in
[CODEX.md](CODEX.md).

### Requirements

Python 3.9+. Windows hooks require it as `python`; the bundled `agw.cmd`
launcher tries `python` and then `py.exe -3`. POSIX hooks try `python3` and
then `python`. Optional: `pandoc` (docx↔markdown) and `openpyxl`
(xlsx→csv) for high-fidelity document checkout; without them files are checked
out in plain-copy mode. Fleet rollout: see
[enterprise/DEPLOYMENT.md](enterprise/DEPLOYMENT.md).

## Updating

New versions ship as a `version` bump on the default branch. Clients cache by
that string, so an update only lands once it changes:

- **Claude Code:** `/plugin marketplace update synaptic-guardrails`, then
  `/plugin install agentic-guardrails@synaptic-guardrails`.
- **Codex desktop:** open Plugins and use **Refresh** on the imported marketplace
  or workspace plugin when that control is available, then restart Codex. A
  personal/local marketplace may refresh automatically at startup and may not
  show a separate Update button. Confirm the loaded version in the plugin
  details or Guardrails session-start message.

## What's inside

| Piece | Purpose |
|---|---|
| `hooks/` | PreToolUse/PostToolUse/SessionStart wiring, the enforcement surface (works in Claude Code and Codex) |
| `scripts/claude/` | Thin Claude adapter: tool call → neutral `ToolEvent`, decision → hook JSON. Fails **closed** (any internal error → "ask", never silent allow) |
| `scripts/codex/` | Thin Codex adapter: same `ToolEvent` contract, plus `apply_patch` envelope parsing (Add→write, Update→edit+snapshot, Delete→blocked under CRUA) |
| `scripts/core/` | Platform-neutral policy engine: shell parser (substitutions, `bash -c`, xargs, wrappers, decode-pipes), folder profiles, archive store, recovery metadata, and policy health |
| `scripts/agw/` + `bin/agw` / `bin/agw.cmd` | The `agw` CLI ("agent workspace"): `scan`, `checkout`, `diff`, `publish`, `archive`, `restore`, `undo`, `move`, `snapshot`, `status`, `log`, `doctor`, plus `office` for targeted in-place docx/xlsx/pptx edits (replace-text, set-cell, append-rows) with automatic pre-image snapshots |
| `policies/` | Editable YAML rules: command rules, content/snippet rules (regex → deny/ask), path zones. Per-machine drop-ins in `~/.agw/policies.d/` |
| `skills/` | Teach the agent the workflows: agent-workspace, synced-folders, gdocs-bridge, restore |
| `commands/` | `/agw-status`, `/agw-publish`, `/agw-restore`, `/guardrails-report` (Codex reads the equivalents from `codex-prompts/`) |
| `enterprise/` | Managed-settings template + deployment guide |

## The agent's vocabulary

Denied primitives always come with a safe replacement in the denial message,
so the agent self-corrects instead of fighting the rails:

| Instead of | The agent uses |
|---|---|
| `rm file` | `agw archive file` (reversible) |
| editing `report.docx` in place | `agw checkout` → edit markdown → `agw publish` |
| `python -c` openpyxl one-liners | `agw office set-cell` / `replace-text` / `append-rows` |
| `mv` (untracked) | `agw move` (transactional, undoable) |
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

Content scans are span-aware: a destructive string that only appears as a search
pattern or echoed data (`grep "DROP TABLE" schema.sql`) is not treated as an
executed command, so it isn't blocked.

### Human-readable approvals and connected services

Approval dialogs describe the action, affected category, reason, consequence,
and safety measure without requiring the user to interpret raw shell syntax.
They offer **Allow once** and **Cancel (recommended)**; known reversible
Guardrails restore/mutation operations instead recommend Allow. If an action is
cancelled or blocked, the agent is instructed to explain why in plain language
and recommend a safe way to continue toward the user's goal.

Current host hook events expose connector names and inputs but not trusted MCP
capability annotations. Guardrails therefore classifies connected-service tools
by action name: recognized reads, recovery, and archive operations defer to the
host; create/update/send/share/merge-style changes ask; and permanent
delete/destroy/trash operations are blocked under CRUA. Unrecognized connector
verbs currently defer to the host rather than creating an extra Guardrails
dialog. This vocabulary is deliberately tested and maintained as connectors
evolve.

## Customizing

- **Block arbitrary code/content patterns:** drop a YAML file in
  `policies/content-rules.d/` with `pattern` (regex), `action` (`deny`/`ask`),
  `message`. Built-in examples block AWS keys and private-key material.
- **Zone a folder:** mark globs `no-access`, `read-only`, or `workspace` in
  `~/.agw/policies.d/*.yaml`.
- **Archive location:** defaults to `~/.agw` (deliberately outside synced
  trees); override with `AGW_HOME`. On ephemeral or remote runners whose home
  directory is wiped per session, point it at a mounted persistent volume.
- **Enforcement level:** `AGW_LEVEL` (or `settings.level`) picks a bundle:
  `strict`, `standard` (default), `relaxed`, or `observe`. Observe mode shadows
  ordinary policy-pack asks/denies but keeps non-waivable safety invariants; it
  does not create a separate command ledger. Safe by default; the company sets
  one knob.
  See [enterprise/DEPLOYMENT.md](enterprise/DEPLOYMENT.md) for the full table.
- **Disk budget:** `AGW_ARCHIVE_MAX_BYTES` caps the store (0 = unlimited);
  oldest redundant pre-image copies are evicted first, never the sole copy of an
  archived file.

### Activity history and recovery metadata

Claude or Codex task history is the human activity log. Guardrails does not
create a second command/event ledger, key, migration journal, provenance file,
or quarantine. Existing `audit.jsonl` and legacy-quarantine files are left
completely untouched and unread.

`/guardrails-report` uses only privacy-safe CRUA metadata already needed for
recovery: archive-store health and recovery-copy totals, open checkout status,
and policy health/revision. It never reconstructs raw commands or reads legacy
audit material. If command-level decision counts or trends are requested, the
report says plainly that Guardrails does not keep that metric.

This change does not affect pre-image snapshots, archive transactions, restore,
pending approvals, or policy revisions. Activity-history availability never
changes an allow, ask, or deny decision.

## Testing

```
python3 -m pytest tests/   # Office tests run when openpyxl/python-docx are installed
```

Includes a bypass corpus (nested `bash -c`, command substitution, xargs, wrapper
commands, encode/decode pipes, interpreter one-liners, PowerShell/cmd deletion)
that must always resolve to deny/ask, golden subprocess tests of the actual hook
(including the crash-fails-closed contract), and store concurrency tests. See
[../TESTING.md](../TESTING.md) for the full plan.

## Roadmap

Cowork support (hooks don't fire there yet —
[../docs/plans/0001-cowork-hook-enablement.md](../docs/plans/0001-cowork-hook-enablement.md)),
plan→apply transactions for bulk reorganization, the `hydrate` verb, a Cursor
adapter on the same core engine, and an instruction compiler. Also planned is
an on-demand, report-only connector policy auditor that inventories exposed
connector tools, flags unclassified or ambiguous action verbs, and proposes
reviewed Codex/Claude policy and test updates without executing connector
actions or changing policy automatically. Design notes in
[../PLAN.md](../PLAN.md), research trail in [../RESEARCH.md](../RESEARCH.md).
