# Enterprise Deployment

How to roll agentic-guardrails out to a fleet so it is **on by default and
cannot be silently turned off**.

## 1. Host the marketplace

Put this repository (or a fork with your own policy packs) in an internal git
remote your developers can read. The repo doubles as a plugin marketplace via
`.claude-plugin/marketplace.json`.

Sanity check from any machine:

```bash
claude  # then:
/plugin marketplace add https://github.com/ProfSynapse/agentic-guardrails-plugin.git
/plugin install agentic-guardrails@synaptic-guardrails
```

If the marketplace UI reports a sync failure for the owner/repo shorthand, use
the full repository URL form shown above.

## 2. Enforce via managed settings

Copy `managed-settings.template.json` to the managed-settings path for each OS
(deploy with MDM/Intune/Jamf/GPO — the file must not be user-writable):

| OS | Path |
|---|---|
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.json` |
| Linux / WSL | `/etc/claude-code/managed-settings.json` |
| Windows | `C:\Program Files\ClaudeCode\managed-settings.json` |

Fill in `<ORG-MARKETPLACE-URL>`. The two keys that matter:

- `extraKnownMarketplaces` — registers your marketplace on every machine.
- `enabledPlugins` — force-enables the plugin; users cannot disable it.

`marketplace.json` already sets `"installationPreference": "required"` so
interactive installs are also nudged to keep it on.

### Optional hardening

- `"allowManagedHooksOnly": true` — blocks all user/project hooks except
  managed ones. Maximum integrity, but it disables developers' personal hooks;
  pilot first.
- Managed `permissions.deny` rules (see the template comment) survive even a
  plugin compromise — cheap defense in depth.

## 3. Customize policy

Three layers, no code required:

1. **`policies/core.yaml`** (in your fork) — org-wide command rules.
2. **`policies/content-rules.d/*.yaml`** — content/snippet rules: secrets
   formats, banned code patterns, regulated strings. Each rule is a regex +
   action (`deny`/`ask`) + message.
3. **`~/.agw/policies.d/*.yaml`** on individual machines — per-user/team
   drop-ins, e.g. zone rules marking folders `no-access`, `read-only`, or
   `workspace`.

A malformed pack never disables protection: it is skipped, reported by
`agw doctor`, and the built-in guards keep running (fail-closed by design —
the hook answers "ask" on any internal error, never silent-allow).

## 4. Choose an enforcement level

The company picks one "level" and the individual knobs follow from it. Safe by
default: omit everything and you get `standard`. Set `AGW_LEVEL` in the managed
`env` block (fleet-wide) or per machine; individual `AGW_*` knobs override it.

| Level | Blocks destruction/exfil | rm of build dirs (node_modules, dist) | Credential reads | Ask-once memory |
|---|---|---|---|---|
| `strict` | yes | archived, never rm'd | ask every time | off |
| `standard` (default) | yes | allowed (pointless to archive) | ask, remembered per session | on |
| `relaxed` | yes | allowed | allowed, audited only | on |
| `observe` | **logs only, blocks nothing** | n/a | n/a | n/a |

`observe` is the trial mode: deploy it first to see what the guardrails *would*
do (everything lands in `~/.agw/audit.jsonl` with `"observe": true`) without
disrupting anyone, then graduate to `standard`. Every level keeps taking
pre-image snapshots, so "nothing is destroyed" holds even in `observe`.

Override individual knobs when needed: `AGW_SESSION_MEMORY`,
`AGW_REGENERABLE_RM`, `AGW_RELAXED_ACCESS`, `AGW_ENFORCEMENT`. A policy pack can
also set these under a `settings:` block (`level`, `regenerable_globs` to extend
the build-dir allowlist, `archive_max_bytes`).

### Archive disk budget

The store grows as it keeps pre-image snapshots. `AGW_ARCHIVE_MAX_BYTES` (or
`settings.archive_max_bytes`) caps it; `0`/unset means unlimited (the safe
default). When over budget, only the **oldest redundant pre-image copies** are
evicted — never a move-archive (the sole copy of an rm'd file) and never the
newest version of anything. `agw doctor` reports current size and budget.

## 5. Requirements per machine

- Python 3.9+ on PATH as `python3` (no third-party packages required;
  PyYAML and pandoc/openpyxl are used when present and improve conversion
  fidelity — install them for the full docx/xlsx checkout experience).
- For the `agw office` in-place editing verbs, install the libraries for the
  formats your users touch: `openpyxl` (xlsx), `python-docx` (docx),
  `python-pptx` (pptx). `agw doctor` reports which are available.
- `bin/agw` on PATH is convenient but optional; the hook teaches the agent the
  full path via session context regardless.
- **Persistent store location.** The archive/session store defaults to `~/.agw`.
  Set `AGW_HOME` to a persistent, **non-cloud-synced** path. This matters most in
  **Cowork**: hooks there run inside a per-session Linux VM whose home (`~`) is
  wiped on teardown, so `~/.agw` would not survive the session — point `AGW_HOME`
  at a mounted persistent volume so archives and approvals persist.

## 6. Verify a deployment

On a target machine:

```bash
agw doctor --json          # store writable, converters found, packs loaded
claude                     # then ask it to: rm some test file
```

Expected: the delete is denied with a message redirecting to `agw archive`,
and the attempt appears in `~/.agw/audit.jsonl`. Run `/guardrails-report` in
Claude for a readable audit summary.

## 7. What this does and does not cover

Covered: Claude Code and Cowork tool calls (Bash, Write/Edit, Read, MCP tools)
on the machine, machine-wide — including synced OneDrive/SharePoint/Drive/
Dropbox folders.

Not covered: actions outside the agent (the human's own shell), Cowork
computer-use clicking inside other apps, and cloud-side operations done by
connectors that bypass the local filesystem. Pair with provider-side retention
(Drive trash, SharePoint recycle bin, versioning) for those.
