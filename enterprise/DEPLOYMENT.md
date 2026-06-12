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
/plugin marketplace add git@your-git:tools/agentic-guardrails-plugin.git
/plugin install agentic-guardrails@synaptic-guardrails
```

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

## 4. Requirements per machine

- Python 3.9+ on PATH as `python3` (no third-party packages required;
  PyYAML and pandoc/openpyxl are used when present and improve conversion
  fidelity — install them for the full docx/xlsx checkout experience).
- For the `agw office` in-place editing verbs, install the libraries for the
  formats your users touch: `openpyxl` (xlsx), `python-docx` (docx),
  `python-pptx` (pptx). `agw doctor` reports which are available.
- `bin/agw` on PATH is convenient but optional; the hook teaches the agent the
  full path via session context regardless.

## 5. Verify a deployment

On a target machine:

```bash
agw doctor --json          # store writable, converters found, packs loaded
claude                     # then ask it to: rm some test file
```

Expected: the delete is denied with a message redirecting to `agw archive`,
and the attempt appears in `~/.agw/audit.jsonl`. Run `/guardrails-report` in
Claude for a readable audit summary.

## 6. What this does and does not cover

Covered: Claude Code and Cowork tool calls (Bash, Write/Edit, Read, MCP tools)
on the machine, machine-wide — including synced OneDrive/SharePoint/Drive/
Dropbox folders.

Not covered: actions outside the agent (the human's own shell), Cowork
computer-use clicking inside other apps, and cloud-side operations done by
connectors that bypass the local filesystem. Pair with provider-side retention
(Drive trash, SharePoint recycle bin, versioning) for those.
