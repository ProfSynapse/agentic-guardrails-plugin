# V1 Plan — Agentic Guardrails Plugin

> **Mission**: make it stupid-easy for a company to flip one switch and have agentic tools like Cowork be safe on the whole computer. The model: **you bring the cloud to your machine** — SharePoint, Google Drive, Dropbox synced as local folders with offline access — and the plugin makes every folder the agent touches safe. Three pillars:
>
> 1. **Nothing is ever destroyed** — CRUA (Create, Read, Update, **Archive**) replaces delete everywhere; every superseded version is recoverable.
> 2. **The agent works in a workspace, not on your originals** — proprietary formats are checked out to open formats (markdown/csv), edited there, then published back with the prior version archived.
> 3. **Every folder has a profile, every rule is yours** — synced cloud folders, git repos, and plain folders each get sync-aware handling automatically; admins bar arbitrary commands, code snippets, and content patterns with drop-in policy files.

See [RESEARCH.md](RESEARCH.md) for the findings this plan rests on.

---

## 1. The core insight: synced folders are the connector

The native cloud connectors are read-mostly (Drive: no update/move/delete; M365: fully read-only). But users already mount these clouds as local folders — Google Drive for Desktop, OneDrive/SharePoint sync, Dropbox. There, the agent gets full read/write and **the sync client is the transport**: edit locally, versioning and propagation happen upstream (SharePoint even auto-versions every save).

So the architecture inverts from "wrap the cloud APIs" to: **the local machine is the agent workspace; folder profiles teach the plugin how each kind of folder behaves**. A "connector" in our world is just a folder profile — and adding a custom one is dropping a YAML file, not writing an MCP server.

This is also where the danger lives. Synced folders have failure modes plain folders don't, including a **live, unfixed Cowork data-loss bug** ([claude-code#62140](https://github.com/anthropics/claude-code/issues/62140): Cowork read a truncated OneDrive placeholder, edited it, wrote it back, and destroyed the cloud copy). Sync-aware guardrails are a headline feature no one else ships.

## 2. Product shape

One plugin, standard Claude Code plugin format (works in Cowork, Claude Code CLI, and the desktop Code tab from a single source):

- **Marketplace** (`marketplace.json` in this repo) for individuals/teams.
- **Enterprise**: custom org marketplace or MDM-deployed org-plugins directory with `installationPreference: "required"` (users cannot remove it), plus a `managed-settings.json` template (`enabledPlugins`, `allowManagedHooksOnly`) for Claude Code fleets.

```
agentic-guardrails-plugin/
├── .claude-plugin/
│   ├── plugin.json
│   └── marketplace.json
├── hooks/
│   └── hooks.json               # PreToolUse guards (Bash, Write|Edit, Read, mcp__*) + PostToolUse audit
├── scripts/
│   ├── core/                    # platform-NEUTRAL engine — imports nothing Claude-specific
│   │   ├── events.py            # neutral schemas: ToolEvent (exec|read|write|edit|mcp) → Decision (allow|ask|deny + message)
│   │   ├── engine.py            # policy evaluation (profile × rules → decision)
│   │   ├── shellparse.py        # shell-aware command parsing + wrapper recursion
│   │   ├── profiles.py          # folder-profile detection + behavior dispatch
│   │   └── auditlog.py          # JSONL audit writer (+ redaction)
│   ├── claude/                  # Claude ADAPTER (thin): translates hook stdin/stdout ↔ core schemas
│   │   ├── pretooluse.py        # Claude tool_input → ToolEvent; Decision → permissionDecision JSON
│   │   ├── posttooluse.py
│   │   └── sessionstart.py      # bootstrap config, warm caches, inject agw vocabulary as additionalContext
│   └── agw/                     # "agent workspace" CLI (already platform-neutral)
│       ├── agw.py               # verb dispatcher — see §5 for the full verb set
│       └── converters/          # pandoc/markitdown/openpyxl wrappers + detection
├── bin/
│   └── agw                      # PATH shim → scripts/agw/agw.py (plugins can ship bin/)
├── profiles/                    # folder profiles = our "connectors" (drop-in extensible)
│   ├── local.yaml
│   ├── git.yaml
│   ├── gdrive-sync.yaml
│   ├── onedrive-sharepoint.yaml
│   ├── dropbox.yaml
│   └── _template.yaml           # documented template for custom profiles
├── policies/                    # drop-in extensible rule packs
│   ├── core.yaml                # destructive commands, protected paths (always on)
│   ├── sync-safety.yaml         # placeholder/stub/conflict-artifact rules
│   ├── content-rules.d/         # arbitrary content/snippet bans (admin drop-ins)
│   │   └── examples.yaml
│   └── strict.yaml
├── skills/
│   ├── agent-workspace/SKILL.md    # the CRUA workflow — auto-triggers on file-manipulation tasks
│   ├── synced-folders/SKILL.md       # how to behave in cloud-synced folders
│   ├── gdocs-bridge/SKILL.md         # .gdoc stubs: export via connector/API, never edit the stub
│   └── restore/SKILL.md              # user-invocable /restore
├── commands/                    # /agw-status, /agw-publish, /agw-restore, /guardrails-report
├── enterprise/
│   ├── managed-settings.template.json
│   └── DEPLOYMENT.md
├── tests/
├── RESEARCH.md
├── PLAN.md
└── README.md
```

Python (3.9+, stdlib-first) everywhere: it's in the Cowork VM and on virtually all machines, cross-platform (solves Windows-host hooks), and testable.

### Platform strategy: Claude first, built portable

Claude/Cowork is v1, but ChatGPT/Codex, Cursor, and others get the same treatment later — and the ecosystem proves the pattern (cc-safety-net runs one guard core across Codex, Gemini CLI, and Copilot CLI; Cursor exposes enterprise hooks returning allow/warn/deny/step-up; Codex has approval policies + rules). So the hard rule from day one:

- **Everything valuable is platform-neutral**: the policy engine, shell parser, folder profiles, archive store, plan→apply transactions, audit log, and the entire `agw` CLI live in `scripts/core/` + `scripts/agw/` and speak only the neutral schemas (`ToolEvent` in → `Decision` out). No Claude imports, no `tool_input` field names, no hook JSON.
- **Each platform is a thin adapter**: `scripts/claude/` translates Claude hook stdin/stdout to/from the neutral schemas (~100 lines). A Codex adapter maps the same engine into its approval/rules mechanism; a Cursor adapter into its hooks API. Per-platform packaging (Claude plugin manifest, Cursor extension, Codex config) wraps the same core.
- **Instructions compile from one source**: the "teach the agent" content (CRUA workflow, agw vocabulary, synced-folder behavior) is authored once and rendered per-platform — Claude skills + CLAUDE.md, AGENTS.md for Codex, `.cursor/rules` for Cursor.
- **Policies are the product**: a company writes its rule packs once; the same YAML enforces on every platform its people use. That's the moat — multi-platform consistency is something no per-tool hook collection offers.

V1 ships from this repo as the Claude plugin (adapter + core bundled in one marketplace artifact). When platform #2 lands, the repo becomes a monorepo with per-platform build outputs; the boundary is already drawn, so the split is mechanical. Per-platform capability research (Codex/Cursor/Gemini hook surfaces in detail) is deferred to that phase.

## 3. Pillar 1 — the guard hooks + extensible policy engine

The guard pipeline (`claude/pretooluse.py` adapter → `core/engine.py`) runs on `PreToolUse` for `Bash`, `Write|Edit`, `Read`, and `mcp__*`. Decision = **folder profile** (where is this happening?) × **policy rules** (what is being attempted?). Everything is YAML; companies edit policy, never code.

### Rule classes (this is the "bar anything arbitrarily" requirement)

```yaml
# policies/content-rules.d/acme-corp.yaml — an admin drop-in
commands:                              # match parsed bash commands
  - pattern: "aws s3 rb*"
    action: deny
    reason: "Bucket removal is not permitted from agent sessions."
snippets:                              # match content being WRITTEN (Write/Edit/heredocs)
  - pattern: "eval\\s*\\("            # regex against new file content
    action: ask
    applies_to: ["*.py", "*.js"]
  - pattern: "Authorization: Bearer"   # block hardcoding creds
    action: deny
paths:                                 # zone rules, machine-wide
  - glob: "~/Documents/Legal/**"
    zone: read-only
  - glob: "~/Pictures/**"
    zone: no-access
mcp_tools:                             # connector tool surface rules
  - matcher: "mcp__*__delete*"
    action: deny
```

- **`commands`** — evaluated against shell-aware-parsed Bash (`shlex` + operator splitting, recursion into `bash -c`/`xargs`/`find -exec`, interpreter one-liner inspection, base64-decode-pipe detection). **Fail-closed**: un-parseable → `ask`.
- **`snippets`** — evaluated against the content of Write/Edit calls and heredoc/`tee` payloads in Bash. This is how a company bans specific code patterns, API calls, or secret formats from ever being written, anywhere on the machine.
- **`paths`** — machine-wide zones: `open` / `workspace` (CRUA enforced) / `read-only` / `no-access`. Protected by default regardless of zone: archive stores, the plugin's own files, policy files, `~/.ssh`, sync-client staging dirs (`.tmp.driveupload`, `.dropbox.cache`).
- **`mcp_tools`** — deny/ask on connector tool calls (e.g., any MCP `delete*`/`trash*`).

All rule packs in `policies/` and `content-rules.d/` merge at load (deny wins over ask wins over allow). Adding a company rule = dropping one YAML file into the plugin before distribution, or into a designated local dir.

### Built-in core tiers (policies/core.yaml)

| Tier | Examples | Response |
|---|---|---|
| **Deny + redirect** | `rm`, `rmdir`, `find -delete`, `shred`, `dd of=/dev/*`, `mkfs`, truncation of non-workspace files, `git push --force`, `git reset --hard`, `git clean -f`, `chmod -R 777`, `sudo`, `curl\|bash`, `DROP TABLE`, `DELETE` without `WHERE` | deny, with a message that **teaches the redirect**: "Deletion is disabled. Use `agw archive <path>` — reversible with `agw restore`." |
| **Ask** | `git checkout -- <file>`, `git stash drop`, cross-folder `mv`, package installs, writes to `open`-zone files not seen before in session | ask, with plain-English consequences |
| **Allow** | everything else, incl. all `agw` subcommands | defer |

### Sync-safety rules (policies/sync-safety.yaml) — the new headline

Active automatically when the folder profile is a sync provider:

- **Placeholder guard**: before any Read-then-Edit or Write to a file in a synced folder, check for cloud-only placeholder (`Blocks==0 && Size>0` POSIX heuristic; `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` on Windows; `SF_DATALESS` on macOS). Placeholder → **deny with hydration instructions** ("pin / mark Available offline first"). Directly prevents the #62140 corruption class.
- **Shrink guard**: deny writes that shrink an existing file >X% vs. its current size without an explicit ask (the truncated-read-write-back signature).
- **Stub guard**: `.gdoc`/`.gsheet`/`.gslides` are pointer files — deny all edits, route to the `gdocs-bridge` skill (export via connector/API).
- **Mass-hydration guard**: recursive read/grep/glob over a streaming/On-Demand tree → ask first (it downloads everything); warn about macOS dataless-dir materialization via `**` globs.
- **Artifact hygiene**: never clobber `[Conflict]`/`conflicted copy`/device-name copies; skip `~$`/`.~lock` lock files; ask before editing a file Office currently holds open.

### Audit

Deny/ask decisions and all archive actions append JSONL (timestamp, session, tool, input digest, rule id, profile, action taken) to the machine-level store `~/.agw/audit.jsonl`. `/guardrails-report` summarizes. v2: OTel exporter matching Cowork's enterprise event streaming (Cowork's audit-log void makes this genuinely valuable).

### Honest posture

Pattern matching stops the *accident* class (the family-photos failure mode, the placeholder corruption), not a determined adversary — Cowork's VM is the security boundary. Fail-closed parsing, documented limits, AST parsing (tree-sitter-bash) in v2.

## 4. Pillar 2 — the agent workspace (CRUA)

`agw init` (auto-suggested by the skill) sets up a folder as a workspace zone:

```
<folder>/
├── _workspace/              # open-format working copies (md, csv) — agent edits HERE
│   └── Q3-report.docx.md
├── .agw/state.json          # checkout registry: source ↔ working copy ↔ base hash ↔ profile
└── Q3-report.docx           # live file — only replaced by `agw publish`

~/.agw/                      # machine-level store, ALWAYS outside synced trees
├── archive/<folder-id>/<name>/
│   ├── v001_2026-06-12T14-03_Q3-report.docx
│   └── manifest.json        # source path, hash, converter, profile, who/when/why
├── audit.jsonl
└── config.yaml              # zones, policy dirs, retention
```

**Why the archive lives outside the folder** (changed from the first draft): research is unambiguous that high-churn rotating archives inside synced folders are an anti-pattern — every version re-uploads, burns quota (SharePoint versions count against storage), and no provider supports excluding a subfolder from sync. Plain local folders may opt into in-place `_archive/` via profile setting (nicer discoverability); synced profiles force the central store.

### Lifecycle commands

- **`agw checkout <file>`** — convert proprietary → open format into `_workspace/` (docx→md via pandoc, xlsx→csv-per-sheet, pptx→md outline), record base hash. Plain-text files check out as plain copies. **Profile-aware**: in synced folders, verifies full hydration first (pins/hydrates or instructs), refuses `.gdoc` stubs (→ `gdocs-bridge` skill).
- **`agw publish <file>`** — the Update that archives:
  1. Conflict check (live hash ≠ base hash → stop and ask; in synced folders also checks for conflict-copy siblings).
  2. Version-bump: copy current live file to `~/.agw/archive/.../vNNN_<timestamp>` + manifest.
  3. Convert back (md→docx with `--reference-doc` style extracted from the original; csv→xlsx).
  4. Fidelity warning: re-export the new file, diff against working copy, surface losses before finalizing.
  5. Replace the live file — **profile-aware write strategy**: atomic temp+rename for local/git; retry-with-backoff in-place strategy for synced folders (sync clients briefly lock files mid-sync; delete+create breaks cloud version-history continuity).
  6. Upstream versioning (SharePoint auto-versions, Drive keeps 30d/100 revisions) is a bonus second net — never the primary record.
- **`agw archive <path>`** — the delete replacement (what deny-hooks redirect `rm` to): move into the archive store + manifest.
- **`agw restore <name> [version]`** / **`agw status`** / **`agw log`** / **`agw doctor`** (environment check: converters available, profiles detected, placeholder support).

Retention: default keep-everything; pruning is an explicit human command, never automatic, never agent-callable (denied by our own hooks).

## 5. The script layer — safe verbs, and why hooks and scripts are one mechanism

The research consensus is that allowlists beat denylists (Cursor deprecated its denylist feature entirely after bypass research). So the design is not "block 600 bad commands" — it's: **deny the raw primitives, give the agent a small vocabulary of named verbs that are safe by construction, and make hooks trust exactly that vocabulary.** Every deny message teaches the verb that replaces it. The agent gets *faster* (one verb replaces dozens of tool calls and permission prompts) and the company gets *safer* from the same mechanism.

### The verb set (`agw <verb>`, shipped in `bin/` on PATH)

| Verb | Replaces (denied primitive) | What it does | Hook tier |
|---|---|---|---|
| `scan <folder>` | recursive `ls`/`grep`/`find` in synced trees | Inventory without hydration: types, sizes, placeholder/stub status, lock artifacts. JSON + summary out. | allow |
| `hydrate <path>` | blind reads that auto-download | Pin/download placeholders with size estimate; refuses over policy threshold without ask | ask if large |
| `checkout <file>` | editing originals directly | Proprietary → open format into `_workspace/`, base hash recorded, hydration verified | allow |
| `convert <file> --to md` | ad-hoc pandoc incantations | One-shot conversion for read-only analysis (no checkout registry) | allow |
| `diff <file>` | — | Working copy vs live, or live vs any archived version | allow |
| `publish <file>` | `cp`/`mv` over originals | Archive current version → convert back → fidelity check → profile-aware replace | ask (shows fidelity diff) |
| `archive <path>` | `rm`, `rmdir`, `find -delete` | Move to archive store + manifest; reversible | allow |
| `move/rename <src> <dst>` | cross-folder `mv` | Manifest-logged, undoable move | allow |
| `snapshot <folder>` | — | Point-in-time backup of a folder into the archive store before any bulk operation | allow |
| `organize --plan` / `apply <plan-id>` | bulk `mv`/`rm` sprees | The "clean up this folder" verb — see plan→apply below | plan: allow; apply: ask |
| `restore <name> [vN]` / `undo [op-id]` | — | Bring back any archived version; invert the last logged operation | allow |
| `status` / `log` / `doctor` | — | Open checkouts, op history, environment health | allow |
| `prune` | — | Reclaim archive space. **Human-only**: always ask-tier + interactive confirmation | ask, always |

Design rules for every verb: single-purpose; reversible by construction (anything displaced lands in the archive store first); dual output (machine-readable JSON for the agent + one-line human summary); dry-runnable; self-logging to the audit trail (script-side log + hook-side log = two independent views).

### Plan → apply: transactional bulk operations

The family-photos incident's root cause was that **the approved description didn't match the executed action**. Plan→apply closes that gap structurally:

1. `agw organize <folder> --plan` (or `--plan` on any bulk verb) computes the full operation — every file, source, destination — writes it to `~/.agw/plans/<id>.json`, and prints the manifest. **Nothing is touched.** Always allowed.
2. `agw apply <plan-id>` executes *exactly* the stored plan. The PreToolUse hook intercepts `apply`, loads the plan file, and puts the **literal manifest summary in the ask prompt** ("moves 47 files to archive: 12 .tmp, 35 .docx from ~/Desktop/…"). What the user approves is the manifest, not the agent's paraphrase.
3. Plans are content-hashed and expire (TTL ~15 min); a stale or edited plan fails closed. A snapshot is taken automatically before apply, so even an approved-but-regretted plan is one `agw undo` away.

(Same staged-write shape as Canva's MCP editing transactions — prior art that this pattern works for agents.)

### The trust handshake: how hooks know to trust `agw`

The scripts are the privileged layer — the hooks delegate dangerous operations to them, so they're the trusted computing base and must be hardened accordingly:

- **Binary identity**: the hook allows `agw` only when the resolved command path is under `${CLAUDE_PLUGIN_ROOT}` (no `$PATH` lookalikes, no `python3 some/other/agw.py`).
- **Self-protection**: deny-tier rules protect the plugin's own files — no Write/Edit/Bash against `${CLAUDE_PLUGIN_ROOT}/**`, the policy dirs, `~/.agw/` internals (archive is append-only except via `restore`/`prune`), or the plans directory. The agent cannot edit the referee.
- **Verb-level policy**: the hook parses the `agw` subcommand and applies the tier table above — so even within the trusted CLI, `prune` always asks and `apply` requires a fresh plan. Companies can re-tier verbs in policy YAML (e.g., make `publish` allow-tier for a docs team).
- **Hardened internals**: argument validation, refuses paths outside session-granted roots, never shells out with user-controlled input, no network. The CLI assumes a hostile/confused caller.
- **Friction win**: because hooks return `permissionDecision: allow` for trusted verbs, the everyday CRUA loop runs with *zero* permission prompts — fewer prompts than vanilla Cowork, with stronger guarantees. That's the adoption pitch: guardrails that make the agent feel faster, not slower.

## 6. Pillar 3 — folder profiles (the "easy custom connectors" answer)

A profile = detection rules + behavior overrides, in one YAML:

```yaml
# profiles/onedrive-sharepoint.yaml
name: onedrive-sharepoint
detect:
  env: ["OneDrive", "OneDriveCommercial"]          # path under these roots
  path_prefix: ["~/Library/CloudStorage/OneDrive-*"]
  registry: ['HKCU\Software\Microsoft\OneDrive\Accounts\*\UserFolder']
behavior:
  placeholder_check: windows-attrs | posix-blocks
  archive_location: central           # never in-tree
  write_strategy: retry-in-place
  upstream_versioning: sharepoint      # informs publish messaging
  skip_artifacts: ["~$*", "*-ConflictedCopy*", "*.tmp"]
  policies: [sync-safety]
```

Built-ins: `local`, `git` (relaxed CRUA for text files — git already versions them; policy flag `git_passthrough`), `gdrive-sync`, `onedrive-sharepoint`, `dropbox`. **A custom connector = copy `_template.yaml`, fill in detection + behavior, drop it in `profiles/`** — e.g., a company NAS mount, Box Drive, an internal DMS sync tool. No code unless the format needs a custom converter, which is one Python class in `converters/`.

Detection runs once per folder per session (SessionStart hook warms a cache in `.agw/`), so per-tool-call guard latency stays low.

## 7. Skills (the teaching layer)

Hooks enforce; skills make the agent do it right so denials are rare:

- **`agent-workspace`** — CRUA philosophy, checkout-edit-publish, "never operate on originals."
- **`synced-folders`** — cloud-sync behavior: hydration before edit, no mass scans, conflict artifacts, sync lag ("your edit reaches SharePoint when the client syncs — don't verify via the cloud API immediately").
- **`gdocs-bridge`** — the one place the Drive connector remains essential: `.gdoc` stubs have no local content; export via `download_file_content(exportMimeType: text/markdown)` into the workspace, publish back as new file (connector limitation: new URL) or via Drive API in v2.
- **`restore`** (user-invocable `/restore`) — guided recovery.
- `CLAUDE.md` snippet generator for connected folders (belt-and-suspenders; Cowork loads folder CLAUDE.md).

## 8. Build phases

### Phase 0 — Validation spikes (cheap, de-risks everything)
- [ ] Cowork hook coverage: do plugin PreToolUse hooks fire for Bash? Write/Edit? Read? `mcp__*` connector tools?
- [ ] Placeholder semantics through the Cowork VM mount vs. host file tools (validate `Blocks==0` heuristic both ways; reproduce/verify #62140 class).
- [ ] VM environment: Python version, pandoc availability, pip/apt through the egress filter, mounted-path shape seen by hooks.
- [ ] Profile detection signals on real machines: `~/Library/CloudStorage/*`, OneDrive env/registry, DriveFS registry, Dropbox `info.json`.
- [ ] Marketplace install + `required` org install on a Team plan; `${CLAUDE_PLUGIN_ROOT}` resolution in Cowork.

### Phase 1 — Guard hooks + policy engine (v0.1: "the safety net")
- [ ] Neutral schemas first: `ToolEvent`/`Decision` in `core/events.py` — the platform boundary everything else builds against.
- [ ] Policy schema + loader (core / sync-safety / content-rules.d merging, deny>ask>allow).
- [ ] `core/engine.py` + `claude/pretooluse.py` adapter: shell-aware parsing, wrapper recursion, fail-closed ask; snippet rules on Write/Edit + heredocs; path zones.
- [ ] **Placeholder, shrink, and stub guards** (the #62140 killer — ship early, it's the headline).
- [ ] **Write/Edit auto-snapshot** (pre-image to archive store, hash-deduped) + fail-to-ask crash wrapper + latency cache (gap decisions 1–3).
- [ ] Deny-with-redirect messages; audit JSONL + `/guardrails-report`.
- [ ] Test suite: bypass corpus (xargs, find -exec, base64, interpreter one-liners, bash -c nesting) + placeholder/stub fixtures — denied or asked, never allowed.

### Phase 2 — Folder profiles + agent workspace (v0.2: "CRUA everywhere")
- [ ] `profiles.py` detection + cache; built-in profiles; `_template.yaml` + custom-profile docs.
- [ ] `agw` CLI core verbs: scan/hydrate/checkout/convert/diff/publish/archive/move/snapshot/restore/undo/status/log/doctor; central archive store; hash conflict checks; profile-aware write strategies (atomic vs retry-in-place); self-logging.
- [ ] Plan→apply transaction engine: plan manifests in `~/.agw/plans/`, content hashing + TTL, auto-snapshot before apply, hook-side manifest surfacing in ask prompts.
- [ ] Hook↔script trust handshake: binary-identity check via `${CLAUDE_PLUGIN_ROOT}`, verb-tier table in policy YAML, self-protection deny rules for plugin/policy/archive/plans paths.
- [ ] Converters: pandoc md↔docx with reference-doc styling; openpyxl csv↔xlsx; markitdown fallback; graceful copy-only degradation.
- [ ] Fidelity diff warning on publish; `agent-workspace` + `synced-folders` skills; `/agw-*` commands.

### Phase 3 — Bridges + packaging (v1.0)
- [ ] `gdocs-bridge` skill (connector export path for stubs); restore skill.
- [ ] `marketplace.json`, README quickstart, `enterprise/DEPLOYMENT.md` + managed-settings template, demo gif.
- [ ] Windows host validation (PowerShell-free Python hooks); version pinning + update story.

### Phase 4 — v2 horizon (designed-for, not built)
- **Platform adapters**: Codex (approval policies/rules), Cursor (enterprise hooks), Gemini CLI, Copilot CLI — same core engine, agw CLI, and policy YAML; per-platform capability research happens here. Repo becomes a monorepo with per-platform build artifacts.
- Instruction compiler: one authored source → Claude skills/CLAUDE.md, AGENTS.md, `.cursor/rules`.
- Bundled Drive MCP server for true in-place `.gdoc` updates (`files.update` keeps file ID/sharing/links); M365 Graph equivalent.
- tree-sitter-bash AST parsing; OTel audit exporter; policy dashboard; graduated "watch mode" (step-up approval on sensitive zones).

## 9. Gap-review decisions (pre-v1)

From the red-team pass on this plan; binding unless revisited:

1. **Crash policy — fail to `ask`, never open, never brick**: a top-level catch-all in the adapter converts any internal failure (exception, bad YAML, timeout risk) into `ask` with a warning. Hook exit-code semantics make uncaught crashes *silent allows* — this is the most important correctness rule in the codebase. Corrupt policy packs degrade to core defaults + ask.
2. **Write/Edit auto-snapshot**: PreToolUse on `Write|Edit` archives the file's pre-image (hash-deduped) before the edit lands. Makes "nothing is ever destroyed" true machine-wide even when the agent never touches `agw`. Cheapest big win in the design — ships in Phase 1.
3. **Latency budget**: policy parsed once at SessionStart into a cache; profile detection cached per folder; CI enforces p95 ≤ 150ms per hook invocation (revisit after Phase 0 measurement). If Python startup breaks the budget, a compiled dispatcher fronts the engine.
4. **Concurrency**: file locking around `state.json` and version allocation; audit/manifest writes append-only. Parallel sub-agents are the normal case in Cowork, not an edge case.
5. **Windows host runtime is unverified**: vanilla Windows has no `python3`; hook execution environment is a Phase 0 question. Contingencies: bundled runtime, PyInstaller exe, or PowerShell shim for the guard path.
6. **Compliance purge path**: `agw prune --compliance` (human-only, audited, documented) reconciles never-delete with GDPR erasure; per-zone `no_archive_copy` for regulated folders; DEPLOYMENT.md documents exactly where archived data lands (`~/.agw`) for DLP review.
7. **Audit redaction**: secret-format patterns (reused from snippet rules) scrub tool inputs before logging.
8. **Escape hatch**: deny messages address the *user* too ("to do this yourself, run it in your terminal"); `/guardrails-allow <rule-id>` grants a scoped, logged, session-long exemption; a false-positive report command feeds policy tuning. Frustrated users uninstall — the escape hatch is a retention feature.
9. **Edge cases owned in Phase 1–2 tests**: filenames with spaces/unicode, Windows MAX_PATH in archive paths, case-insensitive filesystems, oversized snapshot preflight, archive-store disk thresholds.
10. **Out of scope for v1, stated loudly in README**: computer use (no hook surface, unsandboxed), exfiltration through *allowed* channels (egress policy's job), malicious local users (the VM/OS is the security boundary; we prevent accidents).
11. **Onboarding**: SessionStart bootstraps `~/.agw/config.yaml`, runs silent `doctor`, and injects the `agw` vocabulary as additionalContext every session (skill auto-trigger is fallible; this isn't). Uninstall leaves the archive store intact as plain files — documented.
12. **Acceptance scenarios live in [TESTING.md](TESTING.md)** — the photos scenario, placeholder/stub guards, bypass corpus, crash resilience, and a friction anti-test (benign work must produce zero denies).

## 10. Risks

| Risk | Mitigation |
|---|---|
| Hooks don't cover some Cowork tool | Phase 0 spike first; CLAUDE.md + skills give right behavior even without enforcement |
| Placeholder detection differs across VM/host/WSL paths | Test all three in Phase 0; when uncertain, treat as placeholder (fail closed: ask) |
| Pandoc absent in VM and uninstallable | Copy-only checkout fallback (archive safety still holds); host-side conversion via plugin MCP in v2 |
| Sync client races (mid-sync locks, lag, conflict copies) | Retry-with-backoff writes, conflict-sibling checks at publish, skill teaches sync-lag patience |
| Central archive store grows unbounded | `agw status` surfaces size; human-only prune command; per-folder retention knobs |
| Round-trip fidelity loss blamed on plugin | Fidelity diff + explicit warning; original always recoverable from archive |
| Regex bypass criticism | Honest positioning (accident-prevention; VM is the boundary), fail-closed parsing, AST in v2 |
| Anthropic ships native sync-safety or Drive update tools | Profiles/policy/archive value is independent of transport; connector-specific code is isolated in profiles + one skill |
| Workspace friction on trivial tasks | CRUA scoped to proprietary formats + bulk ops; `git_passthrough` for text in git repos; zones let users mark `open` folders |
| Platform divergence (Codex/Cursor hook semantics differ from Claude's allow/ask/deny) | Neutral `Decision` schema includes the superset (e.g., step-up/warn map to ask); adapters degrade gracefully where a platform lacks a tier; core never special-cases a platform |
