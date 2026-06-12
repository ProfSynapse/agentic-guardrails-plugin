# Research Synthesis — Agentic Guardrails Plugin

*Compiled 2026-06-12 from official Anthropic docs, live connector tool-surface inspection, and ecosystem survey.*

---

## 1. The platform: what Cowork actually supports

Cowork is the agentic mode in the Claude desktop app (GA on all paid plans since April 2026, macOS + Windows). Facts that shape our design:

### Architecture (critical)
- **Folder-scoped file access** — users grant specific local folders; Claude can read/write/create/delete within them. No full-disk access. ([support article](https://support.claude.com/en/articles/13345190-get-started-with-claude-cowork))
- **Split execution**: the agent loop + file read/write + local plugin MCP servers run **natively on the host**; shell commands and code run in an **isolated Linux VM** (Apple Virtualization.framework / Hyper-V) with folders mounted at `/sessions/<name>/mnt/<folder>`, network egress filtering, per-session isolation. ([architecture overview](https://support.claude.com/en/articles/14479288-claude-cowork-desktop-architecture-overview))
- **Computer use runs outside the VM, unsandboxed**, with no admin controls today.
- Cowork edits **real files in place** — there is no copy-on-write or shadow-copy mode. This is exactly the gap our agent-workspace pattern fills.

### Extensibility surface
- Cowork uses the **Claude Code plugin format**: `.claude-plugin/plugin.json` + `skills/`, `commands/`, `agents/`, `hooks/hooks.json`, `.mcp.json`, `scripts/`. Anthropic's own [knowledge-work-plugins](https://github.com/anthropics/knowledge-work-plugins) repo installs into both Cowork and Claude Code from one source.
- **Hooks and sub-agents run in Cowork** (not in plain chat). ([Use plugins in Claude](https://support.claude.com/en/articles/13837440-use-plugins-in-claude))
- **Cowork does NOT surface `settings.json` permission rules, env vars, or CLI flags.** `CLAUDE.md` from connected folders is loaded, but there is no permissions engine exposed to users. → **Hooks shipped inside a plugin are the only programmatic enforcement surface in Cowork.** ([claude-code#44098](https://github.com/anthropics/claude-code/issues/44098), [extensions doc](https://claude.com/docs/cowork/3p/extensions))

### Enterprise distribution
- Org plugin management: custom marketplace (≤50MB ZIP or GitHub-synced, up to 500 plugins) or MDM-deployed org-plugins directory (`/Library/Application Support/Claude/org-plugins/` on macOS, `C:\Program Files\Claude\org-plugins\` on Windows).
- Per-plugin `installationPreference`: `required` (cannot be uninstalled) / `auto_install` / `available` / not available. Enterprise group-level overrides.
- Managed settings (Claude Code side): `enabledPlugins` force-enable, `allowManagedHooksOnly`, `allowManagedPermissionRulesOnly`, `strictKnownMarketplaces`. Server-managed settings sync from the admin console.
- **Audit gap**: Cowork activity is excluded from Audit Logs / Compliance API / Data Exports; only OpenTelemetry event streaming (tool calls, file access, approval decisions) is available. An audit-logging story inside the plugin has real enterprise value.

## 2. Hooks: the enforcement mechanism

- `PreToolUse` hooks receive `{tool_name, tool_input, session_id, cwd, ...}` as JSON on stdin; they can return `hookSpecificOutput.permissionDecision: "allow"|"deny"|"ask"|"defer"` with a reason, or simply **exit 2** to block (stderr is shown to Claude).
- Matchers filter by tool name (regex; `Bash`, `Write|Edit`, `mcp__*__delete*`), plus an `if` condition on tool input.
- **A blocking PreToolUse hook takes precedence over allow rules and fires even under bypass-permissions modes** — this is why every serious guardrail project builds on hooks, not deny rules.
- `PostToolUse` is the audit-logging point. `SessionStart` can initialize workspace state. `${CLAUDE_PLUGIN_ROOT}` resolves to the installed plugin dir in hook commands.
- Hook docs: [hooks reference](https://code.claude.com/docs/en/hooks), [hooks guide](https://code.claude.com/docs/en/hooks-guide.md).

## 3. Connectors and the cloud round-trip (CRUA implications)

Verified against the live tool surfaces (2026-06-12):

| Connector | Capabilities | CRUA impact |
|---|---|---|
| **Google Drive** | `search_files`, `read_file_content`, `download_file_content` (with `exportMimeType`), `get_file_metadata/permissions`, `create_file`, `copy_file`, `list_recent_files`. **No update, move, rename, trash, or delete.** | Read ✓, Create ✓, Archive ≈ (copy, but can't move/retire the old live file), Update ✗ (new file = new ID/URL) |
| **Gmail** | Drafts + label CRUD only; cannot send | n/a |
| **Google Calendar** | Full CRUD including delete | Proves write connectors are a product choice, not a platform limit |
| **Microsoft 365** | Strictly read-only (search/analyze SharePoint, OneDrive, Outlook, Teams) | No write path at all via connector |

Key API facts for a future true-update path:
- Google Docs ↔ **markdown is native since July 2024**: `text/markdown` is an official export MIME type, and markdown imports/converts on `files.create`/`files.update`. ([export formats](https://developers.google.com/workspace/drive/api/guides/ref-export-formats))
- `files.update` with media upload **replaces a Doc's content in place — same file ID, same sharing, same links** (proven in [google_workspace_mcp#604](https://github.com/taylorwilsdon/google_workspace_mcp/issues/604)).
- Archive = `files.copy` + `files.update(addParents=<Archive>)`. Never `files.delete`; never trash.
- Docs revision history auto-purges over time → explicit archive copies are the durable record, not revisions.
- Markdown round-trip is **lossy** for Docs (comments, suggestions, headers/footers, complex tables) — must warn/diff before publish.
- M365 via Graph: `PUT /driveItem/{id}/content` replaces content and SharePoint versioning auto-snapshots (up to 500 versions) — archive is nearly free there.
- Open-source Drive MCP servers with real update + revision tools exist (e.g. [piotr-agier/google-drive-mcp](https://github.com/piotr-agier/google-drive-mcp): `updateGoogleDoc`, `getRevisions`, `restoreRevision`, trash-only delete) — reference implementations for a v2 bundled MCP server.

### Local format conversion tooling
- **pandoc** — the only mainstream tool that goes both directions (docx ↔ md, with `--reference-doc` styling, `--extract-media`). Primary engine.
- **markitdown** (Microsoft) — broadest one-way coverage (docx/xlsx/pptx/pdf → md). Read-side fallback.
- **openpyxl / python-docx** — surgical in-place edits when regeneration is wrong.
- **LibreOffice headless** — heavy fallback for fidelity-critical conversions.

## 4. Competitive landscape and the gap

Existing guardrails (damage-control, Boucle, claude-code-safety-net, mafiaguy, karanb192…) are all **block/ask pattern-matchers** on PreToolUse. Documented weaknesses:

- **Regex denylists are evadable** (variable indirection ~95% success, base64/hex decode-and-pipe ~97.5%, interpreter one-liners, write-then-execute). Cursor *deprecated its denylist feature entirely* after [Backslash's research](https://www.backslash.security/blog/cursor-ai-security-flaw-autorun-denylist). Best practice: semantic/AST parsing + allowlist-leaning posture + OS sandbox as the real boundary; patterns are UX, not security.
- Claude Code's own deny rules were silently skipped on >50-subcommand lines until v2.1.90 — pattern engines have failure modes too.

**Confirmed real-world failure mode we're targeting**: the ~Feb 2026 incident where Cowork asked permission to delete "temporary Office files," got approval, and an `rm -rf` wiped two decades of family photos. The prompt was shown and approved — **the description didn't match the action**. Plus an 11GB deletion during a "clean up this folder" request. Anthropic's own safety guidance: dedicated working folder, keep backups, treat web/MCP/plugins as injection surface.

**Gaps no existing tool fills** (our value proposition):
1. **Reversibility as the core primitive** — nobody does transactional file ops (intercept deletes → archive). trash-cli/ai-trash prior art shows demand; no packaged plugin does it.
2. **The agent workspace** — no guardrail combines command-blocking with a work-in-a-copy → review → publish lifecycle.
3. **Enterprise distribution** — hook collections are curl-installed and trivially deletable; a `required` org plugin survives uncooperative users and prompt-injected agents.
4. **Audit logging** — JSONL/OTel-compatible logs of denied/archived operations; Cowork has an audit-log void.
5. **Cloud-doc safety** — nobody round-trips Google Docs/Office files with versioned archives.

## 5. Synced cloud folders as local workspaces (the primary use case)

Users mount SharePoint/OneDrive/Google Drive/Dropbox as local folders with offline access; the sync client is the cloud transport. Facts that change the design:

### Google Drive for Desktop
- Two modes: **streaming** (default — virtual drive, files are cloud-only until used) and **mirroring** (real local copies). Streamed, non-cached files are unreadable offline and "difficult to stream" for some apps.
- **`.gdoc`/`.gsheet`/`.gslides` are JSON pointer stubs with no content** — filesystem editing is impossible and corrupts the pointer. Native Docs must go through export (connector/API) — the only place the cloud connector remains necessary.
- Edits to a synced `.docx` upload as revisions of the same Drive file, but binary revision history is only **30 days / 100 revisions** — an agent making rapid saves flushes it fast. Not an undo log.
- Conflict artifacts: `[Conflict]` files; hidden `.tmp.drivedownload`/`.tmp.driveupload` staging dirs at root.

### OneDrive / SharePoint sync
- **Files On-Demand placeholders auto-hydrate on read** — a recursive scan triggers mass downloads. Windows attribute flags: `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`, `PINNED`, `UNPINNED`. Storage Sense can silently re-dehydrate unpinned files at any time.
- **Live Cowork data-loss bug ([claude-code#62140](https://github.com/anthropics/claude-code/issues/62140))**: Cowork read a truncated placeholder via the WSL path (saw 24KB of a 258KB file), edited it, wrote back — destroying the cloud copy. Open, unfixed. Detection heuristic: `stat` shows **`Blocks == 0 && Size > 0`**. This is a guardrail no one ships.
- SharePoint versioning is automatic and generous (500 major versions default; renames create versions too) but versions count against storage quota. OneDrive personal ≈ 30 days/~25 versions.
- Conflicts: device-name "ConflictedCopy" files; Office's `~$file.docx` locks + merge layer collide with non-Office programmatic edits to open files.
- **Cannot exclude an arbitrary subfolder from sync** (extension-based admin ignore lists only).

### Dropbox
- Online-only files via File Provider/dataless; version history 30–180–365 days by plan (doesn't count against quota); `conflicted copy YYYY-MM-DD by Device` artifacts; `.dropbox.cache` staging dir.

### Detection signals (for a folder-profile system)
- macOS (all providers): path prefix `~/Library/CloudStorage/<Provider>-<account>` — near-universal.
- Windows: `%OneDrive*%` env vars + `HKCU\Software\Microsoft\OneDrive\Accounts\*\UserFolder`; `HKCU\SOFTWARE\Google\DriveFS\Share`; Dropbox `info.json` in `%APPDATA%`/`~/.dropbox`.
- Placeholders: Windows attribute flags; POSIX/WSL `Blocks==0 && Size>0`; macOS `SF_DATALESS` in `st_flags`. Caveat: on macOS, even stat'ing can materialize dataless intermediate dirs; `**` globs can mass-materialize.

### Consequences for the design
1. **Detect synced roots and apply a cloud-sync folder profile** automatically.
2. **Never read-modify-write a placeholder** — hydrate/pin first or refuse; reject writes that dramatically shrink a file vs. prior size.
3. **Block edits to `.gdoc`-family stubs**; route to export/API path.
4. **Keep archives and high-churn state OUTSIDE the synced tree** (no subfolder exclusion exists; churn burns quota/bandwidth; the `.pst` guidance is canonical: continuously-modified files don't belong in synced folders).
5. **Don't trust sync version history as the undo log** — our own archive is the durable record.
6. Throttle recursive scans in On-Demand trees; skip lock/conflict artifacts; retry transient rename failures (sync clients briefly lock files mid-sync — KeePassXC had to add a non-atomic save fallback for exactly this).

## 6. Open questions to resolve during build

1. **Tool availability inside the Cowork VM** — is pandoc present? Can we `pip install markitdown` / `apt install pandoc` through the egress filter? Fallback: pure-Python converters vendored in the plugin, or host-side MCP server doing conversion (plugin MCP servers run on the host, not in the VM).
2. **Hook path semantics in Cowork** — tool_input paths will be VM paths (`/sessions/.../mnt/...`) for Bash but host paths for native file tools; hook scripts must normalize both.
3. **Do `PreToolUse` hooks in Cowork cover the native file tools** (Write/Edit/delete) or only Bash? Needs empirical testing — the docs say hooks run, but per-tool coverage in Cowork is undocumented.
4. **Windows**: hook scripts need a no-bash story on the host side (PowerShell or Python entry points) even though the VM is Linux.
5. **Connector tool interception** — can PreToolUse match `mcp__google_drive__create_file` etc. in Cowork to enforce CRUA on connector calls? Matcher syntax supports `mcp__*`; Cowork behavior needs testing.
6. **Placeholder semantics across the VM boundary** — how do OneDrive/Drive placeholders appear to Cowork's Linux VM mounts vs. host-native file tools? (The #62140 corruption came via a WSL-style path.) The `Blocks==0 && Size>0` heuristic needs validation in both contexts.
7. **Dropbox `com.dropbox.ignored` xattr** (per-folder sync exclusion) — documented but unverified; if reliable, it's the one provider where an in-tree archive could be sync-excluded.
