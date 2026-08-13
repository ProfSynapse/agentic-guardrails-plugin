# agentic-guardrails

Make agentic coding tools safe on a real computer, including the
OneDrive/SharePoint/Google Drive/Dropbox folders synced to it, with one plugin
install.

**Supported hosts:** Claude Code (terminal and desktop app) and OpenAI Codex —
the safety engine and the `agw` CLI are identical across both; only a thin
adapter differs. Cowork support is planned but **not working yet**: its hooks
don't fire there. Tracking:
[docs/plans/0001-cowork-hook-enablement.md](docs/plans/0001-cowork-hook-enablement.md).

> **Release status:** `0.3.23` is the Windows-first stable release.
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
- Exact UTF-8 text reads are bounded and paginated through `agw file read`.
  The default output budget is normally sufficient; oversized lines return an
  exact byte continuation instead of requiring a larger guessed limit.
- Sensitive-read and credential-search prompts name the sanitized filename or
  scope, detected risk category, and the reason approval was triggered.
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

Then run `/plugins` inside Codex, install **Agentic Guardrails**, and approve its
hooks in the host's trust UI (`/hooks` in Codex CLI; desktop may show a trust
dialog). The full walkthrough — including the `apply_patch` deletion
guard and a smoke test to confirm interception on your build — is in
[plugin/CODEX.md](plugin/CODEX.md).

### Requirements

Python 3.9+. Windows hooks require it as `python`; the bundled `agw.cmd`
launcher tries `python` and then `py.exe -3`. POSIX hooks try `python3` and
then `python`. Optional: `pandoc` (docx↔markdown) and `openpyxl`
(xlsx→csv) for high-fidelity document checkout; without them files are checked
out in plain-copy mode. Fleet rollout: see
[plugin/enterprise/DEPLOYMENT.md](plugin/enterprise/DEPLOYMENT.md).

Third-party Office libraries are not bundled with the plugin. The built-in
OOXML backend uses only the Python standard library for `.docx`/`.pptx` text
reads and localized text mutations, plus `.xlsx`/`.xlsm` single-cell edits.
Advanced workbook reads and table/row mutations still require `openpyxl` in
the same Python runtime selected by the launcher. Package-preservation checks
reject edits that unexpectedly rewrite unrelated parts of an Office file.

| Format | Standard-library operations | Optional dependency tier |
|---|---|---|
| `.docx` | `info`, `get-text`, `replace-text`, `outline`, `read-blocks`, `patch` | None for these operations |
| `.pptx` | `info`, `get-text`, `replace-text` | None for these operations |
| `.xlsx` / `.xlsm` | guarded `set-cell` | `openpyxl` for workbook/table reads, formulas, appended rows, and table mutations |

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
| `scripts/agw/` + `bin/agw` / `bin/agw.cmd` | The `agw` CLI ("agent workspace"): bounded `file read`, recoverable text writes, scans, recovery, publishing, and targeted Office operations |
| `policies/` | Editable YAML rules: command rules, content/snippet rules (regex → deny/ask), path zones. Per-machine drop-ins in `~/.agw/policies.d/` |
| `skills/agentic-guardrails/` | One compact workflow router with safety references loaded only when needed |
| CLI help | Progressive command discovery through `agw --help`, verb help, and Office operation help |
| `enterprise/` | Managed-settings template + deployment guide |

## The agent's vocabulary

Denied primitives always come with a safe replacement in the denial message,
so the agent self-corrects instead of fighting the rails:

| Instead of | The agent uses |
|---|---|
| `rm file` | `agw archive file` (reversible) |
| editing `report.docx` in place | `agw checkout` → edit markdown → `agw publish` |
| editing a Drive-hosted macro workbook | `agw checkout workbook.xlsm` → edit the external working copy in Excel → `agw publish` |
| `python -c` openpyxl one-liners | `agw office set-cell` / `replace-text` / `append-rows` |
| several dependent text edits | `agw file plan` then `agw file apply-plan` |
| one-off write-capable script | `agw run --output PATH --expected-hash HASH -- command` |
| hash-bound single-use script execution | `agw run-plan create` then `agw run-plan apply` |
| publish several staged artifacts | `agw publish-plan create` then `agw publish-plan apply` |
| discover an existing script contract | `agw workflow match -- command` |
| draft a contract without trusting or writing it | `agw workflow propose ... -- command` |
| repeated versioned script | `agw run --workflow ID -- command` after explicit trust |
| inspect an exact CLI contract | `agw schema file apply-plan --json` |
| reverse one exact mutation | `agw undo --transaction ID` |

Structured Office operations are also available:

~~~text
agw office info workbook.xlsx --scope tables --json
agw office validate workbook.xlsx --tier excel-strict --json
agw office read-table workbook.xlsx --table RecordsTable --columns RecordID,Status --limit 50 --json
agw office validate-preservation staged.xlsm --against original.xlsm --json
agw office ensure-table workbook.xlsx --sheet Records --table RecordsTable --headers-json '["RecordID","Status"]' --create-sheet
agw office append-table-row workbook.xlsx --table RecordsTable --row-json '{"RecordID":"R-2"}' --unique-column RecordID
agw office update-table-row workbook.xlsx --table RecordsTable --key-column RecordID --key R-2 --set-json '{"Status":"Closed"}'
agw office outline report.docx --json
agw office patch report.docx --expected-file-hash HASH --ops-file patch.json
~~~

Every JSON-bearing option also accepts `-` to read its payload from standard
input. This avoids native argument-quoting problems and is the preferred compact
form in PowerShell:

~~~powershell
'{"RecordID":"R-2","Status":"Needs review"}' | agw office append-table-row workbook.xlsx --table RecordsTable --row-json -
'["RecordID","Status"]' | agw office ensure-table workbook.xlsx --sheet Records --table RecordsTable --headers-json - --create-sheet
'[{"op":"replace_block","id":"p2-abc123","text":"Revised text with spaces."}]' | agw office patch report.docx --ops-json -
~~~

This applies to `--rows`, `--headers-json`, `--columns-json`, `--where-json`,
`--row-json`, `--unique-columns-json`, `--set-json`, `--key-json`, and
`--ops-json`. A command can consume only one stdin payload;
use the corresponding file option when multiple structured inputs are needed.

Reads are paginated and compact. Writes validate a staged Office package,
archive one exact pre-image, reject source drift, and atomically replace the
live file. Table operations return sheet, table, range, row count, and file
hashes. `ensure-table` is idempotent and can create an explicitly requested
sheet or convert an explicit rectangular range. Appends can enforce atomic
single or composite uniqueness with `--unique-column` or
`--unique-columns-json`. Read-only inspection reports detected preservation
risks; mutation refuses unsupported or lossy OOXML. `set-cell` uses a surgical
adapter for `.xlsm`, retaining every unrelated package part byte-for-byte.
Preserved `.xlsx`/`.xlsm` checkouts default to a non-synced Guardrails workspace
for desktop Excel editing. Publish refuses live drift, validates VBA and other
protected package content, archives one exact pre-image, and atomically replaces
the synced target. Other Excel table writes support `.xlsx` and remain refused
for `.xlsm`. Word
patches provide general block-level editing for top-level body paragraphs,
headings, and list items.

For dependent changes across several UTF-8 files, `agw file plan` accepts one
version-1 operations JSON document containing `write`, `patch`, and `replace`
items. It validates exact target versions and materializes the proposed results
into a self-contained plan without changing the targets. `agw file apply-plan`
requires the returned plan hash, rechecks every target, captures every pre-image,
and publishes the set under one lock. A handled publication failure rolls back
already-published members; durable per-file recovery receipts remain available
if the host or machine stops between filesystem replacements. Use the leaf help
for the compact schema and arguments; plan files contain proposed file content
and should be protected like the target files.
JSON failures distinguish `preimage_hash_conflict`, `patch_context_conflict`,
`patch_hunk_count_mismatch`, and `replace_match_conflict`. Count mismatches also
return the hunk/header, patch line, expected and observed counts, and a corrected
header suggestion so an agent can repair the diff without parsing prose.

Write-capable scripts remain fail-closed unless every output is declared before
execution. One-off runs use exact `--output` arguments; reviewed repeated tools
can install a data-only, script-hash-bound manifest with `agw workflow trust`
and then use `agw run --workflow ID`. A repository cannot trust its own
manifest merely by placing it beside a script. Exact existing outputs receive
verified pre-images and exact absent outputs receive tombstones before launch.
Runs use bounded time and output capture. The default `observed` mode does not
claim isolation; unavailable read-only, strict, or network-denied execution
fails closed without silently downgrading.
Before direct script execution, `agw workflow match -- <command>` checks verified
machine-local records for the exact runtime, script path, script hash, and bound
arguments. A single exact match can be routed automatically by supported hooks;
multiple matches remain explicit. Ambiguous source-only write evidence reports
the triggering line and primitive, requires one-run review in standard mode,
stays blocked in strict mode, and is shadowed in observe mode.
JSON matching includes stable per-candidate mismatch reasons. `agw workflow
match` also ranks verified candidates as `exact`, `parameterizable`, `near`, or
`incompatible`. It emits `recommended_argv` only when a candidate is revalidated
against the same command and output contract. `suggested_argv` is a deprecation
object with `replacement:"recommended_argv"` and `value_included:false`; consumers
must read that one authoritative array. The input command, normalized arguments,
and nested diagnostics are omitted
from the response so candidate values stay hashed and raw values are not multiplied. `agw
workflow propose` returns an
inert validated v2 proposal without writing or trusting it.

Migration note for 0.4: `suggested_argv` is no longer an argv array and must not
be executed or compared as one. JSON consumers should read the sole value-bearing
`recommended_argv` array and may use the `suggested_argv` object only to discover
that replacement. This metadata-only shape avoids duplicating potentially private
command values in diagnostics.
Manifest v2 also binds the exact script arguments, so `agw run --workflow ID`
can reconstruct the reviewed command without agents restating Unicode paths or
flags. Use `agw workflow init` to generate v2, `validate` before trust, and
`status` to reconcile machine-local trust for a synced manifest. V1 remains
readable for compatibility but does not bind arguments.
Manifest v3 adds named runtime values in reviewed argument positions. Invoke it
compactly with `agw run --workflow ID --param NAME=VALUE`; supported constraints
are inline enum, hash-bound enum file, conservative regex, integer range, and
bounded path. Missing, invalid, repositioned, and extra arguments fail before
execution. Enum files are compiled into the sealed trust record, so repository
changes cannot silently expand an already-trusted workflow.
Exact outputs are independent of optional observed roots, so a recoverable state
file can be paired with a separate dynamic cache root. Observed roots only detect
unclaimed after-the-fact changes; they do not prevent writes or recover an
unknown file. Executed JSON results make the classification explicit:
`unchanged_outputs` lists exact declared paths whose before/after states compare
equal, while `ignored_sidecar_changes` lists every observed change suppressed by
an output pattern together with its root, relative path, and matched pattern.
An unchanged path may still be missing when a required absent output stayed
absent; equality is not proof that a path was never touched. Dry runs do not emit
post-execution inventories. See the
[trusted-workflow reference](plugin/skills/agentic-guardrails/references/trusted-workflows.md).
`agw run --dry-run` is deliberately contract-only: it does not execute the
command or predict its writes. JSON identifies this explicitly as
`"validation_scope":"contract_only"`.

For a stronger execution boundary, `agw run-plan create` writes a canonical,
hash-bound plan through the same reversible file-write machinery as other
Guardrails files. `agw run-plan apply` requires the plan's canonical SHA-256.
Each plan is single-use and is consumed after its durable claim, including when
the later process or contract check fails. `stdout-read-only` is refused before
claim or execution unless the installed provider truly enforces a read-only
filesystem; the default observed runner never claims that support. JSON reports
process, contract, precondition, policy, and environment outcomes independently,
plus whether the composite outcome came from live evaluation or conservative
legacy projection.

`agw publish-plan` publishes a bounded staged batch as a `recoverable-set` with
`per-file-sequential` visibility: recovery is durable for the set, but readers
may observe intermediate mixtures while individual atomic replacements occur.
Create writes the inert plan recoverably and apply requires its canonical hash.
`publish-plan recover TRANSACTION_ID --action inspect` authenticates and
classifies an incomplete PREPARED publication without mutation.
`finalize-observed` records COMMITTED only when every target is already in its
exact after-state. PREPARED `rollback` currently returns
`prepared_rollback_unavailable` without fallback or writes because safe rollback
requires a future crash-resumable journal. Automatic roll-forward is unavailable;
omitting `--action` also fails without mutation.

Successful file mutations include an explicit recovery receipt and an exact
`agw undo --transaction ID` command. Multi-file plans and declared runs share a
parent transaction. Archive maintenance never prunes arbitrary recovery
artifacts: at the high-water mark it may reclaim only expired records explicitly
classified as mutation preimages. `agw checkout close PATH` preserves the working
copy, and `agw checkout reopen TRANSACTION_ID` restores its tracking.

Folder discovery is hard-bounded by a parent process. Plain
`agw scan <folder> --json` now uses the safe profile by default: 3 seconds,
5,000 files, 10,000 total entries, depth 4, and no per-file stat. `--fast`
remains as a compatibility alias. Use `--deep` to explicitly select the larger
30-second/100,000-file/200,000-entry/depth-64 profile, or set a narrower or
larger explicit `--max-seconds`, `--max-files`, `--max-entries`, and
`--max-depth` within the CLI's absolute safety ceilings.
The deadline includes path validation, profile detection, enumeration, metadata
inspection, cleanup, and bounded result construction. If a filesystem call
blocks, the parent terminates the scan worker and returns the progress received
so far with `complete: false`, `stop_reason`, inspected counts, and cleanup
status. Fast/no-size scans avoid per-file `stat()` calls and report
`placeholder_detection: "limited"`. Mounted Google Drive, OneDrive/SharePoint,
and Dropbox roots are detected automatically where local path or volume signals
are available; `--profile` provides a validated override for known roots.

`agw search <text> <folder> --json` provides the same killable bounded defaults
for content search, with 100 returned matches and a 1 MiB per-file ceiling.
`--regex`, `--ignore-case`, repeatable `--include`/`--exclude` globs, `--files`
for filename matching, `--max-matches`, `--max-file-bytes`, the traversal limits
above, and explicit `--deep` are available. `agw list <folder> --json` returns a
bounded path list (500 results by default) with `--kind`, `--name`, `--exclude`,
and `--max-results` filters. Content searches skip credential-type files, binary
files, cloud placeholders, Google pointer stubs, links, and common dependency/
build/cache directories. Scan,
list, and search skip `.git`, `node_modules`, `.venv`, `vendor`, `target`, `dist`,
`build`, `__pycache__`, and related caches unless one is the exact root.

Raw discovery is shape-checked before launch. Standard mode keeps exact-file and
narrow project-local searches/listings, but redirects drive/home/cloud roots,
outside-project recursion, dependency/cache scopes, dynamic paths, ignore-
disabling flags, and link-following traversal to `agw list` or `agw search`.
Strict mode redirects every recursive raw discovery. This applies to shell tools
(`rg`, `grep`, `find`, `fd`, `tree`, recursive `ls`/`Get-ChildItem`) and native
Glob/Grep tools; Guardrails never silently rewrites their differing semantics.
| `mv` (untracked) | `agw move` (transactional, undoable) |
| bulk folder surgery | `agw snapshot` first, then work |

Exception: `rm` of purely regenerable build/dependency dirs (`node_modules`,
`dist`, `.venv`, `__pycache__`...) is allowed at `standard` and above (pointless
and huge to archive). `strict` archives even those. The list is extensible via
`settings.regenerable_globs`.

Escalations (`ask`): `git checkout -- <file>`, shrink-suspicious writes
(replacing a large file with tiny content), reading cloud-only placeholders,
publish conflicts, `agw prune`, reading credential-type
files (.env, keys, `~/.aws`...), files whose content prescan finds secrets or
"CONFIDENTIAL" markings ("this might contain a password, confirm"), and
bounded credential-keyword searches outside the active project. Combining a
credential file with a
network tool in one command (`curl -d @.env ...`) is denied as exfiltration. Hard denies: `rm`/`shred`/
`find -delete`, `git push --force` / `reset --hard` / `clean -f`, `dd` to
devices, `mkfs`, `sudo`, decode-to-shell and download-to-shell pipes,
destructive SQL/interpreter one-liners, writes to `.gdoc` stubs, placeholders,
protected zones, the plugin itself, the archive store, and unbounded discovery.

Content scans are span-aware: a destructive string that only appears as a search
pattern or echoed data (`grep "DROP TABLE" schema.sql`) is not treated as an
executed command, so it isn't blocked.

### Human-readable approvals and connected services

Approval dialogs describe the action, affected category, reason, and consequence
without requiring the user to interpret raw shell syntax. They add a recovery
line only when it communicates a distinct, factual recovery limitation.
Those facts are produced locally from the shared command contract, policy rule,
and parsed targets; no model generates a rationale or confidence score. A prompt
with unresolved operation or target evidence is denied before any approval UI
can open. Unsupported `agw` operations are likewise denied with a bounded verb
label and a route to `agw --help` rather than an uninformative confirmation.
Connected-service prompts name the sanitized service, action, and target name or
identifier when available; message bodies, tokens, and raw payloads stay hidden.
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
  one knob. `AGW_STRICT_DISCOVERY` can independently require bounded Guardrails
  for every recursive discovery command.
  See [plugin/enterprise/DEPLOYMENT.md](plugin/enterprise/DEPLOYMENT.md) for the
  full table.
- **Recovery-cache budget:** the standard policy is 4 GiB, with automatic
  maintenance at 90% and a target of 80%. `AGW_ARCHIVE_MAX_BYTES=0` explicitly
  selects unlimited retention. Every mutation preimage is protected for seven
  days; days 8–30 retain daily generations, and a path inactive for more than
  30 days retains its newest usable point. Move/delete archives, manual
  snapshots, evidence, corrupt records, and unclassified legacy records are
  never automatic candidates.

Retention does not run at SessionStart. Each operation that would grow the
recovery store performs a cheap size/admission preflight; the bounded full
inventory and pruning pass runs only after that operation reaches the
high-water mark. `agw status` and `agw doctor` are read-only retention reports
and never invoke maintenance; manual `agw prune` is optional.

### Activity history and recovery metadata

Claude or Codex task history is the human activity log. Guardrails does not
create a second command/event ledger, key, migration journal, provenance file,
or quarantine. Existing `audit.jsonl` and legacy-quarantine files are left
completely untouched and unread.

Guardrails reports use only privacy-safe CRUA metadata already needed for
recovery: archive-store health and recovery-copy totals, open checkout status,
and policy health/revision. They never reconstruct raw commands or read legacy
audit material. If command-level decision counts or trends are requested, say
plainly that Guardrails does not keep that metric.

This change does not affect pre-image snapshots, archive transactions, restore,
pending approvals, or policy revisions. Activity-history availability never
changes an allow, ask, or deny decision.

## Testing

```
python3 -m pytest tests/   # optional-library integration tests skip when unavailable
```

Includes a bypass corpus (nested `bash -c`, command substitution, xargs, wrapper
commands, encode/decode pipes, interpreter one-liners, PowerShell/cmd deletion)
that must always resolve to deny/ask, golden subprocess tests of the actual hook
(including the crash-fails-closed contract), and store concurrency tests. See
[TESTING.md](TESTING.md) for the full plan.

## Roadmap

Cowork support (hooks don't fire there yet —
[docs/plans/0001-cowork-hook-enablement.md](docs/plans/0001-cowork-hook-enablement.md)),
the `hydrate` verb, a Cursor adapter on the same core engine, and an instruction
compiler, and killable worker isolation for hard-bounded workflow manifest/script
validation on stalled virtual filesystems. Also planned is
an on-demand, report-only connector policy auditor that inventories exposed
connector tools, flags unclassified or ambiguous action verbs, and proposes
reviewed Codex/Claude policy and test updates without executing connector
actions or changing policy automatically. Design notes in
[PLAN.md](PLAN.md), research trail in [RESEARCH.md](RESEARCH.md).
