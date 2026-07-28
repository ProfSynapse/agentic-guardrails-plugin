---
name: agent-workspace
description: >
  CRUA workflow for editing Office and proprietary documents (docx, xlsx, pptx,
  pdf) safely. Use when asked to modify, update, fill in, or rewrite a document
  file — checkout converts it to markdown/csv in _workspace/, you edit the copy,
  publish archives the old version and replaces the original. Never edit
  proprietary formats in place.
---

# Agent Workspace (CRUA)

The guardrails plugin enforces **CRUA**: Create, Read, Update, **Archive** —
never delete, never overwrite without a recoverable prior version.

## The flow

1. **Checkout** — `agw checkout <file>`
   Converts the document to an open format (docx → markdown, xlsx → one csv per
   sheet) inside `_workspace/` next to the original, and records the original's
   hash so conflicts are detected later. If the file can't be converted, it is
   copied as-is ("plain copy mode") — still edit only the workspace copy.

2. **Edit the working copy** — use normal Write/Edit tools on the file under
   `_workspace/`. Never edit the original directly; the hook will ask or deny.

3. **Diff (optional)** — `agw diff <file>` shows working copy vs. original.

4. **Publish** — `agw publish <file>`
   - Archives the current live file as a new version (recoverable forever).
   - Converts the working copy back to the original format (docx publishes use
     the original as a style reference, so formatting survives).
   - Atomically replaces the original.
   - **Exit code 3 = conflict**: someone changed the original since checkout.
     Report this to the user; do not pass `--force` without their say-so.

## Other verbs

| Verb | What it does |
|---|---|
| `agw status` | List open checkouts and their state |
| `agw scan <folder> [bounds]` | Metadata-only inventory of placeholders, pointer stubs, and sync artifacts |
| `agw archive <path>` | Reversible "delete" — moves into the archive store |
| `agw restore <path> [--version N]` | Bring back any archived version |
| `agw undo` | Revert the last archive/move operation |
| `agw move <src> <dest>` | Logged, undoable move/rename |
| `agw snapshot <folder>` | Whole-folder backup before bulk work |
| `agw log [path]` | Show the operation log |
| `agw doctor` | Environment self-check (converters, store writability) |
| `agw office <op> <file>` | Targeted in-place Office edits (see below) |

All verbs accept `--json` for machine-readable output.

## Small Office edits: `agw office`

For a targeted change to a docx/xlsx/pptx file, skip the checkout round-trip —
these edit in place and archive a pre-image snapshot first, so they are as
reversible as everything else:

```
agw office info <file>                       # structure: sheets, headings, slides
agw office get-text <file>                   # plain-text extract (docx/pptx)
agw office replace-text <file> --find "Old Name" --replace "New Name"
agw office replace-text <file> --find "Q3" --dry-run    # list matches first
agw office replace-text <file> --find "Q3" --replace "Q4" --all     # every one
agw office replace-text <file> --find "Q3" --replace "Q4" --nth 2   # just one
agw office set-cell <file.xlsx> --sheet Q3 --cell B2 --value 55
agw office append-rows <file.xlsx> --sheet Q3 --from-csv new-rows.csv
agw office info <file.xlsx> --scope tables --json
agw office read-table <file.xlsx> --table RecordsTable --columns RecordID,Status --limit 50 --json
agw office ensure-table <file.xlsx> --sheet Records --table RecordsTable --headers-json '["RecordID","Status"]' --create-sheet
agw office append-table-row <file.xlsx> --table RecordsTable --row-json '{"RecordID":"R-2"}' --unique-column RecordID
agw office update-table-row <file.xlsx> --table RecordsTable --key-column RecordID --key R-2 --set-json '{"Status":"Closed"}'
agw office outline <file.docx> --limit 50 --json
agw office patch <file.docx> --expected-file-hash HASH --ops-file patch.json
```

On PowerShell, pipe structured JSON through stdin instead of fighting native
argument quoting. JSON-bearing options accept `-` as the stdin sentinel:

```powershell
'{"RecordID":"R-2","Status":"Needs review"}' | agw office append-table-row <file.xlsx> --table RecordsTable --row-json -
'[{"op":"replace_block","id":"p2-abc123","text":"Revised text with spaces."}]' | agw office patch <file.docx> --ops-json -
```

This works for `--rows`, `--headers-json`, `--columns-json`, `--where-json`,
`--row-json`, `--unique-columns-json`, `--set-json`, `--key-json`, and
`--ops-json`. Use only one stdin payload per command; use a JSON file when an
operation needs multiple structured inputs.

`replace-text` works like the Edit tool: if `--find` matches more than once
it refuses rather than mass-editing. Either make `--find` longer and unique,
or run `--dry-run` to see every match (numbered, with location and context)
and then target with `--nth N` or replace everywhere with `--all`.

Values auto-coerce to numbers/booleans/formulas (`=SUM(...)`); add `--text`
to keep them as literal text. Use `agw office` for point edits; use
checkout/publish when restructuring a document or doing heavy rewriting.
Never edit Office files with ad-hoc interpreter one-liners (python -c with
openpyxl etc.) — those bypass the snapshot contract and will be blocked
or escalated.

Structured reads are compact and bounded: table headers are returned once with
row arrays, and table/Word reads support pagination. Word block IDs are bound
to the returned file hash, so `patch` requires `--expected-file-hash`.

Use `ensure-table` only with an explicit sheet and headers or rectangular
range. It refuses ambiguous or destructive conversion. Use
`--expected-file-hash` when coordinating with a prior read, and `--dry-run`
before structural changes. For deterministic appends, specify one or more
uniqueness columns; an identical retry is a no-op and a differing row returns a
structured conflict. Supply formulas only as typed JSON values such as
`{"$formula":"=B2*2"}`.

All Office writes use one guarded transaction: validate a same-directory
staged file, archive the exact live pre-image, check for source drift, and
publish atomically. Dry-runs create no archive or live-file change. `.xlsx` is
the supported Excel write format; `.xlsm` writes and unsupported complex OOXML
are refused rather than risk lossy edits. Read-only JSON remains available and
reports detected preservation risks.

## Rules

- `rm`, `rmdir`, `shred`, `find -delete` and equivalents are blocked.
  When you need to remove something: `agw archive <path>`.
- Don't write into the archive store (`~/.agw` or `$AGW_HOME`) directly.
- `agw prune` is human-only; never run it on a user's behalf.
- If publish or archive fails, report the error verbatim — never fall back to
  copying over the original by hand.
