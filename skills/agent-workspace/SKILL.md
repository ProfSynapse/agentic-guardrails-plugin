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
| `agw scan <folder>` | Inventory a folder: placeholders, gdoc stubs, sync artifacts |
| `agw archive <path>` | Reversible "delete" — moves into the archive store |
| `agw restore <path> [--version N]` | Bring back any archived version |
| `agw undo` | Revert the last archive/move operation |
| `agw move <src> <dest>` | Logged, undoable move/rename |
| `agw snapshot <folder>` | Whole-folder backup before bulk work |
| `agw log [path]` | Show the operation log |
| `agw doctor` | Environment self-check (converters, store writability) |

All verbs accept `--json` for machine-readable output.

## Rules

- `rm`, `rmdir`, `shred`, `find -delete` and equivalents are blocked.
  When you need to remove something: `agw archive <path>`.
- Don't write into the archive store (`~/.agw` or `$AGW_HOME`) directly.
- `agw prune` is human-only; never run it on a user's behalf.
- If publish or archive fails, report the error verbatim — never fall back to
  copying over the original by hand.
