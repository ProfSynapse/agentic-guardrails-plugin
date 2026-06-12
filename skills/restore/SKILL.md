---
name: restore
description: >
  Recovering lost or overwritten files from the guardrails archive store. Use
  when the user says a file was deleted, overwritten, truncated, or "messed
  up", or asks to roll back to an earlier version or undo a recent file
  operation.
---

# Restore & Recovery

Everything the guardrails touch is recoverable: every archive, every publish,
and every native Write/Edit (a pre-image snapshot is taken automatically before
the tool runs). Deletion is disabled, so "deleted" almost always means
"archived" or "overwritten with a snapshot available".

## Find what exists

```
agw log <path>          # operations involving this path
agw log                 # recent operations, newest last
agw status              # open checkouts
```

`agw log --json` gives structured entries with version numbers, timestamps,
hashes, and the archived copy's location.

## Bring it back

```
agw restore <path>              # latest archived version
agw restore <path> --version 3  # a specific version
agw undo                        # revert the single most recent archive/move
```

Restore is itself non-destructive: if a live file exists at the target path,
it is archived first, then the requested version is put in place. You can
restore back and forth between versions without losing anything.

## Triage guide

| Symptom | Likely cause | Fix |
|---|---|---|
| "File is gone" | Archived (rm was redirected) or moved | `agw log <path>`, then `agw restore` or `agw undo` |
| "File has wrong/old content" | Overwritten by a Write/Edit | `agw log <path>` — pre-image snapshots appear as copy-mode archives; restore the version wanted |
| "Publish clobbered a colleague's edit" | Forced publish over a conflict | The pre-publish copy is archived; `agw restore <path> --version N` |
| "Whole folder is wrong" | Bulk operation | `agw log` for the folder's files; restore individually, or use a prior `agw snapshot` |

## Boundaries

- Restore from the store with `agw` verbs only — never copy files out of
  `~/.agw/archive` by hand (the manifest would no longer match reality).
- `agw prune` (permanent removal of old versions) is human-only. If the user
  asks you to free space, point them at the command and its
  `--yes-i-am-a-human` flag; do not run it for them.
- If a version the user expects is missing, say so plainly — don't reconstruct
  content from memory and present it as a restore.
