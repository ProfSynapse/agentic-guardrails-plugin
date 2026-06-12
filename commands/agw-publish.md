---
description: Publish a checked-out working copy back over the original (archives prior version)
argument-hint: "[file]"
---

Publish the workspace edits for `$ARGUMENTS` (if empty, run `agw status --json`
and publish the single open checkout; if several are open, list them and ask
which).

Steps:
1. `agw diff <file>` — show the user a concise summary of what will change.
2. `agw publish <file>`.
3. If exit code is 3 (CONFLICT — the original changed since checkout): do NOT
   retry with `--force`. Show both the external change and the workspace edits,
   and ask the user how to proceed. Only use `--force` on their explicit
   instruction, and remind them the overwritten version remains restorable.
4. On success, confirm: what was published, the archived version number of the
   prior copy, and that `agw restore <file>` can roll it back.
