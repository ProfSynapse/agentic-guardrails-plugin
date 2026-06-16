---
description: Restore a file from the guardrails archive (latest or a chosen version)
argument-hint: "[file] [version]"
---

Restore `$ARGUMENTS` from the archive store.

1. Run `agw log <file> --json` to list available versions (number, timestamp,
   reason). If `$ARGUMENTS` is empty, run `agw log --json` and ask the user
   which file they mean.
2. If the user named a version, `agw restore <file> --version N`; otherwise
   show the version list and confirm which one - "latest" is the default only
   when there's a single candidate or the user already said "latest".
3. Remind the user the current live file is archived automatically before the
   restore, so this is reversible.
4. Confirm the result by checking the restored file exists and reporting its
   size/first lines.
