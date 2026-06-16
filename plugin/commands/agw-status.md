---
description: Show open agent-workspace checkouts and recent guardrail activity
---

Run `agw status --json` and `agw log --json` (last ~20 entries), then summarize
for the user:

1. Open checkouts: file, when checked out, whether the working copy differs
   from the original (use `agw diff` per checkout if quick), and whether the
   original changed underneath (conflict risk).
2. Recent operations: archives, publishes, restores, moves — one line each.
3. Anything needing attention: stale checkouts, conflicts, a degraded policy
   pack reported by `agw doctor`.

Keep it short; tables are fine. If `$ARGUMENTS` names a path, scope the report
to that path.
