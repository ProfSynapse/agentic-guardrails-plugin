---
description: Audit report - what the guardrails allowed, asked about, and blocked recently
argument-hint: "[days|date]"
---

Produce a guardrails activity report for this machine.

1. Read the audit log at `$AGW_HOME/audit.jsonl` (default `~/.agw/audit.jsonl`)
   - append-only JSONL with a timestamp per entry. Default to the last 24h;
   honor a day-count or date in `$ARGUMENTS` if given. Tail it rather than
   reading the whole file.
2. Summarize:
   - Counts by decision: allow / ask / deny / defer.
   - Every **deny** with its rule id and the command or path involved.
   - Notable **ask** escalations (placeholder reads, shrink guards, conflicts).
   - Archive store health: `agw doctor --json` (writability, size, degraded
     policy packs).
3. Flag patterns worth the user's attention: repeated denials of the same
   command (agent fighting the rails), writes denied in protected zones,
   decode-pipe or download-pipe attempts.

The audit log already redacts secrets, but quote commands sparingly anyway.
Output a compact markdown report.
