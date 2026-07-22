---
description: Guardrails recovery and policy health report
---

Produce a compact, human-readable Guardrails recovery and policy report.

1. Treat Claude or Codex task history as the human activity log. Guardrails
   does not keep a separate command/event ledger, so decision counts and
   command-level trends are unavailable. Say that plainly if they are requested.
2. Use only privacy-safe CRUA metadata already maintained for recovery:
   - archive-store health and retained recovery-copy totals;
   - open checkout/working-copy status;
   - policy health and revision;
   - recovery availability reported by the normal Guardrails status/doctor
     interfaces.
3. Do not open, tail, migrate, summarize, or count records in any legacy
   `audit.jsonl` or legacy quarantine. Their presence is not report data.
4. Never reconstruct commands, filenames, paths, user identifiers, reasons, or
   exceptions. Do not infer them from fingerprints or task output.
5. Explain findings and next steps in ordinary language. If a metric is not
   available, write "Guardrails does not keep that metric." Never give shell or
   PowerShell commands as a substitute for human instructions.
