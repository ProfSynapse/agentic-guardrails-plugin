# Diagnostics and reports

Use only privacy-safe recovery metadata already maintained by Guardrails:
archive-store health and retained-copy totals, open checkout state, incomplete
Office transactions, policy health, and policy revision.

Guardrails does not maintain a general command or human-activity ledger. Do not
read, migrate, summarize, or count legacy `audit.jsonl` or quarantine records.
Never reconstruct commands, paths, filenames, user identifiers, reasons, or
exceptions from fingerprints or task output. If a requested metric is not
available, say that Guardrails does not keep it.
