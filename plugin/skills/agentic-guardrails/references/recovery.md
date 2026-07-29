# Recovery

Guardrails archives removals and captures pre-images before protected writes.
Recovery operations are themselves reversible: if a live target exists, it is
archived before an older version is restored.

Use status/history output to identify the target and available versions before
restoring when the requested version is ambiguous. Use undo only for the single
most recent reversible move/archive operation. Confirm the recovered path after
the operation.

Never copy files directly out of the archive store or edit its manifests. If an
expected version is absent, say so instead of reconstructing content from memory.
Permanent pruning is human-only and must not be performed by an agent.
