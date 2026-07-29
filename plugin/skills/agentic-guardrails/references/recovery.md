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

Use `unlink-link` for a Windows junction or symbolic link. It inspects the
reparse point without following the target, records its type and target as a
recoverable archive artifact, and removes only the link object. Ordinary files
and directories are refused. Supply `--expected-target` when the intended link
destination is known.

For write-capable scripts, declare exact outputs plus bounded output roots and
any intentional sidecar patterns. A successful process exit is not a successful
Guardrails run when undeclared files were created, modified, or removed.
