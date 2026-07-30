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

For write-capable scripts, declare exact outputs. Exact mode hashes and snapshots
only those paths; it does not enumerate their parents, so large folders and
unrelated application updates add no scan cost or false side-effect report.

Add an explicit, narrow `--output-root` only when strict sidecar enforcement is
needed, and declare intentional relative sidecar patterns. Root manifests report
unclaimed observed changes and fail the run when unexpected files are created,
modified, or removed. They cannot prove which process caused a change, so avoid
observing broad or actively changing application/sync folders.
