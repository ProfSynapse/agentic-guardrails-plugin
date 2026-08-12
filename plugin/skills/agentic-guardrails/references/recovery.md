# Recovery

Guardrails archives removals and captures pre-images before protected writes.
Recovery operations are themselves reversible: if a live target exists, it is
archived before an older version is restored.

Use status/history to identify ambiguous versions. Undo applies only to the
latest reversible move/archive. Confirm the recovered path.

Never copy directly from the archive or edit its manifests. If a version is
absent, say so. Agents never delete artifacts manually. Automatic retention
prunes only expired `mutation_preimage` records.

No SessionStart pruning: store-growing mutations check admission, and only
high-water pressure triggers bounded inventory/pruning. Status and doctor are
read-only; manual prune is optional.

Use `unlink-link` for a Windows junction or symbolic link. It inspects the
reparse point without following the target, records its type and target as a
recoverable archive artifact, and removes only the link object. Ordinary files
and directories are refused. Supply `--expected-target` when the intended link
destination is known.

For write-capable scripts, declare exact outputs separately from observed roots.
Exact mode hashes and snapshots only those paths; it does not enumerate parents,
so unrelated updates add no scan cost or false report. A state output may sit
outside a separate cache root.

Add an explicit, narrow `--output-root` only when strict sidecar enforcement is
needed, and declare intentional relative sidecar patterns. Root manifests report
unclaimed observed changes and fail the run when unexpected files are created,
modified, or removed. This is post-execution detection, not recoverability or
prevention. It cannot prove which process caused a change, so avoid observing
broad or actively changing application/sync folders.
