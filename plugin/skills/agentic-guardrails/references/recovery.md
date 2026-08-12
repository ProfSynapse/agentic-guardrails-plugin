# Recovery

Guardrails archives removals and captures pre-images before protected writes.
Recovery is reversible: an existing live target is archived before restoration.
Use status/history for ambiguous versions and verify the recovered path. Never
copy from the archive, edit its manifests, or delete artifacts manually.
Automatic retention removes only expired `mutation_preimage` records.

`unlink-link` records a junction/symlink and removes only that link object. It
refuses ordinary files/directories; use `--expected-target` when known.

Declare script outputs separately from observed roots. Exact outputs are hashed
and snapshotted without enumerating siblings. Narrow observed roots detect
undeclared sidecars after execution; they neither prevent writes nor recover
unknown files.

A run plan uses the recoverable file boundary and its canonical hash. Apply
revalidates the plan and provider before a durable claim. After claim it is
consumed even if execution or output validation fails. `stdout-read-only`
requires true read-only filesystem enforcement; the observed runner lacks it.

A publish plan is a bounded staged/target set: recovery is set-wide, but changes
have per-file sequential visibility. For PREPARED state, use `publish-plan recover
ID --action inspect`. `finalize-observed` records COMMITTED only when every target
already matches its after-hash. `rollback` is unavailable without a future
crash-resumable journal and performs no fallback or writes. Roll-forward is unavailable.
