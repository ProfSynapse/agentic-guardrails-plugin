# Recovery

Guardrails archives removals and captures pre-images before protected writes.
Restoration first archives any live target. Use history for ambiguous versions;
never edit archive artifacts. Retention removes only expired pre-images.

For an explicit undo of a change from this conversation, use the successful
result's `recovery.undo_argv`, adding `--json`:

```sh
agw undo --transaction TRANSACTION_ID --json
```

Use the exact returned ID, not a guessed version or an unscoped `agw undo`.
This targeted undo validates the recorded live state and refuses conflicts;
it does not need a preliminary target read or history lookup. Consult history
when the receipt is missing or the intended version is ambiguous. Inspect any
refusal before choosing another action.

`unlink-link` records a junction/symlink and removes only that link object. It
refuses ordinary files/directories; use `--expected-target` when known.

Declare exact outputs separately from observed roots. Roots detect undeclared
sidecars after execution; they neither prevent writes nor recover unknown files.
Exact outputs do not enumerate siblings. `run --dry-run` is contract-only.

A run plan is hash-bound and revalidated before its durable claim. It is then
consumed even on failure. `stdout-read-only` requires true filesystem enforcement.

A publish plan is a bounded set with per-file sequential visibility. For
PREPARED, use `publish-plan recover ID --action inspect`. `finalize-observed`
records COMMITTED only for exact all-after state; other refusal stays PREPARED.
`rollback` restores authenticated before-state. Its journal is lazy, bounded to
64 members/64 KiB, and process-crash-resumable; all-before creates none. Progressed
failures remain retryable `BLOCKED`. The guarantee covers accidental AGW process
termination on a functioning local OS/filesystem with cooperating AGW locks and
acknowledged writes—not malicious/non-cooperating same-user filesystem
race/substitution, full power-loss durability, or simultaneous set visibility.
Detected collisions, links/hardlinks, or recorded filesystem identity changes
fail closed. Inode reuse from non-cooperating same-user unlink/recreate is outside
this process-crash guarantee. Recovery never executes content/commands or rolls
forward.
