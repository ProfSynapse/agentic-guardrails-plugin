# Recovery

Removals and protected-write pre-images are archived. Restore archives the live
target first. Never edit artifacts. Retention removes only expired pre-images.

Undo this conversation's change with returned `recovery.undo_argv` plus `--json`:
`agw undo --transaction ID --json`. Use the exact ID. It checks live-state
conflicts without a pre-read. Use history if the receipt/version is unclear.

`unlink-link` records/removes only a link, refusing ordinary files/directories.
Use `--expected-target` when known.

Exact outputs scan no siblings. Observed roots only detect sidecars afterward;
they do not prevent writes or recover unknown files. `run --dry-run` is contract-only.

Run plans are hash-bound, revalidated before claim and consumed even on failure. `stdout-read-only` requires true filesystem enforcement.

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
