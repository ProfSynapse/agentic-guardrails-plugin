# Media choices

Reuse explicit user choice for this target, action and recovery behavior.
"Replace cover.png and keep a recovery copy" needs no second confirmation.
"Use the new cover" leaves recovery undecided: ask once and wait.
IDs bind files, not human consent.

- Replace with recovery, keep both (`save-separately`), or cancel.
- Removal: archive with recovery or cancel; no permanent-delete fallback.
- Cancel leaves files intact; it never creates another output.

Use `agw media prepare PATH --json`; add `--staged FILE` for a revision or
`--operation archive` for removal. Preparation copies no bytes. Without a stage,
create at `staged_path`, never overwriting. Use returned `continue_argv` without
a preliminary help call.

Replacement verifies published bytes and returns `operations` recovery receipts.
Retain `recovery.undo_argv`; see [recovery](recovery.md). Hash again only for
unresolved verification.

Keep-both reuses a supplied revision beside the original: `separate_result`
identifies it; do not create a third copy. Other supplied stages are copied
independently. Owned stages are promoted without duplicating bytes.

On `media_capacity_blocked`, offer returned choices only: keep both/cancel for
replacement, cancel for removal. Use the SAME ID; never reprepare or replay
replacement. Cleanup handles eligible history; pruning cannot remove protected
copies.

Prepare changed/expired plans again. Inspect claimed/uncertain failures with
`agw media status ID --json` and transaction inspection; never retry. Only a
proven pre-publication capacity refusal permits continuation.

Report the result/path briefly; run routine recovery for the user. Sole copies
stay protected.
PDFs retain automatic recovery. There is no render-size limit or timed trash.
