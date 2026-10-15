# Media choices

On `media_review_required` / `clarify-media-operation`, reuse an explicit user
choice for this exact target, action and recovery behavior without asking again.
"Replace cover.png and keep a recovery copy" already chooses replace.
"Use the new cover" does not choose what happens to the old one: ask.
Otherwise ask once and wait. An ID alone never authorizes continuation.

- Replacement: replace with recovery, save separately, or cancel.
- Removal: archive with recovery, or cancel.
- Never offer permanent deletion/replacement without recovery.
- Cancel does not create a timestamped file or execute another operation.

The refusal supplies an ID, staged/output paths and exact `continue_argv`.
Prepare: `agw media prepare PATH --json`; add `--staged FILE` for
an existing finished replacement, or `--operation archive` for removal.
This does not copy the original.

After clarification, create the finished output at `staged_path` using
create-new behavior when `supplied_stage` is empty. Otherwise preserve that
exact supplied version. Submit the chosen continuation as a new tool call;
never retry the original overwrite. IDs bind state, not human consent.

The CLI rechecks identity, policy, expiry and recovery budgets. It cannot
replace permanently or overwrite a separate destination. Expired/changed
operations need preparation again. Claimed operations cannot replay: use
`agw media status ID --json`, inspect files and follow transaction recovery.

Cancel/expiry retain stages. Success retires verified owned stages; supplied
files remain. Sole recovery copies and removal archives never auto-expire.
Only eligible redundant history is auto-pruned; protected copies block growth.
No seven-day bin or render size cap. PDFs/documents keep automatic recovery.
