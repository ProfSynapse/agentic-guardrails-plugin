# Media choices

Reuse an explicit user choice for this target, action and recovery behavior.
"Replace cover.png and keep a recovery copy" needs no second confirmation.
"Use the new cover" leaves recovery undecided: ask once and wait.
IDs bind files, not human consent.

- Replace with recovery, keep both (`save-separately`), or cancel.
- Removal: archive with recovery or cancel; no permanent-delete fallback.
- Cancel leaves files intact; it never creates another output.

Use `agw media prepare PATH --json`; add `--staged FILE` for a finished
replacement or `--operation archive` for removal. Preparation copies no bytes. If no supplied stage exists, create the replacement at `staged_path`
without overwriting. Use the returned `continue_argv`.

Keep-both reuses a finished revision already beside the original. The returned
`separate_result` identifies that existing path; do not create a third copy.
Other supplied stages are copied independently to the proposed output path.
Owned stages are promoted there without duplicating bytes.

On `media_capacity_blocked`, offer only the returned choices: keep both or
cancel for replacement, cancel for removal. Use the SAME ID; do not reprepare or replay replacement. Automatic cleanup already handles
eligible history; manual pruning cannot delete protected copies.

Changed/expired plans require preparation again. Claimed or uncertain failures
still require `agw media status ID --json` and transaction inspection; never
retry them. Only a proven pre-publication capacity refusal permits continuation.

Report the result and actual path briefly. Run the CLI for the user; don't
send them to a terminal for routine recovery. Sole copies remain protected.
PDFs retain automatic recovery. There is no render-size limit or timed trash.
