# Synced and virtual folders

Cloud-sync trees may block on metadata, contain placeholders or Google pointer
stubs, and hold sync conflicts.

Start broad discovery with bounded `agw scan`, then refine its subtree using
`agw list` or `agw search`. `--deep` is explicit. Never begin with unbounded
shell, PowerShell, interpreter, Glob, or Grep traversal. Standard permits narrow
project-local raw discovery; strict routes every recursive form through AGW.

All three run in a killable worker and return useful partial progress at any time,
file, entry, depth, match, or size bound. A no-size scan has limited placeholder
detection; an empty list does not prove hydration. Content search skips sensitive
files and checks placeholders before opening.

Never edit a cloud-only placeholder. Ask the user to make it available offline,
then scan again. Leave conflict copies, upload temporaries, and Office lock files
untouched unless the user explicitly identifies one as the target.

Prefer staged, atomic publishing over long-running in-place writes in a synced
tree. Use `publish-file` to validate and hash a temporary artifact before one
recoverable atomic replacement. Busy/sharing-violation retries are bounded; a
failed publish leaves the live target unchanged and preserves the staged output.
Keep the Guardrails archive store outside the synced root.

Preserved Excel checkouts default outside the synced tree. For `.xlsm`, hydrate
the live file, edit only the checkout in desktop Excel, close Excel, validate
macro/package preservation, and publish with the recorded live hash. If another
editor or service changed the Drive copy, treat it as a conflict and re-checkout.
