# Synced and virtual folders

OneDrive, SharePoint, Google Drive, and Dropbox trees may block during metadata
calls, contain cloud-only placeholders, expose Google pointer stubs, or hold sync
conflict artifacts.

Use the bounded scan as the default first step for broad discovery or recursive
listing. Narrow later content searches to the returned subtree; do not begin with
an unbounded recursive shell, PowerShell, or interpreter traversal.

The scan runs filesystem work in a killable worker and returns partial progress
when a time, file, or depth bound is reached. Partial output is useful, not a CLI
failure. A fast/no-size scan deliberately reports limited placeholder detection;
an empty placeholder list does not prove that every file is hydrated.

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
