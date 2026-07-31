# Office safety

Use targeted operations for exact changes and preserved checkout/edit/publish
for substantial Excel work. CSV checkout is lossy. Consult leaf `--help`.

Writes validate a stage, archive one pre-image, reject drift, and replace
atomically. Dry runs change nothing. Pass read hashes to writes; never force
publish conflicts. Use uniqueness constraints for retry-safe appends.

Reads are compact and paginated. Formula reads do not calculate formulas. Risks
name exact parts; `normalize` removes only allowlisted metadata. On PowerShell,
prefer stdin or JSON files and use one stdin payload per command.

For `.xlsm`, keep the Drive file binary and available offline. `checkout`
defaults to a non-synced Guardrails workspace. Open that copy in desktop Excel
for broad edits, close Excel, then `publish`; publication revalidates protected
package content, rejects live drift, snapshots, and replaces atomically. Never
convert a VBA workbook to Google Sheets.

`set-cell` is the only targeted `.xlsm` write: its surgical adapter changes one
worksheet XML part and byte-preserves every unrelated part. Other `.xlsm`
mutations remain refused. VBA, signatures, ActiveX, embeddings, custom UI,
external links, connections, and data-model parts are immutable by default.
Never use ad hoc openpyxl, ZIP/XML, Python, or Node mutation.

Use `office validate-preservation` to check a staged copy explicitly.
`publish-file` checks `.xlsm` against an existing target automatically; a new
target requires an explicit preservation baseline.
