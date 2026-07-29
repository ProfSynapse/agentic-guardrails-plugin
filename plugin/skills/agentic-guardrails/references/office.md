# Office safety

Use targeted operations for exact changes and style-preserving
checkout/edit/publish for substantial Excel work. CSV checkout is explicitly
lossy. Consult leaf `--help` instead of examples stored in context.

Writes validate a staged package, archive one live pre-image, reject drift, and
replace atomically. Dry runs change nothing. Lossy OOXML mutations are refused.
`set-cell` may use a surgical adapter when it can preserve unknown extensions and
every unrelated part; other operations still refuse unsupported packages.

Reads are compact and paginated. Pass returned hashes to coordinated writes. Use
uniqueness constraints for retry-safe appends: identical retries are no-ops and
differing duplicates conflict. Never force publish or hash conflicts.

Use `read-table --include-formulas`, bounded `read-range --formulas`, or
`validate-formulas`; none calculates formulas. Risks identify exact extensions
and parts. `normalize` removes only allowlisted metadata.

On PowerShell, prefer stdin or JSON files. Use one stdin payload per command and
keep formulas explicitly typed.

Macro-enabled and complex packages may remain readable while writes are refused.
Never fall back to ad hoc `openpyxl`, ZIP/XML, Python, or Node mutation when the
Guardrails Office operation refuses the file. Use `publish-file` for a validated
temporary workbook that must be hash-guarded onto a busy synced target.
