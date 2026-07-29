# Office safety

Use a targeted Office operation for small, exact changes. Use checkout/edit/publish
for substantial restructuring or rewriting. Consult the relevant leaf `--help`
instead of relying on examples stored in context.

Targeted writes are one guarded transaction: validate a same-directory staged
package, archive the exact live pre-image, reject source drift, and replace
atomically. Dry runs create neither an archive nor a live-file change. Unsupported
or lossy OOXML mutations are refused; do not bypass a preservation refusal.

Structured reads are compact and paginated. When a read returns a file hash, pass
it as the expected hash for a coordinated write. Use uniqueness constraints for
retry-safe appends. An identical retry is a no-op; a differing duplicate is a
conflict. Treat publish or hash conflicts as user decisions and never force them
without explicit authorization.

Use `read-table --include-formulas` when verification needs both cached values
and underlying formulas. Use bounded `read-range --formulas` for non-table cells,
and `validate-formulas` for structural formula inventory and cached-value coverage;
it does not calculate formulas. Preservation risks report exact extension URIs,
namespaces, elements, and parts. `normalize` removes only explicitly allowlisted
compatibility metadata and refuses unknown extensions.

On PowerShell, prefer stdin or JSON files over inline structured JSON. Use one
stdin payload per command. Formula values must remain explicitly typed rather
than being inferred from arbitrary text.

Macro-enabled and complex packages may remain readable while writes are refused.
Never fall back to direct `openpyxl`, ZIP/XML, Python, or Node mutation when the
Guardrails Office operation refuses the file.
