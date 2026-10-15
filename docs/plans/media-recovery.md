# Recovery storage and media

Status: automatic capacity fixes implemented on `fix/automatic-backup-capacity`.
The separate media tiers below are a proposed next stage, not shipped behavior.

## Current behavior

Guardrails provides local undo copies, not an off-machine backup service.
The shared recovery budget defaults to 4 GiB. Store-growing operations trigger
cleanup at 90%, targeting 80%; there is no daemon or scheduled task to install.
An idle store does not grow, so cleanup belongs on admission rather than startup.

Unchanged files reuse the verified newest copy before capacity admission.
Multi-file admission counts only actual new captures under the same lock.
At high water, normal expired-history cleanup runs first; redundant recent
copies can then yield behind a newer verified copy. Up to four planning passes
bound one invocation. If the store still cannot admit the operation, it refuses
before the requested write and reports the shortfall. Huge backlogs can require
further maintenance; the pass bound is not a guarantee of reaching low water.

A normal batch has at most 256 artifacts and 1 GiB. One indivisible eligible
artifact may exceed the batch budget when reclaimed alone, up to the configured
store cap. This exception is checked at planning and apply time. It changes
batching, not eligibility. Files exceeding a newly lowered store cap are outside
this exception. Manual snapshots, move/delete archives, recovery pins, incomplete
or corrupt records, and the newest usable copy of each source remain protected.

Native pre-write hooks separately default to a 100 MiB per-file limit
(`AGW_PRESNAP_MAX_BYTES`). The retention fixes do not raise it or make multi-GiB
capture fit inside a host hook deadline. Oversized-source workflows need an
explicit capture/publication path before overwrite; they must not skip recovery.

## Proposed storage classes

| Content | Recovery treatment | What may expire automatically |
| --- | --- | --- |
| PDFs and editable documents | Preserve exact original bytes, including annotations and embedded content. Extracted text or OCR is a derived artifact, not a restore point. | Redundant verified generations under the document-history budget. |
| Original video, audio and images | Immutable media objects, referenced by recovery manifests. Prefer producing a new output over overwriting an original. | Redundant objects only when all retained references are gone; keep originals and pinned versions. |
| Rendered video, transcodes, previews, waveforms and OCR | Explicitly declared derived outputs with source references and a reproducible recipe. | Under a separate derived-cache budget, provided the sources and required recipe remain available. |
| Delivered masters or otherwise irreplaceable outputs | Explicit keep/pin status, whether originally generated or recorded. | Only redundant unpinned history, never solely because the extension looks like media. |

Classification must come from a workflow declaration or user policy. A `.mp4`
can be the only recording of an event, and a `.pdf` can be a signed original;
neither extension authorizes automatic disposal. Existing data stays protected
until its class and references are known.

## Next implementation stage

1. Introduce separate document-history, media-object and derived-cache quotas
   beneath a total disk budget. Report usage, reclaimable bytes, protected bytes,
   largest objects and the specific reason a requested capture cannot fit.
   Media should not consume the reserved document-history allowance.
2. Store immutable binary objects by verified content hash with per-operation
   manifests. Reuse bytes across paths and policy revisions while keeping each
   operation's receipt and policy binding distinct. Do not hardlink live source
   files into recovery storage; later source edits must not alter history.
3. Add a durable, resumable large-file capture job outside the short hook path.
   Stage and verify the full original before authorizing overwrite. Handle
   cancellation, source changes and insufficient disk without deleting sources.
4. Garbage-collect only unreferenced objects under the recovery lock after
   tracing all retained manifests and in-flight jobs. Unknown or corrupt
   references stop collection. Test crashes before/after object and manifest
   publication, concurrent captures, and restores after collection.
5. Keep a larger persistent local volume or a verified external backup reference
   as an explicit policy choice for originals that cannot fit locally. A path,
   cloud-sync status, or URL alone is not proof that bytes are recoverable.
   No external destination, transfer, or deletion is configured by this change.

Acceptance for that stage: repeated operations on unchanged media add metadata
only; restoring reproduces the exact bytes; media pressure preserves document
headroom; derived outputs never lose their only inputs; interrupted captures
cannot authorize an overwrite; missing or corrupt objects cause a clear refusal.
