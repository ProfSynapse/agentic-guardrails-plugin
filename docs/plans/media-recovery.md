# Recovery storage and media

Status: automatic capacity fixes and storage-budget separation implemented on
`fix/automatic-backup-capacity` (PR #62). Not yet released or installed.
Content-addressed objects and resumable large-file capture remain future work.

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

## Implemented storage classes and budgets

| Class | Default budget | Capture classification |
| --- | --- | --- |
| Documents | 2 GiB reserved; can borrow unused space up to the 4 GiB total | PDFs, text, Office files and other non-media files. Exact original bytes are retained. |
| Media | 1.5 GiB maximum | Video, audio and raster images; directory snapshots conservatively count here because they may contain mixed media. |
| Derived outputs | 0.5 GiB maximum | Only an explicit `archive_storage_rules` policy match; a filename such as `render.mp4` is insufficient. |
| Unclassified | Shared non-document allowance | Metadata, orphan bytes, and unknown classes. These bytes are counted, never treated as free space. |

The default document reserve is half the total. Media gets three quarters of
the remaining allowance; derived outputs get one quarter. Documents can borrow
unused space, but media and derived outputs cannot borrow the reserve. Separate
class caps, the shared non-document allowance, and the total cap all apply.
An existing store over a newly lowered cap is not forcibly purged: protected
copies survive and new growth is refused as needed. Zero-growth verified reuse
still works. Reservations constrain new admission; they cannot retroactively
free space occupied by protected legacy data.

Accounting class and retention eligibility are separate. A `.mp4` may be the
only recording of an event; a `.pdf` may be a signed original. Neither a file
extension nor a `derived` rule authorizes discarding the sole recovery copy.
Derived outputs currently retain the same newest-copy, verification and recovery
pin protections as documents/media. No source/recipe availability is assumed.

Automatic cleanup scopes its plans to the class being admitted. Media pressure
cannot evict document history; document pressure cannot evict media history.
Mixed captures admit all class totals before creating new copies. Up to four
planning passes bound an invocation. Manual maintenance checks all classes.
The same source identity/version groups and restore paths continue to apply.

New transaction manifests record their accounting class. Existing manifests
are not rewritten or moved: missing classes use the built-in file-type mapping
for accounting. New derived rules do not reclassify old or reused copies.
Folders are conservatively media unless a policy explicitly classifies their
contents as documents. Classification never relaxes existing safety-archive,
manual-snapshot, unclassified-record or in-flight recovery protections.

### Configuration

Optional settings (matching environment variables use `AGW_` plus the uppercase
setting name):

- `archive_max_bytes`: total cap, 4 GiB by default; `0` explicitly disables all
  budgets. Nonzero class limits/reserve with an unlimited total are rejected.
- `archive_document_reserve_bytes`: defaults to half the total.
- `archive_media_max_bytes`: defaults to 75% of the allowance after the reserve.
- `archive_derived_max_bytes`: defaults to the other 25%.
- `archive_storage_rules`: ordered policy-only rules; first match wins.
  Patterns match normalized absolute paths, with `/` separators. Matching follows
  the host's case convention. At most 64 rules are accepted.

Media plus derived limits must not exceed the total minus the document reserve.
A class cap of zero permits no positive payload growth in that class; it does
not mean unlimited. Invalid budgets fail before capture. The total cap continues
to count all archive bytes, including metadata.

Example in an authorized policy pack:

```yaml
settings:
  archive_max_bytes: 8589934592
  archive_document_reserve_bytes: 4294967296
  archive_media_max_bytes: 3221225472
  archive_derived_max_bytes: 1073741824
  archive_storage_rules:
    - pattern: '**/renders/**'
      storage_class: derived
    - pattern: '**/scanned-documents/**'
      storage_class: documents
```

`agw status` and `agw doctor` report each class's usage, limit, protected bytes,
potentially reclaimable bytes, and five largest archived artifacts in JSON.
Potential reclaim is based on protection metadata and still requires verification
before deletion. The report includes inventory completeness; these commands do
not prune. Admission errors identify the specific class or shared constraint.
Routine captures use advisory class counters rather than rescanning every
artifact; invalid counters are rebuilt from authoritative records.

## Next implementation stage

1. Store immutable binary objects by verified content hash with per-operation
   manifests. Reuse bytes across paths and policy revisions while keeping each
   operation's receipt and policy binding distinct. Do not hardlink live source
   files into recovery storage; later source edits must not alter history.
2. Add a durable, resumable large-file capture job outside the short hook path.
   Stage and verify the full original before authorizing overwrite. Handle
   cancellation, source changes and insufficient disk without deleting sources.
3. Garbage-collect only unreferenced objects under the recovery lock after
   tracing all retained manifests and in-flight jobs. Unknown or corrupt
   references stop collection. Test crashes before/after object and manifest
   publication, concurrent captures, and restores after collection.
4. Keep a larger persistent local volume or a verified external backup reference
   as an explicit policy choice for originals that cannot fit locally. A path,
   cloud-sync status, or URL alone is not proof that bytes are recoverable.
   No external destination, transfer, or deletion is configured by this change.

5. Add source/recipe-backed disposal for derived outputs only after verifying
   reproducible inputs, and an explicit keep/pin status for delivered masters.
   Until then even explicitly derived output retains its newest recovery copy.

Acceptance for the future object-storage stage: repeated operations on unchanged media add metadata
only; restoring reproduces the exact bytes; media pressure preserves document
headroom; derived outputs never lose their only inputs; interrupted captures
cannot authorize an overwrite; missing or corrupt objects cause a clear refusal.
