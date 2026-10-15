# Recovery storage and media

Status: automatic capacity fixes, storage-budget separation and conversational
media continuations implemented on
`fix/automatic-backup-capacity` (PR #62). Not yet released. Revision `8d1faf8`
is installed in an isolated Linux worker pilot for Codex and Claude Code;
[live-host validation](../LINUX_VALIDATION.md#worker-pilot-validation-2026-10-15)
verified the conversational media flow in both hosts.
Content-addressed objects and resumable large-file capture remain future work.

## Reducing dependence on agent instructions

Natural-language pilot tests found that correct storage enforcement alone does
not produce a consistent user experience. Both hosts originally asked again
after an explicit replace-with-recovery request. Relaxing that wording then led
Claude to treat a generic update request as a recovery choice. A full protected
store correctly refused replacement, but Claude offered manual pruning that
could not remove the protected copies. Clarified instructions and corrected CLI
help address immediate confusion; they do not turn conversation into a reliable
consent channel. See the dated natural-workflow results in Linux validation.

Implemented follow-up: keep-both reuses a supplied finished file already beside
the original, and a proven pre-publication capacity refusal exposes preserving
alternatives on the same operation ID. The code chooses the output path and
restricts available actions. The model no longer needs to create a new operation
or decide whether another copy is necessary in those paths. Ambiguous failures
retain inspection requirements; conversational choice is still not authenticated
approval.

Proposed next work, not implemented policy:

1. Give the publication API a configured preservation default. An ambiguous
   media write would deliver a separate output and report its actual path;
   explicit replacement would remain a distinct operation requiring verified
   recovery. Apply this to typed publication operations, not blind rewriting of
   arbitrary shell commands or implicit changes to downstream file references.
   The default needs a product decision: an extra file may not satisfy a request
   to update an existing path, and accumulating outputs also consumes disk.
2. Have preparation compute feasible actions and their storage costs. Return
   structured reasons when replacement is unavailable and the exact supported
   next operations, rather than expecting the agent to invent remediation.
   Recheck admission under the recovery lock at execution time; a preview is
   not a disk reservation. Keep durable claims and ambiguous-failure inspection.
   The implemented same-ID capacity alternative does not precompute all storage
   costs or reserve physical disk space.
3. Bound generated output independently of recovery. A staging wrapper can own
   new output and reject publication over a limit, but a post-render size check
   does not stop a 20 GiB render from filling disk. A hard growth limit needs
   filesystem quotas or enforcement in a controlled writer/worker. Free-space
   checks and polling are useful early warnings, not hard guarantees.
4. Keep automatic retention in code, with deterministic eligibility and receipt
   validation. If sole-copy expiration is ever added, require a separately agreed
   policy and a real review surface; never infer permission from file type, an
   operation ID, or an agent-supplied approval flag. Give users a storage summary
   and selectable eligible cleanup instead of requiring terminal maintenance.

The release criterion should include uncoached workflows with wrong or missing
agent explanations: originals stay recoverable, no unsupported deletion option
exists, normal edits require no user intervention, and capacity failures have a
short usable route forward. Test typed APIs independently of prompts, then test
both real hosts repeatedly to measure questions, retries, copies and latency.

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

### Implemented conversational media continuation

Existing video, audio and raster-image changes through native pre-write hooks,
AGW file/run capture, and staged publication now stop before automatic capture.
`agw archive` similarly stops for an exact media removal. The refusal creates a
small pending operation, asks the agent to clarify with the user, and supplies
exact continuation arguments. Raw removal remains blocked by the existing
delete rules; its archive continuation reaches the same media review gate.
Explicit snapshots and restoration retain their existing recovery semantics.

`agw media prepare PATH [--staged FINISHED_FILE] [--operation replace|archive]`
can also prepare explicitly. `agw media continue ID --action ACTION` supports
replace/save-separately/cancel for replacement and archive/cancel for removal.
`agw media status ID` inspects current state and recovery details. All accept
`--json`; the agent, not the user, runs the CLI after clarification.

Preparation binds original stat identity, parent-directory identities, policy
revision and exact output paths without reading/copying original media bytes.
An optional supplied stage is additionally hash/identity bound. Otherwise an
absent same-directory stage path is assigned, and continuation verifies the
completed output there. Plans expire after 24 hours; at most 256 bounded metadata
records are retained. Preparation expires only old metadata, never media files.
Claimed records are retained for inspection even after their deadline.
Completed/cancelled metadata can retire earlier to admit a new operation at
the metadata cap; associated recovery artifacts and user files are unaffected.
Repeated preparation of the same pending state reuses its operation.

Continuations are durably claimed before side effects and cannot replay after
success, cancellation or an ambiguous execution failure. Changed originals,
parents, policies or supplied stages fail closed. IDs do not authenticate human
approval; agent-supplied consent flags are deliberately absent. The safety
guarantee is recoverability/preservation, not independent proof of consent.

Only a typed capacity refusal from the pre-publication snapshot boundary (or
archive admission before removal) can enter `capacity-blocked`, after target,
policy and staged version are revalidated. An individually oversized original
can enter that state before any original-byte read. `media_capacity_blocked`
returns only `save-separately`/`cancel` for replacement or `cancel` for removal,
with exact continuation commands using the same ID. Replacement cannot replay
from that state. The preserving alternative is freshly claimed and revalidated;
owned stage versions observed at the refusal are bound too. Generic error codes,
rolled-back writes, crashes and uncertain failures do not qualify. To attempt
replacement after an authorized budget change, prepare a new operation.

Replacement reuses verified publication snapshots and transaction recovery.
Explicit CLI capture can exceed the short native-hook 100 MiB ceiling, but
never bypasses total or class budgets. A file individually too large for its
recovery allowance is refused before reading its original bytes. There is no
permanent-delete fallback. For newly prepared operations, keep-both reuses a
supplied finished file in the target directory after identity/hash validation,
returns that actual path with `changed: 0`, and creates neither a copy nor a
hardlink alias. An owned same-directory stage is promoted with no-clobber
link/unlink without duplicating its bytes. A supplied stage outside the target
directory is copied independently to the planned destination and retained.
Previously prepared plans keep their bound output paths. Filesystems
without the required link operation refuse owned-stage promotion. Cancellation
does not create output or discard an already-created stage.

Successful replacement retires only a verified owned stage. Supplied stages,
cancelled stages and uncertain partial outputs remain available for inspection.
These names are not automatically disposable. Publication can need transient
candidate space in addition to original/stage/recovery bytes. This is not a
render output-size limit or physical-disk reservation.

The proposed seven-day media bin is **not** implemented: sole usable recovery
copies and removal archives remain protected. Eligible redundant history is
pruned automatically; a full store of protected originals still refuses growth.
Adding sole-copy expiration requires a separate explicitly accepted retention
policy and trustworthy approval path. No hidden expiration is introduced here.

As with the existing publication engine, claims cover cooperating Guardrails
operations on a functioning local filesystem. They are not a sandbox against
malicious same-user code, non-cooperating filesystem substitution, arbitrary
commands that evade target analysis, or power-loss durability across platforms.

Official host references checked 2026-10-15:
- [Codex hooks](https://learn.chatgpt.com/docs/hooks#pretooluse): deny and supported
  input rewriting; hook `ask` remains unsupported and does not block a call.
- [Claude Code hooks](https://code.claude.com/docs/en/hooks#pretooluse-decision-control):
  deny, ask and input rewriting. This workflow uses deny feedback on both hosts.

### Future object storage

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
