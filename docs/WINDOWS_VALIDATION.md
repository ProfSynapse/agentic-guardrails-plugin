# Native Windows candidate validation — 2026-10-15

The user completed the corrected Codex hook review; all three hashes are
verified trusted. Live Windows validation runs in the logged-in desktop session
with the Codex workspace-write sandbox enabled. The tests found a real Windows
bootstrap defect; installed/trusted metadata alone was insufficient evidence
of protection.

## Environment and scope

Native Windows over Tailscale SSH, Python 3.12, Claude Code 2.1.299, Codex CLI
0.162.1, Windows PowerShell 5.1. Synthetic fixtures and isolated recovery stores
live under `%LOCALAPPDATA%\agw-release-checks\20261015`. No user documents were
used. The local `agw-windows-pilot` marketplace uses candidate versions only;
`0.7.0-rc.1` / `0.7.0-rc.2` are test labels, not published releases.

The first candidate used runtime/router `d24588c` (source checkout `17c8078`).
Commit `d4fdad9` adds the missing Windows media/retention/publication CI shard
and three disk-full regressions. Subsequent changes fix the Codex Windows
bootstrap, without changing retention or media publication policy.

## Deterministic checks and upgrade

- Native Windows media, retention, file operations and publication suites:
  **231 passed, 1 skipped**. The skip is the large sparse-file fixture; a physical
  20 GiB file was not allocated on Windows.
- Added ENOSPC faults at candidate copy, backup copy and publication. The tests
  verify original/staged bytes, partial-copy handling, inspection-required state
  and refused replay. These inject OS errors; they do not fill the disk or
  simulate power loss.
- Both hosts upgraded normally from v0.6.0 to the first local candidate, with
  existing archives retained. Both restored the old v0.6.0 archive exactly and
  preserved the replacement. All 82 initial runtime/hook/policy/skill files
  matched their source. Evidence: `upgrade-results.json`.
- CI at `d4fdad9` passed on Windows, Linux and macOS, including the new shard.

## Claude live workflows

Run from the exact `smoke` project root where the pilot is installed. Earlier
runs from child case folders did not activate the project-scoped plugin and
are excluded. Corrected runs include SessionStart evidence and actual archive
bytes, rather than relying on model claims.

| Workflow | Observed outcome | Tool calls by turn |
| --- | --- | --- |
| Text date change, then undo | Both preimages archived; original restored | 2, 1 |
| Explicit image replacement, then restore | Exact original archived; revision retained; replacement also recoverable after undo | 4, 5 |
| Full protected media budget, then keep both | Original untouched; same operation ID; supplied revision reused with zero extra media copies | 4, 1 |
| Request to wait, then cancel | Neither original nor revision changed; no new output | 6, 0 |

The capacity response offered keep-both/cancel but appended that the storage cap
would need raising for replacement. It did not change settings or remove
protected copies. Wording and verification call counts remain model-dependent;
the deterministic state machine enforces preservation.

Evidence beneath `smoke\cases`: Claude case suffixes `1792092019991044200`
(capacity), `1792092101824380800` (replace/restore), `1792092163769875400`
(text), `1792092181640716500` (cancel). Each contains turn logs and results.

## Codex activation defect and correction

The user completed `/hooks`; `hooks/list` independently reported all three pilot
hooks enabled and trusted, with no load warnings. A stale skill-by-name setting
also disabled the router; enabling only that setting restored skill discovery
(the original config was backed up). It did not fix hook execution.

A read-only app-server probe then captured `hook/started` followed by a failed
SessionStart hook. Replaying the actual command in Windows PowerShell 5.1
reported that `||` is not a valid statement separator. Codex selects the local
shell for hooks; the previous Windows command assumed cmd syntax. Early text
edits without archives are **not protection passes**. After enabling the skill,
subsequent live attempts stopped with `launcher_unavailable`; those also do not
establish hook enforcement. No trust record was manufactured or bypassed.

The Codex Windows manifest now uses `cmd.exe /d /c call` to invoke packaged
`scripts/codex/_dispatch.cmd`. The bootstrap probes `py.exe -3`, then `python`,
before invoking the Python adapter once. It preserves stdin and the adapter's
exit status (PowerShell maps a final native failure to process exit 1). With no
Python, PreToolUse emits a supported deny response; other lifecycle hooks report
a startup failure. No PATH or execution-policy change is needed. Claude's
working hook command and POSIX commands are unchanged.

The **20 native bootstrap regressions passed**: actual manifest execution in
cmd and PowerShell, all three lifecycle events, Python-only PATH, Python
Launcher, missing Python, spaced Unicode/ampersand paths, and failed adapters
that must not be retried. Focused Linux artifact/host/dispatcher checks passed
**135 tests, 56 skipped**; Windows-only cases account for the additional skips.
The broader native Windows artifact/host/dispatcher run passed **181 tests,
10 skipped**. These checks also exposed two fixture assumptions: ancestor project
markers and exact casing of Windows parent paths. The diagnostic fixture now
marks its own project; Unicode path tests verify the exact leaf name and file
identity instead of requiring identical parent-path casing. These changes do
not weaken the content or recovery assertions.

The corrected Codex pilot is installed as local `0.7.0-rc.2`; all 85 runtime,
hook, policy, skill and launcher files match the staged source. The user reviewed
the modified definitions; `hooks/list` confirms all three current hashes trusted.
An app-server probe recorded SessionStart completing with Guardrails context,
and live PreToolUse calls rewrote the short launcher to the installed package.

The first post-review sessions still could not execute the launcher inside the
Windows sandbox over SSH: process exit `-1073741502`. A standalone `codex sandbox`
PowerShell probe reproduced the same error without a Guardrails operation.
The identical sandbox probes succeeded from a temporary non-admin scheduled task
using the existing interactive logon. Live workflow tests therefore use that
session with the workspace-write sandbox still enabled. No sandbox, hook trust,
ACL or execution-policy setting was weakened; no account password was captured.
The SSH failures are excluded from workflow passes, and further hook review
would not fix that environment-specific process-start problem.

## Codex live workflows after hook review

All four fresh conversations (eight turns) passed in the interactive Windows
session with the normal workspace-write sandbox. Recovery files were inspected,
and text restoration was checked byte-for-byte including CRLF line endings.

| Workflow | Observed outcome | Tool calls by turn | Seconds by turn |
| --- | --- | --- | --- |
| Text date change, then undo | Original and edited preimages archived; exact original restored | 10, 5 | 71.7, 45.5 |
| Explicit image replacement, then restore | Original archive verified; original restored and revised source preserved | 6, 4 | 66.7, 39.8 |
| Full protected media budget, then keep both | Same operation ID; original unchanged; supplied revised file reused, zero extra copies | 5, 1 | 48.3, 19.4 |
| Request to wait, then cancel | Prepared operation cancelled; both images unchanged, no new media file | 4, 1 | 39.8, 20.7 |

No repeat authorization was requested for the explicitly authorized replacement.
The capacity response offered only keep-both/cancel and no cleanup or settings
workaround, although it repeated the question and quoted a skill instruction.
The preserving follow-up needed one tool call. Ordinary text editing remained
verbose internally: ten calls versus Claude's two in its observed run. These
are single-run timings, not controlled latency benchmarks; further help-lookup
and wording polish remains worthwhile without changing the preservation rules.

Evidence: `interactive-matrix-done.json` and `interactive-results.json` under the
Windows test root. Case suffixes: `1792093879485912100` (text),
`1792094071100977000` (replace/restore), `1792094177747391900` (capacity),
`1792094245688038700` (cancel). Local evidence mirror:
`/var/tmp/agw-windows-release/interactive-results.json`. The harness initially
mistook an archive directory ending in `.md` for a file; filtering regular files
fixed verification without repeating the successful text conversation. Both
temporary scheduled tasks were removed after completion. CI on `a6c6665` passed
on all three platforms; this follow-up changes evidence documentation only.

The tested native Windows recovery gate is complete. PR62 remains draft; no
release version, tag, merge or publication was performed.

These checks do not establish a render/output quota, off-machine backup,
cloud-placeholder parity, every host/tool surface, or arbitrary host-failure
safety. macOS CI is not a live macOS host test.

## Codex efficiency follow-up (2026-10-16)

The skill router now directs the agent to command shapes in the selected
reference instead of a help-discovery sequence. Text guidance supplies bounded
read and hash-bound replacement commands and explains the checks the operation
already performs. Recovery guidance reuses the exact receipt's undo command;
media guidance explains its verified publication and recovery receipts. Extra
previews or semantic checks remain appropriate when they answer an unresolved
question. Runtime, enforcement, hook commands and consent rules are unchanged.

Two fresh text/edit-undo conversations per variant used the same natural user
requests, synthetic CRLF fixture and isolated recovery stores. Both variants
ran native Codex 0.162.1 with `gpt-6.1-sol`, high reasoning and the workspace-write
sandbox, sequentially in the existing interactive Windows session. Counts
include instruction reads and shell calls. No CLI syntax or transaction IDs
were supplied in the user prompts.

| Variant | Edit calls | Undo calls | Edit seconds | Undo seconds |
| --- | --- | --- | --- | --- |
| Baseline, run 1 | 10 | 4 | 76.0 | 36.8 |
| Baseline, run 2 | 10 | 5 | 74.1 | 45.2 |
| Candidate, run 1 | 5 | 2 | 46.7 | 33.6 |
| Candidate, run 2 | 4 | 2 | 40.8 | 47.6 |

Across these samples, edit calls fell 55% and undo calls 56%. Mean edit time
fell from 75.1 to 43.8 seconds; mean undo time was essentially unchanged
(41.0 versus 40.6 seconds). These are two samples per variant, not a general
latency guarantee. Root help appeared in one candidate edit, and both undo turns still
reread the result; the improvement does not eliminate every redundant call.
Both candidate runs retained exact before/after recovery bytes and restored
the original byte-for-byte, including CRLF.

Four further candidate conversations passed. Explicit image replacement used
four calls and restore used three; full-budget replacement refusal used five,
then same-ID keep-both used one; cancellation used three then one; ambiguous
replacement followed by keep-both used three then one. Original/archive bytes
and the revised source were verified. Both keep-both cases completed one
operation and created no extra copy; cancellation resolved the prepared
operation. Exact root file inventories for all eight valid conversations
(six candidate, two baseline; sixteen turns) contained no unexpected files.

Focused file, recovery-transaction and media tests passed **108 tests,
1 skipped**; the skill validator passed. The existing conflict tests verify
that hash-bound writes and targeted undo refuse changed live state, which
supports skipping a redundant preliminary check without weakening the guard.

The pilot was disabled in saved Windows settings at the start. Tests enabled
it only with a process-scoped config override; `hooks/list` verified all three
existing hashes trusted. A preliminary run without that override produced no
archive and failed the harness checks; it is preserved under
`excluded-plugin-disabled` and excluded from the comparison. No trust record,
saved plugin enablement or security setting was changed.

Evidence: `baseline-results.json`, `candidate-results.json`, their completion
markers, per-case JSONL, instruction snapshots and the runner under
`%LOCALAPPDATA%\agw-release-checks\20261015\efficiency-20261016`. Local mirror and
harness: `/var/tmp/agw-codex-efficiency-20261016`. Both temporary scheduled tasks were removed, and original cached/marketplace
instructions were restored and checked against their snapshots. Runtime hashes
and the saved disabled pilot setting remained unchanged. The candidate guidance
is retained in this PR and the benchmark ZIP.

## Final release preparation (2026-10-16)

CI on `2136a63` passed Windows but caught the progressive-context size gate on
Linux/macOS. The router and text/recovery/media references were tightened to
retain the command shapes, receipts, conflict handling and preservation rules
within the existing budgets. The context suite passed **12 tests** afterward;
no threshold was relaxed. The live measurements above describe the pre-trim
wording, rather than a fresh benchmark of this editorial trim. Release manifests
and packaging expectations now use `0.7.0`. Catalog refs stay on `main` until
the verified release tag exists, followed by a separate pinning PR.

The full Python 3.11 release suite passed **2,096 tests, 78 skipped** with the
CI dependency versions. Windows previously omitted 41 default test modules
from its literal shards, including the context-size check. The workflow now
assigns all 70 default modules exactly once, adds three bounded groups, and
reconciles that inventory before testing. Release CI must pass those added
Windows groups before publication.

The first expanded Windows CI run exposed nine test assertions that compared
Windows paths with POSIX-rendered launcher paths or escaped `python -v` output.
Tests now distinguish the native PowerShell spelling from POSIX surfaces and
decode verbose path literals before checking the exact cache/module location.
No runtime or trust behavior changed. A direct native run exercised all 41
added modules; the remaining failures were in these two assertion files. Their
corrected native rerun passed **43 tests, 1 skipped** (the same focused Linux
run passed **44 tests**). Final CI reruns the complete shard inventory.
