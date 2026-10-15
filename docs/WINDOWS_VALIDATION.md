# Native Windows candidate validation — 2026-10-15

Release remains gated on a fresh Codex hook review and live enforcement rerun.
The tests found a real Windows bootstrap defect; installed/trusted metadata alone
was insufficient evidence of protection.

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
The broader checks also exposed two fixture assumptions: ancestor project
markers and exact casing of Windows parent paths. The diagnostic fixture now
marks its own project; Unicode path tests verify the exact leaf name and file
identity instead of requiring identical parent-path casing. These changes do
not weaken the content or recovery assertions.

The corrected Codex pilot is installed as local `0.7.0-rc.2`; all 85 runtime,
hook, policy, skill and launcher files match the staged source. The hook definitions
changed, so the user's prior trust hashes no longer authorize them. Review the
new definitions with `/hooks`, start a fresh task and rerun text recovery,
media replacement/restore, full-budget keep-both and cancellation. Until then,
Codex live Windows parity remains unverified and the release stays draft.

These checks do not establish a render/output quota, off-machine backup,
cloud-placeholder parity, every host/tool surface, or arbitrary host-failure
safety. macOS CI is not a live macOS host test.
