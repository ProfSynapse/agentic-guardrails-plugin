# Agentic Guardrails codebase audit, 2026-09-17

**Scope**: full tree at `ab35a72` (v0.4.4). Four parallel passes (hook latency,
PowerShell and Windows shell handling, store reliability and fail-closed,
tests/packaging/docs), with every P1 claim reproduced by hand through the real
`_dispatch.py pretooluse` entry point. Latency numbers were measured on Linux;
Windows figures are estimates and marked as such. Reproduction scripts and a
40-command PowerShell corpus are described inline so they can be turned into
tests.

**Headline**: the fundamentals are strong. Archive transactions are genuinely
crash-safe, publication conflict detection uses SHA-256 rather than mtime,
retention can never delete a sole copy, the `agw` trust handshake is
path-identity based, and the dispatcher's crash-to-ASK net is airtight and
free. The unreliability and slowness the user feels come from three specific
places, all fixable without weakening any of the five safety contracts:

1. **The hook does too much per call.** Every Read/Write/Edit/Bash/MCP call
   imports the whole `core` package (~55 ms), re-parses `core.yaml` (~10 ms),
   and every Write/Edit walks the entire archive store twice under a global
   lock. Measured 90 ms per call on Linux with an empty store; estimated
   250 to 700 ms on Windows, growing linearly with the store.
2. **PowerShell is classified against a POSIX mental model.** Out of 40
   everyday PowerShell commands, 18 are wrongly blocked (including
   `Get-ChildItem` inside any OneDrive folder and `Remove-Item node_modules`)
   and 12 destructive ones pass silently (`bash.exe -c "rm -rf"`, `wsl rm -rf`,
   `robocopy /MIR`, `Start-Process powershell -ArgumentList`).
3. **Two lock and timeout mismatches turn safety into silence.** The store lock
   waits 30 s inside a hook the host kills at 15 s, so under the parallel tool
   calls Claude Code issues, the hook is killed and the write proceeds with no
   snapshot. An unrecognized tool name produces empty stdout, which the host
   treats as allow.

---

## 1. P1: fail-open, bypass, data loss, or bricked session

| # | Finding | Location | Status |
|---|---|---|---|
| F1 | **Store lock timeout (30 s) exceeds the PreToolUse hook timeout (15 s).** `Lock("recovery-store", timeout=30.0)` is held across `maintain_retention` (two full `os.walk`s of the archive) plus the pre-image copy and hashing. Claude Code runs independent tool calls in parallel, so hooks serialize on it. With one holder, a second hook measured 24.6 s; the host kills it at 15 s and the tool call runs **with no pre-image**. Contracts 1 and 2 break silently. | `core/preimages.py:175`, `core/store.py:549,1349,1432,1684`, `hooks/hooks.json:10` | CONFIRMED |
| F2 | **Unrecognized tool name is a silent allow.** Any payload whose `tool_name` the adapter does not know falls to `events.OTHER`, the engine returns DEFER, `pretooluse.py` prints nothing, exit 0. `{"tool_name":"Shell","tool_input":{"command":"rm -rf ~/Documents"}}` is allowed with no stderr. The day the host renames a tool, the plugin becomes a no-op with zero signal. Field drift (`tool_input.path` instead of `file_path`) does fail closed correctly; the gap is tool identity only. | `claude/adapter_common.py:65`, `codex/adapter_common.py:88`, `claude/pretooluse.py:216,252` | CONFIRMED |
| F3 | **`.exe`-suffixed and full-path interpreters are never recursed.** `head_base = toks[0].rsplit("/",1)[-1].lower()` splits on `/` only and strips `.exe` after the `_SHELLS` test. `bash -c "rm -rf X"` is denied; `bash.exe -c "rm -rf X"` (Git Bash's own spelling on Windows) is silently allowed. Same for `sh.exe`, `C:\Windows\System32\cmd.exe /c del`, full path to `powershell.exe` / `pwsh.exe`. | `core/shellparse.py:395,442,454` | CONFIRMED |
| F4 | **`wsl`, `robocopy`, `Start-Process`, `fsutil`, `xcopy` are not modelled anywhere.** `wsl rm -rf /mnt/c/Users/jo/Documents`, `robocopy src dst /MIR` (deletes destination files), `Start-Process powershell -ArgumentList '-Command','Remove-Item -Recurse C:\x'` all pass silently. `powershell -File .\wipe.ps1` is explicitly not inspected. | `core/engine.py:239-241`, `core/shellparse.py:499` | CONFIRMED |
| F5 | **Every ASK without structured targets is upgraded to DENY.** `prompt_request.validation_problem()` returns unresolved for any decision carrying no target paths, and the adapter sets `action = DENY`. This converts the entire shipped `core.yaml` `action: ask` set (`pip install`, `npm install -g`, `npm publish`, `kubectl delete`, `docker system prune`) plus `builtin:eval` (`Invoke-Expression`) and `builtin:chmod-r` into hard blocks whose message ("could not identify enough structured information to request informed approval") names no safe alternative. Breaks contract 3 and the documented `deny > ask > allow` semantics. | `claude/pretooluse.py:203-205` | CONFIRMED |
| F6 | **The regenerable-directory allowance never works on a real machine.** `builtin:rm-regenerable` ALLOWs `rm -rf node_modules`, but `mutations.plan` still lists the directory as a target and `preimages.prepare` rejects anything that is not a regular file ("Only ordinary local files can be safely backed up here"), producing a non-waivable `invariant:prestate-unavailable` DENY. Reproduced for `node_modules`, `build`, `dist`, `.venv` when the directory exists. Tests pass only because the test cwd has no such directories. | `core/engine.py:1703-1708`, `core/preimages.py:158-160` | CONFIRMED |
| F7 | **`$var`-headed PowerShell segment returns `[]` with no flag**, and `_detect_dialect`'s cmdlet regex (`[A-Z][a-z]+-[A-Z][a-z]+`) misfires on `Content-Type`, `X-Request-Id`, `My-App`, so `tool=Bash` commands are misdetected as PowerShell. Combined: `$RM -rf ~/My-Documents` on the Bash tool is a silent allow. | `core/shellparse.py:163-170,404-405` | CONFIRMED |
| F8 | **Windows hook launcher has no fallback.** POSIX `command` is `python3 … \|\| python …`; `commandWindows` is `py.exe -3 …` only. Microsoft Store Python, some python.org custom installs, and conda do not ship `py.exe`. A hook whose executable cannot spawn is a host hook error and the tool call proceeds: guardrails absent, not fail-closed. `README.md:74` says the opposite ("Windows hooks require it as `python`"). `agw.cmd` does the probe correctly; the hooks do not. | `hooks/hooks.json:9-11`, `hooks/hooks-codex.json:10` | CONFIRMED mismatch, failure mode PLAUSIBLE |
| F9 | **Hook cost grows without bound with the store; snapshots never dedupe.** `archive_size_bytes()` is a full `os.walk` + `getsize`, called twice per `maintain_retention`, which runs once in `preimages.prepare` and again in `archive_file`; `archive_tx.discover` reads every transaction manifest. `preimages.prepare` passes `dedupe=False`, so every Write/Edit stores a full new copy. Measured: Edit 103 ms → 151 ms at 2,025 archived files on ext4. On NTFS with Defender, thousands of entries × four walks lands in the tens of seconds, i.e. straight into F1. | `core/store.py:1523,1698,1733`, `core/preimages.py:173,200`, `core/archive_transactions.py:374` | CONFIRMED |
| F10 | **Capacity wall bricks all file mutation for 7 days.** `mutation_preimage` entries are protected for 7 days and are the only prunable class. Once projected size exceeds `max_bytes` (4 GiB default), nothing is reclaimable and every write is DENIED with "Retry with one direct, file-specific operation", which can never succeed and never names `agw prune` or `AGW_ARCHIVE_MAX_BYTES`. Reproduced with a 20 MiB cap at edit #10. One heavy Office session (~40 edits of a 100 MB file) reaches the default. | `core/store.py:1737`, `core/retention_policy.py:17-20`, `core/preimages.py:127` | CONFIRMED |
| F11 | **`agw undo` restores without a hash check, outside any lock, and moves the artifact out of the store.** `restore()` correctly gates on `entry_is_verified`; `undo_last()` calls `shutil.move(op["dest"], op["src"])` on a raw oplog row with no fingerprint, no transaction, no lock. A corrupted artifact is moved over the live path and removed from the store in one step. The `if op.get("undone")` guard is dead code (nothing writes `undone` onto the original row). | `core/store.py:1465-1487` | CONFIRMED |
| F12 | **Per-call import and policy parse dominate latency.** One import line pulls 12 `core` modules (`difflib, secrets, hmac, tempfile, zlib, ast, inspect, subprocess, ctypes`). `load_policy` re-reads and digests `core.yaml` and lists two policy dirs on every call; `sessionstart.py:76`'s "warms cache" comment is wrong, nothing persists across processes. `profiles._cache` is process-scoped and so never hits. | `claude/pretooluse.py:36-38`, `core/engine.py:374,463`, `core/approvals.py:5-6`, `core/profiles.py:52-66` | CONFIRMED (measured) |
| F13 | **Stdlib-only mode (documented as primary) does not fail closed on a corrupt policy.** `miniyaml._scalar` accepts `pattern: [unclosed` as a plain string; PyYAML rejects it. So a corrupt custom policy pack loads as HEALTHY instead of DEGRADED/UNAVAILABLE. Two tests in `test_policy_health.py` fail in a stdlib-only venv. CI installs PyYAML on every matrix leg, so this path has never been exercised. | `core/miniyaml.py:25`, `core/engine.py:463-467`, `.github/workflows/conformance.yml:17` | CONFIRMED |

### Measured latency (Linux, warm bytecode cache, median of 10)

| Scenario | ms |
|---|---:|
| `python3 -c pass` baseline | 9 |
| PreToolUse Read (12-byte file) | 90 |
| PreToolUse Bash `ls` | 100 |
| PreToolUse Edit (small file) | 101 |
| PreToolUse mcp__ call | 95 |
| PostToolUse Read | 76 |
| PreToolUse Edit, archive holding 2,025 files | 151 |
| 4 parallel Edits, wall clock | 355 to 444 |
| PreToolUse Read with `__pycache__` unwritable | 145 |
| Floor for "parse stdin and decide" | 16 |

Phase split: `core` import 51 to 60 ms, `load_policy` 11 to 14 ms with PyYAML
(2 ms with miniyaml), `preimages.prepare` 3.5 to 10.5 ms on a tiny file (four
full passes over the file: hash, copy, hash, hash). An Edit issues 24 `fsync`
calls; on NTFS each is typically 1 to 5 ms. Windows estimate: 2.5 to 4× Linux,
so roughly 0.6 to 1.0 s of hook overhead per Edit before the store grows.

## 2. P2: frequent friction and user-visible failure

| # | Finding | Location |
|---|---|---|
| G1 | **Any cwd inside a cloud-synced tree makes all raw discovery a non-waivable DENY.** Bare `Get-ChildItem`, `gci`, `ls`, `rg`, `Select-String -Recurse` in a repo under `OneDrive - Acme/` are blocked by `builtin:unbounded-discovery`. The README markets OneDrive as the flagship scenario. Almost certainly the biggest single source of "issues in PowerShell". Fix: treat a project root that happens to live under OneDrive as project-local; apply the cloud-tree rule only when the scope is outside the active project. | `core/engine.py:1137` |
| G2 | `-Force` is in `_DISCOVERY_RISK_FLAGS`, so `Get-ChildItem -Recurse -Force` (the standard listing idiom; `-Force` only reveals hidden files there) is denied. Scope it to `fd`/`find`. | `core/engine.py:1072-1077` |
| G3 | `-WhatIf` is parsed but never honoured: `Remove-Item .\temp -Recurse -WhatIf` (dry run) is denied. | `core/engine.py:1703`, `core/powershell_bind.py:14` |
| G4 | Splatting (`Set-Content @params`) and here-strings are non-waivable DENY rather than ASK. Route "binding incomplete" to ASK. | `core/powershell_bind.py:113,169` |
| G5 | Backtick line continuation always raises `ParseUncertain`; multi-line PowerShell is never parsed, and ALLOWs as "uncertain, non-mutating" when `_MUTATION_EVIDENCE_RE` misses (a fail-open edge). `launcher._collapse_powershell_line_continuations` already does this correctly; call it. | `core/shellparse.py:150-151` |
| G6 | **Office publish uses bare `os.replace` with no retry.** `file_ops.replace_with_retry` handles winerror 32/33 but `office_tx` does not use it. Word or Excel holding the file open gives an immediate `PermissionError`, the `finally` unlinks the stage, and the mutation is lost with a raw OS error. Read-only attributes are never detected anywhere. | `agw/office_tx.py:1621,1658-1663`, `agw/file_ops.py:1639` |
| G7 | **Temp files are staged inside the user's synced folder.** Six sites do `tempfile.mkstemp(dir=os.path.dirname(target))`. In OneDrive/Dropbox this exposes `.agw-publish-*.docx` to the sync client and Defender before the replace (the very sharing violation G6 then hits), and a crash leaves them to be uploaded. Stage under `$AGW_HOME/stage/` on the same volume, or use a prefix sync clients ignore. | `agw/publication.py:576`, `agw/office_tx.py:1572`, `agw/file_ops.py:958,1054`, `agw/office_surgical.py:313`, `agw/office_ooxml.py:50` |
| G8 | **Codex PostToolUse grants session approvals with no verification.** Calls `store.session_approve` for any decision with a memo key; no pending record, fingerprint, revision, or ASK check. The Claude adapter does all four. | `codex/posttooluse.py:44-47` vs `claude/posttooluse.py:45-61` |
| G9 | Cloud placeholders are guarded on `event.paths` only, not on `clobber_targets` (`>` redirects, `mv`/`cp`/`tee` destinations). `echo x > "…\OneDrive\big.xlsx"` is not denied and forces a full cloud hydration inside the 15 s hook. | `core/engine.py:712,1888,1958`, `core/profiles.py:194-198` |
| G10 | `AGW_ENFORCEMENT`, `AGW_LEVEL`, `AGW_HOME` are honoured from the environment, and `.claude/settings.json` (whose `env` block the host injects into hooks) is not in `protected_globs`. An agent can write `{"env":{"AGW_ENFORCEMENT":"observe"}}` and downgrade every waivable rule from the next hook onward. Non-waivable invariants still hold. | `core/engine.py:311-328,377-385`, `core/store.py:179` |
| G11 | PostToolUse imports the heavy modules before `consume_pending_approval`, which returns `None` on nearly every call. Reordering measured 76 → 39 ms; a tiny `os/json/hashlib`-only gate reaches ~20 ms. Zero safety change. | `claude/posttooluse.py:36-40` |
| G12 | No fast path for Read/MCP. The matchers are worth keeping (credential-filename asks, MCP-shell exec), but a benign Read of `small.txt` loads the whole engine. With a cached policy (F12) this is ~20 ms instead of 90. | `claude/pretooluse.py:34-69` |
| G13 | `_prescan_file` reads 64 KB and runs 7 regexes on every Read (6 ms on a 128 KB `.py`), then `_is_low_confidence_context` discards the contextual hits for dev-source suffixes. Check the context first; keep the five hard markers always on. | `core/engine.py:77,106,130` |
| G14 | 15 s PreToolUse timeout covers `preimages.prepare`, which copies up to `AGW_PRESNAP_MAX_BYTES` (100 MB default) with four full passes. On a OneDrive or network path this can exceed 15 s, and the host then runs the tool unguarded. Codex's hook budget is 120 s. | `hooks/hooks.json:12`, `claude/pretooluse.py:31`, `core/preimages.py:198-220` |
| G15 | `.gitattributes` forces LF into `plugin/bin/agw.cmd`. `cmd.exe` parses batch files by byte offset and LF-only files are a known source of intermittent `goto`-label and parenthesised-block failures; `agw.cmd` uses both. Add `*.cmd text eol=crlf`. Separately, `.gitattributes:18` protects `synthetic/cowork-safety-lab/workspace/**`, a path that does not exist (real path is `synthetic/safety-lab/`), so the byte-exact `.gdoc` fixture is unprotected on Windows checkouts. | `.gitattributes:8,16,18` |
| G16 | README release banner says `0.3.23` is the Windows-first stable release. No `v0.3.23` tag ever existed (tags jump `v0.3.6` → `v0.3.26`); every manifest and the latest tag agree on `0.4.4`. | `README.md:16-21` |
| G17 | Reserved Windows names (`aux.txt`, `con.md`) yield an illegal archive directory name; `ensure_directory` retries 0.5 s then raises → permanent DENY for that file. No `\\?\` long-path prefixing anywhere and the archive path adds ~150 characters, so deep source paths hit MAX_PATH with the same result. | `core/store.py:509-511`, `agw/agw.py:810` |
| G18 | Windows CI never executes `commandWindows` end to end; `test_host_conformance.py:58` only asserts the string starts with `py.exe -3 `. 28 test files, including all path-safety, store I/O, retention, and Office publication suites, run only on the Unix leg. | `.github/workflows/conformance.yml`, `tests/test_host_conformance.py:58` |

## 3. P3: hygiene

- `_RetentionLock` (`core/retention.py:1044-1066`) is `O_CREAT|O_EXCL` with no staleness check; a SIGKILL (the hook timeout) leaves `retention.lock` forever. Only reachable from `agw` CLI paths, not the hook.
- Fail-closed handler writes onto a possibly-dirty stdout (`claude/pretooluse.py:259-263`, `codex/pretooluse.py:332-336`): a failure mid-`json.dump` leaves a partial object followed by a second one, which the host cannot parse (= allow). Low likelihood; buffer to a string and write once.
- The POSIX `python3 … || python …` fallback is safe today because every adapter exits 0 and decisions travel as JSON. If any leg ever exits non-zero after writing output, the second leg gets drained stdin and appends a second JSON object. Run the fallback only on exit 127.
- 13 bare `except Exception: pass` out of 81 handlers. Worst: `core/engine.py:737-738` swallows redirect-parse failures in `clobber_targets` whose own docstring says a miss is silent data loss; `claude/sessionstart.py:80-81` swallows `load_policy`, so a corrupt policy pack produces no session-start warning.
- The audit log is a deliberate no-op (`core/auditlog.py:34`). This is why F1 and F2 are invisible: there is no forensic trail when a hook is killed or falls through. A cheap append-only line per decision (no fsync) would make both diagnosable.
- `approvals.py:252-259` accepts `timeout_s` and discards it; `TaskDialogIndirect` blocks indefinitely. Only the Codex adapter opens the dialog, where the 120 s hook budget can expire while the modal is open.
- `core/approvals.py:5-6` imports `ctypes` and `ctypes.wintypes` unconditionally on every platform.
- `mutations._canonical` (`mutations.py:633`) keys pre-images by `realpath`; Windows trailing-dot/space paths resolve to the same file under different keys, so a pre-image can be filed under a key that never matches on restore.
- `canonical_path` uses `os.path.normcase` (no-op off Windows), so `Doc.docx` and `doc.docx` get separate archive histories on APFS.
- `store.py:509` truncates the sanitized basename to 80 chars; two long-named files share an archive directory. Harmless today because `list_versions` reconciles by transaction id.
- `synthetic/safety-lab/workspace/secrets/.env` is git-tracked with `API_TOKEN=sk-example-…` and `DB_PASSWORD=…`; generic secret scanners will flag it. It is not wired into pytest.
- If `__pycache__` is unwritable (Program Files deployment, AV blocking `.pyc` writes) every call pays +54 ms recompiling. Ship precompiled bytecode or run `compileall` from SessionStart.
- Test coverage is the root cause of F5 and F6: `tests/test_bypass_corpus.py` `BENIGN` has zero PowerShell entries, and every assertion in `test_windows_shell.py` and `test_bypass_corpus.py` calls `engine.evaluate` directly, so neither `mutations.plan` nor `presentation.build_prompt` is ever in the loop.

## 4. What is already good (do not re-fix)

- **Archive transactions are crash-safe** (`core/archive_transactions.py:499-606`): manifest first, artifact published via `os.replace`, re-fingerprinted after publish, source re-verified immediately before removal. `manifest.jsonl` and the oplog are derived after COMMITTED and `list_versions` reconciles, so an orphan index row cannot resurrect a purged artifact.
- **Locking is real and cross-platform**: `fcntl.flock` / `msvcrt.locking` on a persistent `.gate` file, owner published via `os.link`, stale owners reclaimed by liveness check. Only the timeout values are wrong.
- **Publication conflict detection uses SHA-256**, re-checked under the lock and again before `os.replace`. Exactly right for synced folders.
- **Retention cannot delete a sole copy**: only `mode == "copy"` + `mutation_preimage` records, age-protected, hash-verified before staging, applied through a durable journal with rename-back on failure. No traced `os.remove`/`rmtree` touches user data.
- **The trust handshake is path-identity based** (`engine.py:1508-1537`), resolved through `shutil.which`/`realpath` under `plugin_root`; no env var or marker file grants trust.
- **Fail-closed on crash is airtight**: `_dispatch.py` covers import errors and interpreter-level failures; empty stdin, non-JSON, and `tool_input` type drift all produce a proper ASK; a broken `AGW_HOME` produces a legible DENY. Stdio is reconfigured to UTF-8 on all three streams, so the PowerShell 5.1 OEM code page hazard is handled.
- **Wrapper recursion** for `-Command`, positional body, `-EncodedCommand` (base64/UTF-16LE, fail-closed on undecodable), `cmd /c|/k` is thorough wherever the interpreter name is matched. `_double_winpath_backslashes`, `_code_view`, and `_REDIR_EXPRESSION_RE` each kill a real false-positive class.
- **`agw.cmd`** probes `python` then `py.exe -3` with a major-version check, quotes `%~dp0` correctly, and preserves the child exit code.
- **Tests**: 1216 pass in 78 s with no mocks in the sampled engine/adapter/store suites; Windows-only OS-semantics tests are honestly `skipif`-gated. Packaging exclusions (`tests/`, `synthetic/`, `__pycache__`) are enforced by `test_packaging.py`. Version alignment across both `plugin.json` files, both marketplace manifests, and the `v0.4.4` tag is correct.
- **No per-call subprocess, network, sqlite, workspace walk, or glob** on the hook path. `store.session_approved` and `consume_pending_approval` are genuinely cheap.

## 5. Suggested sequencing

**Week 1: stop the silent failures (all small, none weaken a contract).**
F1 lock timeout to ~8 s with explicit ASK on `TimeoutError` · F2 unknown tool → ASK · F3 normalize interpreter head (`/`, `\`, strip `.exe/.cmd/.bat`) before every wrapper test · F8 `commandWindows` fallback to `python` and fix README:74 · F5 fall back to a plain-reason ASK instead of DENY · F6 drop regenerable dirs from `mutation_plan.targets` · G1 project-under-OneDrive is project-local · G3 honour `-WhatIf` · G15 `*.cmd eol=crlf` and fix the dead `.gitattributes` path.

**Week 2: halve the per-call cost.**
F12 lazy imports per event kind and a persisted policy cache keyed on (path, size, mtime_ns, digest); try `miniyaml` first · F9 running byte counter instead of `os.walk`, `dedupe=True` for pre-images, lock only around an applied prune · G11 cheap gate first in PostToolUse · G12/G13 Read fast path · single-pass hash+copy in `preimages.prepare` · batch `fsync` to the commit marker.

**Week 3: close the bypasses and the Windows edges.**
F4 model `wsl`, `Start-Process`, `robocopy /MIR|/PURGE|/MOV`, `-File` · F7 `FLAG_INDIRECT` for `$var` heads and a stricter cmdlet regex · G2/G4/G5 · G6 use `replace_with_retry` in `office_tx` · G7 stage outside the synced folder · G9 placeholder check over clobber targets · F13 `miniyaml` bracket balance plus a stdlib-only CI leg.

**Week 4: the store's long tail.**
F10 remediation text plus reclaim of non-newest same-source pre-images · F11 route `undo_last` through `publish_restore` under the lock with `entry_is_verified` · G8 port the Claude PostToolUse checks to Codex · G10 protect `.claude/settings*.json` · G17 reserved names and `\\?\` prefixing · G18 run the full suite on the Windows leg and spawn the literal `commandWindows` line in one test · a minimal append-only decision log so the next silent failure is diagnosable.

**Tests to add alongside**: an adapter-level fixture that drives the full `pretooluse` pipeline (not `engine.evaluate`), with the 40-command PowerShell corpus as its benign/deny spec, run against a cwd that actually contains `node_modules`, `build`, `dist`, and a folder named `OneDrive - Acme`.

---

## 6. Resolution, 2026-09-17 (branch `claude/kind-curie-rfhklm`)

Seven work packages landed the same day, each in its own branch, gated by the
full suite and by a 46-row decision corpus driven through the real hook. The
suite went from 1216 to 1718 passing tests; the corpus from 21 to 46 rows
matching. Every P1 above is closed. Findings map to merges as follows.

| Finding | Status | Merge |
|---|---|---|
| F1 lock timeout vs hook budget | Fixed: 8 s hook budget, "store busy" refusal | wp-a |
| F2 unknown tool silent allow | Fixed: ASK naming the tool, both hosts | wp-d |
| F3 `.exe` / full-path interpreters | Fixed: one normalized head before every wrapper test | wp-b |
| F4 wsl, robocopy, Start-Process, xcopy, fsutil, -File | Fixed; -File is ASK; destinations pre-imaged | wp-b, wp-f |
| F5 ASK upgraded to DENY | Fixed: generic prompt from the rule's own reason | wp-c |
| F6 regenerable dirs blocked | Fixed: skipped from the plan with an honest receipt | wp-c, wp-f |
| F7 `$var` heads, dialect misdetection | Fixed: FLAG_INDIRECT, verb-prefixed cmdlet detection, POSIX -rf evidence | wp-b, wp-f |
| F8 Windows launcher without fallback | Fixed: `py.exe -3 || python`; POSIX fallback only on 127 | wp-d |
| F9 archive walk per Edit, no dedupe | Fixed: running counter, single admission, dedupe, single-pass hashing, 24 → 8 fsyncs | wp-a |
| F10 capacity wall | Fixed: reclaim behind a verified newer copy; refusal names `agw prune` and the sizes | wp-a, wp-f |
| F11 unsafe `agw undo` | Fixed: locked, verified restore | wp-a |
| F12 per-call import and policy parse | Fixed: lazy imports, persisted policy and profile caches, miniyaml first | wp-e |
| F13 miniyaml not fail-closed | Fixed, plus a stdlib-only CI leg | wp-d |
| G1 OneDrive project denies discovery | Fixed: project-local scope | wp-c |
| G2 `-Force` on Get-ChildItem | Fixed: scoped to finders | wp-c |
| G3 `-WhatIf` ignored | Fixed, including the `-wi` alias | wp-c, wp-f |
| G4 splatting and here-strings non-waivable | Fixed: `$`/`@` shapes ask; backticks and wildcards stay fail-closed | wp-b, wp-f |
| G5 backtick continuation | Fixed: exact backtick-newline collapses | wp-b |
| G8 Codex approvals unverified | Fixed: Claude gate ported | wp-d |
| G9 placeholders on clobber targets | Fixed | wp-c |
| G11, G12, G13 PostToolUse order, Read fast path, prescan | Fixed | wp-e |
| G15 `.gitattributes` | Fixed: CRLF batch files, two dead rules revived | wp-d |
| G16 README banner | Fixed | wp-d |
| Codex native `shell` / `local_shell` / `exec_command` / `write_stdin` (found during D) | Fixed: matched, routed, `agw` door works through them | wp-g, wp-h |
| P3 ctypes import, session-start policy warning, dirty stdout, bytecode | Fixed | wp-d, wp-e |

**Measured after** (Linux, warm bytecode, median of 10, empty store):

| Scenario | Before | After |
|---|---:|---:|
| PreToolUse Read | 94 | 32 |
| PreToolUse Bash | 99 | 75 |
| PreToolUse Edit | 96 | 79 |
| PreToolUse mcp__ | 95 | 55 |
| PostToolUse Read | 73 | 26 |
| Pre-image prepare, 2000-entry store | 129 | 22 |
| fsyncs per Edit | 24 | 8 |

**Still open**

- G6 and G7 (Office publish `os.replace` without retry; temp files staged inside the synced folder), G10 (`.claude/settings.json` not in protected globs), G14 (100 MB pre-image inside the 15 s budget), G17 (reserved names, long paths), G18 (full suite on the Windows CI leg, no live `commandWindows` spawn), and the P3 `_RetentionLock` staleness and macOS case-folding items.
- Bash, Edit and MCP hook latency sit at 55 to 79 ms against targets of 35 to 65. The remaining cost is `core.events` (dataclasses), the MCP rule tables living in `engine`, and `workflows` importing `store` at module level; the fix directions are in the wp-e merge message.
- `Glob`/`Grep` are modeled as reads but not in either matcher.
- Windows plus Codex native tools is untested on a real Windows machine.
- Both hook command strings changed (F8) and the Codex matcher changed (native tools): Codex installs pin the hook-definition hash and must re-trust. Say so at the top of the release notes.
