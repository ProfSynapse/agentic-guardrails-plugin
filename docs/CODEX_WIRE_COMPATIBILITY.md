# Codex hook wire compatibility and diagnostic cleanup

## Release scope and evidence (2026-10-05)

The Codex PreToolUse adapter must emit only host-supported fields. Codex 0.160.0
rejects unknown fields at both the top level and inside `hookSpecificOutput`.
The old `agwRefusal` field invalidated an otherwise valid deny response: the
native synthetic tool executed despite reviewer absence. The repaired adapter
omits that field; refusal details remain inside `permissionDecisionReason`.
Claude's adapter was not changed for this incident because no equivalent failure
was established there.

The captured schema in `tests/codex_wire_contract.py` comes directly from the
pinned Linux x86_64 Codex 0.160.0 binary (SHA256
`12eb3e81114588aca3b7998f4f19e8997b056aca08e57a7ca7c8a3ec8c652aad`).
It is the full embedded `pre-tool-use.command.output` schema. The regression
oracle validates all keywords in that fixture and rejects unknown keywords in
future fixture edits. `tests/test_codex_adapter.py` validates every subprocess
response against it; startup-failure regressions use the same oracle. Dedicated
tests cover shell, native exec, patch, MCP and unknown-tool denials, malformed
input, rejected extra fields and optional exact native schema equality.

Native absent-reviewer, decline and fresh-approval synthetic checks passed on
Codex 0.160.0 and Claude 2.1.285. These are the tested versions, not a claim of
compatibility with all versions. Codex schema validation, hook crashes/timeouts,
account apps and alternate routes still need review when hosts change. A parser
can accept `ask` without implementing a blocking prompt; the Codex adapter must
resolve independent approval itself and emit a supported final decision.

The native schema-equality test is optional: set `AGW_CODEX_PINNED_BINARY` to
the exact pinned Codex binary to run it; otherwise it skips. The rest of the
oracle runs everywhere.

## Release scope

This fix ships in the regular plugin release. It changes only the Codex adapter
response body (no hook command or matcher change), so it does not by itself move
the hook definition hash Codex pins. The Linux owner-review provider and action
contracts ship alongside it as opt-in experimental features; see
[LINUX_REVIEW.md](LINUX_REVIEW.md) and [ACTION_CONTRACTS.md](ACTION_CONTRACTS.md).
