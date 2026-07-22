# Host support and release parity

The policy engine in `plugin/scripts/core` is host-neutral. A host is supported
only when its manifest, hook lifecycle, adapter normalization, and packaged
artifact all pass the conformance suite. Sharing the core alone is not a safety
claim.

| Host | Registry state | Release blocking | Safety support claim |
|---|---|---:|---|
| Claude Code | supported | yes | Maintained and tested |
| OpenAI Codex | supported | yes | Maintained and tested |
| Cowork | planned / unsupported | no | None; required hooks are not available |
| Cursor | planned / unsupported | no | None |
| Gemini CLI | planned / unsupported | no | None |
| GitHub Copilot | planned / unsupported | no | None |

## Maintained-host contract

Claude Code and Codex releases must both pass:

1. `PreToolUse`, `PostToolUse`, and `SessionStart` manifest conformance.
2. Equivalent `Bash`, `PowerShell`, and `Monitor` normalization to `EXEC`.
   The Monitor normalizer contract accepts only a literal
   `tool_input.command` string and evaluates it with the Bash rules. This is a
   tested envelope contract, not a claim that a live Monitor host was probed.
3. Equivalent shared-core decisions for the same normalized operation.
4. Platform-native CLI guidance (`bin/agw` on POSIX and `bin/agw.cmd` on
   Windows).
5. Clean packed-artifact execution using only files inside the copied plugin
   subtree.
6. Plugin-root-qualified dispatch with no cache, adjacent-repository, or
   `PYTHONPATH` fallback.
7. SessionStart and launchers never persistently modify process, user, or
   machine PATH; Windows launcher tests use only Python and System32 on PATH.
8. Windows hook manifests invoke `py.exe -3` with a plugin-root-qualified
   dispatcher path. Missing Python Launcher guidance is written for people and
   never proposes PATH edits or file-association execution.

A planned host becomes supported only after it has an explicit manifest and
adapter, lifecycle fixtures, platform launcher coverage, and inclusion in the
release-blocking CI matrix. The shared core is intentionally future-compatible,
but it does not make an unintegrated host safe by itself.
