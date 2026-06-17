# ADR 0001: Get agentic-guardrails hooks firing in Claude Cowork

- Status: Proposed
- Date: 2026-06-17
- Deciders: Joseph Rosenbaum
- Related: Codex hook non-enforcement fix (plugin 0.2.7 / 0.2.8)

## Context

Guardrail enforcement worked in Claude Code and (after the 0.2.8 fix) in the
Codex Desktop app, but Cowork was a dead end: delete probes succeeded with no
`audit.jsonl` entry. Inspection of the live Cowork session on 2026-06-17
explained why.

Session inspected:
`%APPDATA%/Claude/local-agent-mode-sessions/08b30b03.../fe53a255.../`

```jsonc
// cowork_settings.json
"enabledPlugins": {
  "cowork-plugin-management@knowledge-work-plugins": true   // only this
},
"extraKnownMarketplaces": {
  "agentic-guardrails-plugin": {
    "source": { "source": "github", "repo": "ProfSynapse/agentic-guardrails-plugin" }
  }
}
```

Findings:

1. The plugin was registered as a *known marketplace* but never added to
   `enabledPlugins`. The `.agwbak` diff confirms the only change ever applied
   was the `extraKnownMarketplaces` entry.
2. The session's `rpm/` directory contains only `manifest.json` (51 bytes). No
   plugin is materialized, so there are zero guardrail hooks loaded.
3. Therefore nothing fails to fire because nothing exists to fire. Cowork was
   never running the plugin.

This is the same failure *class* as the Codex `_comment` parse bug: zero
handlers contributed, masked by a UI that looks healthy. The difference is the
layer. Codex failed at hook-file parse; Cowork fails at plugin enablement.

The Claude hook command is a POSIX bash shim:

```
AGW_PY="$(command -v python3 || command -v python || command -v py || echo python3)"; exec "$AGW_PY" -c "..."
```

This is the same category of shell-specific command that fail-opened under
Codex's PowerShell. We have not yet observed it run in Cowork, so the shell it
executes under on Windows is still unknown.

## Decision

Treat Cowork enablement as a layered pipeline and verify each layer on disk
rather than trusting the Cowork UI:

```
known marketplace -> enabled plugin -> hooks materialized under rpm/ -> hook fires -> audit entry written
```

Do not assume any downstream layer from an upstream one. Registering a
marketplace does not enable a plugin; enabling a plugin does not guarantee
materialization; materialization does not guarantee the hook command runs in a
compatible shell.

## Plan

1. Enable, do not just register. In Cowork, enable `agentic-guardrails` so it
   lands in `enabledPlugins`, not only `extraKnownMarketplaces`.
2. Fully restart Cowork so it materializes the plugin under the session's
   `rpm/` directory. If the backend serves stale code, bump the version and
   remove/re-add the marketplace entry (see cache-bust note below).
3. Verify on disk: confirm a real plugin directory plus `hooks/hooks.json`
   exists under `rpm/`, and that `enabledPlugins` now lists the plugin.
4. Probe and check audit: run one delete probe, then check
   `~/.agw/audit.jsonl` (= `C:\Users\Joseph\.agw\audit.jsonl`) for a fresh
   entry.
5. If the tool succeeds with no audit entry, that is the Codex fail-open
   signature. Investigate which shell Cowork runs the bash shim under on
   Windows. If it is non-POSIX, the fix mirrors the Codex 0.2.8 work: a
   shell-agnostic command form.

## What transfers from the Codex investigation

- The diagnostic method transfers wholesale: stop trusting the UI, verify each
  layer on disk and in the audit log.
- The shell-mismatch lesson is the next thing to watch once hooks materialize.
- What does not transfer: Codex trust hashes, `${PLUGIN_ROOT}` rust-side
  substitution, and `commandWindows`. Cowork uses Claude's `CLAUDE_PLUGIN_ROOT`
  plus the bash shim, with no per-command trust gate.

## Consequences

- Positive: a repeatable verification checklist that distinguishes
  "not enabled" from "enabled but not firing" from "firing but fail-open".
- Negative: each layer must be checked manually until we have a script that
  asserts the full pipeline.
- Risk: editing the live session `cowork_settings.json` directly is fragile.
  Cowork may overwrite it on restart. Prefer enabling through the Cowork UI.

## References

- `~/.agw/audit.jsonl` host store (= `C:\Users\Joseph\.agw\audit.jsonl`),
  reachable from `/mnt/c`.
- Memory: cowork-hooks-do-not-fire, cowork-marketplace-cache-bust,
  cowork-stale-plugin-copies, codex-hook-trust-gate.
