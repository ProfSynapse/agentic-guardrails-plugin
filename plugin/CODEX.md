# Agentic Guardrails on OpenAI Codex

This plugin runs on **OpenAI Codex CLI** as well as Claude Code (terminal and
desktop app). The safety engine (`scripts/core`) and the `agw` CLI are identical
across hosts; only a thin adapter layer (`scripts/codex`) differs. One package,
two hosts. Other hosts are planned but unsupported and carry no safety claim;
see [`../docs/HOST_PARITY.md`](../docs/HOST_PARITY.md).

## What carries over

| Capability | Claude Code | Codex |
|---|---|---|
| Pre/Post-tool hooks | `PreToolUse` / `PostToolUse` | same event names + JSON schema |
| Block / ask / allow | `permissionDecision` | identical |
| Session context | `SessionStart` | identical |
| Skill | `skills/agentic-guardrails/SKILL.md` | compact router; loads safety references progressively |
| Command discovery | CLI `--help` hierarchy | progressively scoped; no duplicated prompt catalog |
| `agw` CLI | platform-neutral `agw` short form | same |

### The one real difference: `apply_patch`

Codex routes **all** file mutation through a single `apply_patch` tool (there is
no separate Write/Edit). The Codex adapter parses the patch envelope
(`scripts/codex/applypatch.py`) to recover which files a patch touches and what
kind of change each is:

- **Add File** → treated as a write (new content scanned for secrets).
- **Update File** → treated as an edit; the original is snapshotted first.
- **Delete File** → **blocked** under CRUA, exactly like shell `rm`. Use
  `agw archive <path>` instead. An agent cannot route a deletion around the
  guardrails by expressing it as a patch.
- An **unparseable patch** hard-denies, never silently allows or prompts
  without known targets.

## Install

The plugin is the same git subdirectory used for Claude Code (`plugin/`). The
repo doubles as a Codex marketplace - just give Codex the GitHub URL:

1. **Add the marketplace and install** - from a shell:

   ```bash
   codex plugin marketplace add https://github.com/ProfSynapse/agentic-guardrails-plugin --ref main
   ```

   Then inside Codex run `/plugins` and install **Agentic Guardrails**. Codex
   reads `.agents/plugins/marketplace.json` at the repo root (it also accepts the
   legacy `.claude-plugin/marketplace.json`), resolves the `git-subdir` source to
   the `plugin/` directory, then loads `.codex-plugin/plugin.json` and its
   manifest-selected `hooks/hooks-codex.json`. To pull a later version:
   `codex plugin marketplace upgrade`
   (the bumped `version` in `.codex-plugin/plugin.json` busts the cache).
2. **Trust the hooks** - Codex requires command hooks to be trusted before they
   run. Approve `agentic-guardrails` in the host's hook-trust UI. Codex CLI uses
   `/hooks`; desktop builds may show a trust dialog instead. (Enterprise: ship
   managed hooks via `requirements.toml` to skip the prompt.)
3. **Command discovery** - use the packaged CLI's progressive `--help` hierarchy.
   Operational syntax is not duplicated into user-level prompts.
4. **Short launcher** - invoke `agw` on every platform. The
   SessionStart context teaches that compact form, and the trusted PreToolUse
   hook rewrites only a literal leading launcher token to this installed
   package before policy evaluation and execution. No PATH or shell-profile
   change is required. On Windows the hook resolves `agw` to the packaged
   `agw.cmd`; that suffix remains a backward-compatible implementation detail.
   The launcher invokes Python explicitly and never asks Windows to open a `.py`
   file by file association.

   If literal `agw` cannot be invoked, stop with the stable reason code
   `launcher_unavailable`; never search the plugin cache for a launcher. Ask the
   user to enable the Guardrails hooks and start a new task. `agw doctor --json`
   reports the launcher contract when bootstrap succeeds.

   Codex records trust against each hook definition's exact hash. Keep manifest
   launcher commands stable and put behavior changes in the dispatchers; changing
   a command makes Codex skip it until the user reviews it again in the host's
   hook-trust UI (`/hooks` in Codex CLI).

## How the shared hook shim picks the host

Codex selects `hooks/hooks-codex.json` through `.codex-plugin/plugin.json` and
dispatches directly to `scripts/codex/*` with `PLUGIN_ROOT`. Claude Code uses
`hooks/hooks.json` and dispatches to `scripts/claude/*`. Both maintained
manifests cover Bash, PowerShell, and Monitor through the shared EXEC policy.
The same adapters expand the short launcher for interactive Bash/PowerShell
calls. Monitor commands remain literal and receive no shortcut expansion.

## Verify before relying on it

`apply_patch` hook interception landed relatively recently in Codex (it was
broken until ~April 2026, [openai/codex#16732]). Smoke-test on your installed
build:

```
# In a Codex session with the plugin enabled and trusted, ask it to delete a
# file via apply_patch. Expect a DENY citing `agw archive`, not a deletion.
```

`Bash` interception has always worked; confirm `apply_patch` does on your version.

[openai/codex#16732]: https://github.com/openai/codex/issues/16732
