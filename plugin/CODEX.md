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
| Skills | `skills/*/SKILL.md` | same files, listed in `.codex-plugin/plugin.json` |
| Slash commands | `commands/*.md` | `codex-prompts/*.md` → `~/.codex/prompts/` |
| `agw` CLI | `bin/agw` on POSIX, `bin/agw.cmd` on Windows | same |

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
   the manifest-selected `hooks/hooks-codex.json`. To pull a later version:
   `codex plugin marketplace upgrade`
   (the bumped `version` in `.codex-plugin/plugin.json` busts the cache).
2. **Trust the hooks** - Codex requires command hooks to be trusted before they
   run. Run `/hooks` inside Codex and trust `agentic-guardrails`. (Enterprise:
   ship them as managed hooks via `requirements.toml` to skip the prompt.)
3. **Prompts (optional)** - copy `codex-prompts/*.md` into `~/.codex/prompts/`
   to get `/prompts:agw-status`, `/prompts:agw-publish`, `/prompts:agw-restore`,
   `/prompts:guardrails-report`. These are user-level in Codex; plugins bundle
   skills and hooks but not slash commands.
4. **`agw` on PATH (optional)** - add `plugin/bin` to PATH. Use `bin/agw` on
   POSIX and `bin/agw.cmd` on Windows. The Windows launcher invokes Python
   explicitly and never asks Windows to open a `.py` file by file association.

## How the shared hook shim picks the host

Codex selects `hooks/hooks-codex.json` through `.codex-plugin/plugin.json` and
dispatches directly to `scripts/codex/*` with `PLUGIN_ROOT`. Claude Code uses
`hooks/hooks.json` and dispatches to `scripts/claude/*`. Both maintained
manifests cover Bash, PowerShell, and Monitor through the shared EXEC policy.

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
