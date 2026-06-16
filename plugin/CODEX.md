# Agentic Guardrails on OpenAI Codex

This plugin runs on **OpenAI Codex CLI** as well as Claude Code / Cowork. The
safety engine (`scripts/core`) and the `agw` CLI are identical across hosts;
only a thin adapter layer (`scripts/codex`) differs. One package, two hosts.

## What carries over

| Capability | Claude Code | Codex |
|---|---|---|
| Pre/Post-tool hooks | `PreToolUse` / `PostToolUse` | same event names + JSON schema |
| Block / ask / allow | `permissionDecision` | identical |
| Session context | `SessionStart` | identical |
| Skills | `skills/*/SKILL.md` | same files, listed in `.codex-plugin/plugin.json` |
| Slash commands | `commands/*.md` | `codex-prompts/*.md` → `~/.codex/prompts/` |
| `agw` CLI | `bin/agw` | same |

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
- An **unparseable patch** fails closed to *ask*, never a silent allow.

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
   `hooks/hooks.json`. To pull a later version: `codex plugin marketplace upgrade`
   (the bumped `version` in `.codex-plugin/plugin.json` busts the cache).
2. **Trust the hooks** - Codex requires command hooks to be trusted before they
   run. Run `/hooks` inside Codex and trust `agentic-guardrails`. (Enterprise:
   ship them as managed hooks via `requirements.toml` to skip the prompt.)
3. **Prompts (optional)** - copy `codex-prompts/*.md` into `~/.codex/prompts/`
   to get `/prompts:agw-status`, `/prompts:agw-publish`, `/prompts:agw-restore`,
   `/prompts:guardrails-report`. These are user-level in Codex; plugins bundle
   skills and hooks but not slash commands.
4. **`agw` on PATH (optional)** - add `plugin/bin` to PATH, or invoke
   `python3 <PLUGIN_ROOT>/scripts/agw/agw.py`. The SessionStart context tells the
   agent both forms.

## How the shared hook shim picks the host

`hooks/hooks.json` is a single self-locating shim used by both hosts. It detects
Codex by the presence of `CODEX_HOME` or the bare `PLUGIN_ROOT` env var (Codex
sets both `PLUGIN_ROOT` and, for compatibility, `CLAUDE_PLUGIN_ROOT`; Claude sets
only the latter). On Codex it dispatches `scripts/codex/*`; on Claude,
`scripts/claude/*`. The Claude resolution path is unchanged.

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
