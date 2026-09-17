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

### Two tool vocabularies, one set of guardrails

Codex builds do not agree on what their tools are called. Some emit the
Claude-style names (`Bash`, `Read`, `apply_patch`); others emit Codex's own:

| Codex-native tool | Payload | Guarded as |
|---|---|---|
| `shell`, `local_shell` | `command` is an **argv list** (`["bash", "-lc", "rm -rf x"]`), plus optional `workdir`, `timeout_ms`, `with_escalated_permissions`, `justification` | shell execution - the argv is normalized to one command line and evaluated by the full Bash rule set |
| `exec_command` (unified exec) | `cmd` is a single command **string**, plus optional `workdir`, `shell`, `login`, `yield_time_ms`, `max_output_tokens` | shell execution; a `shell` naming `pwsh`/`powershell`/`cmd` selects that dialect |
| `write_stdin` | `chars` sent to an already-running exec session by `session_id` | **always asks** - the characters are not a command this hook can read, and they may complete whatever is waiting at that prompt |
| `view_image`, `update_plan` | - | inert; not intercepted at all |

Both vocabularies are in `hooks/hooks-codex.json`, so the same install guards
either build. An argv shape the adapter cannot read - a missing `command`, a
non-list, a list holding a non-string - fails closed to the same ASK rather
than evaluating as an empty (and therefore harmless) command.

`["bash", "-lc", <script>]` is unwrapped to the script itself before
evaluation. The shared parser recurses a literal `-c`, not the combined `-lc`
spelling Codex uses, and an unrecursed wrapper hides everything inside it.

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
   a command - or the matcher, which is part of the same definition - makes Codex
   skip the hook until the user reviews it again in the host's hook-trust UI
   (`/hooks` in Codex CLI). After upgrading to a release that added the
   Codex-native tool names to the matcher, re-trust there before relying on it.

## How the shared hook shim picks the host

Codex selects `hooks/hooks-codex.json` through `.codex-plugin/plugin.json` and
dispatches directly to `scripts/codex/*` with `PLUGIN_ROOT`. Claude Code uses
`hooks/hooks.json` and dispatches to `scripts/claude/*`. Both maintained
manifests cover Bash, PowerShell, and Monitor through the shared EXEC policy,
and the Codex manifest additionally covers `shell`, `local_shell`,
`exec_command`, and `write_stdin`. The same adapters expand the short launcher
for interactive Bash/PowerShell calls. Monitor commands remain literal and
receive no shortcut expansion, and so do the Codex-native exec surfaces: a
literal `agw` issued through `shell` is evaluated, not rewritten.

## Verify before relying on it

`apply_patch` hook interception landed relatively recently in Codex (it was
broken until ~April 2026, [openai/codex#16732]). Smoke-test on your installed
build:

```
# In a Codex session with the plugin enabled and trusted, ask it to delete a
# file via apply_patch. Expect a DENY citing `agw archive`, not a deletion.
```

`Bash` interception has always worked; confirm `apply_patch` does on your version.

### Confirm interception on a build that uses the native tool names

Which vocabulary your build emits decides which matcher entry fires, so prove
it rather than assuming. In a session with the plugin enabled and trusted:

```
# 1. Ask for a deletion in a throwaway directory:
#       "run rm -rf ./scratch-dir for me"
#    Expect a DENY naming `agw archive`. A deletion that just happens means the
#    hook never fired for that tool name.
#
# 2. Ask it to type into a running process:
#       "start `python3 -i`, then send `import os` to it"
#    Expect an approval prompt (or a block when no approval provider is
#    available) before any characters are sent.
#
# 3. Ask for something harmless - "run git status" - and confirm it is NOT
#    prompted for. Every command prompting is the other failure mode: a
#    guardrail agents learn to route around.
```

If step 1 deletes without a decision, check `/hooks` in Codex CLI: the hook
definition changed when the native tool names were added, so an install
trusted against the previous definition skips it until it is re-approved.

[openai/codex#16732]: https://github.com/openai/codex/issues/16732
