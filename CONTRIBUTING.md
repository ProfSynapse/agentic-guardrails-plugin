# Contributing

Thanks for helping make agentic tools safer. This project guards real files on
real machines, so the bar is: every change keeps the safety contracts intact.

## The safety contracts (non-negotiable)

Any PR that weakens one of these will be asked to rework:

1. **Fail closed.** The hook adapter must answer "ask" on any internal error,
   never silently allow. A crash, a parse failure, or a corrupt policy pack
   must degrade to more caution, not less.
2. **Nothing is destroyed.** No code path may delete user data. Removal means
   archiving to the store; replacement means archiving the prior version
   first. `agw prune` stays human-gated.
3. **Denials teach.** Every deny message must name the safe alternative
   (`agw archive`, checkout/publish, etc.). An agent that hits a wall with no
   door will route around the wall.
4. **The core stays platform-neutral.** `scripts/core/` must not import or
   assume anything Claude-specific. Platform knowledge lives in thin adapters
   (`scripts/claude/`, future `scripts/codex/`, `scripts/cursor/`).
5. **No new runtime dependencies.** The plugin must run on a stock Python
   3.9+ install. Optional tools (PyYAML, pandoc, openpyxl) may improve
   behavior when present but never be required.

## Getting started

```bash
pip install pytest
python3 -m pytest tests/
```

The suite runs in a few seconds with no network and no third-party packages
beyond pytest. All tests must pass; new behavior needs new tests.

## What kind of tests to write

- **New command/bypass patterns** go in `tests/test_bypass_corpus.py`. The
  corpus is the specification: an entry asserts the engine resolves it to
  deny or ask. If you found a bypass, add the exact command line that slipped
  through, then fix the engine until the test passes. Benign commands that
  must never be blocked go in the `BENIGN` list.
- **Engine rules** (zones, guards, redirects) go in `tests/test_engine_rules.py`.
- **Hook behavior** (the actual subprocess contract, including crash-fails-
  closed) goes in `tests/test_adapter.py`.
- **Store/CLI behavior** goes in `tests/test_store_agw.py`. Tests run with
  `AGW_HOME` pointed at a tmp dir by the autouse fixture; never touch the
  real `~/.agw`.

## Reporting a bypass

A command or content pattern that gets through the guardrails is the most
valuable contribution there is. Open an issue with the exact input, the
decision you got, and the decision you expected, or just send a PR adding it
to the bypass corpus. If the bypass has serious data-destruction potential on
default installs, email joseph@synapticlabs.ai instead of filing it publicly.

## Adding policy rules

Rule packs are YAML in `policies/` (see `core.yaml` and
`content-rules.d/examples.yaml` for the shapes). Keep org-specific or
niche rules in drop-ins rather than `core.yaml`; core ships to everyone, so
it should only contain rules that are near-universally correct. Remember the
YAML must parse under `scripts/core/miniyaml.py` too, since PyYAML may be
absent; run the tests to confirm.

## Adding a platform adapter

1. Create `scripts/<platform>/` that maps the platform's hook/extension events
   into `core.events.ToolEvent` and maps `Decision` back into the platform's
   response format.
2. Honor the fail-closed contract in the adapter's top-level handler.
3. Mirror `tests/test_adapter.py` with golden subprocess tests for the new
   adapter.
4. Do not fork the engine. If the engine is missing something a platform
   needs, extend `ToolEvent`/`Decision` neutrally.

## Style

- Python, standard library only, readable over clever. Match the existing
  code's comment density (sparse; comments explain constraints, not syntax).
- Keep modules small and single-purpose; the parser, engine, store, and
  adapters stay separate.
- Skill and command markdown should tell the agent what to do and why the
  rule exists; agents follow rules better when the reason is one line away.

## Releases

Bump `version` in `.claude-plugin/plugin.json` and `metadata.version` in
`.claude-plugin/marketplace.json` together. Changes to hook wiring or
managed-settings templates should be called out prominently in release notes,
since enterprise deployments pin them.
