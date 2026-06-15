# Releasing

This plugin is distributed through its own repo acting as a marketplace
(`.claude-plugin/marketplace.json`). Installs are **pinned to a git tag**, so
`main` can move freely without changing what users get — they only update when
a new tag is published and the marketplace entry points at it.

## Why versioning matters

Claude resolves a plugin's version from the first of:

1. `version` in `.claude-plugin/plugin.json`
2. `version` in the plugin's `marketplace.json` entry
3. the git commit SHA of the plugin's source

Because (1) is set, **pushing commits without bumping `version` does nothing for
installed users** — Claude sees the same version and keeps the cached copy. Every
release must bump the version.

## Cut a release (e.g. 0.2.0 → 0.3.0)

1. Land your changes on `main` and run the tests:

   ```bash
   python3 -m pytest tests/
   ```

2. Bump the version in **both** files to the new number (keep them in sync):
   - `.claude-plugin/plugin.json` → `"version": "0.3.0"`
   - `.claude-plugin/marketplace.json` → the plugin entry's `"version"` **and**
     `source.ref` → `"v0.3.0"`

3. Commit:

   ```bash
   git add .claude-plugin/plugin.json .claude-plugin/marketplace.json
   git commit -m "Release v0.3.0"
   git push origin main
   ```

4. Tag and publish a GitHub release (the tag is what `source.ref` resolves to):

   ```bash
   gh release create v0.3.0 --title "v0.3.0" --notes "..."
   ```

   The tagged commit must contain the version bump above. Order matters: push the
   release commit to `main` first, then tag it.

## How users update

```
/plugin marketplace update synaptic-guardrails
/plugin install agentic-guardrails@synaptic-guardrails
```

`marketplace update` re-reads `marketplace.json` from `main` (which now points at
the new tag); `install` fetches the plugin contents at that tag. Optionally,
fleets can set `"autoUpdate": true` on the marketplace in managed settings.

## Notes

- The marketplace **catalog** (`marketplace.json`) is read from the default branch
  (`main`) HEAD. The plugin **contents** are read from the pinned `source.ref` tag.
  So the catalog on `main` is your release pointer; the tag is the frozen payload.
- Claude reads the git repo contents at the ref — it does **not** read GitHub
  Release notes/assets. The GitHub release is for humans and to create the tag.
- Use annotated, immutable tags. Don't move a published tag; cut a new version.
