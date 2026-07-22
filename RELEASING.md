# Releasing

Published builds are distributed through `.claude-plugin/marketplace.json` and
must be pinned to an immutable git tag. A release candidate may temporarily use
`source.ref: main` while it is being validated; that is a candidate pointer,
not a published immutable release.

## Why versioning matters

The following distributable versions must remain identical:

1. `plugin/.claude-plugin/plugin.json`
2. `plugin/.codex-plugin/plugin.json`
3. the plugin entry in `.claude-plugin/marketplace.json`

Because (1) is set, **pushing commits without bumping `version` does nothing for
installed users** — Claude sees the same version and keeps the cached copy. Every
release must bump the version.

## Release gate for `0.3.0-rc.2`

1. Keep `source.ref` on `main` while validating. Never point it at
   `v0.3.0-rc.2` before that tag exists.

2. Confirm all three versions are `0.3.0-rc.2`, then run:

   ```bash
   python -m pytest -q
   python -m pytest -q tests/test_packaging.py tests/test_host_conformance.py
   ```

   For the Windows-first `0.3.0-rc.2` field test, Windows CI and the packed-
   artifact tests are release-blocking. Linux and macOS remain in the matrix as
   advisory preview signals; failures there must be documented but do not block
   committing or locally installing this RC. Equivalent Linux/macOS validation
   is required before promoting the candidate to stable `0.3.0`.

   Windows must use explicit literal shards rather than a monolithic pytest
   step. The workflow's timeout values are hard failure caps, not expected
   runtimes: 10 minutes for packed-artifact tests, 8 minutes for adapters and
   broader engine/store groups, and 5 minutes for the no-persistence and small
   presentation/host-contract groups. Collection reconciliation must show every
   default test module in exactly one Windows shard.

   The no-persistence activity-history gate is mandatory. `core.auditlog` must
   return the fixed successful `host-history` status without creating or reading
   files, starting subprocesses, invoking permission helpers, or importing the
   experimental v2 module. Existing legacy ledger/quarantine bytes and paths
   remain untouched. Twenty complete fresh hook subprocesses—ten Claude and ten
   Codex—must exit normally with p95 below two seconds. The authoritative
   `.plugin-pack` allowlist and a freshly copied artifact must both exclude
   `scripts/core/auditlog_v2.py` while retaining `scripts/core/auditlog.py`.

   Claude and Codex manifests must dispatch only through their host-provided
   plugin root; cache, adjacent-repository, and `PYTHONPATH` fallbacks are release
   blockers. On Windows, run the packed `bin\agw.cmd` gate with a clean PATH
   containing only the selected Python directory and Windows System32. No hook,
   SessionStart adapter, installer, or launcher may persistently modify user or
   machine PATH.

   Windows hook commands must use `py.exe -3` with the host-provided plugin
   root. A bare `agw.cmd` is never trusted by basename: tests must prove its
   resolved origin is exactly the packaged launcher and that a workspace or
   PATH shim receives no Guardrails privileges. Monitor coverage validates only
   the documented literal `tool_input.command` normalization contract; do not
   describe it as a live-host probe.

   Approval-copy tests must cover the maintained prompt families using only
   closed rule/context mappings and safe category/count labels. Raw commands,
   detailed paths, free-form reasons, exceptions, and audit canaries must never
   appear. Native buttons are `Allow once` and `Cancel (recommended)`, with
   cancel as the default and copy stating that cancel makes no changes.

   Recursive credential-keyword searches are ordinary diagnostics only when
   their static scope is verified inside project source, tests, documentation,
   plans, logs, or the project root and the operation is read-only. Outside,
   cloud, home, credential-file, redirected, dynamic, and changing forms must
   retain their protection for both hosts and packed artifacts.

   Lifecycle documentation must identify Claude/Codex task history as the human
   activity log. Reports use only existing CRUA recovery, checkout, and policy
   metadata; they never inspect legacy audit/quarantine data or reconstruct raw
   commands. Unavailable command-level metrics are disclosed plainly.

   Automated tests verify the activation context, API signatures, packaged
   manifest, cleanup, button mapping, and sanitized errors. They cannot visually
   certify an interactive Windows dialog. After code acceptance, QA must run
   exactly one manual smoke (not during automated implementation):

   ```powershell
   python tests/manual_windows_approval_smoke.py --i-understand-this-opens-a-dialog
   ```

   Confirm native styling, the three exact headings, `Allow once`, default
   `Cancel (recommended)`, and no duplicated action. Close or cancel the test-only dialog; the
   script performs no underlying operation.

3. Commit and push the verified candidate. Do not tag an unverified tree.

   ```bash
   git add plugin .claude-plugin/marketplace.json docs/HOST_PARITY.md RELEASING.md .github/workflows/conformance.yml
   git commit -m "Release candidate v0.3.0-rc.2"
   git push origin main
   ```

4. Create the immutable tag from that exact verified commit:

   ```bash
   gh release create v0.3.0-rc.2 --target <verified-commit-sha> \
     --title "v0.3.0-rc.2" --prerelease --notes "..."
   ```

5. Verify the tag resolves to that commit. Only then change `source.ref` from
   `main` to `v0.3.0-rc.2`, rerun JSON and artifact conformance, and commit/push
   the catalog pointer update. This tag-exists gate is mandatory.

## How users update

```
/plugin marketplace update synaptic-guardrails
/plugin install agentic-guardrails@synaptic-guardrails
```

`marketplace update` re-reads `marketplace.json` from `main`; after step 5 it
points at the verified tag. `install` fetches the plugin contents at that tag. Optionally,
fleets can set `"autoUpdate": true` on the marketplace in managed settings.

## Notes

- The marketplace **catalog** (`marketplace.json`) is read from the default branch
  (`main`) HEAD. The plugin **contents** are read from the pinned `source.ref` tag.
  So the catalog on `main` is your release pointer; the tag is the frozen payload.
- Claude reads the git repo contents at the ref — it does **not** read GitHub
  Release notes/assets. The GitHub release is for humans and to create the tag.
- Use annotated, immutable tags. Don't move a published tag; cut a new version.
