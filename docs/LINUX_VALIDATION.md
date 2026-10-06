# Linux validation and deployment boundaries

## Validation performed 2026-10-04

Ubuntu 26.04, Python 3.14, Codex CLI 0.160.0 and Claude Code 2.1.285.
Baseline source: `7a71da4bc2d44750b565af080a6693319cacdb1e` (version 0.5.0).
Tests used isolated temporary recovery stores and synthetic inputs. No remote
shell commands, connector sends or destructive host operations were executed.

- Baseline suite: **1,788 passed, 56 skipped**. Windows-only cases and optional
  integrations remain unverified on that machine.
- Additional probes: shell and apply-patch deletion denied; `git status`
  deferred to the host; connected-service send denied without an approval
  provider. Fixture contents remained intact.
- Missing-adapter startup emitted `ask`, inconsistent with Codex's enforcement
  contract. Three new subprocess regressions reproduced the defect for missing,
  import-failing and syntax-invalid adapters before the fix. The dispatcher now
  emits `deny`; nonblocking lifecycle events remain nonblocking.
- Focused post-fix adapter, lifecycle and packaged-artifact suites:
  **271 passed, 39 skipped**.

These results establish source/adapter behavior, not live host enforcement.
Versions up to 0.5.0 do not contain the dispatcher fix; it ships in 0.6.0.

## Remaining deployment gates

1. Install a reviewed release containing the dispatcher fix. Trust its hooks
   through the host's supported UI. Do not synthesize trust records or bypass
   trust to declare a deployment verified.
2. Start a fresh task. In a disposable fixture, verify a real shell deletion
   and apply-patch deletion are blocked, safe status reads work, and archive /
   restore succeeds. Check native exec, stdin, connectors and any nested tool
   orchestrator exposed by that host. Record the observed event names.
3. Validate failure behavior for missing Python, timeout, malformed hook output
   and hook process failure. A Python dispatcher cannot protect a call if it
   never starts or the host ignores its output.
4. Provide a supported remote-human approval mechanism for Linux before
   expecting Codex ASK operations to be usable. The current Windows-only
   native provider returns `provider-unavailable` on Linux. Keep denial intact;
   do not weaken enforcement or preapprove requests as a workaround.

The manifest does not explicitly match `functions.exec`. Passing that tool
directly to the adapter denies as unrecognized, but this proves nothing about
whether the host invokes hooks on nested calls. Verify interception of the
underlying operations on the actual host before making a coverage claim.

## Boundaries outside the plugin

The default engine deferred synthetic `ssh example.invalid true`, `docker ps`
and an opaque connector `request` carrying a POST. None was executed. Ordinary
SSH use and unknown connector verbs are not a default-deny capability boundary.
Do not infer safety from a tool name alone; a generic request API needs typed
operation restrictions or host/provider authorization outside the model.

Use an isolated worker identity with no administrative groups, rootful Docker
socket, SSH agent, owner credentials or writable policy installation. Expose
only the current task's files and needed services. Keep runtime and policy
updates under an administrator identity. Same-user mode bits and editable
instructions do not isolate an agent from its owner's authority.

Enforce directional network access independently: operator devices may reach
the worker service; workers do not receive general access back to those devices.
Account for both overlay and LAN routes. Sync is a separate write path: editing
a local synced vault can modify every device even without remote execution.
Use read-only source mirrors plus isolated worktrees, and a separately authorized
publication step when that distinction matters.

Read-only Drive/email access still permits disclosure. Scope retrieval, withhold
send/share/delete capabilities, and separate sensitive reading from arbitrary
network egress. Local read-only mounts do not constrain cloud connectors or
browser sessions. Snapshots support recovery; they do not enforce access.

Sources: [Codex hook contract](https://learn.chatgpt.com/docs/hooks),
[Tailscale grants](https://tailscale.com/docs/reference/syntax/grants),
[Docker privilege warning](https://docs.docker.com/engine/install/linux-postinstall/).
