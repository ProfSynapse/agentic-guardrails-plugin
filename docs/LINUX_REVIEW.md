# Linux human review (experimental, not deployed)

The optional `linux-socket` approval provider sends the complete canonical tool
request to a foreground terminal owned by a **different Unix account**. The
owner sees the tool, working directory, submitted arguments, modeled events,
and policy revision, then types a request-specific approval phrase.

Both peers check Linux SO_PEERCRED. Same-UID review is refused. The abstract Unix
socket has no TCP listener or filesystem socket permissions to relax. A wrong
peer, absent server, missing host session/event identity, expired request,
malformed reply, changed fingerprint or unanswered prompt denies.

An owner-private SQLite ledger atomically claims (worker UID, session ID, event
ID) before review. Approved, declined and interrupted requests cannot be replayed,
including after restart. A grant is committed as consumed before responding.
The ledger stores identities, fingerprints and states, not message content.

## Scope and limits

This is **single-use approval issuance**, not exactly-once tool execution. The
host still dispatches its own tool after approval. Runtime-enforced execution
tickets or a broker that owns the consequential API call remain required for a
strong dispatch guarantee.

The terminal shows all submitted JSON arguments, escaping terminal control
characters. A file path or remote object ID does not reveal the corresponding
file contents. Mutable attachments, remote state and dynamic tool effects need
snapshot/hash binding or broker-side validation before live use.

Policy, hook code and reviewer configuration must be outside the worker's write
authority. Credentials that can send/publish/administer must also be held outside
the worker. Without these restrictions the worker can bypass the hook entirely.
Owner-desktop computer control must not give the worker access to the review
terminal. Information-flow tracking and browser/shell confinement remain future
work.

The server is bounded to 256 KiB wire messages, 10 seconds for incoming framing,
100 seconds maximum review, and 10,000 ledger entries. Partial messages have an
absolute receive deadline. Capacity exhaustion denies; records must not be
silently deleted to re-enable old events. Use a deliberate session/ledger
rotation policy before a long-running deployment.

## Operator setup (plan; never point an agent at a reviewer it controls)

1. Create the unprivileged worker account. Keep it out of sudo/docker/lxd.
2. Prepare owner-controlled plugin/policy copies and an owner-only ledger
   directory (0700). Do not copy owner OAuth, SSH or browser credentials into the
   worker home. File access grants and a separate pilot service need their own
   review; creating the account does not move existing agent services.
3. In an owner terminal, from the installed plugin's `scripts` directory:
   `python3 -m core.linux_review --name synaptic-review --worker-uid WORKER_UID --ledger OWNER_PRIVATE_DIRECTORY/reviews.sqlite`
   The command requires an interactive terminal and a private ledger location.
   Ctrl-C closes the service; pending callers cannot obtain approval.
4. Configure only the pilot worker with `AGW_APPROVAL_PROVIDER=linux-socket`,
   `AGW_REVIEW_SOCKET=synaptic-review`, and `AGW_REVIEWER_UID=OWNER_UID`.
   Protect this configuration and the execution boundary against worker changes.
5. Exercise synthetic calls from the real worker account. Verify displayed
   content, approve/decline, expiry, disconnect, wrong UID, replay and altered
   arguments. Do not activate live send/share/admin tools based on unit tests.

No server, environment override, service switch or account permission change is
performed by adding this source. An agent running as the reviewer's own account cannot review itself
through this provider.

## Test evidence and remaining gates

`tests/test_linux_review.py` exercises the actual Linux peer-credential API and
same-account refusal. Successful client transport tests simulate the different
reviewer UID; they are **not** a real two-account integration test. Ledger tests
cover decline, crashes, restart, replay, changed payloads, expiry and content
minimization. Framing tests cover duplicate keys, non-finite numbers, oversized
messages and slow partial input.

The first related regression selection passed 351 tests with 40 skips.
Run tests in fresh, narrow temporary directories. The previous aggregate
artifact directory exceeded 20,000 entries; do not widen the observer or scan
/tmp or home. Pytest's generated fixture artifacts are currently reported as
unclaimed by `agw run`; passing pytest is not a clean declared-output inventory.
A reviewed fixture-output workflow remains a separate runner improvement.
