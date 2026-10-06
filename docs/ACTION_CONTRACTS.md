# Native action contracts (experimental)

This prototype borrows OpenAPPA's explicit tool contracts and per-action human
attention model. It is an independent Python implementation, with no copied
upstream code, new runtime dependencies, or APPA service.

Design references reviewed at OpenAPPA commit
`c7c1e1ef36aa07604b421c48be266d7397557656`:
- https://www.openappa.com/contracts
- https://www.openappa.com/add-to-agent

## Scope

The engine evaluates contracts for structured MCP events on the existing Claude
and Codex adapter paths. The feature is off unless a policy pack supplies
`settings.action_contracts`. It does not alter ordinary native file editing.

A contract never grants permission or bypasses another guard. Its result merges
with the existing decision, with the strongest restriction winning. Contract
review/denial requirements survive observe mode. A contract cannot grant itself
authority through tool input. Policy configuration is trusted administrative
input, not data supplied by the agent's tool arguments.

## Example (synthetic tools only)

A JSON custom policy pack can contain:

```json
{
  "settings": {
    "action_contracts": {
      "version": 1,
      "unmatched": "deny",
      "tools": {
        "mcp__fixture__lookup": {
          "effect": "read",
          "required": ["id"],
          "arguments": ["id"]
        },
        "mcp__fixture__dispatch": {
          "effect": "send",
          "required": ["to", "body"],
          "arguments": ["to", "body"]
        }
      }
    }
  }
}
```

Do not copy this into a live policy without enumerating the intended tool surface.
`unmatched: deny` blocks **all unmatched MCP tools**, including otherwise harmless
ones. `defer` retains existing behavior outside explicitly named tools and therefore
does not establish complete mediation.

Names match exactly and are case-sensitive; wildcard contracts are rejected.
Missing required arguments and extra top-level arguments deny. Argument values
are not semantically validated by this envelope check.

Effects:
- `read`, `draft`, `edit`: no additional restriction; existing policy still applies.
- `send`, `share`, `publish`, `admin`: fresh human review.
- `blocked`: deny.

Unknown fields, versions, effects and malformed contracts are errors. Loader
validation marks a malformed pack degraded; cached settings are also validated.

Fresh review propagates through decision merging, clears resource approval
memory keys, and disables approval de-duplication even for an identical host
event ID. Existing operation fingerprints bind review to tool arguments, working
directory, modeled events and policy revision.

## Current limitations / release gates

- The Linux native approval provider is unavailable. Codex denies review-required
  calls without a working provider. The optional terminal reviewer is described in LINUX_REVIEW.md; it is not deployed or verified between real accounts.
- Existing prompts summarize connector targets; hashing the complete operation
  does **not** prove that a human saw its complete recipients, body, attachments
  or effect. A reviewed exact-action display and transport are prerequisites for
  enabling consequential actions.
- Fresh per-invocation review is not a durable, single-use execution ticket.
  Exactly-once dispatch/replay protection needs a broker that owns execution.
- There is no information-flow ledger or audience/trust propagation yet.
- Shell, browser clicks, computer use, implicit reads, nested tool coverage and
  remote devices are not confined by these MCP contracts.
- A same-user agent able to edit policy, hooks or credentials can bypass this
  layer. OS separation and broker-owned credentials remain separate work.
- No live policy pack is installed by this change. Source tests do not prove
  full enforcement in any particular host.

## Validation

`tests/test_action_contracts.py` uses fake tools and isolated temporary policy
packs. It covers contract validation, exact tool matching, argument-envelope
failures, preservation of deletion denials, observe-mode behavior, fresh review,
argument/policy fingerprint changes, policy cache reload, malformed packs, and
actual Codex adapter subprocess responses without an approval channel.

No email, publishing, sharing or remote-administration operation is executed.
