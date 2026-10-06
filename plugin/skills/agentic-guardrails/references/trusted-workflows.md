# Trusted workflows

Trust seals a script hash, arguments, outputs, and provenance locally; repo
manifests stay inert until approved. V2 is exact; v3 adds typed parameters.

Run `agw workflow match -- <command>` first. One exact match may route;
ambiguity stays explicit. Proposals are inert.

Records keep manifest, contract, script, source and approval provenance, plus
one compressed script snapshot (128 KiB max) replaced on refresh.

For legitimate script drift:

```text
agw workflow refresh-plan ID --plan-file refresh.json
agw workflow refresh refresh.json --expected-plan-hash SHA256 --approve-refresh
```

Plans expire after 30 minutes. Contract changes fail closed; use
`workflow trust --replace`. `agw workflow export ID` rebuilds an inert manifest.

V3 parameters: enum, hash-bound enum files, regex, integers, rooted paths (an
optional `pattern` matches the path under its root). Pass `--param name=value`.

`limits.timeout_seconds` (1-14400) is a reviewed run time limit; otherwise 300.
`--timeout-seconds` only shortens. Long runs: host background mode.

Outputs may be optional; `expected` is `any`, `absent`, `present`, or SHA-256.
Observed roots (v3: a directory path parameter) inventory sidecars without
pre-images. Tampering, drift, wildcards, traversal and ambiguity fail closed.
Keep `AGW_HOME` private and unsynced: its seal is not an OS sandbox.
