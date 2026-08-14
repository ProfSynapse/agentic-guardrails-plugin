# Trusted workflows

Trust seals a script hash, arguments, outputs, and provenance locally; repo
manifests stay inert until approved. V2 is exact; v3 adds typed parameters.

Run `agw workflow match -- <command>` first. JSON reports stable mismatch codes;
one exact match may route, while ambiguity stays explicit. Proposals are inert.

Records retain manifest, contract, script, source-label, and approval
provenance. One compressed UTF-8 script snapshot is embedded in the sealed
record (128 KiB maximum) and replaced on refresh. Oversized/non-UTF-8 scripts
stay hash-bound but require full retrust.

For legitimate script drift:

```text
agw workflow refresh-plan ID --plan-file refresh.json
agw workflow refresh refresh.json --expected-plan-hash SHA256 --approve-refresh
```

Plans expire after 30 minutes and bind the trust seal, source, and bounded
diffs. Apply requires an unchanged contract and reviewed source. Drift, replay,
or contract changes fail closed; use `workflow trust --replace` for contracts.

`agw workflow export ID` reconstructs an inert manifest, including legacy
records; add `--output FILE --expected-file-hash absent` for guarded output.
Legacy records need one explicit retrust before refresh.

V3 parameters support enum, hash-bound enum files, regex, integers, and rooted
literal paths. Run with repeated `--param name=value`; parameters cannot widen
roots.

Outputs may be optional. `expected` is `any`, `absent`, `present`, or SHA-256.
Observed roots cover sidecars without pre-images. No manifest code is evaluated;
tampering, drift, wildcards, traversal, duplicates, and ambiguity fail closed.
Keep `AGW_HOME` private and unsynced: its seal is not an OS sandbox.
