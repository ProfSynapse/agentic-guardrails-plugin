# Trusted write workflows

Trust seals hashes, arguments, and outputs locally; repo manifests stay inert
until approved. V2 is exact; v3 adds typed slots:

Run `agw workflow match -- <command>` first. One exact match may route;
multiple matches stay explicit. JSON explains mismatches; proposals are inert.

```json
{"schema":"agw.workflow/v3","id":"org.example.load",
 "command":{"runtime":"python","script":"load.py","script_sha256":"SHA256",
 "args":["--profile",{"parameter":"profile"},"--read-only"]},
 "parameters":{"profile":{"type":"enum","values":["alpha","beta"]}},
 "allowed_roots":["{cwd}/state"],
 "outputs":[{"path":"{cwd}/state/marker.json","expected":"any"}]}
```

Run `agw run --workflow org.example.load --param profile=alpha`. Repeat
`--param`; invalid, moved, missing, duplicate, or extra values fail before run.

Types: `enum`; hash-bound UTF-8 `enum-file`; bounded `regex`; ranged canonical
`integer`; and literal `path` under `root`.

Templates support `{param:NAME}` plus `:basename`/`:sha256`, paths, and
`{arg:N}`. Parameters cannot widen roots. `{temp}` is sealed locally.

`"optional":true` lets an absent output stay absent; existing files stay
protected. Observed roots cover sidecars without pre-images. Executed JSON lists
equal pre/post exact paths in `unchanged_outputs` and pattern-suppressed changes
plus match evidence in `ignored_sidecar_changes`. Unchanged does not prove
untouched; a required absent output is also missing.

`expected`: `any`, `absent`, `present`, or SHA-256. No code is evaluated.
Tampering, drift, wildcards, duplicates, traversal, and ambiguity fail closed.
V1 stays readable but unbound. Keep `AGW_HOME` private and unsynced; its seal is
not an OS sandbox.
