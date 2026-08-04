# Trusted write workflows

Trust seals script/manifest hashes, arguments, and outputs locally; repository
manifests remain inert until approved. V2 is exact; v3 adds typed slots:

```json
{"schema":"agw.workflow/v3","id":"org.example.load",
 "command":{"runtime":"python","script":"load.py","script_sha256":"SHA256",
 "args":["--profile",{"parameter":"profile"},"--read-only"]},
 "parameters":{"profile":{"type":"enum","values":["alpha","beta"]}},
 "allowed_roots":["{cwd}/state"],
 "outputs":[{"path":"{cwd}/state/marker.json","expected":"any"}]}
```

Run `agw run --workflow org.example.load --param profile=alpha`. Repeat
`--param`; missing, unknown, duplicate, invalid, moved, or extra values fail
before execution. Explicit commands must match every trusted slot.

Types: reviewed `enum`; hash-bound UTF-8 `enum-file` (`lines`/`json-array`);
bounded `regex`; ranged canonical `integer`; and literal `path` under `root`.

Templates support `{param:NAME}` plus `:basename`/`:sha256`; existing path and
`{arg:N}` forms remain. Parameters cannot widen roots. `{temp}` is compiled into
machine-local trust, not re-read from the execution environment.

`"optional":true` lets an absent output stay absent; existing files remain
protected. Observed roots cover ephemeral sidecars without unknown pre-images.

`expected`: `any`, `absent`, `present`, or SHA-256. No code is evaluated.
Tampering, drift, wildcards, duplicates, traversal, and ambiguity fail closed.
V1 remains readable but unbound; v2 remains exact. Keep `AGW_HOME` private and
outside synced folders. Its seal is not an OS sandbox.
