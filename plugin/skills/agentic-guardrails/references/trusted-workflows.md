# Trusted write workflows

Use this for a reviewed Python, Node, or PowerShell script with deterministic
outputs. Repository manifests are inert until an explicit, user-confirmed trust.

1. Review its script hash, roots, exact outputs, and patterns.
2. Run `agw workflow trust MANIFEST --expected-manifest-hash HASH
   --approve-trust`.
3. Run `agw run --workflow ID -- COMMAND ARGS`. Direct execution stays blocked.

## Manifest v1

```json
{
  "schema": "agw.workflow/v1",
  "id": "org.example.recall",
  "description": "Deterministic state update",
  "command": {
    "runtime": "python",
    "script": "scripts/recall.py",
    "script_sha256": "SHA256"
  },
  "allowed_roots": ["{script_dir}/../state"],
  "outputs": [
    {"path": "{script_dir}/../state/{arg:0:sha256}.json", "expected": "absent"},
    {"path": "{script_dir}/../state/memory.db", "expected": "present"}
  ],
  "observed_roots": [
    {"path": "{script_dir}/../state", "patterns": []}
  ]
}
```

Placeholders: `{cwd}`, `{script_dir}`, `{script_name}`, `{script_stem}`,
`{arg:N}`, `{arg:N:basename}`, `{arg:N:sha256}`. Roots cannot use arguments.
`expected` is `any`, `absent`, `present`, or a SHA-256. No code is evaluated.

Exact existing outputs get pre-images; absent ones get tombstones before launch.
Tampering, script drift, ambiguity, traversal, and out-of-root paths fail closed.
Observed roots are bounded post-run detection, not prevention or recovery.

Professor Synapse and similar tools should declare their marker, database,
sidecars, and temp file. Random names need explicit arguments or deterministic
placeholders; directory diffs are not recovery.

The machine-local seal is not an OS sandbox: a process able to replace its key
and records can forge trust. Keep `AGW_HOME` private and outside synced folders.
