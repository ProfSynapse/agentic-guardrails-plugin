# Trusted write workflows

Use v2 for reviewed Python, Node, or PowerShell scripts with deterministic
arguments and outputs. Repository manifests stay inert until user-confirmed trust.

1. Generate: `agw workflow init --help` (hashes the script and escapes Unicode).
2. Check: `agw workflow validate MANIFEST --json`.
3. Review and trust with the exact manifest hash: `agw workflow trust --help`.
4. Run without restating the command: `agw run --workflow ID`.
5. On another machine, use `agw workflow status MANIFEST` before running.

```json
{
  "schema":"agw.workflow/v2",
  "id":"org.example.index",
  "description":"Rebuild one index",
  "command":{"runtime":"python","script":"scripts/index.py",
    "script_sha256":"SHA256","args":["--output","state/index.md"]},
  "allowed_roots":["{cwd}/state"],
  "outputs":[{"path":"{cwd}/state/index.md","expected":"present"}],
  "observed_roots":[]
}
```

Arguments are exact and hash-bound with the manifest. Supplying different or
extra arguments fails closed. V1 remains readable for compatibility but does not
bind arguments; migrate reusable workflows with `workflow init`.

Placeholders: `{cwd}`, `{script_dir}`, `{script_name}`, `{script_stem}`,
`{arg:N}`, `{arg:N:basename}`, `{arg:N:sha256}`. Roots cannot use arguments.
`expected` is `any`, `absent`, `present`, or a SHA-256. No code is evaluated.

Exact outputs get pre-images/tombstones. Observed roots only detect later
changes; patterns are not pre-imaged. Tampering, script drift, wildcards,
ambiguity, traversal, and out-of-root paths fail closed. Keep machine-local
`AGW_HOME` private and outside synced folders; its seal is not an OS sandbox.
`--progress` reports trust phases; lock wait is 10s. Reads on a stalled virtual
filesystem are not yet hard-bounded.
