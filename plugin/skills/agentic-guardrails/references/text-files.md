# Text files

For an exact substitution, read the relevant page once, then replace using its
`sha256` as `--expected-hash`:

```sh
agw file read PATH --start-line 1 --limit 100 --json
agw file replace PATH --old 'old text' --new 'new text' --expected-hash SHA256 --json
```

Use literal target paths and actual returned hashes. `replace` requires exactly
one match unless `--all` is explicitly requested. It checks the hash, captures
recovery, and verifies the published bytes before returning `after_hash` and
`recovery`. A simple exact substitution needs no separate dry-run or reread
solely to repeat those checks. Preview uncertain edits; inspect the result when
the requested outcome needs additional semantic verification. For multiline or
quote-heavy text, use `--old-file` / `--new-file` instead of inline payloads.

Keep the returned `recovery.undo_argv` for a later undo; see
[recovery](recovery.md). An explicit undo of this change can use that receipt
directly, without rediscovering history or rereading the target first.

Choose the operation by target state and edit shape:

- New file: `agw file write PATH --content-file STAGED --expected-hash absent`.
  Its parent directory must already exist. Create each missing parent with a
  separate literal, exact-target directory command before writing the file.
- Existing file, one or a few exact substitutions: prefer `agw file replace`.
- Existing file, structured changes: use `agw file patch` with a standard
  unified diff. Every hunk needs line ranges such as `@@ -12,2 +12,3 @@`.
  A bare `@@` is `apply_patch` shorthand, not unified-diff syntax, and is
  invalid. Validate with `--dry-run` before applying.
- Several dependent text files: use `agw file plan`, retain its exact plan hash,
  then use `agw file apply-plan`.

A minimal valid patch is:

```diff
--- a/note.md
+++ b/note.md
@@ -1 +1 @@
-old text
+new text
```
