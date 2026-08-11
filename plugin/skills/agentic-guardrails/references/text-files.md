# Text files

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
