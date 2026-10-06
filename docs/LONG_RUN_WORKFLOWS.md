# Long-running generators and shell wrappers

This note records what changed so that legitimate long-running, file-writing
work (for example Remotion renders in Synaptic Studio) can run through
Guardrails directly, and why each relaxation keeps the safety model intact.

## 1. Reviewed run time limit (`limits.timeout_seconds`)

`agw run` kills a command's process tree at 300 seconds. That default is
unchanged for every run that is not a trusted workflow.

A v2 or v3 workflow manifest may declare:

```json
"limits": {"timeout_seconds": 7200}
```

- Range: whole seconds, 1 to 14,400 (4 hours, `MAX_WORKFLOW_TIMEOUT_SECONDS`
  in `plugin/scripts/core/workflows.py`). v1 manifests cannot declare limits.
- `agw run --workflow ID` uses it, and so does the hook's automatic
  trusted-workflow routing, which goes through the same `cmd_run` path
  (`_run_timeout` in `plugin/scripts/agw/agw.py`).
- `--timeout-seconds` can only shorten the bound that applies: 300 seconds for
  an unreviewed run, or the workflow's reviewed limit. It used to be a hidden
  flag that accepted up to 24 hours for any run, which would have made a
  reviewed limit meaningless.
- JSON output reports `execution_policy.timeout_seconds` and
  `execution_policy.timeout_source` (`default`, `workflow` or `explicit`).

Why this is safe: the limit is part of the manifest that `agw workflow trust`
hashes and seals. Raising it changes the manifest hash. Trust then refuses to
replace the existing record without `--replace`, the host asks before any trust
(`builtin:agw-workflow-trust`), editing the stored record breaks its HMAC seal,
and the script-only refresh path cannot change it because it is part of the
contract hash. Manifests without `limits` normalize exactly as before, so
records trusted earlier remain valid. The time limit does not affect output
tracking: pre-images, inventory and recovery are the same for a run of any
length.

Host note: the Claude Code Bash tool has its own timeout (10 minutes at most).
Start a run longer than that with the host's background mode.

## 2. Output roots for generators

These parts were already in place: exact outputs (`outputs[].path`, which may
use `{param:NAME}`) get verified pre-images, and `observed_roots` with relative
`patterns` inventory incidental files as `ignored_sidecar_changes`. Any other
change under an observed root is reported as unclaimed and fails the run.

Two narrow additions:

- **Per-run observed root.** In a v3 manifest, `observed_roots[].path` may use
  `{param:NAME}` when NAME is an unmodified `path` parameter of kind
  `directory` or `any`. The parameter value is already confined to its reviewed
  root, and `resolve_run` still rejects a resolved observed root outside
  `allowed_roots`. One workflow can then serve many project folders without
  observing their whole parent, which is slow, can hit the 20,000-path and
  5-second observation bounds, and widens what counts as a sidecar.
- **Path parameter `pattern`.** A `path` parameter may carry a `pattern`. The
  value's path relative to its resolved root (with `/` separators, after
  realpath) must fully match it, for example
  `[a-z0-9][a-z0-9-]*/renders/[A-Za-z0-9][A-Za-z0-9._-]*[.]mp4`. The same
  safe-regex rules as for regex parameters apply. A pattern can only narrow
  what the root already allows.

Recovery semantics are unchanged. Pattern-matched sidecars are inventoried but
get no pre-image, so anything that must be restorable has to be an exact
output.

## 3. Launcher recognition for safe shell wrappers

Only a leading `agw` used to be expanded to the packaged launcher. Every later
`agw` reached the shell as a bare PATH lookup and was refused as
`builtin:agw-impostor`. `posix_launcher_plan()` in
`plugin/scripts/core/launcher.py` now finds literal `agw` words in POSIX
command positions:

- at the start of the command
- after `;`, `&&`, `||`, `|`, `&` or a newline
- after `do`, `then`, `else`, `elif`, `if`, `while`, `until`, `!` or `time`

The adapter rewrites each of these to the exact packaged path. That covers:

- `cd <literal> && agw ...`
- several `agw` calls joined by `;` or newlines
- `for` loops with `${r%-*}` or `set -- $r`
- a stray `VAR=...` line
- `agw ... | tail -40` and other pipes, including `... | agw file write --content-stdin`

Why this is safe: the rewrite removes the PATH lookup completely. Alias names
cannot contain `/`, and bash does not look up functions for a command name that
contains `/`, so the absolute path always runs the packaged launcher. The plan
refuses to vouch, and leaves the bare word for the engine to deny, when the
same line could change what a later word or the launcher's environment
resolves to:

- `alias`, function definitions, `export`, `declare`, `hash`, `source`, `.`,
  `eval`, `exec`, `trap`, or `set` (except `set --`)
- assignments to `PATH`, `PYTHON*`, `LD_*`, `AGW_*`, `HOME`, `IFS`, `BASH_ENV`
  and similar names
- a prefix assignment on the launcher itself
- command or process substitution, subshells, groups, heredocs or `case`
- any `cd` other than one leading `cd <literal> &&`

Two related engine changes harden launcher checks:

- A bare `agw` is no longer trusted through the hook's own PATH lookup when
  the same line redefines it or changes its environment.
- A launcher name that only appears through `$(...)`, backticks, a variable
  head or `eval` is denied as `builtin:agw-impostor`. Before, it was allowed
  as an indirect command with no mutation evidence.

Commands that start with the accepted `cd <literal> &&` are now evaluated in
that directory by both adapters. Before, relative paths after the `cd` were
resolved against the session folder, so `cd sub && python3 writer.py` could
miss the script's write evidence.

Nothing about variables, globs or substitutions in mutation targets was
relaxed. The shell form of `agw run` with variable arguments is still checked
by `agw` itself at run time, which resolves, pre-images and inventories the
expanded paths.

## 4. Statement boundaries in the shell parser (pre-existing gap)

`shlex` reads a newline as whitespace. As a result, `echo hi<newline>rm -rf x`
parsed as a single `echo` command, and `for f in a; do rm -rf x; done` parsed
as a command named `do`. Neither `rm` was evaluated. The released 0.5.0
package behaves the same way.

`posix_statement_surface()` in `plugin/scripts/core/shellparse.py` now handles
these cases:

- Unquoted newlines become statement separators.
- Comments are dropped without swallowing the newline that ends them.
- Backslash-newline continuations are joined.
- Bodies of heredocs the heredoc regex did not take (`cat <<EOF > f`) are
  skipped.
- Reserved-word prefixes are stripped in the POSIX dialect.

This change only makes more commands visible to the existing rules.

## Example: a Remotion render workflow

```json
{
  "schema": "agw.workflow/v3",
  "id": "studio.remotion-render",
  "description": "Render one composition from a prebuilt bundle to projects/<slug>/renders/<name>.mp4",
  "command": {
    "runtime": "node",
    "script": "<studio>/node_modules/@remotion/cli/remotion-cli.js",
    "script_sha256": "<sha256 of that file>",
    "args": ["render", {"parameter": "bundle"}, {"parameter": "composition"},
             {"parameter": "output"}, "--gl=swangle", "--color-space=bt709"]
  },
  "parameters": {
    "bundle": {"type": "path", "root": "<studio>", "must_exist": true, "kind": "directory"},
    "composition": {"type": "regex", "pattern": "[A-Za-z0-9][A-Za-z0-9-]{0,99}"},
    "output": {"type": "path", "root": "<studio>/projects", "must_exist": false,
               "kind": "file",
               "pattern": "[a-z0-9][a-z0-9-]*/renders/[A-Za-z0-9][A-Za-z0-9._-]*[.]mp4"}
  },
  "allowed_roots": ["<studio>/projects"],
  "outputs": [{"path": "{param:output}", "expected": "any"}],
  "observed_roots": [],
  "limits": {"timeout_seconds": 7200}
}
```

Run it explicitly:

```text
agw run --workflow studio.remotion-render --cwd <studio> \
  --param bundle=<bundle dir> --param composition=<id> --param output=<out.mp4>
```

The Remotion entry script contains no file-write evidence, so the hook does not
route `node .../remotion-cli.js` to the workflow automatically. The trust binds
the entry file's hash, not the rest of `node_modules`, in the same way that a
Python workflow binds its script but not the modules it imports.
