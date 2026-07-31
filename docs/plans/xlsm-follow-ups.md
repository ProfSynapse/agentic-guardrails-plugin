# XLSM implementation follow-ups

These adjacent findings are intentionally separated from the `.xlsm` safety
implementation so they can be fixed and released without weakening its scope.

## Read-only source entrypoint classified as opaque

- **Impact:** low; developer/test friction only. The packaged `agw` launcher is
  unaffected.
- **Reproduction:** invoke the source entrypoint with Python and a leaf `--help`
  argument under an active Guardrails hook.
- **Observed:** the hook treats the interpreter command as an opaque
  write-capable script and requests a declared output contract.
- **Desired:** recognize a narrow, normalized `agw.py ... --help` invocation as
  read-only only when the script identity matches the active packaged plugin.
- **Constraint:** do not generally allow arbitrary `python script.py --help`;
  import-time code can write files.

## Bounded-scan timing test is load-sensitive on Windows

- **Impact:** medium test reliability; the worker still returns structured
  `max_seconds` results and is reaped.
- **Reproduction:** run the parametrized blocking-filesystem scan tests after a
  CPU/process-heavy suite on Windows.
- **Observed:** a 0.6-second deadline sometimes returns in 1.03–1.09 seconds
  against a strict `<1.0` test assertion; an initial progress message can also
  lose the race with forced termination.
- **Desired:** measure and budget Windows process-start/termination overhead
  separately, and make initial progress delivery deterministic without weakening
  the user-facing wall-clock bound.
