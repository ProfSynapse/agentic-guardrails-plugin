"""Parser for Codex's `apply_patch` envelope.

Codex funnels *all* file mutation (what Claude splits across Write / Edit /
NotebookEdit) through a single `apply_patch` tool whose `tool_input.command`
carries a patch in OpenAI's envelope format:

    *** Begin Patch
    *** Add File: path/to/new.txt
    +first line
    +second line
    *** Update File: path/to/existing.py
    *** Move to: path/to/renamed.py
    @@ def f():
    -    old
    +    new
    *** Delete File: path/to/gone.txt
    *** End Patch

The guardrails need three things out of a patch: which files it touches, what
kind of change each is (add / update / delete - delete is the CRUA concern),
and the added content (so secret/content rules can scan what is being written).
This is a tolerant line scanner, not a strict applier: it never raises, and an
unrecognized blob simply yields no files (the adapter treats that as a
fail-closed ASK rather than a silent allow).
"""

_MARKERS = (
    ("*** Add File:", "add"),
    ("*** Update File:", "update"),
    ("*** Delete File:", "delete"),
)


def parse_patch(text: str):
    """Return a list of dicts: {op, path, added, move_to}.

    op      -- "add" | "update" | "delete"
    path    -- the file the marker named
    added   -- newly-added content (joined "+"-prefixed hunk lines), "" for delete
    move_to -- rename destination for an Update File, else None
    """
    files = []
    cur = None
    try:
        for raw in str(text).splitlines():
            stripped = raw.strip()
            marker_hit = None
            for marker, op in _MARKERS:
                if stripped.startswith(marker):
                    marker_hit = (op, stripped[len(marker):].strip())
                    break
            if marker_hit:
                cur = {"op": marker_hit[0], "path": marker_hit[1],
                       "_added": [], "move_to": None}
                if cur["path"]:
                    files.append(cur)
                else:
                    cur = None  # malformed marker with no path - ignore
                continue
            if cur is None:
                continue
            if stripped.startswith("*** Move to:"):
                cur["move_to"] = stripped[len("*** Move to:"):].strip() or None
                continue
            if stripped.startswith("***"):
                # Begin/End Patch, End of File, or the next section's sentinel.
                continue
            # Hunk body: "+" adds (but "+++ " is a diff header, not content),
            # " " context, "-" removal, "@@" hunk header. Only "+" is content.
            if raw.startswith("+") and not raw.startswith("+++"):
                cur["_added"].append(raw[1:])
        for f in files:
            f["added"] = "\n".join(f.pop("_added")) if f["op"] != "delete" else ""
    except Exception:
        # Tolerant by contract: hand back whatever parsed cleanly so far.
        for f in files:
            if "_added" in f:
                f["added"] = "\n".join(f.pop("_added")) if f["op"] != "delete" else ""
    return files
