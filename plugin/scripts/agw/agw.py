#!/usr/bin/env python3
"""agw - the agent workspace CLI. The safe-verb vocabulary that replaces raw
destructive primitives. Every verb is reversible by construction, dual-output
(human line + JSON via --json), and self-logging.

Verbs: init scan checkout convert diff publish archive move rename snapshot
       restore undo status log doctor prune office
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import sys

# Windows consoles default to a legacy code page (cp1252) that cannot encode
# non-ASCII output; force UTF-8 so the CLI never dies with a UnicodeEncodeError
# mid-operation (by print time it has often already mutated state - e.g. a
# checkout that succeeded then crashed on its result line).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))  # scripts/ -> core importable
PLUGIN_ROOT = os.environ.get("CLAUDE_PLUGIN_ROOT") or os.path.dirname(os.path.dirname(_HERE))

from core import profiles as prof          # noqa: E402
from core import store                      # noqa: E402
import converters                           # noqa: E402
import office                               # noqa: E402
import office_tx                            # noqa: E402

SNAPSHOT_MAX_BYTES = int(os.environ.get("AGW_SNAPSHOT_MAX_BYTES", 2 * 1024 ** 3))


def _out(args, human: str, data: dict):
    if getattr(args, "json", False):
        print(json.dumps(data, ensure_ascii=False, default=str,
                         separators=(",", ":")))
    else:
        print(human)


def _err(message: str, code: int = 1):
    print(f"agw: {message}", file=sys.stderr)
    sys.exit(code)


def _json_object_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json_stdin(label: str) -> str:
    limit = 1024 * 1024
    binary = getattr(sys.stdin, "buffer", None)
    if binary is None:  # primarily useful for embedded/test StringIO streams
        raw = sys.stdin.read(limit + 1)
        if len(raw.encode("utf-8")) > limit:
            _err(f"{label}: stdin payload exceeds 1 MiB")
        return raw.lstrip("\ufeff")

    payload = binary.read(limit + 5)
    if len(payload) > limit:
        _err(f"{label}: stdin payload exceeds 1 MiB")
    try:
        if payload.startswith((b"\xff\xfe", b"\xfe\xff")):
            return payload.decode("utf-16")
        return payload.decode("utf-8-sig")
    except UnicodeDecodeError:
        _err(f"{label}: stdin payload must be UTF-8 or BOM-marked UTF-16 JSON")


def _load_json_payload(inline: str, file_path: str, label: str, expected):
    if inline and file_path:
        _err(f"{label}: inline and file payloads are mutually exclusive")
    if file_path:
        resolved = _resolve(file_path)
        if os.path.getsize(resolved) > 1024 * 1024:
            _err(f"{label}: payload file exceeds 1 MiB")
        with open(resolved, encoding="utf-8") as handle:
            raw = handle.read()
    elif inline == "-":
        raw = _read_json_stdin(label)
    else:
        raw = inline
        if len(raw.encode("utf-8")) > 6 * 1024:
            _err(f"{label}: inline payload exceeds 6 KiB; use a payload file")
    if raw.startswith("\ufeff"):
        raw = raw[1:]
    if not raw:
        _err(f"{label}: payload is required")
    try:
        value = json.loads(
            raw, object_pairs_hook=_json_object_no_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {token}")
            ),
        )
    except (json.JSONDecodeError, ValueError) as exc:
        _err(f"{label}: invalid JSON ({exc})")
    if expected is not None and not isinstance(value, expected):
        kind = "object" if expected is dict else "array"
        _err(f"{label}: payload must be a JSON {kind}")
    def count_nodes(item, depth=0):
        if depth > 16:
            raise ValueError("JSON nesting exceeds 16 levels")
        if isinstance(item, dict):
            return 1 + sum(count_nodes(v, depth + 1) for v in item.values())
        if isinstance(item, list):
            return 1 + sum(count_nodes(v, depth + 1) for v in item)
        return 1
    try:
        if count_nodes(value) > 100000:
            _err(f"{label}: payload exceeds 100000 JSON nodes")
    except ValueError as exc:
        _err(f"{label}: {exc}")
    return value


def _resolve(path: str) -> str:
    p = os.path.abspath(os.path.expanduser(path))
    if not os.path.exists(p):
        _err(f"path not found: {p}")
    return p


def _require_archive_store():
    if not store.archive_store_writable():
        _err(
            "Guardrails cannot write a recovery copy from this sandbox. "
            "The original file was not moved or changed. Ask the agent to retry "
            "the same Guardrails operation using the host's normal approval. "
            "Do not change folder permissions or security settings."
        )


# --- verbs -------------------------------------------------------------------

def cmd_init(args):
    folder = _resolve(args.path)
    ws = os.path.join(folder, "_workspace")
    os.makedirs(ws, exist_ok=True)
    profile = prof.detect(folder)
    _out(args, f"initialized workspace in {folder} (profile: {profile.name})",
         {"folder": folder, "workspace": ws, "profile": profile.name})


def cmd_scan(args):
    folder = _resolve(args.path)
    profile = prof.detect(folder)
    stats = {"files": 0, "dirs": 0, "bytes": 0, "by_ext": {}, "placeholders": [],
             "gdoc_stubs": [], "sync_artifacts": [], "profile": profile.name}
    max_entries = 50
    for dirpath, dirnames, filenames in os.walk(folder):
        dirnames[:] = [d for d in dirnames if d not in ("_workspace", ".git", "node_modules")]
        stats["dirs"] += len(dirnames)
        for name in filenames:
            p = os.path.join(dirpath, name)
            stats["files"] += 1
            ext = os.path.splitext(name)[1].lower() or "(none)"
            stats["by_ext"][ext] = stats["by_ext"].get(ext, 0) + 1
            try:
                stats["bytes"] += os.path.getsize(p)
            except OSError:
                pass
            rel = os.path.relpath(p, folder)
            if prof.is_gdoc_stub(p) and len(stats["gdoc_stubs"]) < max_entries:
                stats["gdoc_stubs"].append(rel)
            elif prof.is_placeholder(p) and len(stats["placeholders"]) < max_entries:
                stats["placeholders"].append(rel)
            elif prof.is_sync_artifact(p) and len(stats["sync_artifacts"]) < max_entries:
                stats["sync_artifacts"].append(rel)
    human = (f"{folder} [{profile.name}]: {stats['files']} files, "
             f"{stats['bytes'] / 1e6:.1f} MB; placeholders: {len(stats['placeholders'])}, "
             f"gdoc stubs: {len(stats['gdoc_stubs'])}, "
             f"sync artifacts: {len(stats['sync_artifacts'])}")
    if stats["placeholders"]:
        human += "\n  cloud-only (do NOT edit before hydrating): " + \
                 ", ".join(stats["placeholders"][:10])
    if stats["gdoc_stubs"]:
        human += "\n  google-docs stubs (no local content): " + \
                 ", ".join(stats["gdoc_stubs"][:10])
    _out(args, human, stats)


def cmd_checkout(args):
    src = _resolve(args.path)
    if not os.path.isfile(src):
        _err("checkout takes a single file")
    if prof.is_gdoc_stub(src):
        _err("this is a Google Docs pointer stub with no local content - export it "
             "via the Drive connector instead (gdocs-bridge skill)")
    if prof.is_placeholder(src):
        _err("file is a cloud-only placeholder - hydrate it first ('Always keep on "
             "this device' / 'Available offline')")
    folder = os.path.dirname(src)
    ws = os.path.join(folder, "_workspace")
    result = converters.to_open_format(src, ws)
    state = store.state_load()
    state["checkouts"][src] = {
        "working": result["dest"], "workings": result.get("dests", [result["dest"]]),
        "base_sha256": store.file_sha256(src), "mode": result["mode"],
    }
    store.state_save(state)
    store.oplog_append({"op": "checkout", "src": src, "working": result["dest"]})
    note = "" if result["mode"] == "converted" else \
        " (no converter available - working copy is a plain copy)"
    _out(args, f"checked out -> {result['dest']}{note}",
         {"src": src, **result})


def cmd_convert(args):
    src = _resolve(args.path)
    dest_dir = args.dest or os.path.join(os.path.dirname(src), "_workspace")
    result = converters.to_open_format(src, dest_dir)
    _out(args, f"converted -> {result['dest']} ({result['mode']})", result)


def cmd_diff(args):
    src = _resolve(args.path)
    state = store.state_load()
    entry = state["checkouts"].get(src)
    if not entry:
        _err(f"no checkout registered for {src}")
    working = entry["working"]
    live_hash = store.file_sha256(src)
    drifted = live_hash != entry["base_sha256"]
    try:
        with open(working, encoding="utf-8", errors="replace") as f:
            work_lines = f.readlines()
        base_lines = []
        if working.endswith(".md") or entry["mode"] == "copy":
            tmp = converters.to_open_format(src, os.path.join(store.agw_home(), "tmp"))
            with open(tmp["dest"], encoding="utf-8", errors="replace") as f:
                base_lines = f.readlines()
        diff = "".join(difflib.unified_diff(base_lines, work_lines,
                                            "live(converted)", "working", n=2))
    except Exception as exc:
        diff = f"(diff unavailable: {exc})"
    human = diff or "(no changes in working copy)"
    if drifted:
        human = "WARNING: live file changed since checkout!\n" + human
    _out(args, human, {"src": src, "drifted": drifted, "diff": diff})


def cmd_publish(args):
    src = os.path.abspath(os.path.expanduser(args.path))
    state = store.state_load()
    entry = state["checkouts"].get(src)
    if not entry:
        _err(f"no checkout registered for {src} - use `agw checkout` first")
    working = entry["working"]
    if not os.path.exists(working):
        _err(f"working copy missing: {working}")
    if os.path.exists(src):
        live_hash = store.file_sha256(src)
        if live_hash != entry["base_sha256"] and not args.force:
            _err("CONFLICT: the live file changed since checkout (someone else edited "
                 "it?). Review with `agw diff`, then publish --force to overwrite, or "
                 "re-checkout.", code=3)
        # version-bump: current live file -> archive
        store.archive_file(src, mode="copy", reason="pre-publish version bump",
                           actor="agw publish")
    profile = prof.detect(src)
    tmp_out = src + ".agw-publishing"
    result = converters.to_original_format(working, src, tmp_out)
    try:
        os.replace(tmp_out, src)
    except OSError:
        import shutil as _sh
        import time as _time
        for attempt in range(5):  # retry-in-place for sync-locked files
            try:
                _sh.copy2(tmp_out, src)
                os.unlink(tmp_out)
                break
            except OSError:
                _time.sleep(0.5 * (attempt + 1))
        else:
            _err(f"could not replace {src} (sync client lock?) - converted output "
                 f"left at {tmp_out}")
    entry["base_sha256"] = store.file_sha256(src)
    store.state_save(state)
    store.oplog_append({"op": "publish", "src": src, "working": working,
                        "conversion": result["mode"]})
    note = "" if result["mode"] == "converted" else " (copy mode - no format conversion)"
    versioning = f"; upstream: {profile.upstream_versioning}" if \
        profile.upstream_versioning else ""
    _out(args, f"published {src}{note} - previous version archived"
               f" (restore with `agw restore {os.path.basename(src)}`){versioning}",
         {"src": src, "conversion": result["mode"]})


def cmd_archive(args):
    paths = [_resolve(path) for path in args.paths]
    _require_archive_store()
    results = []
    for p in paths:
        entry = store.archive_file(p, mode="move", reason=args.reason or "agw archive",
                                   actor="agw")
        results.append(entry)
        print(f"archived {p} -> {entry['dest']}")
    if getattr(args, "json", False):
        print(json.dumps(results, default=str))


def cmd_move(args):
    src = _resolve(args.src)
    op = store.logged_move(src, os.path.abspath(os.path.expanduser(args.dest)))
    _out(args, f"moved {op['src']} -> {op['dest']} (undo with `agw undo`)", op)


def cmd_snapshot(args):
    folder = _resolve(args.path)
    total = 0
    for dirpath, dirnames, filenames in os.walk(folder):
        dirnames[:] = [d for d in dirnames if d != "_workspace"]
        for name in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, name))
            except OSError:
                pass
    if total > SNAPSHOT_MAX_BYTES and not args.force:
        _err(f"folder is {total / 1e9:.1f} GB (> {SNAPSHOT_MAX_BYTES / 1e9:.0f} GB "
             "preflight limit). Re-run with --force if you really want this.", code=3)
    _require_archive_store()
    entry = store.archive_file(folder, mode="copy", reason=args.reason or "agw snapshot",
                               actor="agw")
    _out(args, f"snapshot of {folder} -> {entry['dest']} ({total / 1e6:.1f} MB)", entry)


def cmd_restore(args):
    target = os.path.abspath(os.path.expanduser(args.path))
    op = store.restore(target, version=args.version or 0)
    _out(args, f"restored {target} from v{op['version']}", op)


def cmd_undo(args):
    try:
        op = store.undo_last()
    except LookupError as exc:
        _err(str(exc))
    _out(args, f"undid {op['undone']}: {op['restored']} is back", op)


def cmd_status(args):
    state = store.state_load()
    size = store.archive_size_bytes()
    checkouts = state.get("checkouts", {})
    lines = [f"archive store: {store.agw_home()} ({size / 1e6:.1f} MB)",
             f"open checkouts: {len(checkouts)}"]
    for src, entry in list(checkouts.items())[:20]:
        drift = ""
        if os.path.exists(src) and store.file_sha256(src) != entry["base_sha256"]:
            drift = "  [LIVE FILE CHANGED]"
        lines.append(f"  {src} -> {entry['working']}{drift}")
    pending_office = office_tx.transaction_status()
    lines.append(f"incomplete office transactions: {len(pending_office)}")
    for item in pending_office[:20]:
        lines.append(
            f"  {item['mutation_id']} [{item['state']}] "
            f"{item.get('operation', '')}"
        )
    _out(args, "\n".join(lines),
         {"archive_bytes": size, "checkouts": checkouts, "home": store.agw_home(),
          "incomplete_office_transactions": pending_office})


def cmd_log(args):
    ops = store.oplog_read()[-(args.n):]
    lines = [f"{op.get('ts', '?')}  {op.get('op', '?'):9} {op.get('src', '')}"
             for op in ops]
    _out(args, "\n".join(lines) or "(no operations logged)", {"ops": ops})


def cmd_doctor(args):
    from core import engine
    caps = converters.capabilities()
    home = store.agw_home_path()
    writable = store.archive_store_writable()
    profile = prof.detect(os.getcwd())
    cfg = engine.resolve_settings(engine.load_policy(PLUGIN_ROOT))
    try:
        size = store.archive_size_bytes()
    except OSError:
        size = 0
    budget = int(os.environ.get("AGW_ARCHIVE_MAX_BYTES", 0) or 0)
    checks = {
        "agw_home": home, "agw_home_writable": writable,
        "python": sys.version.split()[0], "cwd_profile": profile.name,
        "enforcement_level": cfg.get("level"), "enforcement": cfg.get("enforcement"),
        "session_memory": cfg.get("session_memory"),
        "regenerable_rm": cfg.get("regenerable_rm"),
        "archive_bytes": size,
        "archive_budget": budget or "unlimited",
        **{f"converter_{k}": v for k, v in caps.items()},
        **{f"office_{k}": v for k, v in office.capabilities().items()},
    }
    lines = [f"{'OK ' if v is not False and v is not None else 'MISSING '} {k}: {v}"
             for k, v in checks.items()]
    if not caps["pandoc"]:
        lines.append("note: pandoc not found - Office checkouts degrade to copy-only "
                     "(archive safety unaffected). Install: https://pandoc.org")
    if budget and size > budget:
        lines.append(f"note: archive ({size} B) exceeds budget ({budget} B); "
                     "oldest pre-image snapshots will be evicted on next write.")
    _out(args, "\n".join(lines), checks)


def cmd_office(args):
    path = _resolve(args.path)
    try:
        if args.op == "info":
            if os.path.splitext(path)[1].lower() in (".xlsx", ".xlsm") and args.scope:
                import office_excel
                data = office_excel.workbook_info(path, scope=args.scope)
            else:
                data = office.info(path)
            human = json.dumps(data, ensure_ascii=False, indent=2, default=str)
        elif args.op == "get-text":
            text = office.get_text(path)
            data, human = {"path": path, "text": text}, text
        elif args.op == "replace-text":
            if args.dry_run:
                matches = office.find_matches(path, args.find)
                data = {"matches": matches, "count": len(matches)}
                human = "\n".join(
                    [f"{len(matches)} match(es) for {args.find!r}:"] +
                    [f"  #{m['n']} ({m['where']}) ...{m['context']}..."
                     for m in matches]) if matches else f"no matches for {args.find!r}"
            else:
                data = office.replace_text(path, args.find, args.replace,
                                           all_matches=args.all, nth=args.nth)
                if data["replacements"]:
                    human = (f"replaced {data['replacements']} of {data['matches']} "
                             f"occurrence(s) in {path} (pre-image archived as "
                             f"v{data['snapshot_version']})")
                else:
                    human = f"no matches for {args.find!r}; file untouched"
        elif args.op == "set-cell":
            if not (args.sheet and args.cell):
                _err("set-cell needs --sheet and --cell")
            data = office.set_cell(path, args.sheet, args.cell, args.value,
                                   force_text=args.text)
            human = (f"{args.sheet}!{args.cell}: {data['old']!r} -> {data['new']!r} "
                     f"(pre-image archived as v{data['snapshot_version']})")
        elif args.op == "append-rows":
            if not args.sheet:
                _err("append-rows needs --sheet")
            if args.from_csv:
                import csv
                with open(_resolve(args.from_csv), newline="", encoding="utf-8") as f:
                    rows = list(csv.reader(f))
            else:
                rows = _load_json_payload(
                    args.rows, "", "--rows", list
                ) if args.rows else []
                if not (isinstance(rows, list) and
                        all(isinstance(r, list) for r in rows)):
                    _err("--rows must be a JSON array of arrays")
            if not rows:
                _err("no rows given: use --from-csv FILE or --rows '[[...],...]'")
            data = office.append_rows(path, args.sheet, rows, force_text=args.text)
            human = (f"appended {data['appended']} row(s) to {args.sheet} in {path} "
                     f"(pre-image archived as v{data['snapshot_version']})")
        elif args.op == "read-table":
            import office_excel
            columns = [value for value in args.columns.split(",") if value] \
                if args.columns else None
            where = _load_json_payload(args.where_json, "", "--where-json", dict) \
                if args.where_json else None
            data = office_excel.read_table(
                path, args.table, sheet=args.sheet, columns=columns, where=where,
                offset=args.offset, limit=args.limit, values_only=args.values_only,
            )
            human = (f"{data['table']} on {data['sheet']}: "
                     f"{data['returned']} row(s)"
                     f"{' (more)' if data['more'] else ''}")
        elif args.op == "append-table-row":
            import office_excel
            row = _load_json_payload(
                args.row_json, args.row_file, "append-table-row", dict
            )
            data = office_excel.append_table_row(
                path, args.table, row, sheet=args.sheet,
                expected_sha256=args.expected_file_hash,
                dry_run=args.dry_run,
                coerce_iso_dates=args.coerce_iso_dates,
            )
            human = ("dry-run: " if args.dry_run else "") + \
                f"{data.get('changed', data.get('appended', 0))} row(s) for {args.table}"
        elif args.op == "update-table-row":
            import office_excel
            updates = _load_json_payload(
                args.set_json, args.set_file, "update-table-row", dict
            )
            key = _load_json_payload(
                args.key_json, "", "--key-json", None
            ) if args.key_json else args.key
            if isinstance(key, (dict, list)):
                _err("--key-json must be a JSON scalar")
            data = office_excel.update_table_row(
                path, args.table, args.key_column, key, updates,
                sheet=args.sheet, expected_sha256=args.expected_file_hash,
                dry_run=args.dry_run,
                coerce_iso_dates=args.coerce_iso_dates,
            )
            human = ("dry-run: " if args.dry_run else "") + \
                f"{data.get('changed', data.get('updated', 0))} row(s) for {args.table}"
        elif args.op == "outline":
            import office_word
            data = office_word.outline(path, offset=args.offset, limit=args.limit)
            human = (f"{data['returned']} Word block(s)"
                     f"{' (more)' if data['more'] else ''}")
        elif args.op == "read-blocks":
            import office_word
            ids = [value for value in args.ids.split(",") if value]
            data = office_word.read_blocks(path, ids)
            human = f"{len(data['blocks'])} Word block(s)"
        elif args.op == "patch":
            import office_word
            operations = _load_json_payload(
                args.ops_json, args.ops_file, "patch", list
            )
            data = office_word.patch(
                path, operations, expected_sha256=args.expected_file_hash,
                dry_run=args.dry_run,
            )
            human = ("dry-run: " if args.dry_run else "") + \
                f"{data.get('changed', data.get('patched', 0))} Word operation(s)"
        else:  # pragma: no cover - argparse restricts choices
            _err(f"unknown office op: {args.op}")
    except office.MissingLibrary as exc:
        _err(str(exc), code=2)
    except office.OfficeError as exc:
        _err(str(exc))
    except Exception as exc:
        # Adapter errors are intentionally plain exceptions so optional
        # dependencies remain lazy. Keep CLI errors concise and preserve the
        # established conflict exit code.
        message = str(exc)
        _err(message, code=3 if message.startswith("CONFLICT:") else 1)
    _out(args, human, data)


def cmd_prune(args):
    # Human-only by policy: the guard hook always asks before this verb, and we
    # require an explicit interactive confirmation on top.
    print("prune permanently deletes archived versions. This is the ONLY destructive "
          "verb in agw.", file=sys.stderr)
    if not args.yes_i_am_a_human:
        _err("refusing: pass --yes-i-am-a-human after reviewing `agw status`", code=4)
    _err("prune is not implemented in v0.1 (retention is keep-everything)", code=4)


def main(argv=None):
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="machine-readable output")
    parser = argparse.ArgumentParser(prog="agw", parents=[common],
                                     description="agent workspace - CRUA file safety")
    sub = parser.add_subparsers(dest="verb", required=True)

    def add(name, fn, *specs, **kw):
        p = sub.add_parser(name, parents=[common], **kw)
        for spec in specs:
            p.add_argument(*spec[0], **spec[1])
        p.set_defaults(fn=fn)
        return p

    add("init", cmd_init, (["path"], {"nargs": "?", "default": "."}))
    add("scan", cmd_scan, (["path"], {"nargs": "?", "default": "."}),
        help="inventory a folder without hydrating cloud files")
    add("checkout", cmd_checkout, (["path"], {}),
        help="create an editable open-format working copy")
    add("convert", cmd_convert, (["path"], {}), (["--dest"], {"default": ""}))
    add("diff", cmd_diff, (["path"], {}))
    add("publish", cmd_publish, (["path"], {}), (["--force"], {"action": "store_true"}),
        help="archive current version and replace with the working copy")
    add("archive", cmd_archive, (["paths"], {"nargs": "+"}),
        (["--reason"], {"default": ""}),
        help="reversible delete: move into the archive store")
    add("move", cmd_move, (["src"], {}), (["dest"], {}))
    sub._name_parser_map["rename"] = sub._name_parser_map["move"]
    add("snapshot", cmd_snapshot, (["path"], {"nargs": "?", "default": "."}),
        (["--reason"], {"default": ""}), (["--force"], {"action": "store_true"}))
    add("restore", cmd_restore, (["path"], {}),
        (["--version"], {"type": int, "default": 0}))
    add("undo", cmd_undo)
    add("status", cmd_status)
    add("log", cmd_log, (["-n"], {"type": int, "default": 20}))
    add("doctor", cmd_doctor)
    add("office", cmd_office,
        (["op"], {"choices": ["info", "get-text", "replace-text",
                              "set-cell", "append-rows", "read-table",
                              "append-table-row", "update-table-row",
                              "outline", "read-blocks", "patch"]}),
        (["path"], {}),
        (["--find"], {"default": ""}), (["--replace"], {"default": ""}),
        (["--all"], {"action": "store_true",
                     "help": "replace every occurrence (default refuses if not unique)"}),
        (["--nth"], {"type": int, "default": 0,
                     "help": "replace only the Nth occurrence (1-based, document order)"}),
        (["--dry-run"], {"action": "store_true",
                         "help": "list matches with location/context; change nothing"}),
        (["--sheet"], {"default": ""}), (["--cell"], {"default": ""}),
        (["--value"], {"default": ""}),
        (["--rows"], {"default": "", "help": "JSON array or - for stdin"}),
        (["--from-csv"], {"default": ""}),
        (["--scope"], {"choices": ["tables", "names"], "default": ""}),
        (["--table"], {"default": ""}), (["--columns"], {"default": ""}),
        (["--where-json"], {"default": "",
                             "help": "JSON object or - for stdin"}),
        (["--offset"], {"type": int, "default": 0}),
        (["--limit"], {"type": int, "default": 50}),
        (["--values-only"], {"action": "store_true"}),
        (["--row-json"], {"default": "", "help": "JSON object or - for stdin"}),
        (["--row-file"], {"default": ""}),
        (["--set-json"], {"default": "", "help": "JSON object or - for stdin"}),
        (["--set-file"], {"default": ""}),
        (["--key-column"], {"default": ""}), (["--key"], {"default": ""}),
        (["--key-json"], {"default": "", "help": "JSON scalar or - for stdin"}),
        (["--expected-file-hash"], {"default": ""}),
        (["--coerce-iso-dates"], {"action": "store_true"}),
        (["--ids"], {"default": ""}),
        (["--ops-json"], {"default": "", "help": "JSON array or - for stdin"}),
        (["--ops-file"], {"default": ""}),
        (["--text"], {"action": "store_true",
                      "help": "store values as text, no number/formula coercion"}),
        help="controlled in-place edits to docx/xlsx/pptx (pre-image archived first)")
    add("prune", cmd_prune, (["--yes-i-am-a-human"], {"action": "store_true"}))

    args = parser.parse_args(argv)
    try:
        args.fn(args)
    except PermissionError:
        _err(
            "Guardrails was denied access by the host sandbox and stopped "
            "without changing permissions or bypassing the sandbox. The requested "
            "operation did not complete. Ask the agent to retry using the host's "
            "normal approval."
        )


if __name__ == "__main__":
    main()
