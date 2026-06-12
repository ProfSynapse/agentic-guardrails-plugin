#!/usr/bin/env python3
"""agw — the agent workspace CLI. The safe-verb vocabulary that replaces raw
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

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))  # scripts/ → core importable

from core import profiles as prof          # noqa: E402
from core import store                      # noqa: E402
import converters                           # noqa: E402
import office                               # noqa: E402

SNAPSHOT_MAX_BYTES = int(os.environ.get("AGW_SNAPSHOT_MAX_BYTES", 2 * 1024 ** 3))


def _out(args, human: str, data: dict):
    if getattr(args, "json", False):
        print(json.dumps(data, ensure_ascii=False, default=str))
    else:
        print(human)


def _err(message: str, code: int = 1):
    print(f"agw: {message}", file=sys.stderr)
    sys.exit(code)


def _resolve(path: str) -> str:
    p = os.path.abspath(os.path.expanduser(path))
    if not os.path.exists(p):
        _err(f"path not found: {p}")
    return p


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
        _err("this is a Google Docs pointer stub with no local content — export it "
             "via the Drive connector instead (gdocs-bridge skill)")
    if prof.is_placeholder(src):
        _err("file is a cloud-only placeholder — hydrate it first ('Always keep on "
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
        " (no converter available — working copy is a plain copy)"
    _out(args, f"checked out → {result['dest']}{note}",
         {"src": src, **result})


def cmd_convert(args):
    src = _resolve(args.path)
    dest_dir = args.dest or os.path.join(os.path.dirname(src), "_workspace")
    result = converters.to_open_format(src, dest_dir)
    _out(args, f"converted → {result['dest']} ({result['mode']})", result)


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
        _err(f"no checkout registered for {src} — use `agw checkout` first")
    working = entry["working"]
    if not os.path.exists(working):
        _err(f"working copy missing: {working}")
    if os.path.exists(src):
        live_hash = store.file_sha256(src)
        if live_hash != entry["base_sha256"] and not args.force:
            _err("CONFLICT: the live file changed since checkout (someone else edited "
                 "it?). Review with `agw diff`, then publish --force to overwrite, or "
                 "re-checkout.", code=3)
        # version-bump: current live file → archive
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
            _err(f"could not replace {src} (sync client lock?) — converted output "
                 f"left at {tmp_out}")
    entry["base_sha256"] = store.file_sha256(src)
    store.state_save(state)
    store.oplog_append({"op": "publish", "src": src, "working": working,
                        "conversion": result["mode"]})
    note = "" if result["mode"] == "converted" else " (copy mode — no format conversion)"
    versioning = f"; upstream: {profile.upstream_versioning}" if \
        profile.upstream_versioning else ""
    _out(args, f"published {src}{note} — previous version archived"
               f" (restore with `agw restore {os.path.basename(src)}`){versioning}",
         {"src": src, "conversion": result["mode"]})


def cmd_archive(args):
    results = []
    for path in args.paths:
        p = _resolve(path)
        entry = store.archive_file(p, mode="move", reason=args.reason or "agw archive",
                                   actor="agw")
        results.append(entry)
        print(f"archived {p} → {entry['dest']}")
    if getattr(args, "json", False):
        print(json.dumps(results, default=str))


def cmd_move(args):
    src = _resolve(args.src)
    op = store.logged_move(src, os.path.abspath(os.path.expanduser(args.dest)))
    _out(args, f"moved {op['src']} → {op['dest']} (undo with `agw undo`)", op)


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
    entry = store.archive_file(folder, mode="copy", reason=args.reason or "agw snapshot",
                               actor="agw")
    _out(args, f"snapshot of {folder} → {entry['dest']} ({total / 1e6:.1f} MB)", entry)


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
        lines.append(f"  {src} → {entry['working']}{drift}")
    _out(args, "\n".join(lines),
         {"archive_bytes": size, "checkouts": checkouts, "home": store.agw_home()})


def cmd_log(args):
    ops = store.oplog_read()[-(args.n):]
    lines = [f"{op.get('ts', '?')}  {op.get('op', '?'):9} {op.get('src', '')}"
             for op in ops]
    _out(args, "\n".join(lines) or "(no operations logged)", {"ops": ops})


def cmd_doctor(args):
    caps = converters.capabilities()
    home = store.agw_home()
    writable = os.access(home, os.W_OK)
    profile = prof.detect(os.getcwd())
    checks = {
        "agw_home": home, "agw_home_writable": writable,
        "python": sys.version.split()[0], "cwd_profile": profile.name,
        **{f"converter_{k}": v for k, v in caps.items()},
        **{f"office_{k}": v for k, v in office.capabilities().items()},
    }
    lines = [f"{'OK ' if v not in (False, None) else 'MISSING '} {k}: {v}"
             for k, v in checks.items()]
    if not caps["pandoc"]:
        lines.append("note: pandoc not found — Office checkouts degrade to copy-only "
                     "(archive safety unaffected). Install: https://pandoc.org")
    _out(args, "\n".join(lines), checks)


def cmd_office(args):
    path = _resolve(args.path)
    try:
        if args.op == "info":
            data = office.info(path)
            human = json.dumps(data, ensure_ascii=False, indent=2, default=str)
        elif args.op == "get-text":
            text = office.get_text(path)
            data, human = {"path": path, "text": text}, text
        elif args.op == "replace-text":
            data = office.replace_text(path, args.find, args.replace)
            human = (f"replaced {data['replacements']} occurrence(s) in {path} "
                     f"(pre-image archived as v{data['snapshot_version']})")
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
                rows = json.loads(args.rows or "[]")
                if not (isinstance(rows, list) and
                        all(isinstance(r, list) for r in rows)):
                    _err("--rows must be a JSON array of arrays")
            if not rows:
                _err("no rows given: use --from-csv FILE or --rows '[[...],...]'")
            data = office.append_rows(path, args.sheet, rows, force_text=args.text)
            human = (f"appended {data['appended']} row(s) to {args.sheet} in {path} "
                     f"(pre-image archived as v{data['snapshot_version']})")
        else:  # pragma: no cover — argparse restricts choices
            _err(f"unknown office op: {args.op}")
    except office.MissingLibrary as exc:
        _err(str(exc), code=2)
    except office.OfficeError as exc:
        _err(str(exc))
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
                                     description="agent workspace — CRUA file safety")
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
                              "set-cell", "append-rows"]}),
        (["path"], {}),
        (["--find"], {"default": ""}), (["--replace"], {"default": ""}),
        (["--sheet"], {"default": ""}), (["--cell"], {"default": ""}),
        (["--value"], {"default": ""}),
        (["--rows"], {"default": ""}), (["--from-csv"], {"default": ""}),
        (["--text"], {"action": "store_true",
                      "help": "store values as text, no number/formula coercion"}),
        help="controlled in-place edits to docx/xlsx/pptx (pre-image archived first)")
    add("prune", cmd_prune, (["--yes-i-am-a-human"], {"action": "store_true"}))

    args = parser.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
