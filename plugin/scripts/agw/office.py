"""Controlled in-place edits to Office files (docx/xlsx/pptx).

The sanctioned alternative to ad-hoc interpreter one-liners: every mutating
operation archives a pre-image snapshot before touching the file, so the edit
is reversible with `agw restore` no matter what the library does to the file.

Libraries are optional (python-docx, openpyxl, python-pptx); each operation
reports exactly what to install when its library is missing.
"""
from __future__ import annotations

import os

from core import store


class OfficeError(Exception):
    """Operation failed in a way the caller should report verbatim."""


class MissingLibrary(OfficeError):
    def __init__(self, lib: str, pip_name: str, ext: str):
        super().__init__(f"{ext} support needs the '{pip_name}' package "
                         f"(pip install {pip_name})")
        self.lib, self.pip_name = lib, pip_name


def _docx():
    try:
        import docx
        return docx
    except ImportError:
        raise MissingLibrary("docx", "python-docx", ".docx")


def _openpyxl():
    try:
        import openpyxl
        return openpyxl
    except ImportError:
        raise MissingLibrary("openpyxl", "openpyxl", ".xlsx")


def _pptx():
    try:
        import pptx
        return pptx
    except ImportError:
        raise MissingLibrary("pptx", "python-pptx", ".pptx")


def capabilities() -> dict:
    caps = {}
    for key, loader in (("docx", _docx), ("xlsx", _openpyxl), ("pptx", _pptx)):
        try:
            loader()
            caps[key] = True
        except MissingLibrary:
            caps[key] = False
    return caps


def _ext(path: str) -> str:
    return os.path.splitext(path)[1].lower()


def _snapshot(path: str, op: str) -> dict:
    return store.archive_file(path, mode="copy", dedupe=True,
                              reason=f"pre-image before agw office {op}")


def _collect_paragraphs(path: str):
    """Return (document_object, [(location_label, paragraph), ...]) in
    document order. Paragraph text is run-joined, so matches that span runs
    are visible (Office splits runs at arbitrary points: formatting,
    spellcheck history)."""
    ext = _ext(path)
    if ext == ".docx":
        doc = _docx().Document(path)
        items = [(f"paragraph {i}", p) for i, p in enumerate(doc.paragraphs, 1)]
        for t, table in enumerate(doc.tables, 1):
            for row in table.rows:
                for cell in row.cells:
                    items.extend((f"table {t}", p) for p in cell.paragraphs)
        return doc, items
    if ext == ".pptx":
        prs = _pptx().Presentation(path)
        items = []
        for s, slide in enumerate(prs.slides, 1):
            for shape in slide.shapes:
                if shape.has_text_frame:
                    items.extend((f"slide {s}", p)
                                 for p in shape.text_frame.paragraphs)
        return prs, items
    raise OfficeError(f"replace-text supports .docx and .pptx, not {ext or 'this file'}")


def _repack_runs(paragraph, new_full: str):
    """Distribute new paragraph text into the existing runs, left to right.
    The first affected run's formatting wins for replacement text."""
    remaining = new_full
    runs = list(paragraph.runs)
    for i, run in enumerate(runs):
        if i == len(runs) - 1:
            run.text = remaining
            remaining = ""
        else:
            keep = len(run.text)
            run.text, remaining = remaining[:keep], remaining[keep:]


def find_matches(path: str, find: str) -> list:
    """List every occurrence with a 1-based index, location, and context —
    what an agent uses to choose --nth or confirm --all."""
    if not find:
        raise OfficeError("--find must not be empty")
    _, items = _collect_paragraphs(path)
    matches = []
    for loc, p in items:
        full = "".join(run.text for run in p.runs)
        start = 0
        while True:
            idx = full.find(find, start)
            if idx < 0:
                break
            ctx = full[max(0, idx - 40): idx + len(find) + 40]
            matches.append({"n": len(matches) + 1, "where": loc,
                            "context": ctx})
            start = idx + len(find)
    return matches


# --- read operations (no snapshot needed) -------------------------------------

def get_text(path: str) -> str:
    ext = _ext(path)
    if ext == ".docx":
        doc = _docx().Document(path)
        parts = [p.text for p in doc.paragraphs]
        for table in doc.tables:
            for row in table.rows:
                parts.append("\t".join(c.text for c in row.cells))
        return "\n".join(parts)
    if ext == ".pptx":
        prs = _pptx().Presentation(path)
        parts = []
        for i, slide in enumerate(prs.slides, 1):
            parts.append(f"--- slide {i} ---")
            for shape in slide.shapes:
                if shape.has_text_frame and shape.text_frame.text:
                    parts.append(shape.text_frame.text)
        return "\n".join(parts)
    raise OfficeError(f"get-text supports .docx and .pptx (for {ext or 'this file'}, "
                      "use `agw checkout` / `agw convert`)")


def info(path: str) -> dict:
    ext = _ext(path)
    if ext == ".docx":
        doc = _docx().Document(path)
        headings = [p.text for p in doc.paragraphs
                    if p.style.name.startswith("Heading") and p.text.strip()]
        return {"type": "docx", "paragraphs": len(doc.paragraphs),
                "tables": len(doc.tables), "headings": headings}
    if ext in (".xlsx", ".xlsm"):
        wb = _openpyxl().load_workbook(path, read_only=True)
        sheets = {ws.title: {"rows": ws.max_row, "cols": ws.max_column}
                  for ws in wb.worksheets}
        wb.close()
        return {"type": "xlsx", "sheets": sheets}
    if ext == ".pptx":
        prs = _pptx().Presentation(path)
        titles = []
        for slide in prs.slides:
            title = slide.shapes.title
            titles.append(title.text if title is not None else "")
        return {"type": "pptx", "slides": len(prs.slides), "titles": titles}
    raise OfficeError(f"unsupported extension: {ext or 'none'}")


# --- write operations (snapshot first, always) ---------------------------------

def replace_text(path: str, find: str, replace: str,
                 all_matches: bool = False, nth: int = 0) -> dict:
    """Replace occurrences of `find`. Same contract as a code editor's
    find/replace tool: a non-unique match without explicit targeting is an
    error, not a mass edit.

    - unique match           -> replaced
    - multiple matches       -> OfficeError unless all_matches or nth is given
    - nth=N (1-based, doc order) -> replace only that occurrence
    """
    if not find:
        raise OfficeError("--find must not be empty")
    if all_matches and nth:
        raise OfficeError("--all and --nth are mutually exclusive")
    doc, items = _collect_paragraphs(path)
    total = sum("".join(r.text for r in p.runs).count(find) for _, p in items)
    if total == 0:
        return {"replacements": 0, "matches": 0}
    if nth:
        if not 1 <= nth <= total:
            raise OfficeError(f"--nth {nth} out of range: {total} match(es)")
        targets = {nth}
    elif total > 1 and not all_matches:
        preview = "; ".join(f"#{m['n']} ({m['where']}) ...{m['context']}..."
                            for m in find_matches(path, find)[:5])
        raise OfficeError(
            f"{total} matches for {find!r} — refusing an ambiguous replace. "
            f"Use --all for every occurrence, --nth N for one, or a longer "
            f"--find that is unique. First matches: {preview}")
    else:
        targets = None  # all
    snap = _snapshot(path, "replace-text")
    occurrence, replaced = 0, 0
    for _, p in items:
        full = "".join(run.text for run in p.runs)
        if find not in full:
            continue
        parts = full.split(find)
        out, hit = parts[0], 0
        for part in parts[1:]:
            occurrence += 1
            if targets is None or occurrence in targets:
                out += replace
                hit += 1
            else:
                out += find
            out += part
        if hit:
            _repack_runs(p, out)
            replaced += hit
    if replaced:
        doc.save(path)
    return {"replacements": replaced, "matches": total,
            "snapshot_version": snap.get("version")}


def _coerce(value: str, force_text: bool):
    if force_text:
        return value
    if value.startswith("="):
        return value  # formula
    for caster in (int, float):
        try:
            return caster(value)
        except ValueError:
            continue
    if value.lower() in ("true", "false"):
        return value.lower() == "true"
    return value


def set_cell(path: str, sheet: str, cell: str, value: str,
             force_text: bool = False) -> dict:
    openpyxl = _openpyxl()
    wb = openpyxl.load_workbook(path)
    if sheet not in wb.sheetnames:
        raise OfficeError(f"no sheet named {sheet!r} (have: {', '.join(wb.sheetnames)})")
    snap = _snapshot(path, "set-cell")
    ws = wb[sheet]
    old = ws[cell].value
    ws[cell] = _coerce(value, force_text)
    wb.save(path)
    return {"sheet": sheet, "cell": cell, "old": old, "new": ws[cell].value,
            "snapshot_version": snap.get("version")}


def append_rows(path: str, sheet: str, rows: list, force_text: bool = False) -> dict:
    openpyxl = _openpyxl()
    wb = openpyxl.load_workbook(path)
    if sheet not in wb.sheetnames:
        raise OfficeError(f"no sheet named {sheet!r} (have: {', '.join(wb.sheetnames)})")
    snap = _snapshot(path, "append-rows")
    ws = wb[sheet]
    for row in rows:
        ws.append([_coerce(str(v), force_text) if v is not None else None
                   for v in row])
    wb.save(path)
    return {"sheet": sheet, "appended": len(rows), "rows_now": ws.max_row,
            "snapshot_version": snap.get("version")}
