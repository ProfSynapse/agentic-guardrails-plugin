"""Format converters with graceful degradation: pandoc when available,
copy-only otherwise. Conversion availability never blocks archive safety."""
from __future__ import annotations

import csv
import io
import os
import shutil
import subprocess

PANDOC_FORMATS = {".docx", ".odt", ".rtf", ".epub", ".html"}


def capabilities() -> dict:
    caps = {"pandoc": bool(shutil.which("pandoc"))}
    try:
        import openpyxl  # noqa: F401
        caps["openpyxl"] = True
    except ImportError:
        caps["openpyxl"] = False
    try:
        import markitdown  # noqa: F401
        caps["markitdown"] = True
    except ImportError:
        caps["markitdown"] = False
    return caps


def to_open_format(src: str, dest_dir: str) -> dict:
    """Convert `src` to an editable open-format working copy in dest_dir.
    Returns {dest, mode} where mode is 'converted' or 'copy'."""
    os.makedirs(dest_dir, exist_ok=True)
    name = os.path.basename(src)
    ext = os.path.splitext(src)[1].lower()
    caps = capabilities()

    if ext in PANDOC_FORMATS and caps["pandoc"]:
        dest = os.path.join(dest_dir, name + ".md")
        media = os.path.join(dest_dir, "_media", name)
        subprocess.run(["pandoc", src, "-t", "gfm", "-o", dest,
                        "--extract-media", media],
                       check=True, capture_output=True, timeout=120)
        return {"dest": dest, "mode": "converted", "format": "md"}

    if ext == ".xlsx" and caps["openpyxl"]:
        import openpyxl
        wb = openpyxl.load_workbook(src, read_only=True, data_only=True)
        dests = []
        for sheet in wb.worksheets:
            out = io.StringIO()
            writer = csv.writer(out)
            for row in sheet.iter_rows(values_only=True):
                writer.writerow(["" if v is None else v for v in row])
            dest = os.path.join(dest_dir, f"{name}.{_safe(sheet.title)}.csv")
            with open(dest, "w", encoding="utf-8", newline="") as f:
                f.write(out.getvalue())
            dests.append(dest)
        return {"dest": dests[0] if dests else "", "dests": dests,
                "mode": "converted", "format": "csv"}

    # plain text and unknown formats: working copy is a plain copy
    dest = os.path.join(dest_dir, name)
    shutil.copy2(src, dest)
    return {"dest": dest, "mode": "copy", "format": ext.lstrip(".") or "bin"}


def to_original_format(working: str, original: str, out_path: str) -> dict:
    """Convert a working copy back toward the original's format, writing to
    out_path. Falls back to copying the working file."""
    orig_ext = os.path.splitext(original)[1].lower()
    caps = capabilities()
    if working.endswith(".md") and orig_ext in PANDOC_FORMATS and caps["pandoc"]:
        cmd = ["pandoc", working, "-o", out_path]
        if os.path.exists(original) and orig_ext == ".docx":
            cmd += ["--reference-doc", original]  # preserve original styling
        subprocess.run(cmd, check=True, capture_output=True, timeout=120)
        return {"mode": "converted"}
    shutil.copy2(working, out_path)
    return {"mode": "copy"}


def _safe(text: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in text)[:40]
