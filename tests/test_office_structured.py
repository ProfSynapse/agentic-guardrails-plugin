"""Structured Office reads and guarded mutation contracts."""
import datetime as dt
import json
import os
import subprocess
import sys

import pytest

openpyxl = pytest.importorskip("openpyxl")
from openpyxl.styles import PatternFill
from openpyxl.worksheet.table import Table, TableStyleInfo

REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugin")
AGW = os.path.join(REPO, "scripts", "agw", "agw.py")
sys.path.insert(0, os.path.join(REPO, "scripts", "agw"))

import office_excel  # noqa: E402
import office_word  # noqa: E402
from core import store  # noqa: E402


def run_agw(*args, env=None, check=True, input_text=None):
    process_env = dict(os.environ)
    if env:
        process_env.update(env)
    result = subprocess.run(
        [sys.executable, AGW, *args],
        capture_output=True, text=True, encoding="utf-8",
        env=process_env, input=input_text,
    )
    if check and result.returncode:
        raise AssertionError(result.stderr)
    return result


@pytest.fixture
def table_book(tmp_path):
    path = tmp_path / "table.xlsx"
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Data"
    ws.append(["ID", "Status", "Due", "Total"])
    ws.append(["A-1", "Open", dt.date(2026, 7, 28), "=1+1"])
    ws["A997"].fill = PatternFill("solid", fgColor="FF0000")
    table = Table(displayName="Orders", ref="A1:D2")
    table.tableStyleInfo = TableStyleInfo(
        name="TableStyleMedium2", showRowStripes=True
    )
    ws.add_table(table)
    wb.save(path)
    return str(path)


def test_info_uses_actual_values_not_styled_extent(table_book):
    data = office_excel.workbook_info(table_book)
    sheet = data["sheets"][0]
    assert sheet["used_range"] == "A1:D2"
    assert sheet["rows"] == 2
    assert sheet["worksheet_dimension"] == "A1:D997"
    assert sheet["tables"][0]["headers"] == ["ID", "Status", "Due", "Total"]


def test_read_table_is_typed_and_headers_once(table_book):
    data = office_excel.read_table(
        table_book, "Orders", columns=["ID", "Due"], where={"Status": "Open"}
    )
    assert data["headers"] == ["ID", "Due"]
    assert data["rows"] == [["A-1", "2026-07-28"]]
    assert len(data["hash"]) == 64


def test_append_expands_table_copies_style_and_formula(table_book, agw_home):
    before = store.file_sha256(table_book)
    result = office_excel.append_table_row(
        table_book, "Orders",
        {"ID": "A-2", "Status": "Closed", "Due": "2026-08-01"},
        expected_sha256=before,
    )
    assert result["appended"] == 1
    assert result["snapshot"] == 1
    wb = openpyxl.load_workbook(table_book)
    ws = wb["Data"]
    assert ws.tables["Orders"].ref == "A1:D3"
    assert ws["A3"].value == "A-2"
    assert ws["C3"].value == dt.datetime(2026, 8, 1)
    assert ws["D3"].value == "=1+1"
    assert ws["A3"].style_id == ws["A2"].style_id
    versions = store.list_versions(table_book)
    assert len(versions) == 1
    assert versions[0]["sha256"] == before


def test_update_dry_run_has_no_archive_then_commits(table_book, agw_home):
    before = store.file_sha256(table_book)
    dry = office_excel.update_table_row(
        table_book, "Orders", "ID", "A-1", {"Status": "Closed"},
        expected_sha256=before, dry_run=True,
    )
    assert dry["dry_run"] is True
    assert store.list_versions(table_book) == []
    assert store.file_sha256(table_book) == before

    result = office_excel.update_table_row(
        table_book, "Orders", "ID", "A-1", {"Status": "Closed"},
        expected_sha256=before,
    )
    assert result["updated"] == 1
    wb = openpyxl.load_workbook(table_book)
    assert wb["Data"]["B2"].value == "Closed"


def test_hash_conflict_refuses_without_snapshot(table_book, agw_home):
    with pytest.raises(office_excel.ExcelError, match="CONFLICT"):
        office_excel.update_table_row(
            table_book, "Orders", "ID", "A-1", {"Status": "Closed"},
            expected_sha256="0" * 64,
        )
    assert store.list_versions(table_book) == []


def test_cli_read_table_compact_json(table_book, agw_home):
    result = run_agw(
        "office", "read-table", table_book, "--table", "Orders",
        "--columns", "ID,Status", "--limit", "1", "--json",
    )
    assert "\n" not in result.stdout.rstrip("\n")
    data = json.loads(result.stdout)
    assert data["headers"] == ["ID", "Status"]
    assert data["rows"] == [["A-1", "Open"]]


def test_cli_append_table_row_accepts_stdin_json_with_spaces(table_book, agw_home):
    # Windows PowerShell commonly prefixes native pipeline input with a UTF-8
    # BOM. Exercise that exact byte stream as a permanent regression case.
    payload = "\ufeff" + json.dumps({
        "ID": "A-2", "Status": "Needs review", "Due": "2026-08-01",
    })
    result = run_agw(
        "office", "append-table-row", table_book, "--table", "Orders",
        "--row-json", "-", "--coerce-iso-dates", "--json",
        env={"AGW_HOME": agw_home}, input_text=payload,
    )
    data = json.loads(result.stdout)
    assert data["appended"] == 1

    readback = run_agw(
        "office", "read-table", table_book, "--table", "Orders", "--json",
        env={"AGW_HOME": agw_home},
    )
    assert json.loads(readback.stdout)["rows"][1] == [
        "A-2", "Needs review", "2026-08-01", "=1+1",
    ]


def test_word_outline_and_patch_if_dependency_present(tmp_path, agw_home):
    docx = pytest.importorskip("docx")
    path = tmp_path / "memo.docx"
    document = docx.Document()
    document.add_heading("Overview", level=1)
    document.add_paragraph("Original text.")
    document.save(path)

    view = office_word.outline(str(path))
    paragraph_id = view["blocks"][1][0]
    result = office_word.patch(
        str(path),
        [{"op": "replace_block", "id": paragraph_id, "text": "Revised text."}],
        expected_sha256=view["hash"],
    )
    assert result["patched"] == 1
    assert docx.Document(path).paragraphs[1].text == "Revised text."

    updated = office_word.outline(str(path))
    updated_id = updated["blocks"][1][0]
    cli = run_agw(
        "office", "patch", str(path), "--ops-json", "-",
        "--expected-file-hash", updated["hash"], "--json",
        env={"AGW_HOME": agw_home},
        input_text=json.dumps([{
            "op": "replace_block", "id": updated_id,
            "text": "PowerShell-safe revision with spaces.",
        }]),
    )
    assert json.loads(cli.stdout)["patched"] == 1
    assert docx.Document(path).paragraphs[1].text == \
        "PowerShell-safe revision with spaces."
