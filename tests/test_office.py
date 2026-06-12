"""agw office: controlled in-place Office edits, snapshot-first contract."""
import json
import os
import subprocess
import sys

import pytest

from core import store

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGW = os.path.join(REPO, "scripts", "agw", "agw.py")

openpyxl = pytest.importorskip("openpyxl")
sys.path.insert(0, os.path.join(REPO, "scripts", "agw"))
import office  # noqa: E402


def run_agw(*args, env=None, check=True):
    e = dict(os.environ)
    if env:
        e.update(env)
    result = subprocess.run([sys.executable, AGW, *args],
                            capture_output=True, text=True, env=e)
    if check and result.returncode != 0:
        raise AssertionError(f"agw {' '.join(args)} failed: {result.stderr}")
    return result


@pytest.fixture
def workbook(tmp_path):
    path = tmp_path / "budget.xlsx"
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Q3"
    ws.append(["item", "amount"])
    ws.append(["staplers", 40])
    wb.save(path)
    return str(path)


def test_set_cell_snapshots_first(workbook):
    result = office.set_cell(workbook, "Q3", "B2", "55")
    assert result["old"] == 40 and result["new"] == 55
    versions = store.list_versions(workbook)
    assert len(versions) == 1  # pre-image, taken before the edit
    # the snapshot holds the OLD value
    wb = openpyxl.load_workbook(versions[0]["dest"])
    assert wb["Q3"]["B2"].value == 40


def test_set_cell_coercion_and_text_flag(workbook):
    assert office.set_cell(workbook, "Q3", "B2", "=SUM(B1:B1)")["new"] == "=SUM(B1:B1)"
    assert office.set_cell(workbook, "Q3", "B2", "007", force_text=True)["new"] == "007"
    assert office.set_cell(workbook, "Q3", "B2", "true")["new"] is True


def test_set_cell_bad_sheet_no_snapshot(workbook):
    with pytest.raises(office.OfficeError, match="no sheet named"):
        office.set_cell(workbook, "Nope", "A1", "x")
    assert store.list_versions(workbook) == []  # refused before snapshotting


def test_append_rows(workbook):
    result = office.append_rows(workbook, "Q3", [["pens", 12], ["ink", 30]])
    assert result["appended"] == 2 and result["rows_now"] == 4
    assert len(store.list_versions(workbook)) == 1


def test_cli_set_cell_and_restore_roundtrip(workbook, agw_home):
    run_agw("office", "set-cell", workbook, "--sheet", "Q3",
            "--cell", "B2", "--value", "99")
    wb = openpyxl.load_workbook(workbook)
    assert wb["Q3"]["B2"].value == 99
    run_agw("restore", workbook)
    wb = openpyxl.load_workbook(workbook)
    assert wb["Q3"]["B2"].value == 40


def test_cli_append_rows_from_csv(workbook, tmp_path, agw_home):
    csv_file = tmp_path / "new.csv"
    csv_file.write_text("pens,12\nink,30\n")
    result = run_agw("office", "append-rows", workbook, "--sheet", "Q3",
                     "--from-csv", str(csv_file), "--json")
    assert json.loads(result.stdout)["appended"] == 2


def test_cli_info(workbook, agw_home):
    result = run_agw("office", "info", workbook, "--json")
    data = json.loads(result.stdout)
    assert data["sheets"]["Q3"]["rows"] == 2


def test_cli_missing_flags_fail_clean(workbook, agw_home):
    result = run_agw("office", "set-cell", workbook, check=False)
    assert result.returncode == 1 and "--sheet" in result.stderr


def test_engine_allows_office_verb(evaluate):
    from core.events import ALLOW
    d = evaluate('agw office set-cell budget.xlsx --sheet Q3 --cell B2 --value 5')
    assert d.action == ALLOW


# --- docx ----------------------------------------------------------------------

@pytest.fixture
def document(tmp_path):
    # skipped inside the fixture so missing python-docx doesn't skip the
    # module's xlsx tests too
    docx_lib = pytest.importorskip("docx", reason="python-docx not installed")
    path = tmp_path / "memo.docx"
    doc = docx_lib.Document()
    doc.add_heading("Q3 Memo", level=1)
    p = doc.add_paragraph()
    # force the match to span runs, the case naive per-run replace misses
    p.add_run("The deadline is Oct")
    p.add_run("ober 1 for ACME Corp.")
    table = doc.add_table(rows=1, cols=1)
    table.rows[0].cells[0].text = "ACME Corp budget"
    doc.save(path)
    return str(path)


def test_replace_text_spanning_runs(document):
    result = office.replace_text(document, "October 1", "November 15")
    assert result["replacements"] == 1
    assert "November 15" in office.get_text(document)
    assert "October" not in office.get_text(document)


def test_replace_text_in_tables_and_snapshot(document):
    result = office.replace_text(document, "ACME Corp", "Initech", all_matches=True)
    assert result["replacements"] == 2  # paragraph + table cell
    versions = store.list_versions(document)
    assert len(versions) == 1
    assert "ACME Corp" in office.get_text(versions[0]["dest"])  # pre-image intact


def test_replace_ambiguous_refuses_without_all(document):
    with pytest.raises(office.OfficeError, match="2 matches.*ambiguous"):
        office.replace_text(document, "ACME Corp", "Initech")
    assert store.list_versions(document) == []  # refused before snapshotting
    assert office.get_text(document).count("ACME Corp") == 2  # untouched


def test_replace_nth_targets_one_occurrence(document):
    result = office.replace_text(document, "ACME Corp", "Initech", nth=2)
    assert result["replacements"] == 1 and result["matches"] == 2
    text = office.get_text(document)
    # document order: #1 is the body paragraph (kept), #2 the table cell (replaced)
    assert "for ACME Corp." in text
    assert "Initech budget" in text


def test_replace_nth_out_of_range(document):
    with pytest.raises(office.OfficeError, match="out of range"):
        office.replace_text(document, "ACME Corp", "x", nth=3)


def test_find_matches_lists_locations(document):
    matches = office.find_matches(document, "ACME Corp")
    assert [m["n"] for m in matches] == [1, 2]
    assert matches[0]["where"].startswith("paragraph")
    assert matches[1]["where"].startswith("table")
    assert "ACME Corp" in matches[0]["context"]


def test_cli_dry_run_changes_nothing(document, agw_home):
    result = run_agw("office", "replace-text", document,
                     "--find", "ACME Corp", "--dry-run", "--json")
    data = json.loads(result.stdout)
    assert data["count"] == 2
    assert office.get_text(document).count("ACME Corp") == 2
    assert store.list_versions(document) == []


def test_replace_text_no_match_no_resave(document):
    before = os.path.getmtime(document)
    result = office.replace_text(document, "zzz-not-here", "x")
    assert result["replacements"] == 0
    assert os.path.getmtime(document) == before  # untouched


def test_docx_info(document):
    data = office.info(document)
    assert data["headings"] == ["Q3 Memo"]
