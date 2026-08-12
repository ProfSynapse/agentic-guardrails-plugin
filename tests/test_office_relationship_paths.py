"""Differential and adversarial coverage for shared OPC target resolution."""
from pathlib import Path
import zipfile

import pytest

import office_ooxml
import office_opc
import office_surgical


REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
DOC_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
SHEET_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"


@pytest.mark.parametrize(
    ("target", "classification", "reason"),
    [
        ("worksheets/sheet1.xml", "valid", "canonical_target"),
        ("/xl/worksheets/sheet1.xml", "noncanonical_resolvable",
         "safe_noncanonical_target"),
        ("./worksheets/../worksheets/sheet1.xml", "noncanonical_resolvable",
         "safe_noncanonical_target"),
        ("worksheets/sheet%31.xml", "noncanonical_resolvable",
         "safe_noncanonical_target"),
        ("../../../outside.xml", "unsafe", "package_root_escape"),
        ("//server/share.xml", "unsafe", "internal_authority_or_scheme"),
        ("https://example.test/sheet.xml", "unsafe", "internal_authority_or_scheme"),
        ("https%3A//example.test/sheet.xml", "unsafe", "internal_authority_or_scheme"),
        ("worksheets/sheet%2f1.xml", "unsafe", "encoded_path_separator"),
        ("worksheets\\sheet1.xml", "unsafe", "backslash_path_separator"),
        ("worksheets/sheet1.xml?x=1", "unsafe", "query_or_fragment"),
        ("worksheets/sheet1.xml#x", "unsafe", "query_or_fragment"),
        ("worksheets/%00sheet.xml", "unsafe", "control_character"),
        ("worksheets/sheet%ZZ.xml", "unsafe", "malformed_percent_escape"),
        ("worksheets/missing.xml", "unresolved", "target_part_missing"),
    ],
)
def test_relationship_classifier_matrix(target, classification, reason):
    result = office_opc.resolve_relationship(
        ["xl/workbook.xml", "xl/worksheets/sheet1.xml"],
        "xl/_rels/workbook.xml.rels", "rId1", target,
    )

    assert result.classification == classification
    assert result.reason == reason
    assert result.relationship_part == "xl/_rels/workbook.xml.rels"
    assert result.relationship_id == "rId1"
    assert result.raw_target == target


def test_unique_case_and_nfc_identity_resolve_but_ambiguity_blocks():
    decomposed = "xl/worksheets/cafe\u0301.xml"
    resolved = office_opc.resolve_relationship(
        [decomposed], "xl/_rels/workbook.xml.rels", "rId1",
        "worksheets/CAF\u00c9.xml",
    )
    ambiguous = office_opc.resolve_relationship(
        [decomposed, "xl/worksheets/CAF\u00c9.xml"],
        "xl/_rels/workbook.xml.rels", "rId1", "worksheets/caf\u00e9.xml",
    )

    assert resolved.classification == office_opc.NONCANONICAL_RESOLVABLE
    assert resolved.actual_part == decomposed
    assert ambiguous.classification == office_opc.UNSAFE
    assert ambiguous.reason == "ambiguous_part_identity"


def test_external_relationship_is_recorded_but_never_resolved():
    result = office_opc.resolve_relationship(
        ["xl/workbook.xml"], "_rels/.rels", "external",
        "https://example.test/document", "External",
    )

    assert result.classification == office_opc.VALID
    assert result.reason == "external_target_not_opened"
    assert result.resolved_part == result.actual_part == ""


def _write_workbook(path: Path, target: str) -> Path:
    workbook = (
        f'<workbook xmlns="{SHEET_NS}" xmlns:r="{DOC_REL_NS}">'
        '<sheets><sheet name="Data" sheetId="1" r:id="rId1"/></sheets>'
        '</workbook>'
    ).encode()
    relationships = (
        f'<Relationships xmlns="{REL_NS}"><Relationship Id="rId1" '
        f'Type="{DOC_REL_NS}/worksheet" Target="{target}"/>'
        '</Relationships>'
    ).encode()
    with zipfile.ZipFile(path, "w") as package:
        package.writestr("xl/workbook.xml", workbook)
        package.writestr("xl/_rels/workbook.xml.rels", relationships)
        package.writestr("xl/worksheets/sheet1.xml", f'<worksheet xmlns="{SHEET_NS}"/>')
    return path


@pytest.mark.parametrize(
    "target",
    ["/xl/worksheets/sheet1.xml", "./worksheets/../worksheets/sheet%31.xml"],
)
def test_ooxml_and_surgical_adapters_share_noncanonical_resolution(tmp_path, target):
    path = _write_workbook(tmp_path / "paths.xlsx", target)
    with zipfile.ZipFile(path) as package:
        mapping = office_ooxml._relationship_map(package, "xl/workbook.xml")

    assert mapping["rId1"] == "xl/worksheets/sheet1.xml"
    assert office_surgical.worksheet_part(str(path), "Data") == \
        "xl/worksheets/sheet1.xml"


@pytest.mark.parametrize(
    "target",
    ["../..%2foutside.xml", "worksheets\\sheet1.xml", "//host/sheet.xml"],
)
def test_ooxml_and_surgical_adapters_both_block_unsafe_targets(tmp_path, target):
    path = _write_workbook(tmp_path / "unsafe.xlsx", target)
    with zipfile.ZipFile(path) as package:
        with pytest.raises(office_ooxml.OoxmlError):
            office_ooxml._relationship_map(package, "xl/workbook.xml")
    with pytest.raises(office_surgical.SurgicalCellError):
        office_surgical.worksheet_part(str(path), "Data")
