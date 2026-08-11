"""Tiered, structured validation for OOXML and Excel packages."""
from pathlib import Path
import zipfile

import pytest

import office_tx


CONTENT_TYPES = "http://schemas.openxmlformats.org/package/2006/content-types"
RELATIONSHIPS = "http://schemas.openxmlformats.org/package/2006/relationships"
DOCUMENT_RELS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
SPREADSHEET = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
THREADS = "http://schemas.microsoft.com/office/spreadsheetml/2018/threadedcomments"


def _content_types(*overrides: tuple[str, str]) -> bytes:
    declarations = "".join(
        f'<Override PartName="/{part}" ContentType="{content_type}"/>'
        for part, content_type in overrides
    )
    return (
        f'<Types xmlns="{CONTENT_TYPES}">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        f'{declarations}</Types>'
    ).encode()


def _relationships(*items: tuple[str, str, str]) -> bytes:
    declarations = "".join(
        f'<Relationship Id="{relationship_id}" Type="{relationship_type}" '
        f'Target="{target}"/>'
        for relationship_id, relationship_type, target in items
    )
    return f'<Relationships xmlns="{RELATIONSHIPS}">{declarations}</Relationships>'.encode()


def _base_excel_parts() -> dict[str, bytes]:
    return {
        "[Content_Types].xml": _content_types(
            (
                "xl/workbook.xml",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
            ),
            (
                "xl/worksheets/sheet1.xml",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
            ),
        ),
        "_rels/.rels": _relationships(
            (
                "rId1",
                f"{DOCUMENT_RELS}/officeDocument",
                "xl/workbook.xml",
            ),
        ),
        "xl/workbook.xml": (
            f'<workbook xmlns="{SPREADSHEET}" xmlns:r="{DOCUMENT_RELS}">'
            '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>'
            '</workbook>'
        ).encode(),
        "xl/_rels/workbook.xml.rels": _relationships(
            (
                "rId1",
                f"{DOCUMENT_RELS}/worksheet",
                "worksheets/sheet1.xml",
            ),
        ),
        "xl/worksheets/sheet1.xml": (
            f'<worksheet xmlns="{SPREADSHEET}" xmlns:r="{DOCUMENT_RELS}">'
            '<sheetData/></worksheet>'
        ).encode(),
    }


def _write_package(path: Path, parts: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as package:
        for name, payload in parts.items():
            package.writestr(name, payload)
    return path


def _issue_codes(error: office_tx.OfficeValidationError) -> set[str]:
    return {issue["code"] for issue in error.details["issues"]}


def test_validation_tiers_and_roundtrip_capability(tmp_path):
    target = _write_package(tmp_path / "valid.xlsx", _base_excel_parts())

    package_report = office_tx.validate_office_package(str(target), tier="package")
    strict_report = office_tx.validate_office_package(str(target), tier="excel-strict")
    capabilities = office_tx.office_validation_capabilities()

    assert package_report["valid"] is True
    assert package_report["validators"] == [
        {"name": "package", "valid": True, "issue_count": 0}
    ]
    assert strict_report["valid"] is True
    assert [item["name"] for item in strict_report["validators"]] == [
        "package", "office-schema", "excel-strict",
    ]
    assert capabilities["tiers"] == ["package", "office-schema", "excel-strict"]
    assert capabilities["roundtrip"]["available"] is False
    assert capabilities["roundtrip"]["reason_code"] == \
        "native_roundtrip_adapter_unavailable"


def test_package_failure_has_stable_structured_issue(tmp_path):
    target = tmp_path / "invalid.xlsx"
    target.write_bytes(b"not a zip package")

    with pytest.raises(office_tx.OfficeValidationError) as caught:
        office_tx.validate_office_package(str(target), tier="package")

    assert caught.value.error_code == "office_validation_failed"
    assert _issue_codes(caught.value) == {"package_invalid_zip"}
    assert caught.value.details["report"]["valid"] is False


def test_package_rejects_literal_backslash_before_schema_reads(tmp_path):
    parts = _base_excel_parts()
    parts["xl/backslash.xml"] = b"<unexpected/>"
    target = _write_package(tmp_path / "backslash.xlsx", parts)
    # zipfile normalizes names on Windows, so patch both equal-length ZIP name
    # records to model a package produced by a non-Windows ZIP writer.
    target.write_bytes(
        target.read_bytes().replace(b"xl/backslash.xml", b"xl\\backslash.xml")
    )

    with pytest.raises(office_tx.OfficeValidationError) as caught:
        office_tx.validate_office_package(str(target), tier="office-schema")

    assert _issue_codes(caught.value) == {"package_unsafe_part_name"}
    assert caught.value.details["report"]["validators"] == [
        {"name": "package", "valid": False, "issue_count": 1}
    ]


def test_office_schema_rejects_missing_relationship_target(tmp_path):
    parts = _base_excel_parts()
    parts["xl/_rels/workbook.xml.rels"] = _relationships(
        (
            "rId1",
            f"{DOCUMENT_RELS}/worksheet",
            "worksheets/missing.xml",
        ),
    )
    target = _write_package(tmp_path / "missing-target.xlsx", parts)

    with pytest.raises(office_tx.OfficeValidationError) as caught:
        office_tx.validate_office_package(str(target), tier="office-schema")

    assert "opc_relationship_target_missing_part" in _issue_codes(caught.value)
    issue = next(
        item for item in caught.value.details["issues"]
        if item["code"] == "opc_relationship_target_missing_part"
    )
    assert issue["resolved_target"] == "xl/worksheets/missing.xml"


def test_office_schema_rejects_duplicate_normalized_part_identity(tmp_path):
    parts = _base_excel_parts()
    parts["XL/WORKBOOK.XML"] = parts["xl/workbook.xml"]
    target = _write_package(tmp_path / "duplicate-part.xlsx", parts)

    with pytest.raises(office_tx.OfficeValidationError) as caught:
        office_tx.validate_office_package(str(target), tier="office-schema")

    assert "opc_duplicate_part_identity" in _issue_codes(caught.value)


def test_excel_strict_rejects_unknown_threaded_comment_author(tmp_path):
    parts = _base_excel_parts()
    parts["[Content_Types].xml"] = _content_types(
        (
            "xl/workbook.xml",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
        ),
        (
            "xl/worksheets/sheet1.xml",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
        ),
        (
            "xl/persons/person.xml",
            "application/vnd.ms-excel.person+xml",
        ),
        (
            "xl/threadedComments/threadedComment1.xml",
            "application/vnd.ms-excel.threadedcomments+xml",
        ),
    )
    parts["xl/persons/person.xml"] = (
        f'<personList xmlns="{THREADS}">'
        '<person id="{person-known}" displayName="Known"/>'
        '</personList>'
    ).encode()
    parts["xl/threadedComments/threadedComment1.xml"] = (
        f'<ThreadedComments xmlns="{THREADS}">'
        '<threadedComment ref="A1" personId="{person-missing}" id="{comment-1}"/>'
        '</ThreadedComments>'
    ).encode()
    target = _write_package(tmp_path / "invalid-author.xlsx", parts)

    with pytest.raises(office_tx.OfficeValidationError) as caught:
        office_tx.validate_office_package(str(target), tier="excel-strict")

    issue = next(
        item for item in caught.value.details["issues"]
        if item["code"] == "excel_threaded_comment_person_unknown"
    )
    assert issue["person_id"] == "{person-missing}"
    assert issue["reference"] == "A1"


def test_excel_strict_rejects_duplicate_person_ids(tmp_path):
    parts = _base_excel_parts()
    parts["[Content_Types].xml"] = _content_types(
        (
            "xl/workbook.xml",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
        ),
        (
            "xl/worksheets/sheet1.xml",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
        ),
        ("xl/persons/person.xml", "application/vnd.ms-excel.person+xml"),
    )
    parts["xl/persons/person.xml"] = (
        f'<personList xmlns="{THREADS}">'
        '<person/><person id="duplicate"/><person id="duplicate"/>'
        '</personList>'
    ).encode()
    target = _write_package(tmp_path / "duplicate-person.xlsx", parts)

    with pytest.raises(office_tx.OfficeValidationError) as caught:
        office_tx.validate_office_package(str(target), tier="excel-strict")

    codes = _issue_codes(caught.value)
    assert "excel_person_id_missing" in codes
    assert "excel_person_id_duplicate" in codes


def test_excel_strict_requires_vml_for_legacy_comments(tmp_path):
    parts = _base_excel_parts()
    parts["[Content_Types].xml"] = _content_types(
        (
            "xl/workbook.xml",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
        ),
        (
            "xl/worksheets/sheet1.xml",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
        ),
        (
            "xl/comments1.xml",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.comments+xml",
        ),
    )
    parts["xl/comments1.xml"] = f'<comments xmlns="{SPREADSHEET}"/>'.encode()
    parts["xl/worksheets/_rels/sheet1.xml.rels"] = _relationships(
        ("rIdComment", f"{DOCUMENT_RELS}/comments", "../comments1.xml"),
    )
    target = _write_package(tmp_path / "comments-without-vml.xlsx", parts)

    with pytest.raises(office_tx.OfficeValidationError) as caught:
        office_tx.validate_office_package(str(target), tier="excel-strict")

    codes = _issue_codes(caught.value)
    assert "excel_legacy_comments_vml_relationship_missing" in codes
    assert "excel_legacy_comments_drawing_reference_missing" in codes


def test_excel_strict_requires_macro_relationship(tmp_path):
    parts = _base_excel_parts()
    parts["[Content_Types].xml"] = _content_types(
        (
            "xl/workbook.xml",
            "application/vnd.ms-excel.sheet.macroEnabled.main+xml",
        ),
        (
            "xl/worksheets/sheet1.xml",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
        ),
        ("xl/vbaProject.bin", "application/vnd.ms-office.vbaProject"),
    )
    parts["xl/vbaProject.bin"] = b"synthetic-vba"
    target = _write_package(tmp_path / "macro.xlsm", parts)

    with pytest.raises(office_tx.OfficeValidationError) as caught:
        office_tx.validate_office_package(str(target), tier="excel-strict")

    assert "excel_macro_relationship_missing" in _issue_codes(caught.value)


def test_excel_strict_requires_macro_content_type(tmp_path):
    parts = _base_excel_parts()
    parts["[Content_Types].xml"] = _content_types(
        (
            "xl/workbook.xml",
            "application/vnd.ms-excel.sheet.macroEnabled.main+xml",
        ),
        (
            "xl/worksheets/sheet1.xml",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
        ),
    )
    parts["xl/_rels/workbook.xml.rels"] = _relationships(
        ("rId1", f"{DOCUMENT_RELS}/worksheet", "worksheets/sheet1.xml"),
        ("rIdVba", f"{DOCUMENT_RELS}/vbaProject", "vbaProject.bin"),
    )
    parts["xl/vbaProject.bin"] = b"synthetic-vba"
    target = _write_package(tmp_path / "bad-content-type.xlsm", parts)

    with pytest.raises(office_tx.OfficeValidationError) as caught:
        office_tx.validate_office_package(str(target), tier="excel-strict")

    assert "excel_macro_content_type_invalid" in _issue_codes(caught.value)
