"""Cell-only OOXML edits that preserve unknown package content."""
from __future__ import annotations

import hashlib
import math
import os
import re
import tempfile
import zipfile
from xml.etree import ElementTree
from xml.sax.saxutils import escape

import office_opc


MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
DOC_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
CELL_RE = re.compile(r"^([A-Za-z]{1,3})([1-9][0-9]{0,6})$")
_EXT_RE = re.compile(
    rb"<(?:[A-Za-z_][\w.-]*:)?extLst\b[^>]*>.*?"
    rb"</(?:[A-Za-z_][\w.-]*:)?extLst\s*>", re.DOTALL,
)


class SurgicalCellError(RuntimeError):
    pass


def normalize_coordinate(value: str) -> tuple[str, int, int]:
    match = CELL_RE.fullmatch(str(value or "").strip())
    if not match:
        raise SurgicalCellError("cell must be one finite A1 reference")
    letters, row_text = match.groups()
    column = 0
    for char in letters.upper():
        column = column * 26 + ord(char) - 64
    row = int(row_text)
    if column > 16384 or row > 1048576:
        raise SurgicalCellError("cell is outside Excel worksheet bounds")
    return f"{letters.upper()}{row}", row, column


def _part(package: zipfile.ZipFile, name: str) -> bytes:
    try:
        return package.read(name)
    except KeyError as exc:
        raise SurgicalCellError(f"OOXML package is missing {name}") from exc


def worksheet_part(path: str, sheet_name: str) -> str:
    with zipfile.ZipFile(path) as package:
        workbook = ElementTree.fromstring(_part(package, "xl/workbook.xml"))
        relationship_id = ""
        for sheet in workbook.findall(f".//{{{MAIN_NS}}}sheet"):
            if sheet.attrib.get("name", "").casefold() == sheet_name.casefold():
                relationship_id = sheet.attrib.get(f"{{{DOC_REL_NS}}}id", "")
                break
        if not relationship_id:
            names = [item.attrib.get("name", "") for item in
                     workbook.findall(f".//{{{MAIN_NS}}}sheet")]
            raise SurgicalCellError(
                f"no sheet named {sheet_name!r} (have: {', '.join(names)})"
            )
        relationships = ElementTree.fromstring(
            _part(package, "xl/_rels/workbook.xml.rels")
        )
        target = ""
        target_mode = ""
        for relationship in relationships.findall(f"{{{PKG_REL_NS}}}Relationship"):
            if relationship.attrib.get("Id") == relationship_id:
                target = relationship.attrib.get("Target", "")
                target_mode = relationship.attrib.get("TargetMode", "")
                break
        resolution = office_opc.resolve_relationship(
            package.namelist(), "xl/_rels/workbook.xml.rels", relationship_id,
            target, target_mode, owner_part="xl/workbook.xml",
        )
        if resolution.reason == "external_target_not_opened":
            raise SurgicalCellError("worksheet relationship is external")
        if resolution.reason in {"package_root_escape", "target_part_missing"}:
            raise SurgicalCellError("worksheet relationship escapes the workbook package")
        if not resolution.usable:
            raise SurgicalCellError("worksheet relationship target is invalid")
        return resolution.actual_part


def _find_cell(payload: bytes, coordinate: str):
    quoted = re.escape(coordinate.encode("ascii"))
    pattern = re.compile(
        rb"<c\b(?=[^>]*\br\s*=\s*['\"]" + quoted
        + rb"['\"])[^>]*(?:/>|>.*?</c\s*>)", re.DOTALL,
    )
    matches = list(pattern.finditer(payload))
    if len(matches) > 1:
        raise SurgicalCellError("worksheet contains duplicate cell references")
    return matches[0] if matches else None


def _shared_string(package: zipfile.ZipFile, index: int):
    root = ElementTree.fromstring(_part(package, "xl/sharedStrings.xml"))
    values = root.findall(f"{{{MAIN_NS}}}si")
    if index < 0 or index >= len(values):
        raise SurgicalCellError("shared-string index is outside the string table")
    return "".join(node.text or "" for node in values[index].iter(f"{{{MAIN_NS}}}t"))


def inspect_cell(path: str, sheet_name: str, coordinate: str) -> dict:
    coordinate, _row, _column = normalize_coordinate(coordinate)
    part = worksheet_part(path, sheet_name)
    with zipfile.ZipFile(path) as package:
        payload = _part(package, part)
        match = _find_cell(payload, coordinate)
        if match is None:
            return {"part": part, "coordinate": coordinate, "value": None}
        wrapper = (f'<root xmlns="{MAIN_NS}">'.encode("ascii")
                   + match.group(0) + b"</root>")
        node = ElementTree.fromstring(wrapper)[0]
        formula = node.find(f"{{{MAIN_NS}}}f")
        if formula is not None:
            value = "=" + (formula.text or "")
        else:
            kind = node.attrib.get("t", "")
            raw = node.find(f"{{{MAIN_NS}}}v")
            text = raw.text if raw is not None else None
            if kind == "inlineStr":
                value = "".join(item.text or "" for item in
                                node.iter(f"{{{MAIN_NS}}}t"))
            elif kind == "s" and text is not None:
                value = _shared_string(package, int(text))
            elif kind == "b":
                value = text == "1"
            elif text is None:
                value = None
            elif kind in {"str", "e"}:
                value = text
            else:
                try:
                    number = float(text)
                    value = int(number) if number.is_integer() else number
                except ValueError:
                    value = text
        return {"part": part, "coordinate": coordinate, "value": value}


def _opening_attributes(existing: bytes | None, coordinate: str) -> bytes:
    if existing is None:
        return f' r="{coordinate}"'.encode("ascii")
    opening = existing[:existing.find(b">") + 1]
    match = re.match(rb"<c(?P<attrs>[^>]*?)(?:/)?\s*>", opening, re.DOTALL)
    if not match:
        raise SurgicalCellError("existing cell XML is malformed")
    attrs = match.group("attrs")
    attrs = re.sub(rb"\s+t\s*=\s*(['\"]).*?\1", b"", attrs, flags=re.DOTALL)
    return attrs.rstrip().rstrip(b"/").rstrip()


def _new_cell(existing: bytes | None, coordinate: str, value) -> bytes:
    attrs = _opening_attributes(existing, coordinate)
    if value is None:
        return b"<c" + attrs + b"/>"
    if isinstance(value, bool):
        return b"<c" + attrs + b' t="b"><v>' + (b"1" if value else b"0") + b"</v></c>"
    if isinstance(value, int) and not isinstance(value, bool):
        body = str(value).encode("ascii")
        return b"<c" + attrs + b"><v>" + body + b"</v></c>"
    if isinstance(value, float):
        if not math.isfinite(value):
            raise SurgicalCellError("non-finite numbers are unsupported")
        body = repr(value).encode("ascii")
        return b"<c" + attrs + b"><v>" + body + b"</v></c>"
    text = str(value)
    if text.startswith("="):
        body = escape(text[1:]).encode("utf-8")
        return b"<c" + attrs + b"><f>" + body + b"</f></c>"
    body = escape(text).encode("utf-8")
    space = b' xml:space="preserve"' if text != text.strip() else b""
    return (b"<c" + attrs + b' t="inlineStr"><is><t' + space + b">"
            + body + b"</t></is></c>")


def _insert_cell(payload: bytes, coordinate: str, row_number: int,
                 column_number: int, cell: bytes) -> bytes:
    row_pattern = re.compile(
        rb"<row\b(?=[^>]*\br\s*=\s*['\"]" + str(row_number).encode("ascii")
        + rb"['\"])[^>]*(?:/>|>.*?</row\s*>)", re.DOTALL,
    )
    row_match = row_pattern.search(payload)
    if row_match:
        row = row_match.group(0)
        if re.search(rb"/\s*>$", row):
            opening = re.sub(rb"/\s*>$", b">", row)
            updated = opening + cell + b"</row>"
        else:
            insertion = row.rfind(b"</row")
            for existing in re.finditer(rb"<c\b[^>]*\br\s*=\s*['\"]([A-Za-z]{1,3})[0-9]+['\"]", row):
                column = 0
                for char in existing.group(1).decode("ascii").upper():
                    column = column * 26 + ord(char) - 64
                if column > column_number:
                    insertion = existing.start()
                    break
            updated = row[:insertion] + cell + row[insertion:]
        return payload[:row_match.start()] + updated + payload[row_match.end():]

    sheet_data = re.search(rb"<sheetData\b[^>]*(?:/>|>.*?</sheetData\s*>)", payload,
                           re.DOTALL)
    if not sheet_data:
        raise SurgicalCellError("worksheet has no sheetData element")
    block = sheet_data.group(0)
    new_row = f'<row r="{row_number}">'.encode("ascii") + cell + b"</row>"
    if re.search(rb"/\s*>$", block):
        opening = re.sub(rb"/\s*>$", b">", block)
        updated = opening + new_row + b"</sheetData>"
    else:
        insertion = block.rfind(b"</sheetData")
        for existing in re.finditer(rb"<row\b[^>]*\br\s*=\s*['\"]([0-9]+)['\"]", block):
            if int(existing.group(1)) > row_number:
                insertion = existing.start()
                break
        updated = block[:insertion] + new_row + block[insertion:]
    return payload[:sheet_data.start()] + updated + payload[sheet_data.end():]


def set_cell(path: str, sheet_name: str, coordinate: str, value) -> dict:
    coordinate, row_number, column_number = normalize_coordinate(coordinate)
    part = worksheet_part(path, sheet_name)
    fd, replacement = tempfile.mkstemp(
        prefix=".agw-surgical-", suffix=".xlsx", dir=os.path.dirname(path)
    )
    os.close(fd)
    try:
        with zipfile.ZipFile(path) as source, zipfile.ZipFile(
                replacement, "w") as target:
            target.comment = source.comment
            before_payload = _part(source, part)
            cell_match = _find_cell(before_payload, coordinate)
            existing = cell_match.group(0) if cell_match else None
            cell = _new_cell(existing, coordinate, value)
            if cell_match:
                after_payload = (before_payload[:cell_match.start()] + cell
                                 + before_payload[cell_match.end():])
            else:
                after_payload = _insert_cell(
                    before_payload, coordinate, row_number, column_number, cell
                )
            for item in source.infolist():
                target.writestr(item, after_payload if item.filename == part
                                else source.read(item))
        os.replace(replacement, path)
        return {
            "part": part,
            "before_part_hash": hashlib.sha256(before_payload).hexdigest(),
            "after_part_hash": hashlib.sha256(after_payload).hexdigest(),
        }
    finally:
        if os.path.exists(replacement):
            try:
                os.unlink(replacement)
            except OSError:
                pass


def verify_cell(path: str, sheet_name: str, coordinate: str, expected) -> dict:
    actual = inspect_cell(path, sheet_name, coordinate)
    if actual["value"] != expected:
        raise SurgicalCellError(
            f"staged cell validation failed: expected {expected!r}, got {actual['value']!r}"
        )
    return {"adapter": "ooxml-surgical", "worksheet_part": actual["part"]}


def verify_preservation(before_path: str, after_path: str, worksheet: str) -> dict:
    with zipfile.ZipFile(before_path) as before, zipfile.ZipFile(after_path) as after:
        before_names = before.namelist()
        after_names = after.namelist()
        if before_names != after_names:
            raise SurgicalCellError("surgical edit changed the OOXML part inventory")
        for name in before_names:
            if name == worksheet:
                continue
            if hashlib.sha256(before.read(name)).digest() != hashlib.sha256(after.read(name)).digest():
                raise SurgicalCellError(f"surgical edit unexpectedly changed {name}")
        before_sheet = before.read(worksheet)
        after_sheet = after.read(worksheet)
        if _EXT_RE.findall(before_sheet) != _EXT_RE.findall(after_sheet):
            raise SurgicalCellError("worksheet extension content changed during cell edit")
    return {"verified": True, "adapter": "ooxml-surgical",
            "changed_parts": [worksheet], "unknown_parts_preserved": True}
