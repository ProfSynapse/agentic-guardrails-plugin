"""Structured, schema-agnostic Excel reads and named-table mutations."""
from __future__ import annotations

import copy
import datetime as dt
from typing import Optional

from core import store
try:
    from openpyxl.formula.translate import Translator
    from openpyxl.utils import get_column_letter, range_boundaries
except ImportError:  # optional dependency; _load() reports the actionable error
    Translator = get_column_letter = range_boundaries = None

import office_tx

MAX_INSPECTED_CELLS = 2_000_000
DEFAULT_LIMIT = 50
MAX_LIMIT = 500
MAX_RETURNED_CELLS = 10_000


class ExcelError(Exception):
    pass


def _openpyxl():
    try:
        import openpyxl
        return openpyxl
    except ImportError as exc:
        raise ExcelError(".xlsx support needs the 'openpyxl' package") from exc


def _load(path: str, *, data_only: bool = False):
    kwargs = {
        "data_only": data_only,
        "read_only": False,
        "keep_links": True,
    }
    try:
        return _openpyxl().load_workbook(path, rich_text=True, **kwargs)
    except TypeError:
        return _openpyxl().load_workbook(path, **kwargs)


def _actual_bounds(ws) -> dict:
    cells = getattr(ws, "_cells", None)
    if not isinstance(cells, dict):
        raise ExcelError("installed openpyxl lacks the supported sparse-cell interface")
    if len(cells) > MAX_INSPECTED_CELLS:
        raise ExcelError("worksheet has too many instantiated cells to inspect safely")
    min_row = min_col = max_row = max_col = None
    count = 0
    for cell in cells.values():
        if cell.value is None:
            continue
        count += 1
        min_row = cell.row if min_row is None else min(min_row, cell.row)
        max_row = cell.row if max_row is None else max(max_row, cell.row)
        min_col = cell.column if min_col is None else min(min_col, cell.column)
        max_col = cell.column if max_col is None else max(max_col, cell.column)
    used = None
    rows = cols = 0
    if count:
        used = (
            f"{get_column_letter(min_col)}{min_row}:"
            f"{get_column_letter(max_col)}{max_row}"
        )
        rows = max_row - min_row + 1
        cols = max_col - min_col + 1
    return {
        "used_range": used,
        "rows": rows,
        "cols": cols,
        "nonempty_cells": count,
        "worksheet_dimension": ws.calculate_dimension(),
    }


def _table_headers(ws, table):
    min_col, min_row, max_col, _ = range_boundaries(table.ref)
    headers = [ws.cell(min_row, col).value for col in range(min_col, max_col + 1)]
    if any(value is None or str(value).strip() == "" for value in headers):
        raise ExcelError(f"table {table.displayName!r} has blank headers")
    names = [str(value) for value in headers]
    folded = [value.casefold() for value in names]
    if len(set(folded)) != len(folded):
        raise ExcelError(f"table {table.displayName!r} has duplicate headers")
    return names


def _find_table(wb, name: str, sheet: str = ""):
    matches = []
    for ws in wb.worksheets:
        if sheet and ws.title.casefold() != sheet.casefold():
            continue
        for table in ws.tables.values():
            display = getattr(table, "displayName", None) or getattr(table, "name", "")
            if str(display).casefold() == name.casefold():
                matches.append((ws, table))
    if not matches:
        raise ExcelError(f"no table named {name!r}")
    if len(matches) != 1:
        where = ", ".join(ws.title for ws, _ in matches)
        raise ExcelError(f"table name {name!r} is ambiguous across sheets: {where}")
    return matches[0]


def _totals_count(table) -> int:
    count = getattr(table, "totalsRowCount", None)
    if count is not None:
        return int(count)
    return 1 if getattr(table, "totalsRowShown", False) else 0


def workbook_info(path: str, scope: str = "") -> dict:
    office_tx._package_preflight(path, mutating=False)
    wb = _load(path)
    try:
        sheets = []
        for ws in wb.worksheets:
            bounds = _actual_bounds(ws)
            tables = []
            for table in ws.tables.values():
                headers = _table_headers(ws, table)
                min_col, min_row, max_col, max_row = range_boundaries(table.ref)
                totals = _totals_count(table)
                tables.append({
                    "name": table.displayName,
                    "ref": table.ref,
                    "headers": headers,
                    "rows": max(0, max_row - min_row - totals),
                    "totals_row": bool(totals),
                })
            item = {"name": ws.title, **bounds}
            if scope in ("", "tables"):
                item["tables"] = tables
            if scope == "":
                item["merged_ranges"] = [str(value) for value in ws.merged_cells.ranges]
            sheets.append(item)
        names = []
        if scope in ("", "names"):
            try:
                values = wb.defined_names.values()
            except AttributeError:
                values = wb.defined_names.definedName
            for value in values:
                names.append({
                    "name": value.name,
                    "attr_text": value.attr_text,
                    "local_sheet_id": value.localSheetId,
                })
        result = {"type": "xlsx", "hash": store.file_sha256(path)}
        if scope != "names":
            result["sheets"] = sheets
        if scope in ("", "names"):
            result["defined_names"] = names
        return result
    finally:
        wb.close()


def _json_value(value, cell=None):
    if isinstance(value, dt.datetime) and cell is not None:
        fmt = (cell.number_format or "").lower()
        if not any(token in fmt for token in ("h", "s")):
            return value.date().isoformat()
    if isinstance(value, (dt.datetime, dt.date, dt.time)):
        return value.isoformat()
    return value


def read_table(
    path: str,
    table_name: str,
    *,
    sheet: str = "",
    columns: Optional[list[str]] = None,
    where: Optional[dict] = None,
    offset: int = 0,
    limit: int = DEFAULT_LIMIT,
    values_only: bool = False,
) -> dict:
    if offset < 0 or limit < 1 or limit > MAX_LIMIT:
        raise ExcelError(f"offset must be >= 0 and limit must be 1..{MAX_LIMIT}")
    office_tx._package_preflight(path, mutating=False)
    wb = _load(path, data_only=values_only)
    try:
        ws, table = _find_table(wb, table_name, sheet)
        headers = _table_headers(ws, table)
        selected = columns or headers
        unknown = [name for name in selected if name not in headers]
        if unknown:
            raise ExcelError(f"unknown table column(s): {', '.join(unknown)}")
        if len(selected) != len(set(selected)):
            raise ExcelError("selected columns must be unique")
        where = where or {}
        unknown_where = [name for name in where if name not in headers]
        if unknown_where:
            raise ExcelError(f"unknown filter column(s): {', '.join(unknown_where)}")
        if len(selected) * limit > MAX_RETURNED_CELLS:
            raise ExcelError("requested table page exceeds the returned-cell limit")
        min_col, min_row, max_col, max_row = range_boundaries(table.ref)
        data_end = max_row - _totals_count(table)
        indexes = {name: min_col + headers.index(name) for name in headers}
        matched = []
        for row_no in range(min_row + 1, data_end + 1):
            if all(_json_value(ws.cell(row_no, indexes[key]).value,
                               ws.cell(row_no, indexes[key])) == expected
                   for key, expected in where.items()):
                matched.append(row_no)
        page = matched[offset:offset + limit]
        rows = [
            [_json_value(ws.cell(row_no, indexes[name]).value,
                         ws.cell(row_no, indexes[name])) for name in selected]
            for row_no in page
        ]
        return {
            "hash": store.file_sha256(path),
            "table": table.displayName,
            "sheet": ws.title,
            "ref": table.ref,
            "headers": selected,
            "rows": rows,
            "offset": offset,
            "returned": len(rows),
            "more": offset + len(rows) < len(matched),
            **({"cached_values_may_be_stale": True} if values_only else {}),
        }
    finally:
        wb.close()


def _column_is_date(ws, row: int, col: int) -> bool:
    cell = ws.cell(row, col)
    if getattr(cell, "is_date", False):
        return True
    fmt = (cell.number_format or "").lower()
    return any(token in fmt for token in ("yy", "dd", "mm", "hh", "ss"))


def _coerce(value, *, date_column: bool = False, coerce_iso_dates: bool = False):
    if isinstance(value, dict):
        if set(value) != {"$formula"} or not isinstance(value["$formula"], str):
            raise ExcelError("typed values support only {'$formula': '=...'}")
        formula = value["$formula"]
        if not formula.startswith("="):
            raise ExcelError("explicit formula must start with '='")
        lowered = formula.lower()
        if any(token in lowered for token in ("[", "dde(", "http:", "https:")):
            raise ExcelError("external-reference formulas are unsupported")
        return formula
    if isinstance(value, str) and (date_column or coerce_iso_dates):
        try:
            if "t" in value.lower() or " " in value:
                parsed = dt.datetime.fromisoformat(value)
                if parsed.tzinfo is not None:
                    raise ExcelError("timezone-aware Excel datetimes are unsupported")
                return parsed
            return dt.date.fromisoformat(value)
        except ValueError:
            pass
    return value


def _copy_cell_style(source, target):
    target._style = copy.copy(source._style)
    if source.has_style:
        target.number_format = source.number_format


def append_table_row(
    path: str,
    table_name: str,
    row: dict,
    *,
    sheet: str = "",
    expected_sha256: str = "",
    dry_run: bool = False,
    coerce_iso_dates: bool = False,
) -> dict:
    if not isinstance(row, dict) or not row:
        raise ExcelError("row JSON must be a non-empty object")
    expected_ref = {}

    def build_plan(live_path):
        wb = _load(live_path)
        try:
            ws, table = _find_table(wb, table_name, sheet)
            headers = _table_headers(ws, table)
            unknown = [name for name in row if name not in headers]
            if unknown:
                raise ExcelError(f"unknown table column(s): {', '.join(unknown)}")
            min_col, min_row, max_col, max_row = range_boundaries(table.ref)
            totals = _totals_count(table)
            target_row = max_row if totals else max_row + 1
            for col in range(min_col, max_col + 1):
                if not totals and ws.cell(target_row, col).value is not None:
                    raise ExcelError("table expansion would overwrite populated cells")
            new_ref = (
                f"{get_column_letter(min_col)}{min_row}:"
                f"{get_column_letter(max_col)}{max_row + 1}"
            )
            expected_ref.update({
                "old": table.ref, "new": new_ref, "target_row": target_row,
                "headers": headers,
            })
            return office_tx.MutationPlan(
                "append-table-row",
                {"table": table.displayName, "sheet": ws.title,
                 "old_ref": table.ref, "new_ref": new_ref},
                {"affected": 1},
            )
        finally:
            wb.close()

    def apply(stage, _plan):
        wb = _load(stage)
        try:
            ws, table = _find_table(wb, table_name, sheet)
            min_col, min_row, max_col, max_row = range_boundaries(table.ref)
            totals = _totals_count(table)
            target_row = max_row if totals else max_row + 1
            if totals:
                ws.insert_rows(target_row, 1)
            template_row = target_row - 1
            if template_row <= min_row:
                template_row = min_row
            if ws.row_dimensions[template_row].height is not None:
                ws.row_dimensions[target_row].height = ws.row_dimensions[template_row].height
            headers = expected_ref["headers"]
            for offset, header in enumerate(headers):
                col = min_col + offset
                source = ws.cell(template_row, col)
                target = ws.cell(target_row, col)
                _copy_cell_style(source, target)
                if header in row:
                    target.value = _coerce(
                        row[header],
                        date_column=_column_is_date(ws, template_row, col),
                        coerce_iso_dates=coerce_iso_dates,
                    )
                elif isinstance(source.value, str) and source.value.startswith("="):
                    target.value = Translator(
                        source.value, origin=source.coordinate
                    ).translate_formula(target.coordinate)
                else:
                    target.value = None
            table.ref = expected_ref["new"]
            if getattr(table, "autoFilter", None) is not None:
                table.autoFilter.ref = expected_ref["new"]
            wb.save(stage)
        finally:
            wb.close()

    def validate(stage, _plan):
        wb = _load(stage)
        try:
            ws, table = _find_table(wb, table_name, sheet)
            if table.ref != expected_ref["new"]:
                raise ExcelError("staged table reference did not expand as planned")
            return {"appended": 1}
        finally:
            wb.close()

    try:
        return office_tx.execute_mutation(
            path, operation="append-table-row", plan=build_plan,
            apply=apply, validate=validate,
            expected_sha256=expected_sha256 or None, dry_run=dry_run,
        )
    except office_tx.TransactionError as exc:
        raise ExcelError(str(exc)) from exc


def update_table_row(
    path: str,
    table_name: str,
    key_column: str,
    key,
    updates: dict,
    *,
    sheet: str = "",
    expected_sha256: str = "",
    dry_run: bool = False,
    coerce_iso_dates: bool = False,
) -> dict:
    if not isinstance(updates, dict) or not updates:
        raise ExcelError("set JSON must be a non-empty object")
    target = {}

    def build_plan(live_path):
        wb = _load(live_path)
        try:
            ws, table = _find_table(wb, table_name, sheet)
            headers = _table_headers(ws, table)
            if key_column not in headers:
                raise ExcelError(f"unknown key column: {key_column}")
            unknown = [name for name in updates if name not in headers]
            if unknown:
                raise ExcelError(f"unknown table column(s): {', '.join(unknown)}")
            min_col, min_row, _, max_row = range_boundaries(table.ref)
            data_end = max_row - _totals_count(table)
            key_col = min_col + headers.index(key_column)
            matches = [
                row_no for row_no in range(min_row + 1, data_end + 1)
                if ws.cell(row_no, key_col).value == key
                or (isinstance(key, str) and str(ws.cell(row_no, key_col).value) == key)
            ]
            if len(matches) != 1:
                raise ExcelError(
                    f"expected exactly one matching row; found {len(matches)}"
                )
            target.update({"row": matches[0], "min_col": min_col, "headers": headers})
            changed = sum(
                ws.cell(matches[0], min_col + headers.index(name)).value != value
                for name, value in updates.items()
            )
            return office_tx.MutationPlan(
                "update-table-row",
                {"table": table.displayName, "sheet": ws.title,
                 "matched": 1, "fields": len(updates)},
                {"affected": changed},
                changed=bool(changed),
            )
        finally:
            wb.close()

    def apply(stage, _plan):
        wb = _load(stage)
        try:
            ws, _table = _find_table(wb, table_name, sheet)
            for name, value in updates.items():
                col = target["min_col"] + target["headers"].index(name)
                ws.cell(target["row"], col).value = _coerce(
                    value,
                    date_column=_column_is_date(ws, target["row"], col),
                    coerce_iso_dates=coerce_iso_dates,
                )
            wb.save(stage)
        finally:
            wb.close()

    def validate(stage, _plan):
        wb = _load(stage)
        try:
            ws, _table = _find_table(wb, table_name, sheet)
            for name, value in updates.items():
                col = target["min_col"] + target["headers"].index(name)
                expected = _coerce(
                    value,
                    date_column=_column_is_date(ws, target["row"], col),
                    coerce_iso_dates=coerce_iso_dates,
                )
                if ws.cell(target["row"], col).value != expected:
                    raise ExcelError(f"staged value validation failed for {name!r}")
            return {"updated": 1}
        finally:
            wb.close()

    try:
        return office_tx.execute_mutation(
            path, operation="update-table-row", plan=build_plan,
            apply=apply, validate=validate,
            expected_sha256=expected_sha256 or None, dry_run=dry_run,
        )
    except office_tx.TransactionError as exc:
        raise ExcelError(str(exc)) from exc
