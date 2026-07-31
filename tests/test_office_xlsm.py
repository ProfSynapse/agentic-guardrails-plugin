"""Macro-enabled Excel checkout, preservation, edit, and publish contracts."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

import pytest

openpyxl = pytest.importorskip("openpyxl")

REPO = Path(__file__).resolve().parents[1] / "plugin"
AGW = REPO / "scripts" / "agw" / "agw.py"
sys.path.insert(0, str(REPO / "scripts" / "agw"))

import office_surgical  # noqa: E402
import office_tx  # noqa: E402
import agw as agw_cli  # noqa: E402
from core import store  # noqa: E402


def run_agw(*args, env=None, check=True):
    process_env = dict(os.environ)
    if env:
        process_env.update(env)
    result = subprocess.run(
        [sys.executable, str(AGW), *map(str, args)],
        capture_output=True, text=True, encoding="utf-8", env=process_env,
    )
    if check and result.returncode:
        raise AssertionError(result.stderr)
    return result


def make_synthetic_xlsm(path: Path, *, value="base") -> Path:
    """Build a readable OOXML fixture with a deterministic synthetic VBA part."""
    xlsx = path.with_suffix(".xlsx")
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "Data"
    sheet["A1"] = value
    workbook.save(xlsx)
    with zipfile.ZipFile(xlsx) as source, zipfile.ZipFile(
            path, "w", zipfile.ZIP_DEFLATED) as target:
        for item in source.infolist():
            payload = source.read(item)
            if item.filename == "[Content_Types].xml":
                payload = payload.replace(
                    b"application/vnd.openxmlformats-officedocument."
                    b"spreadsheetml.sheet.main+xml",
                    b"application/vnd.ms-excel.sheet.macroEnabled.main+xml",
                ).replace(
                    b"</Types>",
                    (b'<Override PartName="/xl/vbaProject.bin" '
                     b'ContentType="application/vnd.ms-office.vbaProject"/>'
                     b"</Types>"),
                )
            elif item.filename == "xl/_rels/workbook.xml.rels":
                payload = payload.replace(
                    b"</Relationships>",
                    (b'<Relationship Id="rIdAgwVba" '
                     b'Type="http://schemas.microsoft.com/office/2006/'
                     b'relationships/vbaProject" Target="vbaProject.bin"/>'
                     b"</Relationships>"),
                )
            target.writestr(item, payload)
        target.writestr("xl/vbaProject.bin", b"AGW-SYNTHETIC-VBA\x00\x01\x02")
    xlsx.unlink()
    return path


def rewrite_part(path: Path, part: str, transform) -> None:
    replacement = path.with_suffix(path.suffix + ".rewrite")
    with zipfile.ZipFile(path) as source, zipfile.ZipFile(
            replacement, "w", zipfile.ZIP_DEFLATED) as target:
        for item in source.infolist():
            payload = source.read(item)
            target.writestr(item, transform(payload) if item.filename == part else payload)
    os.replace(replacement, path)


def test_manifest_and_validation_track_vba_exactly(tmp_path):
    original = make_synthetic_xlsm(tmp_path / "macro.xlsm")
    candidate = tmp_path / "candidate.xlsm"
    shutil.copy2(original, candidate)
    manifest = office_tx.package_preservation_manifest(str(original))
    assert manifest["schema"] == "agw-office-preservation-v1"
    assert manifest["categories"] == {"vba": 1}
    assert manifest["protected_parts"]["xl/vbaProject.bin"]["bytes"] > 0

    office_surgical.set_cell(str(candidate), "Data", "B2", "safe")
    verified = office_tx.validate_package_preservation(str(original), str(candidate))
    assert verified["verified"] is True
    assert verified["macros_unchanged"] is True

    rewrite_part(candidate, "xl/vbaProject.bin", lambda payload: payload + b"tampered")
    with pytest.raises(office_tx.PreservationError) as error:
        office_tx.validate_package_preservation(str(original), str(candidate))
    assert error.value.details["risks"][0]["code"] == "altered_protected_ooxml_part"


def test_info_reports_xlsm_protected_content_without_mutation(tmp_path):
    target = make_synthetic_xlsm(tmp_path / "macro.xlsm")
    before = store.file_sha256(str(target))
    info = json.loads(run_agw("office", "info", target, "--json").stdout)
    assert info["type"] == "xlsm"
    assert info["macro_preservation"]["categories"] == {"vba": 1}
    scoped = json.loads(run_agw(
        "office", "info", target, "--scope", "preservation", "--json"
    ).stdout)
    assert scoped["protected_parts"]["xl/vbaProject.bin"]["sha256"]
    assert store.file_sha256(str(target)) == before


def test_set_cell_supports_xlsm_with_exact_unrelated_part_preservation(
        tmp_path, agw_home):
    target = make_synthetic_xlsm(tmp_path / "macro.xlsm")
    with zipfile.ZipFile(target) as package:
        vba_before = package.read("xl/vbaProject.bin")
    before = store.file_sha256(str(target))
    result = run_agw(
        "office", "set-cell", target, "--sheet", "Data", "--cell", "B2",
        "--value", "updated", "--expected-file-hash", before, "--json",
    )
    data = json.loads(result.stdout)
    assert data["adapter"] == "ooxml-surgical"
    assert data["preservation"]["unknown_parts_preserved"] is True
    assert data["macro_preservation"] == {"vba": 1}
    assert office_surgical.inspect_cell(str(target), "Data", "B2")["value"] == "updated"
    with zipfile.ZipFile(target) as package:
        assert package.read("xl/vbaProject.bin") == vba_before
    assert Path(store.list_versions(str(target))[0]["dest"]).exists()


def test_xlsm_checkout_defaults_outside_source_and_publishes_safely(
        tmp_path, agw_home):
    target = make_synthetic_xlsm(tmp_path / "macro.xlsm")
    checkout = json.loads(run_agw("checkout", target, "--json").stdout)
    working = Path(checkout["dest"])
    assert checkout["checkout_mode"] == "preserve"
    assert Path(checkout["workspace"]).is_relative_to(Path(agw_home))
    assert working.parent != target.parent
    office_surgical.set_cell(str(working), "Data", "C3", 42)

    published = json.loads(run_agw("publish", target, "--json").stdout)
    assert published["office_validation"]["macros_unchanged"] is True
    assert office_surgical.inspect_cell(str(target), "Data", "C3")["value"] == 42
    assert Path(store.list_versions(str(target))[0]["dest"]).exists()


def test_publish_file_refuses_macro_loss_before_live_change(tmp_path, agw_home):
    target = make_synthetic_xlsm(tmp_path / "live.xlsm")
    stage = tmp_path / "stage.xlsm"
    shutil.copy2(target, stage)
    rewrite_part(stage, "xl/vbaProject.bin", lambda payload: payload + b"lost")
    before = store.file_sha256(str(target))
    result = run_agw(
        "publish-file", "--staged", stage, "--target", target,
        "--expected-hash", before, "--json", check=False,
    )
    assert result.returncode != 0
    error = json.loads(result.stderr)["error"]
    assert error["code"] == "office_preservation_risk"
    assert store.file_sha256(str(target)) == before
    assert store.list_versions(str(target)) == []


def test_publish_file_rejects_invalid_xlsx_before_snapshot(tmp_path, agw_home):
    target = tmp_path / "live.xlsx"
    stage = tmp_path / "stage.xlsx"
    target.write_bytes(b"existing non-office placeholder")
    stage.write_bytes(b"not an OOXML package")
    before = store.file_sha256(str(target))
    result = run_agw(
        "publish-file", "--staged", stage, "--target", target,
        "--expected-hash", before, "--json", check=False,
    )
    assert result.returncode != 0
    error = json.loads(result.stderr)["error"]
    assert error["code"] == "unsupported_office_file"
    assert store.file_sha256(str(target)) == before
    assert store.list_versions(str(target)) == []


def test_publish_file_accepts_valid_xlsm_and_new_target_needs_baseline(
        tmp_path, agw_home):
    original = make_synthetic_xlsm(tmp_path / "original.xlsm")
    stage = tmp_path / "stage.xlsm"
    shutil.copy2(original, stage)
    office_surgical.set_cell(str(stage), "Data", "D4", "published")
    live_hash = store.file_sha256(str(original))
    published = json.loads(run_agw(
        "publish-file", "--staged", stage, "--target", original,
        "--expected-hash", live_hash, "--json",
    ).stdout)
    assert published["office_validation"]["macros_unchanged"] is True

    shutil.copy2(original, stage)
    new_target = tmp_path / "new.xlsm"
    refused = run_agw(
        "publish-file", "--staged", stage, "--target", new_target,
        "--expected-hash", "absent", "--json", check=False,
    )
    assert refused.returncode != 0
    assert "--preserve-against" in refused.stderr

    created = json.loads(run_agw(
        "publish-file", "--staged", stage, "--target", new_target,
        "--expected-hash", "absent", "--preserve-against", original,
        "--expected-preservation-hash", store.file_sha256(str(original)), "--json",
    ).stdout)
    assert created["office_validation"]["verified"] is True
    assert new_target.exists()


def test_validate_preservation_cli_and_checkout_workspace_override(tmp_path, agw_home):
    original = make_synthetic_xlsm(tmp_path / "original.xlsm")
    candidate = tmp_path / "candidate.xlsm"
    shutil.copy2(original, candidate)
    validated = json.loads(run_agw(
        "office", "validate-preservation", candidate,
        "--against", original, "--json",
    ).stdout)
    assert validated["verified"] is True

    custom = tmp_path / "local-work"
    checkout = json.loads(run_agw(
        "checkout", original, "--workspace-dir", custom, "--json",
    ).stdout)
    assert Path(checkout["workspace"]) == custom
    assert Path(checkout["dest"]).parent == custom


def test_publish_file_implicitly_guards_drift_during_preservation_check(
        tmp_path, monkeypatch, capsys):
    target = make_synthetic_xlsm(tmp_path / "live.xlsm")
    stage = tmp_path / "stage.xlsm"
    shutil.copy2(target, stage)
    original_validate = office_tx.validate_package_preservation

    def validate_then_external_edit(*args, **kwargs):
        result = original_validate(*args, **kwargs)
        office_surgical.set_cell(str(target), "Data", "F6", "external-edit")
        return result

    monkeypatch.setattr(
        office_tx, "validate_package_preservation", validate_then_external_edit
    )
    args = type("Args", (), {
        "staged": str(stage), "target": str(target),
        "expected_hash": "", "expected_staged_hash": "",
        "preserve_against": "", "expected_preservation_hash": "",
        "dry_run": False, "retry_seconds": 0.0, "json": True,
    })()
    with pytest.raises(SystemExit) as stopped:
        agw_cli.cmd_publish_file(args)
    assert stopped.value.code == 3
    assert office_surgical.inspect_cell(str(target), "Data", "F6")["value"] == \
        "external-edit"
    assert stage.exists()
    error = json.loads(capsys.readouterr().err)["error"]
    assert error["code"] == "file_hash_conflict"
