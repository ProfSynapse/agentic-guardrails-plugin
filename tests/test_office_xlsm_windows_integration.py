"""Opt-in native Excel + synced-folder integration for macro workbooks."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugin"
AGW = PLUGIN / "scripts" / "agw" / "agw.py"
EXCEL_SMOKE = Path(__file__).parent / "fixtures" / "excel_xlsm_smoke.ps1"
sys.path.insert(0, str(PLUGIN / "scripts" / "agw"))

import office_surgical  # noqa: E402


def _run_agw(*args, env):
    result = subprocess.run(
        [sys.executable, str(AGW), *map(str, args)],
        capture_output=True, text=True, encoding="utf-8", env=env,
    )
    if result.returncode:
        raise AssertionError(result.stderr)
    return json.loads(result.stdout)


def _excel(operation, path, *, cell="B2", value="edited-by-excel"):
    result = subprocess.run(
        [
            "powershell.exe", "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-File", str(EXCEL_SMOKE),
            "-Operation", operation, "-Path", str(path),
            "-Cell", cell, "-Value", value,
        ],
        capture_output=True, text=True, encoding="utf-8", timeout=120,
    )
    if result.returncode:
        raise AssertionError(result.stderr or result.stdout)
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.mark.skipif(os.name != "nt", reason="native Excel integration is Windows-only")
def test_native_excel_synced_xlsm_checkout_validate_publish(tmp_path):
    configured = os.environ.get("AGW_XLSM_INTEGRATION_ROOT", "").strip()
    if not configured:
        pytest.skip("set AGW_XLSM_INTEGRATION_ROOT for the opt-in Drive smoke test")
    drive_root = Path(configured)
    if not drive_root.is_dir():
        pytest.skip(f"integration root is unavailable: {drive_root}")

    stamp = time.strftime("%Y%m%d-%H%M%S")
    test_folder = drive_root / f"AGW XLSM Integration Test {stamp}"
    test_folder.mkdir()
    live = test_folder / "macro-workbook.xlsm"
    created = _excel("create", live)
    assert live.is_file()

    env = dict(os.environ)
    env["AGW_HOME"] = str(tmp_path / "agw-home")
    checkout = _run_agw("checkout", live, "--json", env=env)
    working = Path(checkout["dest"])
    assert working.is_file()
    assert not working.is_relative_to(drive_root)

    _excel("edit", working, cell="B2", value="published-from-local-checkout")
    validation = _run_agw(
        "office", "validate-preservation", working,
        "--against", live, "--json", env=env,
    )
    assert validation["verified"] is True

    published = _run_agw("publish", live, "--json", env=env)
    assert published["office_validation"]["verified"] is True
    assert office_surgical.inspect_cell(str(live), "Data", "B2")["value"] == \
        "published-from-local-checkout"

    receipt = {
        "test_folder": str(test_folder),
        "live": str(live),
        "working": str(working),
        "macro_injected": created["macro_injected"],
        "office_validation": published["office_validation"],
        "publication": published["publication"],
    }
    (tmp_path / "integration-result.json").write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print("AGW_XLSM_INTEGRATION_RESULT=" + json.dumps(receipt, ensure_ascii=False))
