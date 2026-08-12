from pathlib import Path

import pytest

import agw as agw_cli
from core import store
import file_ops


def test_checkout_publish_uses_shared_office_validation_boundary(tmp_path, monkeypatch):
    source = tmp_path / "live.xlsx"
    working = tmp_path / "working.xlsx"
    source.write_bytes(b"live")
    working.write_bytes(b"candidate")
    state = store.state_load()
    state["checkouts"][str(source)] = {
        "working": str(working), "base_sha256": store.file_sha256(str(source)),
        "checkout_mode": "preserve", "mode": "copy", "workspace": str(tmp_path),
    }
    store.state_save(state)

    def convert(_working, _source, output):
        Path(output).write_bytes(b"invalid-package")
        return {"mode": "copy"}

    validated = []

    def refuse(path, extension, requested_tier="auto"):
        validated.append((path, extension, requested_tier))
        raise agw_cli.office_tx.UnsupportedOfficeFile("invalid package")

    published = []
    monkeypatch.setattr(agw_cli.converters, "to_original_format", convert)
    monkeypatch.setattr(agw_cli, "_validate_office_stage", refuse)
    monkeypatch.setattr(
        agw_cli.file_ops, "publish_staged_file",
        lambda *args, **kwargs: published.append(args),
    )
    args = type("Args", (), {
        "path": str(source), "force": False, "retry_seconds": 0.0, "json": True,
    })()

    with pytest.raises(SystemExit):
        agw_cli.cmd_publish(args)
    assert validated and validated[0][1] == ".xlsx"
    assert published == []


def test_publish_plan_office_callback_returns_package_and_preservation_receipts(
        tmp_path, monkeypatch):
    baseline = tmp_path / "baseline.xlsm"
    candidate = tmp_path / "candidate.xlsm"
    baseline.write_bytes(b"baseline")
    candidate.write_bytes(b"candidate")
    digest = store.file_sha256(str(baseline))
    calls = []
    monkeypatch.setattr(
        agw_cli.office_tx, "validate_office_package",
        lambda path, tier: calls.append(("package", path, tier)) or {
            "valid": True, "tier": tier,
        },
    )
    monkeypatch.setattr(
        agw_cli.office_tx, "validate_package_preservation",
        lambda original, staged, expected_original_sha256: calls.append((
            "preservation", original, staged, expected_original_sha256,
        )) or {"valid": True, "protected_part_count": 3},
    )

    receipt = agw_cli._publication_candidate_validator(str(candidate), {
        "target": str(tmp_path / "live.xlsm"),
        "validation": {
            "kind": "office", "tier": "excel-strict",
            "preserve_against": str(baseline),
            "preserve_against_sha256": digest,
        },
    })

    assert receipt["valid"] is True
    assert receipt["package_validation"] is True
    assert receipt["preservation_validation"] is True
    assert receipt["candidate_sha256"] == store.file_sha256(str(candidate))
    assert receipt["baseline_expected_sha256"] == digest
    assert receipt["baseline_actual_sha256"] == digest
    assert calls[1][-1] == digest


def test_publish_plan_xlsm_requires_authenticated_preservation(tmp_path, monkeypatch):
    candidate = tmp_path / "candidate.xlsm"
    candidate.write_bytes(b"candidate")
    monkeypatch.setattr(
        agw_cli.office_tx, "validate_office_package",
        lambda path, tier: {"valid": True, "tier": tier},
    )
    with pytest.raises(file_ops.FileOperationError, match="authenticated"):
        agw_cli._publication_candidate_validator(str(candidate), {
            "target": str(tmp_path / "live.xlsm"),
            "validation": {
                "kind": "office", "tier": "excel-strict",
                "preserve_against": "", "preserve_against_sha256": "",
            },
        })
