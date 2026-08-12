"""Policy-pack retention settings must govern real CLI store mutations."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

import agw as agw_cli
import file_ops
import office
import office_tx
from core import retention_policy, store


PLUGIN = Path(__file__).resolve().parents[1] / "plugin"
AGW = PLUGIN / "scripts" / "agw" / "agw.py"


def _policy_root(tmp_path: Path, *, maximum: int,
                 high: int | None = None, low: int | None = None,
                 protected_days: int = 7, inactive_days: int = 30) -> Path:
    root = tmp_path / "policy-plugin"
    policies = root / "policies"
    policies.mkdir(parents=True)
    settings = [
        f"  archive_max_bytes: {maximum}",
        f"  archive_min_protected_age_days: {protected_days}",
        f"  archive_inactive_collapse_age_days: {inactive_days}",
        "  archive_max_candidates: 256",
        f"  archive_max_reclaim_bytes: {retention_policy.GIB}",
    ]
    if high is not None:
        settings.append(f"  archive_high_water_bytes: {high}")
    if low is not None:
        settings.append(f"  archive_low_water_bytes: {low}")
    (policies / "core.yaml").write_text(
        "settings:\n" + "\n".join(settings) + "\n", encoding="utf-8"
    )
    return root


def _run(root: Path, *args: str, check: bool = True):
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=str(root))
    result = subprocess.run(
        [sys.executable, str(AGW), *args], capture_output=True, text=True,
        encoding="utf-8", env=env, timeout=30,
    )
    if check and result.returncode:
        raise AssertionError(result.stderr)
    return result


def test_policy_file_hard_cap_controls_status_and_archive_admission(tmp_path):
    root = _policy_root(tmp_path, maximum=64)
    source = tmp_path / "must-survive.txt"
    source.write_text("x" * 256, encoding="utf-8")

    status = json.loads(_run(root, "--json", "status").stdout)
    assert status["retention"]["max_bytes"] == 64

    refused = _run(root, "--json", "archive", str(source), check=False)
    assert refused.returncode == 4
    error = json.loads(refused.stderr)["error"]
    assert error["code"] == "archive_capacity_exceeded"
    assert error["details"]["maximum_bytes"] == 64
    assert source.read_text(encoding="utf-8") == "x" * 256
    assert store.archive_size_bytes() == 0


def test_policy_file_watermarks_control_automatic_cli_maintenance(tmp_path):
    source = tmp_path / "cache-source.bin"
    source.write_bytes(b"a" * 4096)
    first = store.archive_file(
        str(source), mode="copy", retention_class="mutation_preimage",
        retention_config=retention_policy.resolve_retention_policy(
            {"archive_max_bytes": 0}, {}
        ),
    )
    source.write_bytes(b"b" * 4096)
    second = store.archive_file(
        str(source), mode="copy", retention_class="mutation_preimage",
        retention_config=retention_policy.resolve_retention_policy(
            {"archive_max_bytes": 0}, {}
        ),
    )
    incoming = tmp_path / "incoming.txt"
    incoming.write_text("safe", encoding="utf-8")
    maximum = store.archive_size_bytes() + incoming.stat().st_size + 4096
    root = _policy_root(
        tmp_path, maximum=maximum, high=1, low=0,
        protected_days=0, inactive_days=0,
    )

    _run(root, "--json", "archive", str(incoming))

    assert not Path(first["dest"]).exists()
    assert Path(second["dest"]).exists()
    assert not incoming.exists()


def test_file_mutation_loads_policy_pack_for_preimage_admission(tmp_path,
                                                               monkeypatch):
    root = _policy_root(tmp_path, maximum=64)
    monkeypatch.setattr(file_ops, "PLUGIN_ROOT", str(root))
    target = tmp_path / "protected.txt"
    target.write_text("before" * 64, encoding="utf-8")
    before_hash = store.file_sha256(str(target))

    with pytest.raises(file_ops.FileOperationError) as failure:
        file_ops.write_text(
            str(target), "after", expected_hash=before_hash,
            operation="policy-propagation-test",
        )

    assert "configured capacity" in str(failure.value)
    assert target.read_text(encoding="utf-8") == "before" * 64


def test_restore_and_transaction_undo_forward_exact_resolved_policy(
        monkeypatch, tmp_path, capsys):
    expected = retention_policy.resolve_retention_policy(
        {"archive_max_bytes": 1234}, {}
    )
    monkeypatch.setattr(agw_cli.retention_config, "load", lambda _root: expected)
    seen = {}

    def fake_restore(path, version=0, retention_config=None):
        seen["restore"] = retention_config
        return {"version": version or 1}

    def fake_undo(transaction, retention_config=None):
        seen["undo"] = retention_config
        return {"undid_transaction_id": transaction, "operations": []}

    monkeypatch.setattr(agw_cli.store, "restore", fake_restore)
    monkeypatch.setattr(agw_cli.store, "undo_transaction", fake_undo)
    agw_cli.cmd_restore(SimpleNamespace(
        path=str(tmp_path / "target.txt"), version=0, json=True,
    ))
    agw_cli.cmd_undo(SimpleNamespace(transaction="tx-1", json=True))
    capsys.readouterr()

    assert seen == {"restore": expected, "undo": expected}


def test_office_snapshot_boundaries_forward_exact_resolved_policy(monkeypatch):
    expected = retention_policy.resolve_retention_policy(
        {"archive_max_bytes": 1234}, {}
    )
    seen = []

    def fake_archive(path, **kwargs):
        seen.append(kwargs["retention_config"])
        return {"sha256": "before"}

    monkeypatch.setattr(office.retention_config, "load", lambda: expected)
    monkeypatch.setattr(office.store, "archive_file", fake_archive)
    office._snapshot("book.docx", "replace-text")

    monkeypatch.setattr(office_tx.retention_config, "load", lambda: expected)
    monkeypatch.setattr(office_tx.store, "archive_file", fake_archive)
    office_tx._archive_mutation_preimage("book.xlsx", "set-cell", "before")

    assert seen == [expected, expected]
