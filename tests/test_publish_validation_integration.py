from pathlib import Path

import pytest

import agw as agw_cli
from core import store


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
