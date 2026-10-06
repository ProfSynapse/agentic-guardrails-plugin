"""A startup failure must deny even before pretooluse can install its handler."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


DISPATCH = Path(__file__).resolve().parents[1] / "plugin/scripts/codex/_dispatch.py"


@pytest.mark.parametrize("failure", ["missing", "import", "syntax"])
def test_codex_dispatch_startup_failure_denies(tmp_path, failure):
    dispatch = tmp_path / "_dispatch.py"
    shutil.copyfile(DISPATCH, dispatch)
    if failure == "import":
        (tmp_path / "pretooluse.py").write_text(
            "raise ImportError('synthetic startup failure')\n", encoding="utf-8"
        )
    elif failure == "syntax":
        (tmp_path / "pretooluse.py").write_text("if :\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(dispatch), "pretooluse"],
        input="{}", text=True, capture_output=True, timeout=10,
        env=dict(os.environ, AGW_HOME=str(tmp_path / "store")),
    )
    assert result.returncode == 0
    output = json.loads(result.stdout)  # exactly one valid decision
    from codex_wire_contract import validate_wire
    validate_wire(output)
    decision = output["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    assert "failing closed" in decision["permissionDecisionReason"]
    assert "synthetic startup failure" not in result.stdout


@pytest.mark.parametrize("event", ["sessionstart", "posttooluse"])
def test_codex_dispatch_nonblocking_events_do_not_emit_pretooluse_denial(tmp_path, event):
    dispatch = tmp_path / "_dispatch.py"
    shutil.copyfile(DISPATCH, dispatch)
    result = subprocess.run(
        [sys.executable, str(dispatch), event],
        input="{}", text=True, capture_output=True, timeout=10,
        env=dict(os.environ, AGW_HOME=str(tmp_path / "store")),
    )
    assert result.returncode == 0
    assert not result.stdout.strip()
