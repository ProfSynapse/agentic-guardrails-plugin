"""Default release contract: host history replaces a duplicate audit ledger."""
import importlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time

from core import auditlog


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugin"


def _hook(host, payload, home):
    script = PLUGIN / "scripts" / host / "pretooluse.py"
    env = dict(os.environ, AGW_HOME=str(home), AGW_TEST_MODE="1")
    env.pop("PYTHONPATH", None)
    if host == "codex":
        env.update({
            "PLUGIN_ROOT": str(PLUGIN),
            "CODEX_HOME": str(home / "codex-home"),
            "AGW_APPROVAL_PROVIDER": "headless",
        })
    else:
        env["CLAUDE_PLUGIN_ROOT"] = str(PLUGIN)
        env.pop("PLUGIN_ROOT", None)
    started = time.perf_counter()
    result = subprocess.run(
        [sys.executable, str(script)], input=json.dumps(payload),
        capture_output=True, text=True, env=env, timeout=10,
    )
    elapsed = time.perf_counter() - started
    assert result.returncode == 0, result.stderr
    return result.stdout, elapsed


def test_compatibility_api_is_successful_memoryless_and_creates_nothing(
        tmp_path, monkeypatch):
    home = tmp_path / "must-not-be-created"
    monkeypatch.setenv("AGW_HOME", str(home))
    status = auditlog.log("pretooluse", {
        "command": "PRIVATE-CANARY", "path": "PRIVATE-CANARY"
    })
    assert status == auditlog.AuditStatus(True, "host-history")
    assert auditlog.status() == status
    assert auditlog.build_record("pretooluse", {"command": "PRIVATE-CANARY"}) is None
    assert auditlog.tail(100) == []
    assert not home.exists()


def test_existing_legacy_and_quarantine_bytes_are_never_read_or_changed(
        tmp_path, monkeypatch):
    home = tmp_path / "existing-home"
    quarantine = home / "legacy-audit-quarantine"
    quarantine.mkdir(parents=True)
    ledger = home / "audit.jsonl"
    retained = quarantine / "retained.private"
    ledger_bytes = b"LEGACY-PRIVATE-CANARY\n"
    retained_bytes = b"QUARANTINE-PRIVATE-CANARY\n"
    ledger.write_bytes(ledger_bytes)
    retained.write_bytes(retained_bytes)
    monkeypatch.setenv("AGW_HOME", str(home))

    assert auditlog.log("posttooluse", {"payload": "PRIVATE-CANARY"}).ok
    assert ledger.read_bytes() == ledger_bytes
    assert retained.read_bytes() == retained_bytes
    assert sorted(path.relative_to(home) for path in home.rglob("*")) == [
        Path("audit.jsonl"), Path("legacy-audit-quarantine"),
        Path("legacy-audit-quarantine/retained.private"),
    ]


def test_compatibility_calls_never_reach_process_or_permission_helpers(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("forbidden helper was called")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "chmod", forbidden)
    monkeypatch.setattr(os, "chown", forbidden, raising=False)
    monkeypatch.setattr(os, "replace", forbidden)
    monkeypatch.setattr(os, "unlink", forbidden)
    assert auditlog.log("decision", {}).code == "host-history"
    assert auditlog.tail() == []


def test_runtime_import_never_loads_experimental_v2(monkeypatch):
    sys.modules.pop("core.auditlog_v2", None)
    reloaded = importlib.reload(auditlog)
    assert reloaded.status().code == "host-history"
    assert "core.auditlog_v2" not in sys.modules
    source = Path(reloaded.__file__).read_text(encoding="utf-8")
    assert "from .auditlog_v2" not in source
    assert "subprocess" not in source
    assert "ctypes" not in source


def test_legacy_fault_environment_does_not_change_host_decisions(tmp_path):
    payloads = {
        "claude": {
            "tool_name": "PowerShell",
            "tool_input": {"command": "agw future-operation private-value"},
            "cwd": str(ROOT), "session_id": "decision-parity",
            "hook_event_name": "PreToolUse",
        },
        "codex": {
            "tool_name": "PowerShell",
            "tool_input": {"command": "agw future-operation private-value"},
            "cwd": str(ROOT), "session_id": "decision-parity",
            "hook_event_name": "PreToolUse",
        },
    }
    for host, payload in payloads.items():
        baseline, _elapsed = _hook(host, payload, tmp_path / f"{host}-baseline")
        previous = os.environ.get("AGW_AUDIT_FAIL_AT")
        os.environ["AGW_AUDIT_FAIL_AT"] = "security_applied"
        try:
            faulted, _elapsed = _hook(host, payload, tmp_path / f"{host}-faulted")
        finally:
            if previous is None:
                os.environ.pop("AGW_AUDIT_FAIL_AT", None)
            else:
                os.environ["AGW_AUDIT_FAIL_AT"] = previous
        assert faulted == baseline


def test_fresh_hook_process_p95_is_below_two_seconds(tmp_path):
    samples = []
    payload = {
        "tool_name": "Bash", "tool_input": {"command": "git status"},
        "cwd": str(ROOT), "session_id": "performance",
        "hook_event_name": "PreToolUse",
    }
    for number in range(10):
        output, elapsed = _hook("claude", payload, tmp_path / f"claude-{number}")
        assert output == ""
        samples.append(elapsed)
    for number in range(10):
        output, elapsed = _hook("codex", payload, tmp_path / f"codex-{number}")
        assert output == ""
        samples.append(elapsed)
    p95 = statistics.quantiles(samples, n=100, method="inclusive")[94]
    print(f"HOOK_P95_SECONDS={p95:.6f}; MAX_SECONDS={max(samples):.6f}")
    assert len(samples) == 20
    assert p95 < 2.0, {"p95": p95, "maximum": max(samples)}
