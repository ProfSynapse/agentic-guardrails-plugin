"""Real-time smoke test: a reviewed workflow outlives the 300-second default.

This drives the packaged CLI as a subprocess with the production default
(nothing shortened). A script sleeps 330 seconds and then writes its declared
output. Run untrusted, it is killed at 300 seconds; run through a trusted
workflow whose manifest declares `limits.timeout_seconds: 600`, it completes.
Both runs happen concurrently, so the test takes about six minutes.

Opt in with AGW_LONG_RUN_SMOKE=1. AGW_HOME is the per-test temporary store from
conftest, so no live trust record or policy is touched.
"""
import json
import os
import subprocess
import sys
import threading
import time

import pytest

from core import store, workflows

PLUGIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugin")
AGW = os.path.join(PLUGIN, "scripts", "agw", "agw.py")
SLEEP_SECONDS = 330

pytestmark = pytest.mark.skipif(
    os.environ.get("AGW_LONG_RUN_SMOKE") != "1",
    reason="six-minute real-time smoke; set AGW_LONG_RUN_SMOKE=1",
)


def _cli(args, results, key):
    started = time.monotonic()
    proc = subprocess.run([sys.executable, AGW, "--json", *args],
                          capture_output=True, text=True, timeout=900,
                          env=dict(os.environ))
    lines = (proc.stdout.strip() or proc.stderr.strip()).splitlines()
    results[key] = {
        "exit": proc.returncode,
        "wall_seconds": round(time.monotonic() - started, 1),
        "data": json.loads(lines[-1]) if lines else {},
    }


def test_trusted_workflow_runs_past_the_default_bound(tmp_path):
    script = tmp_path / "long_task.py"
    script.write_text(
        "import sys, time\n"
        "time.sleep(float(sys.argv[2]))\n"
        "open(sys.argv[1], 'w').write('finished')\n",
        encoding="utf-8",
    )
    manifest = {
        "schema": "agw.workflow/v3",
        "id": "smoke.long-task",
        "description": "sleep past the default bound, then write one output",
        "command": {
            "runtime": "python", "script": script.name,
            "script_sha256": store.file_sha256(str(script)),
            "args": [{"parameter": "output"}, {"parameter": "seconds"}],
        },
        "parameters": {
            "output": {"type": "path", "root": "{cwd}", "must_exist": False,
                       "kind": "file"},
            "seconds": {"type": "integer", "minimum": 1, "maximum": 3600},
        },
        "allowed_roots": ["{cwd}"],
        "outputs": [{"path": "{param:output}", "expected": "absent"}],
        "observed_roots": [],
        "limits": {"timeout_seconds": 600},
    }
    manifest_path = tmp_path / "long-task.workflow.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    workflows.trust_manifest(str(manifest_path), store.file_sha256(str(manifest_path)))

    untrusted_out = tmp_path / "untrusted.txt"
    trusted_out = tmp_path / "trusted.txt"
    results = {}
    runs = [
        threading.Thread(target=_cli, args=([
            "run", "--output", str(untrusted_out), "--expected-hash", "absent",
            "--cwd", str(tmp_path), "--",
            sys.executable, str(script), str(untrusted_out), str(SLEEP_SECONDS),
        ], results, "untrusted")),
        threading.Thread(target=_cli, args=([
            "run", "--workflow", "smoke.long-task",
            "--param", f"output={trusted_out}",
            "--param", f"seconds={SLEEP_SECONDS}", "--cwd", str(tmp_path),
        ], results, "workflow")),
    ]
    for run in runs:
        run.start()
    for run in runs:
        run.join()
    print(json.dumps({
        key: {"exit": value["exit"], "wall_seconds": value["wall_seconds"],
              "timed_out": value["data"].get("timed_out"),
              "duration_seconds": value["data"].get("duration_seconds"),
              "execution_policy": value["data"].get("execution_policy")}
        for key, value in results.items()
    }, indent=2))

    untrusted = results["untrusted"]
    assert untrusted["exit"] != 0
    assert untrusted["data"]["timed_out"] is True
    assert untrusted["data"]["execution_policy"]["timeout_seconds"] == 300.0
    assert untrusted["data"]["execution_policy"]["timeout_source"] == "default"
    assert 299 <= untrusted["data"]["duration_seconds"] < SLEEP_SECONDS
    assert not untrusted_out.exists()

    workflow = results["workflow"]
    assert workflow["exit"] == 0, workflow
    assert workflow["data"]["ok"] is True
    assert workflow["data"]["timed_out"] is False
    assert workflow["data"]["execution_policy"]["timeout_seconds"] == 600.0
    assert workflow["data"]["execution_policy"]["timeout_source"] == "workflow"
    assert workflow["data"]["duration_seconds"] >= SLEEP_SECONDS
    assert trusted_out.read_text() == "finished"
