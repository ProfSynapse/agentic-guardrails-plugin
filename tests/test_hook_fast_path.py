"""Per-call hook cost: what a routine call is allowed to load and touch.

These drive the real dispatchers as subprocesses, the way the host does, and
observe the import trace (`python -v`) rather than timing: timing is machine
specific, the set of modules a Read pulls in is not. Every optimization here
is paired with a fail-closed check, because a lazy import that fails must
still end in ASK.
"""
import json
import os
import re
import subprocess
import sys
import textwrap

import pytest

REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugin")
SCRIPTS = os.path.join(REPO, "scripts")

# Everything a routine (non-mutating, non-prompting) call must not load: the
# archive store and its transaction machinery, workflows, the mutation
# planner, pre-images, and the prompt/approval renderers.
HEAVY = {
    "core.store", "core.archive_transactions", "core.retention", "core.workflows",
    "core.mutations", "core.preimages", "core.presentation", "core.approvals",
    "core.decisions",
}


def _run(host, event, payload, env_extra=None, verbose=False, stdin=None):
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=REPO, PLUGIN_ROOT=REPO)
    env.pop("PYTHONDONTWRITEBYTECODE", None)
    if env_extra:
        env.update(env_extra)
    cmd = [sys.executable] + (["-v"] if verbose else []) + [
        os.path.join(SCRIPTS, host, "_dispatch.py"), event]
    text = stdin if stdin is not None else json.dumps(payload)
    return subprocess.run(cmd, input=text, capture_output=True, text=True,
                          env=env, timeout=60)


def _imports(result):
    """Module names the interpreter reported loading (import_module included)."""
    return set(re.findall(r"^import '([\w.]+)'", result.stderr, re.M))


def _decision(result):
    out = json.loads(result.stdout) if result.stdout.strip() else {}
    return out.get("hookSpecificOutput", {}).get("permissionDecision", "defer")


def _payload(tool, **tool_input):
    return {"tool_name": tool, "tool_input": tool_input, "cwd": os.getcwd(),
            "session_id": "fast-path", "hook_event_name": "PreToolUse",
            "tool_use_id": "tu-1"}


@pytest.fixture()
def plain_file(tmp_path):
    target = tmp_path / "notes.txt"
    target.write_text("ordinary notes\n", encoding="utf-8")
    return str(target)


# --- F12a: lazy imports per event kind ---------------------------------------

def test_remediation_no_longer_drags_in_the_store():
    """engine -> remediation -> mutations -> workflows -> store was on every call."""
    result = subprocess.run(
        [sys.executable, "-v", "-c", "import core.remediation"],
        capture_output=True, text=True, cwd=SCRIPTS, timeout=60)
    assert result.returncode == 0, result.stderr[-500:]
    loaded = _imports(result)
    assert "core.remediation" in loaded
    assert not loaded & HEAVY, sorted(loaded & HEAVY)


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_read_loads_neither_store_nor_planner(host, plain_file):
    result = _run(host, "pretooluse", _payload("Read", file_path=plain_file), verbose=True)
    assert result.returncode == 0
    assert _decision(result) == "defer", result.stdout
    assert not _imports(result) & HEAVY, sorted(_imports(result) & HEAVY)


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_mcp_read_loads_neither_store_nor_planner(host):
    result = _run(host, "pretooluse",
                  _payload("mcp__github__get_file_contents", owner="a", repo="b"),
                  verbose=True)
    assert result.returncode == 0
    assert _decision(result) == "defer", result.stdout
    assert not _imports(result) & HEAVY, sorted(_imports(result) & HEAVY)


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_mutating_calls_still_plan_and_snapshot(host, plain_file, tmp_path):
    """The lazy imports are a cost decision, not a coverage one."""
    if host == "claude":
        payload = _payload("Edit", file_path=plain_file, old_string="a", new_string="b")
    else:
        patch = ("*** Begin Patch\n*** Update File: %s\n@@\n-ordinary notes\n"
                 "+edited notes\n*** End Patch\n" % plain_file)
        payload = _payload("apply_patch", command=patch)
    result = _run(host, "pretooluse", payload, verbose=True,
                  env_extra={"AGW_HOME": str(tmp_path / "home")})
    assert result.returncode == 0
    assert _decision(result) == "defer", result.stdout
    loaded = _imports(result)
    assert {"core.mutations", "core.preimages", "core.store"} <= loaded
    archive = tmp_path / "home"
    assert any(p.name == "notes.txt" for p in archive.rglob("notes.txt")), \
        "the pre-image was not taken"


@pytest.mark.parametrize("host, expected", [("claude", "ask"), ("codex", "deny")])
def test_failed_lazy_import_still_fails_closed(host, expected, plain_file, tmp_path):
    """A module that only loads at its call site must still land in the net."""
    site = tmp_path / "site"
    site.mkdir()
    (site / "sitecustomize.py").write_text(textwrap.dedent("""
        import sys

        class _Poison:
            def find_spec(self, name, path=None, target=None):
                if name == "core.preimages":
                    raise ImportError("poisoned for the test")
                return None

        sys.meta_path.insert(0, _Poison())
    """), encoding="utf-8")
    if host == "claude":
        payload = _payload("Edit", file_path=plain_file, old_string="a", new_string="b")
    else:
        patch = ("*** Begin Patch\n*** Update File: %s\n@@\n-ordinary notes\n"
                 "+edited notes\n*** End Patch\n" % plain_file)
        payload = _payload("apply_patch", command=patch)
    result = _run(host, "pretooluse", payload,
                  env_extra={"PYTHONPATH": str(site), "AGW_HOME": str(tmp_path / "home")})
    assert result.returncode == 0
    assert _decision(result) == expected, result.stdout
    # Exactly one decision object on stdout: the fail-closed handler must not
    # append a second one to a stream that already carries a decision.
    assert result.stdout.count("hookSpecificOutput") == 1
