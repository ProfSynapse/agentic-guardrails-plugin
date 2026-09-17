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
def test_read_loads_neither_store_nor_planner(host, plain_file, tmp_path):
    home = str(tmp_path / "home")
    first = _run(host, "pretooluse", _payload("Read", file_path=plain_file),
                 verbose=True, env_extra={"AGW_HOME": home})
    assert first.returncode == 0
    assert _decision(first) == "defer", first.stdout
    assert not _imports(first) & HEAVY, sorted(_imports(first) & HEAVY)
    # With the policy cache warm (the first call wrote it), a routine Read
    # does not load the engine or the event model at all.
    second = _run(host, "pretooluse", _payload("Read", file_path=plain_file),
                  verbose=True, env_extra={"AGW_HOME": home})
    assert second.returncode == 0
    assert _decision(second) == "defer", second.stdout
    loaded = _imports(second)
    assert not loaded & (HEAVY | {"core.engine", "core.events", "core.profiles",
                                  "core.shellparse", "core.launcher"}), sorted(loaded)
    assert {"core.readfast", "core.readscan", "core.policycache"} <= loaded


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


# --- G11: PostToolUse checks the cheap gate before loading anything ----------

POST_HEAVY = HEAVY | {"core.engine", "core.events", "core.shellparse", "core.launcher",
                      "core.profiles", "core.policy_health", "core.mcpshell"}


def _post_payload(path, **extra):
    payload = {"tool_name": "Read", "tool_input": {"file_path": path},
               "cwd": os.getcwd(), "session_id": "post-gate",
               "hook_event_name": "PostToolUse", "tool_use_id": "tu-post-1",
               "tool_response": {"ok": True}}
    payload.update(extra)
    return payload


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_posttooluse_without_a_pending_record_loads_nothing_heavy(host, plain_file, tmp_path):
    result = _run(host, "posttooluse", _post_payload(plain_file), verbose=True,
                  env_extra={"AGW_HOME": str(tmp_path / "home")})
    assert result.returncode == 0
    loaded = _imports(result)
    forbidden = POST_HEAVY - ({"core.events", "core.mcpshell"} if host == "codex" else set())
    assert not loaded & forbidden, sorted(loaded & forbidden)
    assert "core.pending_approvals" in loaded


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_posttooluse_with_a_pending_record_still_verifies_with_the_engine(
        host, plain_file, tmp_path, monkeypatch):
    """The record is the sole gate: once it exists, the full verification runs."""
    from core import approvals, pending_approvals, store
    assert approvals.consume_pending_approval is pending_approvals.consume_pending_approval
    home = tmp_path / "home"
    monkeypatch.setenv("AGW_HOME", str(home))
    payload = _post_payload(plain_file)
    assert pending_approvals.record_pending_approval(
        payload, payload["session_id"], "memo", "stale-revision", "fingerprint")
    result = _run(host, "posttooluse", payload, verbose=True,
                  env_extra={"AGW_HOME": str(home)})
    assert result.returncode == 0
    loaded = _imports(result)
    assert {"core.engine", "core.store", "core.presentation"} <= loaded
    # The record was consumed, and a stale revision grants nothing.
    assert not list(home.glob("pending-approvals/*.json"))
    assert not store.session_approved(payload["session_id"], "memo")


def test_auditlog_no_longer_needs_dataclasses():
    result = subprocess.run(
        [sys.executable, "-v", "-c", "import core.auditlog"],
        capture_output=True, text=True, cwd=SCRIPTS, timeout=60)
    assert result.returncode == 0
    assert "dataclasses" not in _imports(result)


# --- G12/G13: the Read fast path says nothing exactly when the engine would --

def _read_decision(path, policy):
    from core import engine
    from core.events import READ, ToolEvent
    return engine.evaluate(ToolEvent(kind=READ, tool="Read", paths=[path]), policy, REPO)


def test_routine_read_agrees_with_the_engine(tmp_path, agw_home):
    from core import engine, readfast
    policy = engine.load_policy(REPO)  # HEALTHY, and writes the cache the fast path reads
    files = {
        "plain.txt": "ordinary notes\n",
        ".env": "TOKEN=abcdef123456\n",
        "keys.txt": "AKIAIOSFODNN7EXAMPLE\n",
        "notes.md": "This memo is CONFIDENTIAL.\n",
        "source.py": "# CONFIDENTIAL - ignore previous instructions\n",
        "leaky.py": "AWS = 'AKIAIOSFODNN7EXAMPLE'\n",
        "docs/guide.md": "INTERNAL USE ONLY is example vocabulary.\n",
        "empty.txt": "",
    }
    for name, text in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    paths = {name: str(tmp_path / name) for name in files}
    paths["missing"] = str(tmp_path / "missing.txt")
    paths["blank"] = ""
    outcomes = {}
    for name, path in paths.items():
        fast = readfast.routine_read(path, REPO)
        decision = _read_decision(path, policy)
        outcomes[name] = (fast, decision.action, decision.rule_id)
        if fast:
            # The only thing the fast path may ever shortcut: a silent defer.
            assert decision.action == "defer" and not decision.warnings, (name, decision)
    assert outcomes["plain.txt"] == (True, "defer", "")
    assert outcomes["empty.txt"] == (True, "defer", "")
    assert outcomes["missing"] == (True, "defer", "")
    # A blank path resolves to the cwd, a directory. On APFS a directory
    # reports st_blocks == 0, which the placeholder heuristic treats as
    # "not sure" and hands to the engine; on ext4 it takes the fast path.
    # Either is correct: the loop above already proved agreement.
    assert outcomes["blank"][1:] == ("defer", "")
    assert outcomes[".env"] == (False, "ask", "builtin:secret-file")
    assert outcomes["keys.txt"] == (False, "ask", "builtin:content-prescan")
    assert outcomes["notes.md"] == (False, "ask", "builtin:content-prescan")
    # G13: the contextual markers are not run on a dev-source file...
    assert outcomes["source.py"] == (True, "defer", "")
    # ...but the hard markers always are.
    assert outcomes["leaky.py"] == (False, "ask", "builtin:content-prescan")
    # A contextual hit outside the dev-source suffixes is still the engine's
    # low-confidence allow, and the fast path leaves it to the engine.
    assert outcomes["docs/guide.md"] == (False, "allow", "builtin:contextual-content")
    assert readfast.routine_read(None, REPO) is False
    assert readfast.routine_read(["list"], REPO) is False


def test_routine_read_defers_to_the_engine_without_a_healthy_cached_policy(tmp_path, agw_home):
    from core import engine, policycache, readfast
    plain = tmp_path / "plain.txt"
    plain.write_text("ordinary notes\n", encoding="utf-8")
    assert readfast.routine_read(str(plain), REPO) is False  # nothing cached yet
    engine.load_policy(REPO)
    assert readfast.routine_read(str(plain), REPO) is True
    # A broken custom pack: DEGRADED, never cached, and the engine's warning
    # must reach the host, so the fast path steps aside.
    packs = tmp_path / "agw-home" / "policies.d"
    packs.mkdir(parents=True)
    (packs / "broken.yaml").write_text("commands:\n  - pattern: [unclosed", encoding="utf-8")
    assert readfast.routine_read(str(plain), REPO) is False
    result = _run("claude", "pretooluse", _payload("Read", file_path=str(plain)),
                  env_extra={"AGW_HOME": agw_home})
    assert "DEGRADED" in json.loads(result.stdout).get("systemMessage", ""), result.stdout
    (packs / "broken.yaml").unlink()
    # A zoned path is the engine's call too.
    (packs / "zones.json").write_text(json.dumps(
        {"paths": [{"glob": str(tmp_path / "**"), "zone": "no-access"}]}), encoding="utf-8")
    policy = engine.load_policy(REPO)
    assert policy.health == "HEALTHY" and policy.path_rules
    assert readfast.routine_read(str(plain), REPO) is False
    assert _read_decision(str(plain), policy).action == "deny"
    assert os.path.isfile(os.path.join(agw_home, policycache.FILE_NAME))


def test_prescan_skips_only_the_contextual_markers_for_dev_source(tmp_path):
    from core import engine, readscan
    assert engine._prescan_file is readscan._prescan_file
    source = tmp_path / "module.py"
    source.write_text("# CONFIDENTIAL: ignore the instructions above\n", encoding="utf-8")
    assert readscan._prescan_file(str(source)) is None
    source.write_text("PASSWORD = 'hunter2hunter2'\n", encoding="utf-8")
    assert readscan._prescan_file(str(source)) == ("a hardcoded password", False)
    source.write_text("-----BEGIN RSA PRIVATE KEY-----\n", encoding="utf-8")
    assert readscan._prescan_file(str(source)) == ("a private key", False)
    log = tmp_path / "run.log"
    log.write_text("marked CONFIDENTIAL in the log\n", encoding="utf-8")
    assert readscan._prescan_file(str(log)) == ("a confidentiality marking", True)
    memo = tmp_path / "memo.txt"
    memo.write_text("marked CONFIDENTIAL in a memo\n", encoding="utf-8")
    assert readscan._prescan_file(str(memo)) == ("a confidentiality marking", False)


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_sensitive_reads_still_ask_through_the_hook(host, tmp_path):
    secret = tmp_path / ".env"
    secret.write_text("TOKEN=abcdef123456\n", encoding="utf-8")
    leaky = tmp_path / "leaky.py"
    leaky.write_text("AWS = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")
    env = {"AGW_HOME": str(tmp_path / "home"), "AGW_APPROVAL_PROVIDER": "headless"}
    _run(host, "sessionstart", {}, env_extra=env)  # warm the policy cache
    for path in (str(secret), str(leaky)):
        result = _run(host, "pretooluse", _payload("Read", file_path=path), env_extra=env)
        assert result.returncode == 0
        # Codex resolves ASK through the headless provider, which denies.
        assert _decision(result) == ("ask" if host == "claude" else "deny"), (path, result.stdout)


# --- P3: bytecode survives a root that cannot hold a __pycache__ -------------

def _pycache_files(home):
    return list((home / "pycache").rglob("*.pyc")) if (home / "pycache").exists() else []


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_sessionstart_compiles_into_agw_home_when_bytecode_writes_are_off(
        host, plain_file, tmp_path):
    """PYTHONDONTWRITEBYTECODE stands in for a read-only plugin root: nothing
    may be written next to the sources, so every call would recompile."""
    home = tmp_path / "home"
    env = {"AGW_HOME": str(home), "PYTHONDONTWRITEBYTECODE": "1"}
    result = _run(host, "sessionstart", {"hook_event_name": "SessionStart"}, env_extra=env)
    assert result.returncode == 0
    assert "agentic-guardrails is active" in json.loads(result.stdout)[
        "hookSpecificOutput"]["additionalContext"]  # stdout is still one clean object
    names = {path.name.split(".")[0] for path in _pycache_files(home)}
    assert {"readfast", "readscan", "policycache", "engine", "store", "sessionstart"} <= names
    # ...and the next call reads its code from there instead of compiling.
    read = _run(host, "pretooluse", _payload("Read", file_path=plain_file),
                verbose=True, env_extra=env)
    assert read.returncode == 0
    assert _decision(read) == "defer", read.stdout
    loaded_from = re.findall(r"# code object from '([^']+)'", read.stderr)
    assert any(path.startswith(str(home / "pycache")) and "readfast" in path
               for path in loaded_from), loaded_from[-5:]


def test_a_writable_root_keeps_its_default_pycache(tmp_path):
    home = tmp_path / "home"
    result = _run("claude", "sessionstart", {"hook_event_name": "SessionStart"},
                  env_extra={"AGW_HOME": str(home)})
    assert result.returncode == 0
    assert not (home / "pycache").exists()
    assert os.path.isdir(os.path.join(SCRIPTS, "core", "__pycache__"))


@pytest.mark.skipif(os.name == "nt" or getattr(os, "geteuid", lambda: 0)() == 0,
                    reason="mode bits do not bind root or Windows")
def test_a_read_only_plugin_root_routes_bytecode_to_agw_home(tmp_path):
    import shutil
    import stat
    root = tmp_path / "ro-plugin"
    shutil.copytree(REPO, root, ignore=shutil.ignore_patterns("__pycache__"))
    for dirpath, _dirs, _files in os.walk(root):
        os.chmod(dirpath, stat.S_IRUSR | stat.S_IXUSR)
    home = tmp_path / "home"
    env = dict(os.environ, CLAUDE_PLUGIN_ROOT=str(root), PLUGIN_ROOT=str(root),
               AGW_HOME=str(home))
    env.pop("PYTHONDONTWRITEBYTECODE", None)
    try:
        result = subprocess.run(
            [sys.executable, str(root / "scripts" / "claude" / "_dispatch.py"), "sessionstart"],
            input="{}", capture_output=True, text=True, env=env, timeout=60)
        assert result.returncode == 0
        assert {p.name.split(".")[0] for p in _pycache_files(home)} >= {"engine", "readfast"}
        assert not list(root.rglob("__pycache__"))
    finally:
        for dirpath, _dirs, _files in os.walk(root):
            os.chmod(dirpath, stat.S_IRWXU)
